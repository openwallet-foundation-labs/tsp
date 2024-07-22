use base64ct::{Base64UrlUnpadded, Encoding};
use clap::{Parser, Subcommand};
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, path::PathBuf};
use tokio::io::AsyncReadExt;
use tracing::{info, trace};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use tsp::{
    cesr::Part, AsyncStore, Error, ExportVid, OwnedVid, ReceivedTspMessage, Vault, VerifiedVid,
};

#[derive(Debug, Parser)]
#[command(name = "tsp")]
#[command(about = "Send and receive TSP messages", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
    #[arg(short, long, default_value = "database", help = "Database name to use")]
    database: String,
    #[arg(
        long,
        default_value = "unsecure",
        help = "Password used to encrypt the database"
    )]
    password: String,
    #[arg(
        short,
        long,
        default_value = "tsp-test.org",
        help = "Test server domain"
    )]
    server: String,
    #[arg(short, long)]
    verbose: bool,
    #[arg(short, long, help = "Always answer yes to any prompts")]
    yes: bool,
    #[arg(short, long, help = "Pretty print CESR messages")]
    pretty_print: bool,
}

#[derive(Debug, Subcommand)]
enum Commands {
    #[command(arg_required_else_help = true)]
    Verify {
        vid: String,
        #[arg(short, long)]
        alias: Option<String>,
        #[arg(short, long)]
        sender: Option<String>,
    },
    #[command(arg_required_else_help = true)]
    Print { alias: String },
    Create {
        username: String,
        #[arg(short, long)]
        alias: Option<String>,
    },
    #[command(arg_required_else_help = true)]
    CreatePeer { alias: String },
    CreateFromFile {
        file: PathBuf,
        #[arg(short, long)]
        alias: Option<String>,
    },
    #[command(arg_required_else_help = true)]
    SetRoute { vid: String, route: String },
    #[command(arg_required_else_help = true)]
    SetParent { vid: String, other_vid: String },
    #[command(arg_required_else_help = true)]
    SetRelation { vid: String, other_vid: String },
    #[command(arg_required_else_help = true)]
    Send {
        #[arg(short, long, required = true)]
        sender_vid: String,
        #[arg(short, long, required = true)]
        receiver_vid: String,
        #[arg(short, long)]
        non_confidential_data: Option<String>,
    },
    #[command(arg_required_else_help = true)]
    Receive {
        vid: String,
        #[arg(short, long)]
        one: bool,
    },
    #[command(arg_required_else_help = true)]
    Request {
        #[arg(short, long, required = true)]
        sender_vid: String,
        #[arg(short, long, required = true)]
        receiver_vid: String,
        #[arg(long)]
        nested: bool,
    },
    Accept {
        #[arg(short, long, required = true)]
        sender_vid: String,
        #[arg(short, long, required = true)]
        receiver_vid: String,
        #[arg(long, required = true)]
        thread_id: String,
        #[arg(long)]
        nested: bool,
    },
    Cancel {
        #[arg(short, long, required = true)]
        sender_vid: String,
        #[arg(short, long, required = true)]
        receiver_vid: String,
    },
}

type Aliases = HashMap<String, String>;

#[derive(Serialize, Deserialize)]
struct DatabaseContents {
    data: Vec<ExportVid>,
    aliases: Aliases,
}

async fn write_database(vault: &Vault, db: &AsyncStore, aliases: Aliases) -> Result<(), Error> {
    let aliases = serde_json::to_value(&aliases).ok();
    vault.persist(db.export()?, aliases).await?;

    trace!("persisted database");

    Ok(())
}

async fn read_database(
    database_name: &str,
    password: &str,
) -> Result<(Vault, AsyncStore, Aliases), Error> {
    match Vault::open_sqlite(database_name, password.as_bytes()).await {
        Ok(vault) => {
            let (vids, aliases) = vault.load().await?;

            let aliases: Aliases = match aliases {
                Some(aliases) => serde_json::from_value(aliases).expect("Invalid aliases"),
                None => Aliases::new(),
            };

            let db = AsyncStore::new();
            db.import(vids)?;

            trace!("opened database {database_name}");

            Ok((vault, db, aliases))
        }
        Err(_) => {
            let vault = Vault::new_sqlite(database_name, password.as_bytes()).await?;

            let db = AsyncStore::new();
            info!("created new database");

            Ok((vault, db, Aliases::new()))
        }
    }
}

fn color_print_part(part: Option<Part>, color: u8) {
    if let Some(Part { prefix, data }) = part {
        print!(
            "\x1b[1;{color}m{}\x1b[0;{color}m{}\x1b[0m",
            Base64UrlUnpadded::encode_string(prefix),
            Base64UrlUnpadded::encode_string(data)
        );
    }
}

fn print_message(message: &[u8]) {
    let Ok(parts) = tsp::cesr::open_message_into_parts(message) else {
        eprintln!("Invalid encoded message");
        return;
    };

    println!("CESR-encoded message:");

    color_print_part(Some(parts.prefix), 31);
    color_print_part(Some(parts.sender), 35);
    color_print_part(parts.receiver, 34);
    color_print_part(parts.nonconfidential_data, 32);
    color_print_part(parts.ciphertext, 33);
    color_print_part(Some(parts.signature), 36);

    println!();
}

async fn run() -> Result<(), Error> {
    let args = Cli::parse();

    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().compact().without_time())
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                if args.verbose {
                    "tsp=trace"
                } else {
                    "tsp=info"
                }
                .into()
            }),
        )
        .init();

    let (vault, mut vid_database, mut aliases) =
        read_database(&args.database, &args.password).await?;
    let server: String = args.server;

    match args.command {
        Commands::Verify { vid, alias, sender } => {
            vid_database.verify_vid(&vid).await?;
            let sender = sender.map(|s| aliases.get(&s).cloned().unwrap_or(s));

            if let Some(alias) = alias {
                aliases.insert(alias.clone(), vid.clone());
            }

            vid_database.set_relation_for_vid(&vid, sender.as_deref())?;

            write_database(&vault, &vid_database, aliases).await?;

            info!(
                "{vid} is verified and added to the database {}",
                &args.database
            );
        }
        Commands::Print { alias } => {
            let vid = aliases.get(&alias).unwrap_or(&alias);

            print!("{vid}");
        }
        Commands::Create { username, alias } => {
            let did = format!("did:web:{server}:user:{username}");

            if let Some(alias) = alias {
                aliases.insert(alias.clone(), did.clone());
                info!("added alias {alias} -> {did}");
            }

            let url = format!("https://{server}/user/{username}");
            let transport = url::Url::parse(&url).unwrap();

            let private_vid = OwnedVid::bind(&did, transport);
            info!("created identity {}", private_vid.identifier());

            reqwest::Client::new()
                .post(format!("https://{server}/add-vid"))
                .json(&private_vid)
                .send()
                .await
                .expect("Could not publish VID on server");

            trace!("published DID document to {url}/did.json");

            vid_database.add_private_vid(private_vid.clone())?;
            write_database(&vault, &vid_database, aliases).await?;
        }
        Commands::CreatePeer { alias } => {
            let transport = url::Url::parse(&format!("https://{server}/user/{alias}")).unwrap();
            let private_vid = OwnedVid::new_did_peer(transport);

            aliases.insert(alias.clone(), private_vid.identifier().to_string());

            vid_database.add_private_vid(private_vid.clone())?;
            write_database(&vault, &vid_database, aliases).await?;

            info!("created peer identity {}", private_vid.identifier());
        }
        Commands::CreateFromFile { file, alias } => {
            let private_vid = OwnedVid::from_file(file).await?;
            vid_database.add_private_vid(private_vid.clone())?;

            if let Some(alias) = alias {
                aliases.insert(alias.clone(), private_vid.identifier().to_string());
            }

            write_database(&vault, &vid_database, aliases).await?;

            info!("created identity from file {}", private_vid.identifier());
        }
        Commands::SetParent { vid, other_vid } => {
            let vid = aliases.get(&vid).unwrap_or(&vid);
            let other_vid = aliases.get(&other_vid).unwrap_or(&other_vid);

            vid_database.set_parent_for_vid(vid, Some(other_vid))?;

            info!("{vid} is now a child of {other_vid}");

            write_database(&vault, &vid_database, aliases).await?;
        }
        Commands::SetRoute { vid, route } => {
            let vid = aliases.get(&vid).cloned().unwrap_or(vid);

            let route: Vec<_> = route
                .split(',')
                .map(|s| aliases.get(s).cloned().unwrap_or(s.to_string()))
                .collect();

            let route_ref = route.iter().map(|s| s.as_str()).collect::<Vec<_>>();

            vid_database.set_route_for_vid(&vid, &route_ref)?;
            write_database(&vault, &vid_database, aliases).await?;

            info!("{vid} has route {route:?}");
        }
        Commands::SetRelation { vid, other_vid } => {
            let vid = aliases.get(&vid).cloned().unwrap_or(vid);
            let other_vid = aliases.get(&other_vid).cloned().unwrap_or(other_vid);

            vid_database.set_relation_for_vid(&vid, Some(&other_vid))?;
            write_database(&vault, &vid_database, aliases).await?;

            info!("{vid} has relation to {other_vid}");
        }
        Commands::Send {
            sender_vid,
            receiver_vid,
            non_confidential_data,
        } => {
            let sender_vid = aliases.get(&sender_vid).unwrap_or(&sender_vid);
            let receiver_vid = aliases.get(&receiver_vid).unwrap_or(&receiver_vid);

            let non_confidential_data = non_confidential_data.as_deref().map(|s| s.as_bytes());

            let mut message = Vec::new();
            tokio::io::stdin()
                .read_to_end(&mut message)
                .await
                .expect("Could not read message from stdin");

            match vid_database
                .send(sender_vid, receiver_vid, non_confidential_data, &message)
                .await
            {
                Ok(()) => {}
                Err(e) => {
                    tracing::error!(
                        "error sending message from {sender_vid} to {receiver_vid}: {e}"
                    );

                    return Ok(());
                }
            };

            if args.pretty_print {
                let cesr_message = vid_database
                    .as_store()
                    .seal_message(sender_vid, receiver_vid, non_confidential_data, &message)?
                    .1;
                print_message(&cesr_message);
            }

            info!(
                "sent message ({} bytes) from {sender_vid} to {receiver_vid}",
                message.len()
            );
        }
        Commands::Receive { vid, one } => {
            let vid = aliases.get(&vid).cloned().unwrap_or(vid);
            let mut messages = vid_database.receive(&vid).await?;

            info!("listening for messages...");

            while let Some(Ok(message)) = messages.next().await {
                let handle_message = |message| {
                    match message {
                        ReceivedTspMessage::GenericMessage {
                            sender,
                            nonconfidential_data: _,
                            message,
                            message_type: _,
                        } => {
                            info!("received message ({} bytes) from {}", message.len(), sender,);
                            println!("{}", String::from_utf8_lossy(&message),);
                        }
                        ReceivedTspMessage::RequestRelationship {
                            sender,
                            thread_id,
                            route: _,
                            nested_vid: None,
                        } => {
                            let thread_id = Base64UrlUnpadded::encode_string(&thread_id);
                            info!(
                                "received relationship request from {sender}, thread-id '{thread_id}'",
                            );
                        }
                        ReceivedTspMessage::AcceptRelationship {
                            sender,
                            nested_vid: None,
                        } => {
                            info!("received accept relationship from {}", sender);
                        }
                        ReceivedTspMessage::RequestRelationship {
                            sender,
                            thread_id,
                            route: _,
                            nested_vid: Some(vid),
                        } => {
                            let thread_id = Base64UrlUnpadded::encode_string(&thread_id);
                            info!("received nested relationship request from '{vid}' (new identity for {sender}), thread-id '{thread_id}'");
                        }
                        ReceivedTspMessage::AcceptRelationship {
                            sender,
                            nested_vid: Some(vid),
                        } => {
                            info!("received accept nested relationship from '{vid}' (new identity for {sender})");
                        }
                        ReceivedTspMessage::CancelRelationship { sender } => {
                            info!("received cancel relationship from {sender}");
                        }
                        ReceivedTspMessage::ForwardRequest {
                            sender, next_hop, ..
                        } => {
                            info!("messaging forwarding request from {sender} to {next_hop}",);
                        }
                        ReceivedTspMessage::NewIdentifier { sender, new_vid } => {
                            info!("received request for new identifier '{new_vid}' from {sender}");
                        }
                        ReceivedTspMessage::Referral {
                            sender,
                            referred_vid,
                        } => {
                            info!(
                                "received relationship referral for '{referred_vid}' from {sender}"
                            );
                        }
                        ReceivedTspMessage::PendingMessage {
                            unknown_vid,
                            payload,
                        } => {
                            use std::io::{self, BufRead, Write};
                            info!("message involving unknown party {}", unknown_vid);
                            print!(
                                "do you want to read a message from '{}' [y/n]? ",
                                unknown_vid
                            );
                            io::stdout().flush().expect("I/O error");

                            let user_affirms = args.yes || {
                                let mut line = String::new();
                                io::stdin()
                                    .lock()
                                    .read_line(&mut line)
                                    .expect("could not read reply");
                                line = line.to_uppercase();

                                matches!(line.trim(), "Y" | "YES")
                            };

                            if user_affirms {
                                trace!("processing pending message");
                                return Some((unknown_vid, payload));
                            }
                        }
                    }

                    None
                };

                if let Some((unknown_vid, mut payload)) = handle_message(message) {
                    let message = vid_database
                        .verify_and_open(&unknown_vid, &mut payload)
                        .await?;

                    info!(
                        "{vid} is verified and added to the database {}",
                        &args.database
                    );
                    let _ = handle_message(message);
                }
                write_database(&vault, &vid_database, aliases.clone()).await?;

                if one {
                    break;
                }
            }
        }
        Commands::Cancel {
            sender_vid,
            receiver_vid,
        } => {
            let sender_vid = aliases.get(&sender_vid).unwrap_or(&sender_vid);
            let receiver_vid = aliases.get(&receiver_vid).unwrap_or(&receiver_vid);

            if let Err(e) = vid_database
                .send_relationship_cancel(sender_vid, receiver_vid)
                .await
            {
                tracing::error!("error sending message from {sender_vid} to {receiver_vid}: {e}");

                return Ok(());
            }

            info!("sent control message from {sender_vid} to {receiver_vid}",);
            write_database(&vault, &vid_database, aliases.clone()).await?;
        }
        Commands::Request {
            sender_vid,
            receiver_vid,
            nested,
        } => {
            let sender_vid = aliases.get(&sender_vid).unwrap_or(&sender_vid);
            let receiver_vid = aliases.get(&receiver_vid).unwrap_or(&receiver_vid);

            if nested {
                match vid_database
                    .send_nested_relationship_request(sender_vid, receiver_vid)
                    .await
                {
                    Ok(vid) => {
                        tracing::info!(
			    "sent a nested relationship request to {receiver_vid} with new identity '{}'",
			    vid.identifier()
                    );
                    }
                    Err(e) => {
                        tracing::error!(
                            "error sending message from {sender_vid} to {receiver_vid}: {e}"
                        );
                        return Ok(());
                    }
                }
            } else if let Err(e) = vid_database
                .send_relationship_request(sender_vid, receiver_vid, None)
                .await
            {
                tracing::error!("error sending message from {sender_vid} to {receiver_vid}: {e}");
                return Ok(());
            }

            info!("sent control message from {sender_vid} to {receiver_vid}",);
            write_database(&vault, &vid_database, aliases.clone()).await?;
        }
        Commands::Accept {
            sender_vid,
            receiver_vid,
            thread_id,
            nested,
        } => {
            let sender_vid = aliases.get(&sender_vid).unwrap_or(&sender_vid);
            let receiver_vid = aliases.get(&receiver_vid).unwrap_or(&receiver_vid);

            let mut digest: [u8; 32] = Default::default();
            Base64UrlUnpadded::decode(&thread_id, &mut digest).unwrap();

            if nested {
                match vid_database
                    .send_nested_relationship_accept(sender_vid, receiver_vid, digest)
                    .await
                {
                    Ok(vid) => {
                        tracing::info!(
			    "formed a nested relationship with {receiver_vid} with new identity '{}'",
			    vid.identifier()
			);
                    }
                    Err(e) => {
                        tracing::error!(
                            "error sending message from {sender_vid} to {receiver_vid}: {e}"
                        );

                        return Ok(());
                    }
                }
            } else if let Err(e) = vid_database
                .send_relationship_accept(sender_vid, receiver_vid, digest, None)
                .await
            {
                tracing::error!("error sending message from {sender_vid} to {receiver_vid}: {e}");

                return Ok(());
            }

            info!("sent control message from {sender_vid} to {receiver_vid}",);
            write_database(&vault, &vid_database, aliases.clone()).await?;
        }
    }

    vault.close().await?;

    Ok(())
}

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("{e}");
        std::process::exit(1);
    }
}
