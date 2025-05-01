use base64ct::{Base64, Base64Unpadded, Base64UrlUnpadded, Encoding};
use bytes::BytesMut;
use clap::{Parser, Subcommand};
use futures::StreamExt;
use rustls::crypto::CryptoProvider;
use std::ops::Deref;
use std::path::PathBuf;
use tokio::io::AsyncReadExt;
use tracing::{debug, error, info, trace};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use tsp_sdk::{
    AskarSecureStorage, AsyncSecureStore, Error, OwnedVid, ReceivedTspMessage, SecureStorage,
    VerifiedVid, Vid,
    cesr::{self, Part},
};

#[derive(Debug, Parser)]
#[command(name = "tsp", version)]
#[command(about = "Send and receive TSP messages", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
    #[arg(short, long, default_value = "wallet", help = "Wallet name to use")]
    wallet: String,
    #[arg(
        long,
        default_value = "unsecure",
        help = "Password used to encrypt the wallet"
    )]
    password: String,
    #[arg(
        short,
        long,
        default_value = "demo.teaspoon.world",
        help = "Test server domain"
    )]
    server: String,
    #[arg(long, default_value = "did.teaspoon.world", help = "DID server domain")]
    did_server: String,
    #[arg(long)]
    verbose: bool,
    #[arg(short, long, help = "Always answer yes to any prompts")]
    yes: bool,
}

#[derive(Debug, Subcommand)]
enum Commands {
    #[command(subcommand, about = "Show information stored in the wallet")]
    Show(ShowCommands),
    #[command(
        arg_required_else_help = true,
        about = "verify and add a identifier to the wallet"
    )]
    Verify {
        vid: String,
        #[arg(short, long)]
        alias: Option<String>,
        #[arg(short, long)]
        sender: Option<String>,
    },
    #[command(arg_required_else_help = true)]
    Print { alias: String },
    #[command(
        arg_required_else_help = true,
        about = "create and register a did:web identifier"
    )]
    Create {
        username: String,
        #[arg(short, long)]
        alias: Option<String>,
    },
    CreatePeer {
        alias: String,
        #[arg(
            long,
            help = "Specify a network address and port instead of HTTPS transport"
        )]
        tcp: Option<String>,
    },
    #[command(
        arg_required_else_help = true,
        about = "import an identity from a file (for demo purposes only)"
    )]
    ImportPiv {
        file: PathBuf,
        #[arg(short, long)]
        alias: Option<String>,
    },
    #[command(about = "Discover DIDs from the DID support server")]
    Discover,
    #[command(arg_required_else_help = true)]
    SetAlias { alias: String, vid: String },
    #[command(arg_required_else_help = true)]
    SetRoute { vid: String, route: String },
    #[command(arg_required_else_help = true)]
    SetParent { vid: String, other_vid: String },
    #[command(arg_required_else_help = true)]
    SetRelation { vid: String, other_vid: String },
    #[command(arg_required_else_help = true, about = "send a message")]
    Send {
        #[arg(short, long, required = true)]
        sender_vid: String,
        #[arg(short, long, required = true)]
        receiver_vid: String,
        #[arg(short, long)]
        non_confidential_data: Option<String>,
    },
    #[command(arg_required_else_help = true, about = "listen for messages")]
    Receive {
        vid: String,
        #[arg(short, long)]
        one: bool,
    },
    #[command(arg_required_else_help = true, about = "propose a relationship")]
    Request {
        #[arg(short, long, required = true)]
        sender_vid: String,
        #[arg(short, long, required = true)]
        receiver_vid: String,
        #[arg(long)]
        nested: bool,
        #[arg(
            short,
            long,
            help = "parent VID of the sender, used to listen for a response"
        )]
        parent_vid: Option<String>,
    },
    #[command(arg_required_else_help = true, about = "accept a relationship")]
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
    #[command(arg_required_else_help = true, about = "break up a relationship")]
    Cancel {
        #[arg(short, long, required = true)]
        sender_vid: String,
        #[arg(short, long, required = true)]
        receiver_vid: String,
    },
    #[command(arg_required_else_help = true, about = "send an identity referral")]
    Refer {
        #[arg(short, long, required = true)]
        sender_vid: String,
        #[arg(short, long, required = true)]
        receiver_vid: String,
        #[arg(long, required = true)]
        referred_vid: String,
    },
    #[command(arg_required_else_help = true, about = "publish a new own identity")]
    Publish {
        #[arg(short, long, required = true)]
        sender_vid: String,
        #[arg(short, long, required = true)]
        receiver_vid: String,
        #[arg(short, long, required = true)]
        new_vid: String,
    },
}

#[derive(Debug, Parser)]
enum ShowCommands {
    #[command(about = "List all local VIDs")]
    Local,
    #[command(
        about = "List all relationships for a specific local VID",
        arg_required_else_help = true
    )]
    Relations { vid: String },
}

async fn write_wallet(vault: &AskarSecureStorage, db: &AsyncSecureStore) -> Result<(), Error> {
    vault.persist(db.export()?).await?;

    trace!("persisted wallet");

    Ok(())
}

async fn read_wallet(
    wallet_name: &str,
    password: &str,
) -> Result<(AskarSecureStorage, AsyncSecureStore), Error> {
    let url = format!("sqlite://{wallet_name}.sqlite");
    match AskarSecureStorage::open(&url, password.as_bytes()).await {
        Ok(vault) => {
            let (vids, aliases) = vault.read().await?;

            let db = AsyncSecureStore::new();
            db.import(vids, aliases)?;

            trace!("opened wallet {wallet_name}");

            Ok((vault, db))
        }
        Err(_) => {
            let vault = AskarSecureStorage::new(&url, password.as_bytes()).await?;

            let db = AsyncSecureStore::new();
            info!("created new wallet");

            Ok((vault, db))
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
    let Ok(parts) = tsp_sdk::cesr::open_message_into_parts(message) else {
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

fn prompt(message: String) -> bool {
    use std::io::{self, BufRead, Write};
    print!("{message}? [y/n] ");
    io::stdout().flush().expect("I/O error");
    let mut line = String::new();
    io::stdin()
        .lock()
        .read_line(&mut line)
        .expect("could not read reply");
    line = line.to_uppercase();

    matches!(line.trim(), "Y" | "YES")
}

async fn run() -> Result<(), Error> {
    let args = Cli::parse();

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .compact()
                .without_time()
                .with_writer(std::io::stderr),
        )
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

    CryptoProvider::install_default(rustls::crypto::aws_lc_rs::default_provider())
        .expect("Failed to install crypto provider");

    let (vault, mut vid_wallet) = read_wallet(&args.wallet, &args.password).await?;
    let server: String = args.server;
    let did_server = args.did_server;

    match args.command {
        Commands::Show(sub) => {
            let (mut vids, aliases) = vid_wallet.export()?;
            vids.sort_by(|a, b| a.id.cmp(&b.id));

            match sub {
                ShowCommands::Local => {
                    for vid in vids.into_iter().filter(|v| v.is_private()) {
                        let transport = if vid.transport.as_str() == "tsp://" {
                            vid.parent_vid.unwrap_or("None".to_string())
                        } else {
                            vid.transport.as_str().to_string()
                        };

                        let did_doc = if vid.id.starts_with("did:web") {
                            tsp_sdk::vid::did::get_resolve_url(&vid.id)?.to_string()
                        } else {
                            "None".to_string()
                        };
                        let alias = aliases
                            .iter()
                            .find_map(|(a, id)| if id == &vid.id { Some(a.clone()) } else { None })
                            .unwrap_or("None".to_string());

                        println!("{}", &vid.id);
                        println!("\t Alias: {}", alias);
                        println!("\t Transport: {}", transport);
                        println!("\t DID doc: {}", did_doc);
                        println!(
                            "\t public enc key: {}",
                            Base64::encode_string(vid.public_enckey.deref())
                        );
                        println!(
                            "\t public sign key: {}",
                            Base64::encode_string(vid.public_sigkey.deref())
                        );
                        println!();
                    }
                }
                ShowCommands::Relations { vid } => {
                    let vid = aliases.get(&vid).unwrap_or(&vid);
                    for vid in vids
                        .into_iter()
                        .filter(|v| v.relation_vid.as_deref() == Some(vid))
                    {
                        let did_doc = if vid.id.starts_with("did:web") {
                            tsp_sdk::vid::did::get_resolve_url(&vid.id)?.to_string()
                        } else {
                            "None".to_string()
                        };

                        let alias = aliases
                            .iter()
                            .find_map(|(a, id)| if id == &vid.id { Some(a.clone()) } else { None })
                            .unwrap_or("None".to_string());

                        println!("{}", &vid.id);
                        println!("\t Relation Status: {}", vid.relation_status);
                        println!("\t Alias: {}", alias);
                        println!("\t Transport: {}", vid.transport);
                        println!("\t DID doc: {}", did_doc);
                        println!(
                            "\t public enc key: {}",
                            Base64::encode_string(vid.public_enckey.deref())
                        );
                        println!(
                            "\t public sign key: {}",
                            Base64::encode_string(vid.public_sigkey.deref())
                        );
                        println!();
                    }
                }
            }
        }
        Commands::Verify { vid, alias, sender } => {
            vid_wallet.verify_vid(&vid, alias).await?;

            vid_wallet.set_relation_for_vid(&vid, sender.as_deref())?;

            write_wallet(&vault, &vid_wallet).await?;

            info!("{vid} is verified and added to the wallet {}", &args.wallet);
        }
        Commands::Print { alias } => {
            let vid = vid_wallet.resolve_alias(&alias)?;

            print!("{vid}");
        }
        Commands::Create { username, alias } => {
            let did = format!(
                "did:web:{}:endpoint:{username}",
                did_server.replace(":", "%3A")
            );

            if let Some(alias) = alias {
                vid_wallet.set_alias(alias.clone(), did.clone())?;
                info!("added alias {alias} -> {did}");
            }

            let transport = url::Url::parse(&format!(
                "https://{server}/endpoint/{}",
                did.replace("%", "%25")
            ))
            .unwrap();

            let private_vid = OwnedVid::bind(&did, transport);
            info!("created identity {}", private_vid.identifier());

            let client = reqwest::ClientBuilder::new();

            #[cfg(feature = "use_local_certificate")]
            let client = client.add_root_certificate({
                tracing::warn!("Using local root CA! (should only be used for local testing)");
                reqwest::Certificate::from_pem(include_bytes!("../test/root-ca.pem")).unwrap()
            });

            let _: Vid = match client
                .build()
                .unwrap()
                .post(format!("https://{did_server}/add-vid"))
                .json(&private_vid.vid())
                .send()
                .await
                .inspect(|r| debug!("DID server responded with status code {}", r.status()))
                .expect("Could not publish VID on server")
                .error_for_status()
            {
                Ok(response) => response.json().await.expect("Could not decode VID"),
                Err(e) => {
                    error!(
                        "{e}\nAn error occurred while publishing the DID. Maybe this DID exists already?"
                    );
                    return Ok(());
                }
            };

            info!(
                "published DID document at {}",
                tsp_sdk::vid::did::get_resolve_url(&did)
                    .unwrap()
                    .to_string()
            );

            vid_wallet.add_private_vid(private_vid.clone())?;
            write_wallet(&vault, &vid_wallet).await?;
        }
        Commands::CreatePeer { alias, tcp } => {
            let transport = if let Some(address) = tcp {
                url::Url::parse(&format!("tcp://{address}")).unwrap()
            } else {
                url::Url::parse(&format!("https://{server}/endpoint/[vid_placeholder]",)).unwrap()
            };
            let private_vid = OwnedVid::new_did_peer(transport);

            vid_wallet.set_alias(alias, private_vid.identifier().to_string())?;

            vid_wallet.add_private_vid(private_vid.clone())?;
            write_wallet(&vault, &vid_wallet).await?;

            info!("created peer identity {}", private_vid.identifier());
        }
        Commands::ImportPiv { file, alias } => {
            let private_vid = OwnedVid::from_file(file).await?;
            vid_wallet.add_private_vid(private_vid.clone())?;

            if let Some(alias) = alias {
                vid_wallet.set_alias(alias, private_vid.identifier().to_string())?;
            }

            write_wallet(&vault, &vid_wallet).await?;

            info!("created identity from file {}", private_vid.identifier());
        }
        Commands::Discover => {
            let url = format!("https://{did_server}/.well-known/endpoints.json");
            info!("discovering DIDs from {}", url);

            let client = reqwest::Client::builder();

            #[cfg(feature = "use_local_certificate")]
            let client = client.add_root_certificate({
                tracing::warn!("Using local root CA! (should only be used for local testing)");
                reqwest::Certificate::from_pem(include_bytes!("../test/root-ca.pem")).unwrap()
            });

            let dids = match client
                .build()
                .unwrap()
                .get(url)
                .send()
                .await
                .expect("could not load discovery list")
                .error_for_status()
            {
                Ok(r) => r
                    .json::<Vec<String>>()
                    .await
                    .expect("could not parse discovery list"),
                Err(e) => {
                    tracing::error!("could not load discovery list: {e}");
                    return Ok(());
                }
            };

            println!("DIDs available on {did_server}:");
            for did in dids {
                println!("- {did}");
            }
        }
        Commands::SetParent { vid, other_vid } => {
            vid_wallet.set_parent_for_vid(&vid, Some(&other_vid))?;

            info!("{vid} is now a child of {other_vid}");

            write_wallet(&vault, &vid_wallet).await?;
        }
        Commands::SetAlias { vid, alias } => {
            vid_wallet.set_alias(alias.clone(), vid.clone())?;
            info!("added alias {alias} -> {vid}");
            write_wallet(&vault, &vid_wallet).await?;
        }
        Commands::SetRoute { vid, route } => {
            let route: Vec<_> = route
                .split(',')
                .map(|s| vid_wallet.resolve_alias(s).unwrap())
                .collect();

            let route_ref = route.iter().map(|s| s.as_str()).collect::<Vec<_>>();

            vid_wallet.set_route_for_vid(&vid, &route_ref)?;
            write_wallet(&vault, &vid_wallet).await?;

            info!("{vid} has route {route:?}");
        }
        Commands::SetRelation { vid, other_vid } => {
            vid_wallet.set_relation_for_vid(&vid, Some(&other_vid))?;
            write_wallet(&vault, &vid_wallet).await?;

            info!("{vid} has relation to {other_vid}");
        }
        Commands::Send {
            sender_vid,
            receiver_vid,
            non_confidential_data,
        } => {
            let non_confidential_data = non_confidential_data.as_deref().map(|s| s.as_bytes());

            let mut message = Vec::new();
            tokio::io::stdin()
                .read_to_end(&mut message)
                .await
                .expect("Could not read message from stdin");

            match vid_wallet
                .send(&sender_vid, &receiver_vid, non_confidential_data, &message)
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

            if args.verbose {
                let cesr_message = vid_wallet
                    .as_store()
                    .seal_message(&sender_vid, &receiver_vid, non_confidential_data, &message)?
                    .1;
                print_message(&cesr_message);
            }

            info!(
                "sent message ({} bytes) from {sender_vid} to {receiver_vid}",
                message.len()
            );
        }
        Commands::Receive { vid, one } => {
            let mut messages = vid_wallet.receive(&vid).await?;

            info!("listening for messages...");

            // closures cannot be async, and async fn's don't easily do recursion
            enum Action {
                Nothing,
                Verify(String),
                VerifyAndOpen(String, BytesMut),
                Forward(String, Vec<BytesMut>, BytesMut),
            }

            while let Some(message) = messages.next().await {
                trace!("Received message: {message:?}");
                let message = match message {
                    Ok(m) => m,
                    Err(_) => break,
                };
                let handle_message = |message: ReceivedTspMessage| {
                    match message {
                        ReceivedTspMessage::GenericMessage {
                            sender,
                            nonconfidential_data: _,
                            message,
                            message_type,
                        } => {
                            let status = match message_type.crypto_type {
                                cesr::CryptoType::Plaintext => "NON-CONFIDENTIAL",
                                _ => "confidential",
                            };
                            let crypto_type = match message_type.crypto_type {
                                cesr::CryptoType::Plaintext => "Plain text",
                                cesr::CryptoType::HpkeAuth => "HPKE Auth",
                                cesr::CryptoType::HpkeEssr => "HPKE ESSR",
                                cesr::CryptoType::NaclAuth => "NaCl Auth",
                                cesr::CryptoType::NaclEssr => "NaCl ESSR",
                            };
                            let signature_type = match message_type.signature_type {
                                cesr::SignatureType::NoSignature => "no signature",
                                cesr::SignatureType::Ed25519 => "Ed25519 signature",
                            };
                            info!(
                                "received {status} message ({} bytes) from {} ({crypto_type}, {signature_type})",
                                message.len(),
                                sender,
                            );
                            println!("{}", String::from_utf8_lossy(&message),);
                        }
                        ReceivedTspMessage::RequestRelationship {
                            sender,
                            thread_id,
                            route: _,
                            nested_vid: None,
                        } => {
                            let thread_id = Base64Unpadded::encode_string(&thread_id);
                            info!(
                                "received relationship request from {sender}, thread-id '{thread_id}'",
                            );
                            println!("{sender}\t{thread_id}");
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
                            let thread_id = Base64Unpadded::encode_string(&thread_id);
                            info!(
                                "received nested relationship request from '{vid}' (new identity for {sender}), thread-id '{thread_id}'"
                            );
                            println!("{vid}\t{thread_id}");
                        }
                        ReceivedTspMessage::AcceptRelationship {
                            sender,
                            nested_vid: Some(vid),
                        } => {
                            info!(
                                "received accept nested relationship from '{vid}' (new identity for {sender})"
                            );
                            println!("{vid}");
                        }
                        ReceivedTspMessage::CancelRelationship { sender } => {
                            info!("received cancel relationship from {sender}");
                        }
                        ReceivedTspMessage::ForwardRequest {
                            sender,
                            route,
                            next_hop,
                            opaque_payload,
                        } => {
                            info!(
                                "messaging forwarding request from {sender} to {next_hop} ({} hops)",
                                route.len()
                            );
                            if args.yes
                                || prompt("do you want to forward this message?".to_string())
                            {
                                return Action::Forward(next_hop, route, opaque_payload);
                            }
                        }
                        ReceivedTspMessage::NewIdentifier { sender, new_vid } => {
                            info!("received request for new identifier '{new_vid}' from {sender}");
                            println!("{new_vid}");
                            return Action::Verify(new_vid);
                        }
                        ReceivedTspMessage::Referral {
                            sender,
                            referred_vid,
                        } => {
                            info!(
                                "received relationship referral for '{referred_vid}' from {sender}"
                            );
                            println!("{referred_vid}");
                            return Action::Verify(referred_vid);
                        }
                        ReceivedTspMessage::PendingMessage {
                            unknown_vid,
                            payload,
                        } => {
                            info!("message involving unknown party {}", unknown_vid);

                            let user_affirms = args.yes
                                || prompt(format!(
                                    "do you want to read a message from '{unknown_vid}'"
                                ));

                            if user_affirms {
                                trace!("processing pending message");
                                return Action::VerifyAndOpen(unknown_vid, payload);
                            }
                        }
                    }

                    Action::Nothing
                };

                match handle_message(message) {
                    Action::Nothing => {}
                    Action::VerifyAndOpen(vid, payload) => {
                        let message = vid_wallet.verify_and_open(&vid, payload).await?;

                        info!("{vid} is verified and added to the wallet {}", &args.wallet);

                        let _ = handle_message(message);
                    }
                    Action::Verify(vid) => {
                        vid_wallet.verify_vid(&vid, None).await?;

                        info!("{vid} is verified and added to the wallet {}", &args.wallet);
                    }
                    Action::Forward(next_hop, route, payload) => {
                        vid_wallet
                            .forward_routed_message(&next_hop, route, &payload)
                            .await?;
                        info!("forwarding to next hop: {next_hop}");
                    }
                }

                write_wallet(&vault, &vid_wallet).await?;

                if one {
                    break;
                }
            }
        }
        Commands::Cancel {
            sender_vid,
            receiver_vid,
        } => {
            if let Err(e) = vid_wallet
                .send_relationship_cancel(&sender_vid, &receiver_vid)
                .await
            {
                tracing::error!("error sending message from {sender_vid} to {receiver_vid}: {e}");

                return Ok(());
            }

            info!("sent control message from {sender_vid} to {receiver_vid}",);
            write_wallet(&vault, &vid_wallet).await?;
        }
        Commands::Request {
            sender_vid,
            receiver_vid,
            nested,
            parent_vid,
        } => {
            // Setup receive stream before sending the request
            let listener_vid = parent_vid.unwrap_or(sender_vid.clone());
            let mut messages = vid_wallet.receive(&listener_vid).await?;

            tracing::debug!("sending request...");
            if nested {
                match vid_wallet
                    .send_nested_relationship_request(&sender_vid, &receiver_vid)
                    .await
                {
                    Ok(vid) => {
                        info!(
                            "sent a nested relationship request to {receiver_vid} with new identity '{}'",
                            vid.identifier()
                        );
                        println!("{}", vid.identifier());
                    }
                    Err(e) => {
                        error!("error sending message from {sender_vid} to {receiver_vid}: {e}");
                        return Ok(());
                    }
                }
            } else if let Err(e) = vid_wallet
                .send_relationship_request(&sender_vid, &receiver_vid, None)
                .await
            {
                tracing::error!("error sending message from {sender_vid} to {receiver_vid}: {e}");
                return Ok(());
            }

            info!(
                "sent relationship request from {sender_vid} to {receiver_vid}, waiting for response...",
            );

            // Give user some feedback for what messages it receives
            // The actual logic for handling the relationship happens internally in the `open_message` function
            while let Some(Ok(message)) = messages.next().await {
                match message {
                    ReceivedTspMessage::GenericMessage { sender, .. } => {
                        info!("received generic message from {sender}")
                    }
                    ReceivedTspMessage::RequestRelationship { sender, .. } => {
                        info!("received relationship request from {sender}")
                    }
                    ReceivedTspMessage::AcceptRelationship { sender, nested_vid } => {
                        info!(
                            "received accept relationship from {sender} (nested_vid: {})",
                            nested_vid.clone().unwrap_or("none".to_string())
                        );
                        if let Some(nested_vid) = nested_vid {
                            println!("{}", nested_vid);
                        }
                        break;
                    }
                    ReceivedTspMessage::CancelRelationship { sender } => {
                        info!("received cancel relationship from {sender}");
                        break;
                    }
                    ReceivedTspMessage::ForwardRequest { sender, .. } => {
                        info!("received forward request from {sender}")
                    }
                    ReceivedTspMessage::NewIdentifier { sender, new_vid } => {
                        info!("received new identifier for {sender}: {new_vid}")
                    }
                    ReceivedTspMessage::Referral {
                        sender,
                        referred_vid,
                    } => info!("received referral from {sender} for {referred_vid}"),
                    ReceivedTspMessage::PendingMessage { unknown_vid, .. } => {
                        info!("received pending message from {unknown_vid}")
                    }
                }
            }

            write_wallet(&vault, &vid_wallet).await?;
        }
        Commands::Accept {
            sender_vid,
            receiver_vid,
            thread_id,
            nested,
        } => {
            let mut digest: [u8; 32] = Default::default();
            Base64Unpadded::decode(&thread_id, &mut digest).unwrap();

            if nested {
                match vid_wallet
                    .send_nested_relationship_accept(&sender_vid, &receiver_vid, digest)
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
            } else if let Err(e) = vid_wallet
                .send_relationship_accept(&sender_vid, &receiver_vid, digest, None)
                .await
            {
                tracing::error!("error sending message from {sender_vid} to {receiver_vid}: {e}");

                return Ok(());
            }

            info!("sent control message from {sender_vid} to {receiver_vid}",);
            write_wallet(&vault, &vid_wallet).await?;
        }
        Commands::Refer {
            sender_vid,
            receiver_vid,
            referred_vid,
        } => {
            if let Err(e) = vid_wallet
                .send_relationship_referral(&sender_vid, &receiver_vid, &referred_vid)
                .await
            {
                tracing::error!("error sending message from {sender_vid} to {receiver_vid}: {e}");

                return Ok(());
            }

            info!("sent control message from {sender_vid} to {receiver_vid}",);
            write_wallet(&vault, &vid_wallet).await?;
        }
        Commands::Publish {
            sender_vid,
            receiver_vid,
            new_vid,
        } => {
            if let Err(e) = vid_wallet
                .send_new_identifier_notice(&sender_vid, &receiver_vid, &new_vid)
                .await
            {
                tracing::error!("error sending message from {sender_vid} to {receiver_vid}: {e}");

                return Ok(());
            }

            info!("sent control message from {sender_vid} to {receiver_vid}",);
            write_wallet(&vault, &vid_wallet).await?;
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
