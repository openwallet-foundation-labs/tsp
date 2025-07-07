use base64ct::{Base64, Base64Unpadded, Encoding};
use bytes::BytesMut;
use clap::{Parser, Subcommand};
use futures::StreamExt;
#[cfg(feature = "create-webvh")]
use pyo3::PyResult;
use rustls::crypto::CryptoProvider;
use std::{ops::Deref, path::PathBuf, str::FromStr};
use tokio::io::AsyncReadExt;
use tracing::{debug, error, info, trace};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
#[cfg(feature = "create-webvh")]
use tsp_sdk::vid::{did::webvh::WebvhMetadata, vid_to_did_document};
use tsp_sdk::{
    Aliases, AskarSecureStorage, AsyncSecureStore, Error, ExportVid, OwnedVid, ReceivedTspMessage,
    RelationshipStatus, SecureStorage, VerifiedVid, Vid,
    cesr::{
        color_format, {self},
    },
    definitions::Digest,
    vid::{VidError, verify_vid},
};
use url::Url;

#[derive(Default, Debug, Clone)]
enum DidType {
    #[default]
    Web,
    Peer,
    #[cfg(feature = "create-webvh")]
    Webvh,
}

impl FromStr for DidType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "web" => Ok(DidType::Web),
            "peer" => Ok(DidType::Peer),
            #[cfg(feature = "create-webvh")]
            "webvh" => Ok(DidType::Webvh),
            _ => Err(format!("invalid did type: {s}")),
        }
    }
}

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
        default_value = "p.teaspoon.world",
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
    #[command(about = "Show information stored in the wallet")]
    Show {
        #[clap(subcommand)]
        sub: Option<ShowCommands>,
    },
    #[command(
        arg_required_else_help = true,
        about = "verify and add a identifier to the wallet"
    )]
    Verify {
        vid: String,
        #[arg(short, long)]
        alias: Option<String>,
    },
    #[command(arg_required_else_help = true)]
    Print { alias: String },
    #[command(
        arg_required_else_help = true,
        about = "create and register a did:web identifier"
    )]
    Create {
        #[arg(short, long)]
        r#type: DidType,
        username: String,
        #[arg(short, long)]
        alias: Option<String>,
        #[arg(
            long,
            help = "Specify a network address and port instead of HTTPS transport"
        )]
        tcp: Option<String>,
    },
    #[cfg(feature = "create-webvh")]
    #[command(about = "Update the DID:WEBVH. Currently, only a rotation of TSP keys is supported")]
    Update {
        #[arg(help = "VID or Alias to update")]
        vid: String,
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
    #[command(arg_required_else_help = true, about = "send a message")]
    Send {
        #[arg(short, long, required = true)]
        sender_vid: String,
        #[arg(short, long, required = true)]
        receiver_vid: String,
        #[arg(short, long)]
        non_confidential_data: Option<String>,
        #[arg(
            long,
            help = "Ask for confirmation before interacting with unknown end-points"
        )]
        ask: bool,
    },
    #[command(arg_required_else_help = true, about = "listen for messages")]
    Receive {
        vid: String,
        #[arg(short, long, help = "Receive only one message")]
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
        #[arg(long, help = "wait for a response")]
        wait: bool,
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
    #[command(about = "List all relationships for a specific local VID")]
    Relations {
        vid: Option<String>,
        #[arg(short, long)]
        unrelated: bool,
    },
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
            let (vids, aliases, keys) = vault.read().await?;

            let db = AsyncSecureStore::new();
            db.import(vids, aliases, keys)?;

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

fn prompt(message: String) -> bool {
    use std::io::{self, BufRead, Write};
    print!("{message}? [y/n]");
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

    let client = reqwest::ClientBuilder::new()
        .user_agent(format!("TSP CLI / {}", env!("CARGO_PKG_VERSION")));
    #[cfg(feature = "use_local_certificate")]
    let client = client.add_root_certificate({
        tracing::warn!("Using local root CA! (should only be used for local testing)");
        reqwest::Certificate::from_pem(include_bytes!("../test/root-ca.pem")).unwrap()
    });

    let client = client.build().unwrap();

    match args.command {
        Commands::Show { sub } => {
            let (mut vids, aliases, _keys) = vid_wallet.export()?;
            vids.sort_by(|a, b| a.id.cmp(&b.id));

            if let Some(ShowCommands::Local) = sub {
                show_local(&vids, &aliases)?;
            }
            if let Some(ShowCommands::Relations { vid, unrelated }) = sub {
                if unrelated {
                    return show_relations(&vids, None, &aliases);
                }
                if let Some(vid) = vid {
                    show_relations(&vids, Some(vid), &aliases)?;
                } else {
                    for vid in vids.iter().filter(|v| v.is_private()) {
                        show_relations(&vids, Some(vid.id.clone()), &aliases)?;
                    }
                }
            } else {
                println!("local VIDs");
                println!();
                show_local(&vids, &aliases)?;
                println!("---------------------------\n");
                for vid in vids.iter().filter(|v| v.is_private()) {
                    show_relations(&vids, Some(vid.id.clone()), &aliases)?;
                }
                println!("---------------------------\n");
                show_relations(&vids, None, &aliases)?;
            }
        }
        Commands::Verify { vid, alias } => {
            vid_wallet.verify_vid(&vid, alias).await?;

            info!("{vid} is verified and added to the wallet {}", &args.wallet);
        }
        Commands::Print { alias } => {
            let vid = vid_wallet
                .resolve_alias(&alias)?
                .ok_or(Error::MissingVid("Cannot find this alias".to_string()))?;

            print!("{vid}");
        }
        Commands::Create {
            r#type,
            username,
            alias,
            tcp,
        } => {
            let transport = if let Some(address) = tcp {
                Url::parse(&format!("tcp://{address}")).unwrap()
            } else {
                Url::parse(&format!("https://{server}/endpoint/[vid_placeholder]",)).unwrap()
            };

            let private_vid = match r#type {
                DidType::Web => {
                    create_did_web(
                        &did_server,
                        transport,
                        &vid_wallet,
                        &username,
                        alias,
                        &client,
                    )
                    .await?
                }
                DidType::Peer => {
                    let private_vid = OwnedVid::new_did_peer(transport);

                    vid_wallet.set_alias(username, private_vid.identifier().to_string())?;

                    info!("created peer identity {}", private_vid.identifier());
                    private_vid
                }
                #[cfg(feature = "create-webvh")]
                DidType::Webvh => {
                    let (private_vid, history, update_kid, update_key) =
                        tsp_sdk::vid::did::webvh::create_webvh(
                            &format!("{did_server}/endpoint/{username}"),
                            transport,
                        )
                        .await?;

                    vid_wallet
                        .add_secret_key(update_kid, update_key)
                        .expect("Cannot store update key");

                    let _: Vid = match client
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
                            return Err(Error::Vid(VidError::InvalidVid(
                                    "An error occurred while publishing the DID. Maybe this DID exists already?"
                                        .to_string(),
                                )));
                        }
                    };
                    info!(
                        "published DID document at {}",
                        tsp_sdk::vid::did::get_resolve_url(private_vid.vid().identifier())?
                            .to_string()
                    );

                    match client
                        .post(format!(
                            "https://{did_server}/add-history/{}",
                            private_vid.vid().identifier()
                        ))
                        .json(&history)
                        .send()
                        .await
                        .inspect(|r| debug!("DID server responded with status code {}", r.status()))
                        .expect("Could not publish history on server")
                        .error_for_status()
                    {
                        Ok(_) => {}
                        Err(e) => {
                            error!(
                                "{e}\nAn error occurred while publishing the DID. Maybe this DID exists already?"
                            );
                            return Err(Error::Vid(VidError::InvalidVid(
                                    "An error occurred while publishing the DID. Maybe this DID exists already?"
                                        .to_string(),
                                )));
                        }
                    };
                    info!("published DID history");
                    if let Some(alias) = alias {
                        vid_wallet.set_alias(alias, private_vid.identifier().to_string())?;
                    }

                    private_vid
                }
            };
            let (_, metadata) = verify_vid(private_vid.identifier())
                .await
                .map_err(|err| Error::Vid(VidError::InvalidVid(err.to_string())))?;
            vid_wallet.add_private_vid(private_vid.clone(), metadata)?;
        }
        #[cfg(feature = "create-webvh")]
        Commands::Update { vid } => {
            let (_, _, keys) = vid_wallet.export()?;
            let vid = vid_wallet.try_resolve_alias(&vid)?;
            info!("Updating VID {vid}");
            let (vid, metadata) = tsp_sdk::vid::did::webvh::resolve(&vid).await?;
            let vid = OwnedVid::bind(vid.identifier(), vid.endpoint().clone());
            let metadata: WebvhMetadata = serde_json::from_value(metadata)
                .expect("metadata should be of type 'WebvhMetadata'");

            let Some(update_keys) = metadata.update_keys else {
                error!("Cannot find update keys to update the DID");
                return Err(Error::MissingPrivateVid(
                    "Cannot find update keys to update the DID".to_string(),
                ));
            };
            let update_key = keys
                .get(&update_keys[0])
                .expect("Cannot find update keys to update the DID");
            let history_entry =
                tsp_sdk::vid::did::webvh::update(vid_to_did_document(vid.vid()), update_key)
                    .await?;

            client
                .put(format!(
                    "https://{did_server}/add-history/{}",
                    vid.identifier()
                ))
                .json(&history_entry)
                .send()
                .await
                .expect("Could not append history");

            let update_response = client
                .put(format!("https://{did_server}/add-vid"))
                .json(vid.vid())
                .send()
                .await
                .expect("Could not update DID")
                .text()
                .await
                .expect("cannot extract text from server response");

            debug!("did server responded: {}", update_response);

            let (_, metadata) = verify_vid(vid.identifier())
                .await
                .map_err(|err| Error::Vid(VidError::InvalidVid(err.to_string())))?;
            vid_wallet.add_private_vid(vid, metadata)?;
        }
        Commands::ImportPiv { file, alias } => {
            let private_vid = OwnedVid::from_file(file).await?;
            vid_wallet.add_private_vid(private_vid.clone(), None)?;

            if let Some(alias) = alias {
                vid_wallet.set_alias(alias, private_vid.identifier().to_string())?;
            }

            info!("created identity from file {}", private_vid.identifier());
        }
        Commands::Discover => {
            let url = format!("https://{did_server}/.well-known/endpoints.json");
            info!("discovering DIDs from {}", url);

            let dids = match client
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
        }
        Commands::SetAlias { vid, alias } => {
            vid_wallet.set_alias(alias.clone(), vid.clone())?;
            info!("added alias {alias} -> {vid}");
        }
        Commands::SetRoute { vid, route } => {
            let route: Vec<_> = route
                .split(',')
                .map(|s| vid_wallet.try_resolve_alias(s).unwrap())
                .collect();

            let route_ref = route.iter().map(|s| s.as_str()).collect::<Vec<_>>();

            vid_wallet.set_route_for_vid(&vid, &route_ref)?;
            info!("{vid} has route {route:?}");
        }
        Commands::Send {
            sender_vid,
            receiver_vid,
            non_confidential_data,
            ask,
        } => {
            let non_confidential_data = non_confidential_data.as_deref().map(|s| s.as_bytes());
            let receiver_vid = vid_wallet.try_resolve_alias(&receiver_vid)?;

            if !vid_wallet.has_verified_vid(&receiver_vid)? {
                if !ask || prompt(format!("Do you want to verify receiver DID {receiver_vid}")) {
                    vid_wallet.verify_vid(&receiver_vid, None).await?;
                    info!(
                        "{receiver_vid} is verified and added to the wallet {}",
                        &args.wallet
                    );
                } else {
                    tracing::error!("Message cannot be sent without verifying the receiver's DID.");
                    return Ok(());
                }
            }

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
                println!("CESR-encoded message:");
                println!("{}", color_format(&cesr_message).unwrap());
            }

            info!(
                "sent message ({} bytes) from {sender_vid} to {receiver_vid}",
                message.len()
            );
        }
        Commands::Receive { vid, one } => {
            let mut messages = vid_wallet.receive(&vid).await?;
            let vid = vid_wallet.try_resolve_alias(&vid)?;

            info!("listening for messages...");

            // closures cannot be async, and async fn's don't easily do recursion
            enum Action {
                Nothing,
                Verify(String),
                VerifyAndOpen(String, BytesMut),
                Forward(String, Vec<BytesMut>, BytesMut),
                AssignDefaultRelation(String, Digest),
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
                                #[cfg(feature = "pq")]
                                cesr::CryptoType::X25519Kyber768Draft00 => "X25519Kyber768Draft00",
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
                            nested_vid,
                        } => {
                            let thread_id_string = Base64Unpadded::encode_string(&thread_id);
                            match nested_vid {
                                Some(vid) => {
                                    info!(
                                        "received nested relationship request from '{vid}' (new identity for {sender}), thread-id '{thread_id_string}'"
                                    );
                                    println!("{vid}\t{thread_id_string}");
                                }
                                None => {
                                    info!(
                                        "received relationship request from {sender}, thread-id '{thread_id_string}'"
                                    );
                                    println!("{sender}\t{thread_id_string}");
                                }
                            }

                            return Action::AssignDefaultRelation(sender, thread_id);
                        }
                        ReceivedTspMessage::AcceptRelationship {
                            sender,
                            nested_vid: None,
                        } => {
                            info!("received accept relationship from {}", sender);
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
                                    "received first time message from '{unknown_vid}', do you want to accept it?"
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
                    Action::VerifyAndOpen(remote_vid, payload) => {
                        let message = vid_wallet.verify_and_open(&remote_vid, payload).await?;

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
                    Action::AssignDefaultRelation(remote_vid, thread_id) => {
                        // if we do not yet have a relationship with the remote VID, create a reverse unidirectional relationship
                        if matches!(
                            vid_wallet.get_relation_status_for_vid_pair(&vid, &remote_vid),
                            Ok(RelationshipStatus::Unrelated)
                        ) {
                            debug!(remote_vid, "setting default relationship");
                            vid_wallet.set_relation_and_status_for_vid(
                                &remote_vid,
                                RelationshipStatus::ReverseUnidirectional { thread_id },
                                &vid,
                            )?;
                        }
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
        }
        Commands::Request {
            sender_vid,
            receiver_vid,
            nested,
            parent_vid,
            wait,
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

            info!("sent relationship request from {sender_vid} to {receiver_vid}",);

            if wait {
                info!("waiting for response...",);

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
                                println!("{nested_vid}");
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
            }
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
        }
    }

    write_wallet(&vault, &vid_wallet).await?;
    vault.close().await?;

    Ok(())
}

fn show_local(vids: &[ExportVid], aliases: &Aliases) -> Result<(), Error> {
    for vid in vids.iter().filter(|v| v.is_private()) {
        let transport = if vid.transport.as_str() == "tsp://" || vid.parent_vid.is_some() {
            vid.parent_vid.clone().unwrap_or("None".to_string())
        } else {
            vid.transport.as_str().to_string()
        };
        let transport = transport.replace("[vid_placeholder]", &vid.id);

        let alias = aliases
            .iter()
            .find_map(|(a, id)| if id == &vid.id { Some(a.clone()) } else { None })
            .unwrap_or("None".to_string());

        println!("{}", &vid.id);
        println!("\t Alias: {alias}");
        println!("\t Transport: {transport}");
        if vid.id.starts_with("did:web") {
            println!(
                "\t DID doc: {}",
                tsp_sdk::vid::did::get_resolve_url(&vid.id)?
            )
        }
        if vid.id.starts_with("did:webvh") {
            println!(
                "\t DID history: {}l",
                tsp_sdk::vid::did::get_resolve_url(&vid.id)?
            );
            println!(
                "\t DID version: {}",
                vid.metadata
                    .as_ref()
                    .and_then(|m| m.get("version_id"))
                    .map(|v| v.to_string())
                    .unwrap_or("None".to_string())
            )
        }
        println!(
            "\t public enc key: ({:?}): {}",
            vid.enc_key_type,
            Base64::encode_string(vid.public_enckey.deref())
        );
        println!(
            "\t public sign key: (Ed25519) {}",
            Base64::encode_string(vid.public_sigkey.deref())
        );
        println!();
    }
    println!();

    Ok(())
}

async fn create_did_web(
    did_server: &str,
    transport: Url,
    vid_wallet: &AsyncSecureStore,
    username: &str,
    alias: Option<String>,
    client: &reqwest::Client,
) -> Result<OwnedVid, Error> {
    let did = format!(
        "did:web:{}:endpoint:{username}",
        did_server.replace(":", "%3A").replace("/", ":")
    );

    if let Some(alias) = alias {
        vid_wallet.set_alias(alias.clone(), did.clone())?;
        info!("added alias {alias} -> {did}");
    }

    let transport = Url::parse(
        &transport
            .as_str()
            .replace("[vid_placeholder]", &did.replace("%", "%25")),
    )
    .unwrap();

    let private_vid = OwnedVid::bind(&did, transport);
    info!("created identity {}", private_vid.identifier());
    println!("{}", serde_json::to_string_pretty(&private_vid).unwrap());

    let _: Vid = match client
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
            return Err(Error::Vid(VidError::InvalidVid(
                "An error occurred while publishing the DID. Maybe this DID exists already?"
                    .to_string(),
            )));
        }
    };
    info!(
        "published DID document at {}",
        tsp_sdk::vid::did::get_resolve_url(&did)?.to_string()
    );

    Ok(private_vid)
}

fn show_relations(vids: &[ExportVid], vid: Option<String>, aliases: &Aliases) -> Result<(), Error> {
    let filtered_vids = if let Some(vid) = vid {
        let vid = aliases.get(&vid).unwrap_or(&vid);
        println!("Relations of local VID {vid}");
        println!();
        vids.iter()
            .filter(|v| v.relation_vid.as_deref() == Some(vid))
            .collect::<Vec<_>>()
    } else {
        println!("Remote VIDs without relation status\n");
        vids.iter()
            .filter(|v| {
                matches!(v.relation_status, RelationshipStatus::Unrelated) && !v.is_private()
            })
            .collect::<Vec<_>>()
    };

    for vid in filtered_vids {
        let transport = if vid.transport.as_str() == "tsp://" || vid.parent_vid.is_some() {
            vid.parent_vid.clone().unwrap_or("None".to_string())
        } else {
            vid.transport.as_str().to_string()
        };

        let transport = transport.replace("[vid_placeholder]", &vid.id);

        let alias = aliases
            .iter()
            .find_map(|(a, id)| if id == &vid.id { Some(a.clone()) } else { None })
            .unwrap_or("None".to_string());

        println!("{}", &vid.id);
        println!("\t Relation Status: {}", vid.relation_status);
        println!("\t Alias: {alias}");
        if vid.id.starts_with("did:web") {
            println!(
                "\t DID doc: {}",
                tsp_sdk::vid::did::get_resolve_url(&vid.id)?
            )
        }
        if vid.id.starts_with("did:webvh") {
            println!(
                "\t DID history: {}l",
                tsp_sdk::vid::did::get_resolve_url(&vid.id)?
            );
            println!(
                "\t DID version: {}",
                vid.metadata
                    .as_ref()
                    .and_then(|m| m.get("version_id"))
                    .map(|v| v.to_string())
                    .unwrap_or("None".to_string())
            )
        }
        println!("\t Transport: {transport}");
        println!("\t Intermediaries: {:?}", vid.tunnel);
        println!(
            "\t public enc key: ({:?}): {}",
            vid.enc_key_type,
            Base64::encode_string(vid.public_enckey.deref())
        );
        println!(
            "\t public sign key: (Ed25519) {}",
            Base64::encode_string(vid.public_sigkey.deref())
        );
        println!();
    }
    println!();

    Ok(())
}

#[cfg(not(feature = "create-webvh"))]
type PyResult<T> = Result<T, ()>;

#[cfg_attr(not(feature = "create-webvh"), tokio::main)]
#[cfg_attr(feature = "create-webvh", pyo3_async_runtimes::tokio::main)]
async fn main() -> PyResult<()> {
    if let Err(e) = run().await {
        eprintln!("{e}");
        std::process::exit(1);
    }

    Ok(())
}
