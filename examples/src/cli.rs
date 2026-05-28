use base64ct::{Base64, Base64Unpadded, Encoding};
use bytes::BytesMut;
use clap::{Parser, Subcommand};
use futures::StreamExt;
use rustls::crypto::CryptoProvider;
use std::{ops::Deref, path::PathBuf, str::FromStr};
use tokio::io::AsyncReadExt;
use tracing::{debug, error, info, trace};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use tsp_sdk::{
    Aliases, AskarSecureStorage, AsyncSecureStore, Error, ExportVid, OwnedVid,
    ReceivedRelationshipDelivery, ReceivedRelationshipForm, ReceivedTspMessage, RelationshipStatus,
    SecureStorage, VerifiedVid, Vid, cesr,
    definitions::Digest,
    vid::{
        ResolutionContext, VerifyVidOptions, VidError,
        did::{
            scid::{
                ScidLocator, ScidMethod, ScidResolutionContext, ScidSourceMethod, ScidVidMetadata,
            },
            webvh::WebvhMetadata,
        },
        verify_vid, verify_vid_with_options, vid_to_did_document,
    },
};
use url::Url;

#[cfg(feature = "bench")]
mod bench;

#[derive(Default, Debug, Clone)]
enum DidType {
    #[default]
    Web,
    Peer,
    Webvh,
    Scid,
}

impl FromStr for DidType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "web" => Ok(DidType::Web),
            "peer" => Ok(DidType::Peer),
            "webvh" => Ok(DidType::Webvh),
            "scid" => Ok(DidType::Scid),
            _ => Err(format!("invalid did type: {s}")),
        }
    }
}

fn parse_crypto_type(value: &str) -> Result<cesr::CryptoType, String> {
    let normalized = value.to_ascii_lowercase().replace('_', "-");
    match normalized.as_str() {
        "hpke-auth" => Ok(cesr::CryptoType::HpkeAuth),
        "hpke-essr" => Ok(cesr::CryptoType::HpkeEssr),
        "nacl-auth" => Ok(cesr::CryptoType::NaclAuth),
        "nacl-essr" => Ok(cesr::CryptoType::NaclEssr),
        "pq" | "x25519-kyber768-draft00" => Ok(cesr::CryptoType::X25519Kyber768Draft00),
        "plaintext" => Err("plaintext is not valid for confidential send".to_string()),
        _ => Err(format!("invalid crypto type: {value}")),
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
        #[arg(long)]
        src: Option<String>,
        #[arg(long)]
        peer_src: Option<String>,
        #[arg(long)]
        source_method: Option<String>,
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
        #[arg(long)]
        source_method: Option<String>,
        #[arg(long)]
        src: Option<String>,
        #[arg(long)]
        peer_src: Option<String>,
    },
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
        #[arg(
            long,
            value_parser = parse_crypto_type,
            help = "Override outbound crypto: hpke-auth, hpke-essr, nacl-auth, nacl-essr, pq"
        )]
        crypto: Option<cesr::CryptoType>,
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
        #[arg(long, conflicts_with = "parallel")]
        nested: bool,
        #[arg(long, conflicts_with = "nested", requires = "new_vid")]
        parallel: bool,
        #[arg(
            long,
            conflicts_with = "nested",
            requires = "parallel",
            help = "existing local VID to propose for a parallel relationship"
        )]
        new_vid: Option<String>,
        #[arg(
            short,
            long,
            conflicts_with = "parallel",
            help = "parent VID of the sender, used to listen for a response"
        )]
        parent_vid: Option<String>,
        #[arg(
            long,
            help = "Ask for confirmation before interacting with unknown end-points"
        )]
        ask: bool,
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
        #[arg(long, conflicts_with = "parallel")]
        nested: bool,
        #[arg(long, conflicts_with = "nested")]
        parallel: bool,
    },
    #[command(arg_required_else_help = true, about = "break up a relationship")]
    Cancel {
        #[arg(short, long, required = true)]
        sender_vid: String,
        #[arg(short, long, required = true)]
        receiver_vid: String,
    },
    #[command(arg_required_else_help = true, about = "manage custom secret data")]
    Secret {
        #[clap(subcommand)]
        sub: CustomSecretManagement,
    },
    #[cfg(feature = "bench")]
    #[command(
        arg_required_else_help = true,
        about = "run transport benchmark traffic tests"
    )]
    Bench {
        #[clap(subcommand)]
        sub: bench::BenchSubcommand,
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

#[derive(Debug, Parser)]
enum CustomSecretManagement {
    #[command(about = "Add a custom secret to the wallet")]
    Add { key: String, value: String },
    #[command(about = "Get a custom secret from the wallet")]
    Get { key: String },
    #[command(about = "Remove a custom secret from the wallet")]
    Remove { key: String },
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

async fn ensure_vid_verified(
    vid_wallet: &AsyncSecureStore,
    receiver_vid: &str,
    wallet_name: &str,
    ask: bool,
) -> Result<(), Error> {
    if vid_wallet.has_verified_vid(receiver_vid)? {
        return Ok(());
    };

    if !ask
        || prompt(format!(
            "Do you want to verify receiver DID {}",
            receiver_vid
        ))
    {
        vid_wallet.verify_vid(receiver_vid, None).await?;
        info!("{receiver_vid} is verified and added to the wallet {wallet_name}");
        Ok(())
    } else {
        tracing::error!("Message cannot be sent without verifying the receiver's DID.");
        Err(Error::UnverifiedVid(
            "Message cannot be sent without verifying the receiver's DID.".to_string(),
        ))
    }
}

fn build_scid_resolution_context(
    vid: &str,
    source_method: Option<String>,
    src: Option<String>,
    peer_src: Option<String>,
) -> Result<Option<ScidResolutionContext>, Error> {
    if !vid.starts_with("did:scid:") {
        return Ok(None);
    }

    if source_method.is_none() && src.is_none() && peer_src.is_none() {
        return tsp_sdk::vid::did::scid::query_resolution_context(vid).map_err(Error::Vid);
    }

    let did = tsp_sdk::vid::did::scid::parse(vid)?;
    let context = build_create_scid_context(source_method, src, peer_src, None)?;

    Ok(Some(canonicalize_scid_context(&did.scid, context)?))
}

fn build_create_scid_context(
    source_method: Option<String>,
    src: Option<String>,
    peer_src: Option<String>,
    default_src: Option<String>,
) -> Result<ScidResolutionContext, Error> {
    let source_method = match source_method {
        Some(source_method) => parse_scid_source_method(&source_method)?,
        None => ScidSourceMethod::Webvh,
    };
    let source_value = src.or(peer_src).or(default_src);

    let locator = match source_method {
        ScidSourceMethod::Webvh => ScidLocator::Src(source_value.ok_or_else(|| {
            Error::Vid(VidError::ResolutionContextRequired(
                "did:scid source path (--src or --peer-src) is required".to_string(),
            ))
        })?),
        ScidSourceMethod::Cheqd => ScidLocator::Network(normalize_scid_cheqd_locator(
            source_value.ok_or_else(|| {
                Error::Vid(VidError::ResolutionContextRequired(
                    "did:scid cheqd network (--src or --peer-src) is required".to_string(),
                ))
            })?,
        )?),
    };

    Ok(ScidResolutionContext {
        version: 1,
        method: ScidMethod::Vh,
        source_method,
        locator,
    })
}

fn parse_scid_source_method(value: &str) -> Result<ScidSourceMethod, Error> {
    match value.to_ascii_lowercase().as_str() {
        "webvh" => Ok(ScidSourceMethod::Webvh),
        "cheqd" => Ok(ScidSourceMethod::Cheqd),
        _ => Err(Error::Vid(VidError::UnsupportedScidSource(
            value.to_string(),
        ))),
    }
}

fn merge_method_state(
    vid_wallet: &AsyncSecureStore,
    method_state: tsp_sdk::WalletMethodState,
) -> Result<(), Error> {
    for (kid, secret) in method_state.secret_keys {
        vid_wallet.add_secret_key(kid, secret)?;
    }

    for (did, context) in method_state.resolution_contexts {
        vid_wallet.register_resolution_context(did, context)?;
    }

    Ok(())
}

fn canonicalize_scid_context(
    scid: &str,
    context: ScidResolutionContext,
) -> Result<ScidResolutionContext, Error> {
    let locator = match context.locator {
        ScidLocator::Src(src) => ScidLocator::Src(normalize_scid_webvh_locator(scid, &src)?),
        ScidLocator::Network(network) => {
            ScidLocator::Network(normalize_scid_cheqd_locator(network)?)
        }
    };

    Ok(ScidResolutionContext {
        version: context.version,
        method: context.method,
        source_method: context.source_method,
        locator,
    })
}

fn normalize_scid_webvh_locator(scid: &str, src: &str) -> Result<String, Error> {
    if src.starts_with("did:webvh:") {
        let parts = src.split(':').collect::<Vec<_>>();
        match parts.get(2) {
            Some(source_scid) if *source_scid == scid => Ok(src.to_string()),
            _ => Err(Error::Vid(VidError::SourceDidMismatch(src.to_string()))),
        }
    } else {
        let Some((host, path)) = src.split_once('/') else {
            return Ok(format!("did:webvh:{scid}:{src}"));
        };
        Ok(format!(
            "did:webvh:{scid}:{}:{}",
            host.replace(':', "%3A"),
            path.replace('/', ":")
        ))
    }
}

fn normalize_scid_cheqd_locator(src: String) -> Result<String, Error> {
    if let Some(network) = src.strip_prefix("did:cheqd:") {
        if network.is_empty() {
            return Err(Error::Vid(VidError::InvalidScid(src)));
        }

        return Ok(network.to_string());
    }

    if src.starts_with("did:") {
        return Err(Error::Vid(VidError::InvalidScid(src)));
    }

    Ok(src)
}

fn merge_scid_metadata(
    verified_metadata: Option<serde_json::Value>,
    private_state: Option<tsp_sdk::vid::did::scid::ScidPrivateState>,
) -> Result<Option<serde_json::Value>, Error> {
    let Some(metadata) = verified_metadata else {
        return Ok(None);
    };

    let mut metadata: ScidVidMetadata =
        serde_json::from_value(metadata).map_err(|error| Error::Vid(VidError::Serde(error)))?;
    metadata.private_state = private_state;

    Ok(Some(
        serde_json::to_value(metadata).map_err(|error| Error::Vid(VidError::Serde(error)))?,
    ))
}

async fn publish_scid_source(
    client: &reqwest::Client,
    did_server: &str,
    source_vid: &Vid,
    source_history: Option<&serde_json::Value>,
    replace: bool,
) -> Result<(), Error> {
    let request = if replace {
        client.put(format!("https://{did_server}/add-vid"))
    } else {
        client.post(format!("https://{did_server}/add-vid"))
    };

    let _: Vid = request
        .json(source_vid)
        .send()
        .await
        .inspect(|r| debug!("DID server responded with status code {}", r.status()))
        .expect("Could not publish VID on server")
        .error_for_status()
        .map_err(|_| {
            Error::Vid(VidError::InvalidVid(
                "An error occurred while publishing the DID. Maybe this DID exists already?"
                    .to_string(),
            ))
        })?
        .json()
        .await
        .expect("Could not decode VID");

    if let Some(source_history) = source_history {
        let request = if replace {
            client.put(format!(
                "https://{did_server}/add-history/{}",
                source_vid.identifier()
            ))
        } else {
            client.post(format!(
                "https://{did_server}/add-history/{}",
                source_vid.identifier()
            ))
        };

        request
            .json(source_history)
            .send()
            .await
            .inspect(|r| debug!("DID server responded with status code {}", r.status()))
            .expect("Could not publish history on server")
            .error_for_status()
            .map_err(|_| {
                Error::Vid(VidError::InvalidVid(
                    "An error occurred while publishing the DID history.".to_string(),
                ))
            })?;
    }

    Ok(())
}

fn map_scid_update_error(error: VidError) -> Error {
    match error {
        VidError::InternalError(message)
            if message
                == "Server has precommit active but wallet has no matching key. Wallet may be out of sync."
                || message == "Cannot find update keys to update the DID" =>
        {
            Error::MissingPrivateVid(message)
        }
        other => Error::Vid(other),
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

    let (vault, vid_wallet) = read_wallet(&args.wallet, &args.password).await?;
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
        Commands::Verify {
            vid,
            alias,
            src,
            peer_src,
            source_method,
        } => {
            let context = build_scid_resolution_context(&vid, source_method, src, peer_src)?;
            let options = VerifyVidOptions {
                resolution_context: context.clone().map(ResolutionContext::Scid),
            };

            vid_wallet
                .verify_vid_with_options(&vid, alias, options)
                .await?;

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
            source_method,
            src,
            peer_src,
        } => {
            let transport = if let Some(address) = tcp {
                Url::parse(&format!("tcp://{address}")).unwrap()
            } else {
                Url::parse(&format!("https://{server}/endpoint/[vid_placeholder]",)).unwrap()
            };

            let (private_vid, metadata) = match r#type {
                DidType::Web => (
                    create_did_web(
                        &did_server,
                        transport,
                        &vid_wallet,
                        &username,
                        alias,
                        &client,
                    )
                    .await?,
                    None,
                ),
                DidType::Peer => {
                    let private_vid = OwnedVid::new_did_peer(transport);

                    vid_wallet.set_alias(username, private_vid.identifier().to_string())?;

                    info!("created peer identity {}", private_vid.identifier());
                    (private_vid, None)
                }
                DidType::Webvh => {
                    let (private_vid, history, keys) = tsp_sdk::vid::did::webvh::create_webvh(
                        &format!("{did_server}/endpoint/{username}"),
                        transport,
                    )
                    .await?;

                    // Store both current and next update keys for precommit support
                    vid_wallet
                        .add_secret_key(keys.update_kid.clone(), keys.update_key)
                        .expect("Cannot store current update key");
                    vid_wallet
                        .add_secret_key(keys.next_update_kid.clone(), keys.next_update_key)
                        .expect("Cannot store next update key");
                    vid_wallet
                        .set_alias(
                            format!("__next_update_kid:{}", private_vid.identifier()),
                            keys.next_update_kid,
                        )
                        .expect("Cannot store next update key reference");

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

                    (private_vid, None)
                }
                DidType::Scid => {
                    let default_src = format!("{did_server}/endpoint/{username}");
                    let context =
                        build_create_scid_context(source_method, src, peer_src, Some(default_src))?;
                    let result =
                        tsp_sdk::vid::did::scid::create(transport, context.clone()).await?;

                    merge_method_state(&vid_wallet, result.method_state)?;
                    publish_scid_source(
                        &client,
                        &did_server,
                        &result.source_vid,
                        result.source_history.as_ref(),
                        false,
                    )
                    .await?;

                    if let Some(alias) = alias {
                        vid_wallet.set_alias(alias, result.private_vid.identifier().to_string())?;
                    }

                    let (_, verified_metadata) = verify_vid_with_options(
                        result.private_vid.identifier(),
                        VerifyVidOptions {
                            resolution_context: Some(
                                vid_wallet
                                    .get_resolution_context(result.private_vid.identifier())?
                                    .ok_or_else(|| {
                                        Error::MissingVid(format!(
                                            "Missing resolution context for {}",
                                            result.private_vid.identifier()
                                        ))
                                    })?,
                            ),
                        },
                    )
                    .await
                    .map_err(|err| Error::Vid(VidError::InvalidVid(err.to_string())))?;

                    (
                        result.private_vid,
                        merge_scid_metadata(verified_metadata, result.metadata.private_state)?,
                    )
                }
            };
            let metadata = match metadata {
                Some(metadata) => Some(metadata),
                None => {
                    let (_, metadata) = verify_vid(private_vid.identifier())
                        .await
                        .map_err(|err| Error::Vid(VidError::InvalidVid(err.to_string())))?;
                    metadata
                }
            };
            vid_wallet.add_private_vid(private_vid.clone(), metadata)?;
            info!("created VID {}", private_vid.identifier());
        }
        Commands::Update { vid } => {
            let (_, _, method_state) = vid_wallet.export()?;
            let vid_alias = vid_wallet.try_resolve_alias(&vid)?;
            info!("Updating VID {vid_alias}");
            let exported = vid_wallet
                .export()?
                .0
                .into_iter()
                .find(|exported| exported.id == vid_alias)
                .ok_or_else(|| Error::MissingVid(format!("Cannot find VID {vid_alias}")))?;
            let private_vid = vid_wallet.get_private_vid(&vid_alias)?;

            if let Some(metadata) = exported.metadata.clone()
                && let Ok(scid_metadata) = serde_json::from_value::<ScidVidMetadata>(metadata)
            {
                let update_result =
                    tsp_sdk::vid::did::scid::update(&private_vid, scid_metadata, &method_state)
                        .await
                        .map_err(map_scid_update_error)?;

                merge_method_state(&vid_wallet, update_result.method_state)?;
                publish_scid_source(
                    &client,
                    &did_server,
                    &update_result.source_vid,
                    update_result.source_history_entry.as_ref(),
                    true,
                )
                .await?;

                let context = vid_wallet
                    .get_resolution_context(update_result.private_vid.identifier())?
                    .ok_or_else(|| {
                        Error::MissingVid(format!(
                            "Missing resolution context for {}",
                            update_result.private_vid.identifier()
                        ))
                    })?;
                let (_, new_metadata) = verify_vid_with_options(
                    update_result.private_vid.identifier(),
                    VerifyVidOptions {
                        resolution_context: Some(context),
                    },
                )
                .await
                .map_err(|err| Error::Vid(VidError::InvalidVid(err.to_string())))?;
                let new_metadata =
                    merge_scid_metadata(new_metadata, update_result.metadata.private_state)?;
                vid_wallet.add_private_vid(update_result.private_vid, new_metadata)?;

                info!("VID updated with presented/source scid flow");
            } else {
                let (resolved_vid, metadata) =
                    tsp_sdk::vid::did::webvh::resolve(&vid_alias).await?;
                let new_vid =
                    OwnedVid::bind(resolved_vid.identifier(), resolved_vid.endpoint().clone());
                let metadata: WebvhMetadata = serde_json::from_value(metadata)
                    .expect("metadata should be of type 'WebvhMetadata'");

                let next_kid_alias = format!("__next_update_kid:{}", resolved_vid.identifier());
                let update_key =
                    if let Ok(Some(next_kid)) = vid_wallet.resolve_alias(&next_kid_alias) {
                        info!("Using pre-committed update key for rotation");
                        method_state.secret_keys.get(&next_kid).ok_or_else(|| {
                            Error::MissingPrivateVid(
                                "Pre-committed key not found in wallet".to_string(),
                            )
                        })?
                    } else {
                        if metadata.next_key_hashes.is_some() {
                            error!("Server has nextKeyHashes but wallet has no precommit key");
                            error!("This wallet may be out of sync - cannot rotate safely");
                            return Err(Error::MissingPrivateVid(
                                "Server has precommit active but wallet has no matching key. \
                             Wallet may be out of sync."
                                    .to_string(),
                            ));
                        }

                        let Some(update_keys) = metadata.update_keys else {
                            error!("Cannot find update keys to update the DID");
                            return Err(Error::MissingPrivateVid(
                                "Cannot find update keys to update the DID".to_string(),
                            ));
                        };

                        info!("Using current update key (migrating legacy DID to precommit)");
                        method_state
                            .secret_keys
                            .get(&update_keys[0])
                            .ok_or_else(|| {
                                Error::MissingPrivateVid(
                                    "Cannot find update keys to update the DID".to_string(),
                                )
                            })?
                    };

                let update_result = tsp_sdk::vid::did::webvh::update(
                    vid_to_did_document(new_vid.vid()),
                    update_key.first_chunk::<32>().ok_or_else(|| {
                        Error::Vid(VidError::WebVHError(
                            "Couldn't get WebVH UpdateKey Secret bytes".to_string(),
                        ))
                    })?,
                )
                .await?;

                vid_wallet
                    .add_secret_key(
                        update_result.next_update_kid.clone(),
                        update_result.next_update_key,
                    )
                    .expect("Cannot store new next update key");
                vid_wallet
                    .set_alias(next_kid_alias, update_result.next_update_kid)
                    .expect("Cannot update next update key reference");

                client
                    .put(format!(
                        "https://{did_server}/add-history/{}",
                        new_vid.identifier()
                    ))
                    .json(&update_result.log_entry)
                    .send()
                    .await
                    .expect("Could not append history");

                let update_response = client
                    .put(format!("https://{did_server}/add-vid"))
                    .json(new_vid.vid())
                    .send()
                    .await
                    .expect("Could not update DID")
                    .text()
                    .await
                    .expect("cannot extract text from server response");

                debug!("did server responded: {}", update_response);

                let (_, new_metadata) = verify_vid(new_vid.identifier())
                    .await
                    .map_err(|err| Error::Vid(VidError::InvalidVid(err.to_string())))?;
                vid_wallet.add_private_vid(new_vid, new_metadata)?;

                info!("VID updated with precommit - next key committed for future rotation");
            }
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
            crypto,
        } => {
            let non_confidential_data = non_confidential_data.as_deref().map(|s| s.as_bytes());
            let receiver_vid = vid_wallet.try_resolve_alias(&receiver_vid)?;

            ensure_vid_verified(&vid_wallet, &receiver_vid, &args.wallet, ask).await?;

            let mut message = Vec::new();
            tokio::io::stdin()
                .read_to_end(&mut message)
                .await
                .expect("Could not read message from stdin");

            let send_result = if let Some(crypto_type) = crypto {
                vid_wallet
                    .send_with_crypto_type(
                        &sender_vid,
                        &receiver_vid,
                        non_confidential_data,
                        &message,
                        crypto_type,
                    )
                    .await
            } else {
                vid_wallet
                    .send(&sender_vid, &receiver_vid, non_confidential_data, &message)
                    .await
            };

            match send_result {
                Ok(()) => {}
                Err(e) => {
                    tracing::error!(
                        "error sending message from {sender_vid} to {receiver_vid}: {e}"
                    );

                    return Ok(());
                }
            };

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
                            receiver: _,
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
                                cesr::CryptoType::X25519Kyber768Draft00 => "X25519Kyber768Draft00",
                            };
                            let signature_type = match message_type.signature_type {
                                cesr::SignatureType::NoSignature => "no signature",
                                cesr::SignatureType::Ed25519 => "Ed25519 signature",
                                cesr::SignatureType::MlDsa65 => "ML-DSA-65 signature",
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
                            receiver: _,
                            thread_id,
                            form,
                            delivery,
                        } => {
                            let thread_id_string = Base64Unpadded::encode_string(&thread_id);
                            match (delivery, form) {
                                (
                                    ReceivedRelationshipDelivery::Direct,
                                    ReceivedRelationshipForm::Direct,
                                ) => {
                                    info!(
                                        "received relationship request from {sender}, thread-id '{thread_id_string}'"
                                    );
                                    println!("{sender}\t{thread_id_string}");
                                    return Action::AssignDefaultRelation(sender, thread_id);
                                }
                                (
                                    ReceivedRelationshipDelivery::Nested { nested_vid: vid },
                                    ReceivedRelationshipForm::Direct,
                                ) => {
                                    info!(
                                        "received nested relationship request from '{vid}' (new identity for {sender}), thread-id '{thread_id_string}'"
                                    );
                                    println!("{vid}\t{thread_id_string}");
                                    return Action::AssignDefaultRelation(sender, thread_id);
                                }
                                (
                                    ReceivedRelationshipDelivery::Direct,
                                    ReceivedRelationshipForm::Parallel { new_vid, .. },
                                ) => {
                                    info!(
                                        "received parallel relationship request for '{new_vid}' from {sender}"
                                    );
                                    println!("{new_vid}\t{thread_id_string}");
                                    return Action::Verify(new_vid);
                                }
                                (
                                    ReceivedRelationshipDelivery::Nested { nested_vid },
                                    ReceivedRelationshipForm::Parallel { new_vid, .. },
                                ) => {
                                    info!(
                                        "received nested parallel relationship request from '{nested_vid}' for '{new_vid}' from {sender}"
                                    );
                                    println!("{new_vid}\t{thread_id_string}");
                                    return Action::Verify(new_vid);
                                }
                                (ReceivedRelationshipDelivery::Routed, _) => {
                                    error!(
                                        "received routed relationship request from {sender}, but routed relationship-forming is not implemented"
                                    );
                                }
                            }
                        }
                        ReceivedTspMessage::AcceptRelationship {
                            sender,
                            receiver: _,
                            form,
                            delivery,
                            ..
                        } => match (delivery, form) {
                            (
                                ReceivedRelationshipDelivery::Direct,
                                ReceivedRelationshipForm::Direct,
                            ) => {
                                info!("received accept relationship from {}", sender);
                            }
                            (
                                ReceivedRelationshipDelivery::Nested { nested_vid: vid },
                                ReceivedRelationshipForm::Direct,
                            ) => {
                                info!(
                                    "received accept nested relationship from '{vid}' (new identity for {sender})"
                                );
                                println!("{vid}");
                            }
                            (
                                ReceivedRelationshipDelivery::Direct,
                                ReceivedRelationshipForm::Parallel { new_vid, .. },
                            ) => {
                                info!(
                                    "received parallel relationship accept for '{new_vid}' from {sender}"
                                );
                                println!("{new_vid}");
                            }
                            (
                                ReceivedRelationshipDelivery::Nested { nested_vid },
                                ReceivedRelationshipForm::Parallel { new_vid, .. },
                            ) => {
                                info!(
                                    "received accept nested parallel relationship from '{nested_vid}' for '{new_vid}' from {sender}"
                                );
                                println!("{new_vid}");
                            }
                            (ReceivedRelationshipDelivery::Routed, _) => {
                                error!(
                                    "received routed relationship accept from {sender}, but routed relationship-forming is not implemented"
                                );
                            }
                        },
                        ReceivedTspMessage::CancelRelationship {
                            sender,
                            receiver: _,
                        } => {
                            info!("received cancel relationship from {sender}");
                        }
                        ReceivedTspMessage::ForwardRequest {
                            sender,
                            receiver: _,
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
            parallel,
            new_vid,
            parent_vid,
            ask,
            wait,
        } => {
            ensure_vid_verified(&vid_wallet, &receiver_vid, &args.wallet, ask).await?;

            // Setup receive stream before sending the request
            let listener_vid = if parallel {
                new_vid
                    .clone()
                    .expect("clap should require --new-vid for --parallel")
            } else {
                parent_vid.unwrap_or(sender_vid.clone())
            };
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
            } else if parallel {
                let new_vid = new_vid
                    .as_deref()
                    .expect("clap should require --new-vid for --parallel");

                if let Err(e) = vid_wallet
                    .send_parallel_relationship_request(&sender_vid, &receiver_vid, new_vid)
                    .await
                {
                    tracing::error!(
                        "error sending message from {sender_vid} to {receiver_vid}: {e}"
                    );
                    return Ok(());
                }

                info!(
                    "sent a parallel relationship request from {sender_vid} to {receiver_vid} with new identity '{new_vid}'"
                );
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
                        ReceivedTspMessage::AcceptRelationship {
                            sender,
                            delivery,
                            form,
                            ..
                        } => {
                            let nested_vid = match delivery {
                                ReceivedRelationshipDelivery::Nested { nested_vid } => {
                                    Some(nested_vid)
                                }
                                _ => None,
                            };
                            let parallel_vid = match form {
                                ReceivedRelationshipForm::Parallel { new_vid, .. } => Some(new_vid),
                                ReceivedRelationshipForm::Direct => None,
                            };
                            info!(
                                "received accept relationship from {sender} (nested_vid: {}, parallel_vid: {})",
                                nested_vid.clone().unwrap_or("none".to_string()),
                                parallel_vid.clone().unwrap_or("none".to_string())
                            );
                            if let Some(nested_vid) = nested_vid {
                                println!("{nested_vid}");
                            }
                            if let Some(parallel_vid) = parallel_vid {
                                println!("{parallel_vid}");
                            }
                            break;
                        }
                        ReceivedTspMessage::CancelRelationship { sender, .. } => {
                            info!("received cancel relationship from {sender}");
                            break;
                        }
                        ReceivedTspMessage::ForwardRequest { sender, .. } => {
                            info!("received forward request from {sender}")
                        }
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
            parallel,
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
            } else if parallel {
                if let Err(e) = vid_wallet
                    .send_parallel_relationship_accept(&sender_vid, &receiver_vid, digest)
                    .await
                {
                    tracing::error!(
                        "error sending message from {sender_vid} to {receiver_vid}: {e}"
                    );

                    return Ok(());
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
        Commands::Secret { sub } => match sub {
            CustomSecretManagement::Add { key, value } => {
                vault.store_kv(&key, value.as_bytes()).await?;
                println!("successfully stored secret '{}'", key);
            }
            CustomSecretManagement::Get { key } => {
                println!(
                    "{:?}",
                    vault
                        .get_kv(&key)
                        .await?
                        .as_deref()
                        .map(String::from_utf8_lossy)
                );
            }
            CustomSecretManagement::Remove { key } => {
                vault.remove_kv(&key).await?;
                println!("successfully removed secret '{}'", key);
            }
        },
        #[cfg(feature = "bench")]
        Commands::Bench { sub } => {
            bench::run(sub, &vid_wallet, &args.wallet).await?;
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
            "\t public sign key: ({:?}) {}",
            vid.sig_key_type,
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

    let response = client
        .post(format!("https://{did_server}/add-vid"))
        .json(&private_vid.vid())
        .send()
        .await
        .inspect(|r| debug!("DID server responded with status code {}", r.status()))
        .expect("Could not publish VID on server");

    let _: Vid = match response.status() {
        r if r.is_success() => response.json().await.expect("Could not decode VID"),
        _ => {
            error!("An error occurred while publishing the DID. Maybe this DID exists already?");
            error!("Response: {}", response.text().await.unwrap());
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

#[tokio::main]
async fn main() -> Result<(), ()> {
    if let Err(e) = run().await {
        eprintln!("{e}");
        std::process::exit(1);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scid_peer_source_method_is_rejected() {
        assert!(matches!(
            parse_scid_source_method("peer"),
            Err(Error::Vid(VidError::UnsupportedScidSource(method))) if method == "peer"
        ));
    }

    #[test]
    fn scid_peer_src_is_treated_as_external_webvh_source_value() {
        let context = build_create_scid_context(
            None,
            None,
            Some("example.com/users/alice".to_string()),
            None,
        )
        .expect("context should build");

        assert_eq!(context.source_method, ScidSourceMethod::Webvh);
        assert_eq!(
            context.locator,
            ScidLocator::Src("example.com/users/alice".to_string())
        );
    }

    #[test]
    fn scid_webvh_locator_escapes_host_port() {
        let locator = normalize_scid_webvh_locator("testscid", "localhost:3000/vid/path")
            .expect("locator should normalize");

        assert_eq!(locator, "did:webvh:testscid:localhost%3A3000:vid:path");
    }
}
