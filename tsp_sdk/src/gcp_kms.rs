//! A [`SecureArea`] over Google Cloud KMS for Ed25519 signing: the key is made in the KMS
//! and never leaves it; `sign` is one `asymmetricSign` call over the raw data,
//! `public_key` one read. X25519 and the post-quantum keys are not the KMS's to hold and
//! are refused here; the software area keeps them and routes the signing keys here (see
//! [`crate::SoftwareSecureArea::attach_remote`]).
//!
//! The grant this needs, and what an attacker gets with it, is the adversary walk in the
//! wallet design note: a custom role on one key ring with create, get, sign and view of the
//! public key, never destroy; the process runs as the VM's attached service account, no
//! credential file; the audit log shows every signature.
//!
//! The KMS signs Ed25519 only at its SOFTWARE protection level, not in its HSMs (the
//! service refuses `EC_SIGN_ED25519` at HSM). A software-level key is still never
//! exportable and every use is logged; what it lacks is the hardware. An HSM would need an
//! ECDSA key, which TSP's VIDs do not use.
//!
//! [`KmsClient`] is the KMS as this module needs it, three calls; [`GcpKms`] is the real
//! one over REST, and tests use a fake.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex, RwLock},
    time::{Duration, Instant},
};

use base64ct::{Base64, Encoding};

use crate::secure_area::{
    KeyInfo, KeyType, RemoteKeys, Secret, SecureArea, SecureAreaError, ed25519_multikey,
};

/// The KMS as the secure area needs it. `version` is the key version's resource name,
/// `projects/…/locations/…/keyRings/…/cryptoKeys/…/cryptoKeyVersions/1`, which is the
/// handle the wallet persists.
pub trait KmsClient: Send + Sync {
    /// Make an Ed25519 signing key named `key_id` in the ring; the version's resource
    /// name once it is enabled.
    fn create_ed25519(&self, key_id: &str) -> Result<String, KmsError>;

    /// The 32-byte Ed25519 public key of a version.
    fn public_key(&self, version: &str) -> Result<[u8; 32], KmsError>;

    /// The 64-byte signature over `data` by a version.
    fn sign(&self, version: &str, data: &[u8]) -> Result<Vec<u8>, KmsError>;
}

#[derive(Debug, thiserror::Error)]
pub enum KmsError {
    /// The grant does not cover the call, or was revoked: what the application must act on.
    #[error("the KMS refused: {0}")]
    Denied(String),
    #[error("no such key in the KMS: {0}")]
    NotFound(String),
    #[error("the KMS could not be reached: {0}")]
    Unreachable(String),
    #[error("the KMS answered something unexpected: {0}")]
    Malformed(String),
}

impl KmsError {
    fn into_area_error(self, alias: &str) -> SecureAreaError {
        match self {
            KmsError::Denied(reason) => SecureAreaError::Locked {
                alias: alias.to_string(),
                reason,
            },
            KmsError::NotFound(_) => SecureAreaError::UnknownKey(alias.to_string()),
            KmsError::Unreachable(e) | KmsError::Malformed(e) => SecureAreaError::Crypto(e),
        }
    }
}

struct KmsKey {
    version: String,
    public: [u8; 32],
}

/// Keys in a KMS, by alias. Only Ed25519 signing keys; the alias is the key's multikey
/// unless the caller names one.
pub struct KmsSecureArea {
    client: Box<dyn KmsClient>,
    keys: RwLock<HashMap<String, KmsKey>>,
}

impl KmsSecureArea {
    pub fn new(client: impl KmsClient + 'static) -> Self {
        Self {
            client: Box::new(client),
            keys: RwLock::new(HashMap::new()),
        }
    }

    fn with_key<T>(
        &self,
        alias: &str,
        f: impl FnOnce(&KmsKey) -> Result<T, SecureAreaError>,
    ) -> Result<T, SecureAreaError> {
        let keys = self
            .keys
            .read()
            .map_err(|_| SecureAreaError::Crypto("secure area lock".into()))?;
        let key = keys
            .get(alias)
            .ok_or_else(|| SecureAreaError::UnknownKey(alias.into()))?;
        f(key)
    }
}

impl SecureArea for KmsSecureArea {
    fn create_key(
        &self,
        alias: Option<&str>,
        key_type: KeyType,
    ) -> Result<KeyInfo, SecureAreaError> {
        if key_type != KeyType::Ed25519 {
            return Err(SecureAreaError::WrongKeyType(format!(
                "the KMS holds Ed25519 keys only, not {}",
                key_type.as_str()
            )));
        }
        // the KMS names keys by an id of its own alphabet; the alias is ours
        let mut r = [0u8; 12];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut r);
        let key_id = format!("tsp-{}", hex(&r));
        let version = self
            .client
            .create_ed25519(&key_id)
            .map_err(|e| e.into_area_error(&key_id))?;
        let public = self
            .client
            .public_key(&version)
            .map_err(|e| e.into_area_error(&key_id))?;
        let alias = alias
            .map(str::to_string)
            .unwrap_or_else(|| ed25519_multikey(&public));
        self.keys
            .write()
            .map_err(|_| SecureAreaError::Crypto("secure area lock".into()))?
            .insert(alias.clone(), KmsKey { version, public });
        Ok(KeyInfo {
            alias,
            public: public.to_vec(),
        })
    }

    /// Forgotten here; the key stays in the KMS, since destroying is not granted and a
    /// destroyed key would freeze an identity. The operator destroys, by hand.
    fn delete_key(&self, alias: &str) -> Result<(), SecureAreaError> {
        if let Ok(mut keys) = self.keys.write() {
            keys.remove(alias);
        }
        Ok(())
    }

    fn public_key(&self, alias: &str) -> Result<Vec<u8>, SecureAreaError> {
        self.with_key(alias, |k| Ok(k.public.to_vec()))
    }

    fn key_type(&self, alias: &str) -> Result<KeyType, SecureAreaError> {
        self.with_key(alias, |_| Ok(KeyType::Ed25519))
    }

    fn sign(&self, alias: &str, data: &[u8]) -> Result<Vec<u8>, SecureAreaError> {
        let version = self.with_key(alias, |k| Ok(k.version.clone()))?;
        self.client
            .sign(&version, data)
            .map_err(|e| e.into_area_error(alias))
    }

    fn key_agreement(&self, alias: &str, _: &[u8]) -> Result<Secret, SecureAreaError> {
        Err(SecureAreaError::WrongKeyType(alias.into()))
    }

    fn kem_decapsulate(&self, alias: &str, _: &[u8]) -> Result<Secret, SecureAreaError> {
        Err(SecureAreaError::WrongKeyType(alias.into()))
    }
}

impl RemoteKeys for KmsSecureArea {
    fn handle(&self, alias: &str) -> Option<String> {
        self.keys.read().ok()?.get(alias).map(|k| k.version.clone())
    }

    fn bind(&self, alias: &str, key_type: KeyType, handle: &str) -> Result<(), SecureAreaError> {
        if key_type != KeyType::Ed25519 {
            return Err(SecureAreaError::WrongKeyType(alias.into()));
        }
        let public = self
            .client
            .public_key(handle)
            .map_err(|e| e.into_area_error(alias))?;
        self.keys
            .write()
            .map_err(|_| SecureAreaError::Crypto("secure area lock".into()))?
            .insert(
                alias.to_string(),
                KmsKey {
                    version: handle.to_string(),
                    public,
                },
            );
        Ok(())
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Where the access token for the KMS comes from.
pub trait TokenSource: Send + Sync {
    fn token(&self) -> Result<String, KmsError>;
}

/// The VM's attached service account, through the metadata server: no credential on disk,
/// a token good for an hour, minted for this VM.
pub struct MetadataServerToken {
    cached: Mutex<Option<(String, Instant)>>,
}

impl MetadataServerToken {
    pub fn new() -> Self {
        Self {
            cached: Mutex::new(None),
        }
    }
}

impl Default for MetadataServerToken {
    fn default() -> Self {
        Self::new()
    }
}

impl TokenSource for MetadataServerToken {
    fn token(&self) -> Result<String, KmsError> {
        if let Ok(cache) = self.cached.lock()
            && let Some((token, until)) = cache.as_ref()
            && Instant::now() < *until
        {
            return Ok(token.clone());
        }
        let body: serde_json::Value = ureq::get(
            "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
        )
        .header("Metadata-Flavor", "Google")
        .call()
        .map_err(|e| KmsError::Unreachable(format!("metadata server: {e}")))?
        .body_mut()
        .read_json()
        .map_err(|e| KmsError::Malformed(format!("metadata server: {e}")))?;
        let token = body["access_token"]
            .as_str()
            .ok_or_else(|| KmsError::Malformed("no access_token from the metadata server".into()))?
            .to_string();
        let expires = body["expires_in"].as_u64().unwrap_or(300);
        // refresh a minute early
        let until = Instant::now() + Duration::from_secs(expires.saturating_sub(60).max(30));
        if let Ok(mut cache) = self.cached.lock() {
            *cache = Some((token.clone(), until));
        }
        Ok(token)
    }
}

/// A token given by the environment, `GCP_ACCESS_TOKEN`: for a developer's machine, where
/// `gcloud auth print-access-token` mints one. Never for a deployment.
pub struct EnvToken(pub String);

impl TokenSource for EnvToken {
    fn token(&self) -> Result<String, KmsError> {
        Ok(self.0.clone())
    }
}

/// Google Cloud KMS over its REST API, for one key ring.
pub struct GcpKms {
    /// `projects/<p>/locations/<l>/keyRings/<r>`
    ring: String,
    token: Box<dyn TokenSource>,
    agent: ureq::Agent,
}

const KMS: &str = "https://cloudkms.googleapis.com/v1";

impl GcpKms {
    pub fn new(ring: &str, token: impl TokenSource + 'static) -> Self {
        // an error status is read like any answer, so the KMS's reason reaches the caller;
        // TLS roots come from the OS trust store, as the SDK's transports do
        let config = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .tls_config(
                ureq::tls::TlsConfig::builder()
                    .root_certs(ureq::tls::RootCerts::PlatformVerifier)
                    .build(),
            )
            .build();
        Self {
            ring: ring.trim_matches('/').to_string(),
            token: Box::new(token),
            agent: ureq::Agent::new_with_config(config),
        }
    }

    /// The token from `GCP_ACCESS_TOKEN` if the environment has one, else the metadata
    /// server: a developer's machine, else a VM.
    pub fn from_env(ring: &str) -> Self {
        match std::env::var("GCP_ACCESS_TOKEN") {
            Ok(t) if !t.is_empty() => Self::new(ring, EnvToken(t)),
            _ => Self::new(ring, MetadataServerToken::new()),
        }
    }

    fn call(
        &self,
        method: &str,
        path: &str,
        body: Option<serde_json::Value>,
    ) -> Result<serde_json::Value, KmsError> {
        let token = self.token.token()?;
        let url = format!("{KMS}/{path}");
        let auth = format!("Bearer {token}");
        let response = match (method, body) {
            ("GET", _) => self.agent.get(&url).header("Authorization", &auth).call(),
            (_, Some(b)) => self
                .agent
                .post(&url)
                .header("Authorization", &auth)
                .send_json(b),
            (_, None) => self
                .agent
                .post(&url)
                .header("Authorization", &auth)
                .send_empty(),
        };
        let mut response = response.map_err(|e| KmsError::Unreachable(e.to_string()))?;
        let status = response.status().as_u16();
        let text = response
            .body_mut()
            .read_to_string()
            .map_err(|e| KmsError::Malformed(e.to_string()))?;
        if status >= 400 {
            let reason = serde_json::from_str::<serde_json::Value>(&text)
                .ok()
                .and_then(|v| v["error"]["message"].as_str().map(str::to_string))
                .unwrap_or(text);
            return Err(match status {
                401 | 403 => KmsError::Denied(format!("{method} {path}: {reason}")),
                404 => KmsError::NotFound(format!("{path}: {reason}")),
                _ => KmsError::Malformed(format!("{method} {path}: {status} {reason}")),
            });
        }
        serde_json::from_str(&text).map_err(|e| KmsError::Malformed(e.to_string()))
    }
}

/// The DER prefix of an Ed25519 SubjectPublicKeyInfo, RFC 8410: what precedes the 32 key
/// bytes in the PEM the KMS returns.
const ED25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

/// The 32 key bytes out of an Ed25519 public key PEM.
pub fn ed25519_from_pem(pem: &str) -> Result<[u8; 32], KmsError> {
    let b64: String = pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("");
    let der = Base64::decode_vec(&b64).map_err(|_| KmsError::Malformed("public key PEM".into()))?;
    if der.len() != 44 || der[..12] != ED25519_SPKI_PREFIX {
        return Err(KmsError::Malformed("not an Ed25519 public key".into()));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&der[12..]);
    Ok(key)
}

impl KmsClient for GcpKms {
    fn create_ed25519(&self, key_id: &str) -> Result<String, KmsError> {
        let created = self.call(
            "POST",
            &format!("{}/cryptoKeys?cryptoKeyId={key_id}", self.ring),
            Some(serde_json::json!({
                "purpose": "ASYMMETRIC_SIGN",
                "versionTemplate": { "algorithm": "EC_SIGN_ED25519", "protectionLevel": "SOFTWARE" },
            })),
        )?;
        let name = created["name"]
            .as_str()
            .ok_or_else(|| KmsError::Malformed("created key has no name".into()))?;
        let version = format!("{name}/cryptoKeyVersions/1");
        // the version may still be generating when the call returns; wait for it
        for _ in 0..30 {
            let state = self.call("GET", &version, None)?;
            match state["state"].as_str() {
                Some("ENABLED") => return Ok(version),
                Some("PENDING_GENERATION") | None => std::thread::sleep(Duration::from_millis(500)),
                Some(other) => {
                    return Err(KmsError::Malformed(format!("key version is {other}")));
                }
            }
        }
        Err(KmsError::Unreachable(
            "the key version did not become enabled".into(),
        ))
    }

    fn public_key(&self, version: &str) -> Result<[u8; 32], KmsError> {
        let answer = self.call("GET", &format!("{version}/publicKey"), None)?;
        let pem = answer["pem"]
            .as_str()
            .ok_or_else(|| KmsError::Malformed("no pem in the public key".into()))?;
        ed25519_from_pem(pem)
    }

    fn sign(&self, version: &str, data: &[u8]) -> Result<Vec<u8>, KmsError> {
        let answer = self.call(
            "POST",
            &format!("{version}:asymmetricSign"),
            Some(serde_json::json!({ "data": Base64::encode_string(data) })),
        )?;
        let signature = answer["signature"]
            .as_str()
            .ok_or_else(|| KmsError::Malformed("no signature".into()))?;
        let bytes = Base64::decode_vec(signature)
            .map_err(|_| KmsError::Malformed("signature is not base64".into()))?;
        if bytes.len() != 64 {
            return Err(KmsError::Malformed("signature is not 64 bytes".into()));
        }
        Ok(bytes)
    }
}

/// A KMS in memory, for tests: keys that never leave this struct, an audit trail of
/// signatures, and a switch that revokes the grant.
#[derive(Default)]
pub struct FakeKms {
    keys: Mutex<HashMap<String, ed25519_dalek::SigningKey>>,
    pub signatures: Mutex<Vec<String>>,
    pub revoked: std::sync::atomic::AtomicBool,
}

impl FakeKms {
    fn granted(&self) -> Result<(), KmsError> {
        if self.revoked.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(KmsError::Denied("the grant was revoked".into()));
        }
        Ok(())
    }
}

impl KmsClient for Arc<FakeKms> {
    fn create_ed25519(&self, key_id: &str) -> Result<String, KmsError> {
        self.granted()?;
        let version =
            format!("projects/test/locations/x/keyRings/r/cryptoKeys/{key_id}/cryptoKeyVersions/1");
        self.keys.lock().unwrap().insert(
            version.clone(),
            ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng),
        );
        Ok(version)
    }

    fn public_key(&self, version: &str) -> Result<[u8; 32], KmsError> {
        self.granted()?;
        self.keys
            .lock()
            .unwrap()
            .get(version)
            .map(|k| k.verifying_key().to_bytes())
            .ok_or_else(|| KmsError::NotFound(version.into()))
    }

    fn sign(&self, version: &str, data: &[u8]) -> Result<Vec<u8>, KmsError> {
        use ed25519_dalek::Signer;
        self.granted()?;
        self.signatures.lock().unwrap().push(version.to_string());
        self.keys
            .lock()
            .unwrap()
            .get(version)
            .map(|k| k.sign(data).to_bytes().to_vec())
            .ok_or_else(|| KmsError::NotFound(version.into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SoftwareSecureArea;

    fn verify(public: &[u8], data: &[u8], sig: &[u8]) -> bool {
        let vk = ed25519_dalek::VerifyingKey::from_bytes(&public.try_into().unwrap()).unwrap();
        vk.verify_strict(data, &ed25519_dalek::Signature::from_slice(sig).unwrap())
            .is_ok()
    }

    #[test]
    fn a_signing_key_made_after_attaching_lives_in_the_kms_and_signs_there() {
        let kms = Arc::new(FakeKms::default());
        let area = SoftwareSecureArea::new();
        area.attach_remote(Arc::new(KmsSecureArea::new(kms.clone())))
            .unwrap();

        let sig = area.create_key(None, KeyType::Ed25519).unwrap();
        let enc = area.create_key(None, KeyType::X25519).unwrap();
        assert!(sig.alias.starts_with("z6Mk"), "named by its multikey");
        assert!(area.has_key(&sig.alias) && area.has_key(&enc.alias));

        let signature = area.sign(&sig.alias, b"hello").unwrap();
        assert!(verify(&sig.public, b"hello", &signature));
        assert_eq!(kms.signatures.lock().unwrap().len(), 1, "signed in the KMS");
        assert!(
            area.all_material().iter().all(|(a, _, _)| a != &sig.alias),
            "no material for the KMS key in the software area"
        );
        assert_eq!(area.remote_handles().len(), 1);

        // the encryption key stays software, and works
        assert!(area.key_agreement(&enc.alias, &[7u8; 32]).is_ok());
    }

    #[test]
    fn a_reopened_wallet_knows_its_kms_keys_by_handle_and_is_locked_until_attached() {
        let kms = Arc::new(FakeKms::default());
        let first = SoftwareSecureArea::new();
        first
            .attach_remote(Arc::new(KmsSecureArea::new(kms.clone())))
            .unwrap();
        let sig = first.create_key(None, KeyType::Ed25519).unwrap();
        let handles = first.remote_handles();

        // what the wallet's storage restores: aliases and handles, no keys
        let reopened = SoftwareSecureArea::new();
        for (alias, key_type, handle) in handles {
            reopened.bind_remote(&alias, key_type, &handle).unwrap();
        }
        assert!(reopened.has_key(&sig.alias));
        assert!(matches!(
            reopened.sign(&sig.alias, b"x"),
            Err(SecureAreaError::Locked { .. })
        ));

        reopened
            .attach_remote(Arc::new(KmsSecureArea::new(kms.clone())))
            .unwrap();
        let signature = reopened.sign(&sig.alias, b"x").unwrap();
        assert!(verify(&sig.public, b"x", &signature));
        assert_eq!(reopened.public_key(&sig.alias).unwrap(), sig.public);
    }

    #[test]
    fn a_revoked_grant_is_a_locked_key() {
        let kms = Arc::new(FakeKms::default());
        let area = SoftwareSecureArea::new();
        area.attach_remote(Arc::new(KmsSecureArea::new(kms.clone())))
            .unwrap();
        let sig = area.create_key(None, KeyType::Ed25519).unwrap();
        kms.revoked.store(true, std::sync::atomic::Ordering::SeqCst);
        assert!(matches!(
            area.sign(&sig.alias, b"x"),
            Err(SecureAreaError::Locked { .. })
        ));
    }

    #[test]
    fn the_kms_public_key_pem_decodes() {
        let key = [0x11u8; 32];
        let mut der = ED25519_SPKI_PREFIX.to_vec();
        der.extend_from_slice(&key);
        let pem = format!(
            "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
            Base64::encode_string(&der)
        );
        assert_eq!(ed25519_from_pem(&pem).unwrap(), key);
        assert!(
            ed25519_from_pem("-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----").is_err()
        );
    }
}
