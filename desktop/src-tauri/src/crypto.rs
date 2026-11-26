use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use hkdf::Hkdf;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use thiserror::Error;
use url::Url;

const EVENT_KDF_INFO: &[u8] = b"all-notify:v1:event";
const BLOB_KDF_INFO: &[u8] = b"all-notify:v1:blob";
const KCV_KDF_INFO: &[u8] = b"all-notify:v1:kcv";
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
const MAX_QR_IMAGE_BYTES: usize = 10 * 1024 * 1024; // 10 MiB cap for dropped QR images

const KEYRING_SERVICE: &str = "com.allnotify.desktop";
const KEYRING_MASTER_KEY_USER: &str = "k_master";
const KEYRING_DEVICE_TOKEN_USER: &str = "device_token";

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("key derivation failed")]
    KdfFailed,
    #[error("encryption failed")]
    EncryptFailed,
    #[error("decryption failed")]
    DecryptFailed,
    #[error("invalid ciphertext encoding")]
    InvalidCiphertext,
    #[error("invalid pairing uri: {0}")]
    InvalidPairingUri(String),
    #[error("qr decode failed: {0}")]
    QrDecodeFailed(String),
    #[error("secret storage error: {0}")]
    SecretStore(String),
}

#[derive(Clone, PartialEq, Eq)]
pub struct DerivedKeys {
    pub k_event: [u8; 32],
    pub k_blob: [u8; 32],
}

impl fmt::Debug for DerivedKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DerivedKeys([REDACTED])")
    }
}

pub fn derive_keys(k_master: &[u8; 32]) -> Result<DerivedKeys, CryptoError> {
    let hk = Hkdf::<Sha256>::new(None, k_master);
    let mut k_event = [0u8; 32];
    let mut k_blob = [0u8; 32];
    hk.expand(EVENT_KDF_INFO, &mut k_event)
        .map_err(|_| CryptoError::KdfFailed)?;
    hk.expand(BLOB_KDF_INFO, &mut k_blob)
        .map_err(|_| CryptoError::KdfFailed)?;
    Ok(DerivedKeys { k_event, k_blob })
}

pub fn compute_kcv(k_master: &[u8; 32]) -> Result<String, CryptoError> {
    let hk = Hkdf::<Sha256>::new(None, k_master);
    let mut out = [0u8; 16];
    hk.expand(KCV_KDF_INFO, &mut out)
        .map_err(|_| CryptoError::KdfFailed)?;
    Ok(hex::encode(out))
}

#[derive(Clone)]
pub struct CryptoEngine {
    keys: DerivedKeys,
}

impl fmt::Debug for CryptoEngine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CryptoEngine([REDACTED])")
    }
}

impl CryptoEngine {
    pub fn new(k_master: &[u8; 32]) -> Result<Self, CryptoError> {
        Ok(Self {
            keys: derive_keys(k_master)?,
        })
    }

    pub fn keys(&self) -> &DerivedKeys {
        &self.keys
    }

    pub fn event_aad(event_id: &str, sender_device_id: &str) -> Vec<u8> {
        format!("v1|{event_id}|{sender_device_id}").into_bytes()
    }

    pub fn blob_aad(blob_id: &str) -> Vec<u8> {
        format!("v1|blob|{blob_id}").into_bytes()
    }

    pub fn encrypt_event(
        &self,
        event_id: &str,
        sender_device_id: &str,
        plaintext: &[u8],
    ) -> Result<String, CryptoError> {
        let mut nonce = [0u8; NONCE_LEN];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        self.encrypt_event_with_nonce(event_id, sender_device_id, &nonce, plaintext)
    }

    pub fn encrypt_event_with_nonce(
        &self,
        event_id: &str,
        sender_device_id: &str,
        nonce: &[u8; NONCE_LEN],
        plaintext: &[u8],
    ) -> Result<String, CryptoError> {
        let aad = Self::event_aad(event_id, sender_device_id);
        let raw = seal_raw(&self.keys.k_event, nonce, &aad, plaintext)?;
        Ok(URL_SAFE_NO_PAD.encode(raw))
    }

    pub fn decrypt_event(
        &self,
        event_id: &str,
        sender_device_id: &str,
        ciphertext_b64: &str,
    ) -> Result<Vec<u8>, CryptoError> {
        if ciphertext_b64.contains('=') {
            return Err(CryptoError::InvalidCiphertext);
        }
        let raw = URL_SAFE_NO_PAD
            .decode(ciphertext_b64)
            .map_err(|_| CryptoError::InvalidCiphertext)?;
        let aad = Self::event_aad(event_id, sender_device_id);
        open_raw(&self.keys.k_event, &aad, &raw)
    }

    pub fn encrypt_blob(&self, blob_id: &str, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let mut nonce = [0u8; NONCE_LEN];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        self.encrypt_blob_with_nonce(blob_id, &nonce, plaintext)
    }

    pub fn encrypt_blob_with_nonce(
        &self,
        blob_id: &str,
        nonce: &[u8; NONCE_LEN],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let aad = Self::blob_aad(blob_id);
        seal_raw(&self.keys.k_blob, nonce, &aad, plaintext)
    }

    pub fn decrypt_blob(&self, blob_id: &str, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let aad = Self::blob_aad(blob_id);
        open_raw(&self.keys.k_blob, &aad, ciphertext)
    }
}

fn seal_raw(
    key: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let ct = cipher
        .encrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| CryptoError::EncryptFailed)?;
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

fn open_raw(key: &[u8; 32], aad: &[u8], raw: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if raw.len() < NONCE_LEN + TAG_LEN {
        return Err(CryptoError::InvalidCiphertext);
    }
    let (nonce, ct) = raw.split_at(NONCE_LEN);
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(XNonce::from_slice(nonce), Payload { msg: ct, aad })
        .map_err(|_| CryptoError::DecryptFailed)
}

#[derive(Clone, PartialEq, Eq)]
pub struct PairingConfig {
    pub version: u32,
    pub server_url: String,
    pub ws_url: String,
    pub token: String,
    pub key_base64url: String,
    pub key_bytes: [u8; 32],
    pub device_id: String,
    pub device_name: String,
    pub can_add_devices: bool,
}

// Never leak secrets (K_master or bearer token) via Debug output.
impl fmt::Debug for PairingConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PairingConfig")
            .field("version", &self.version)
            .field("server_url", &self.server_url)
            .field("ws_url", &self.ws_url)
            .field("device_id", &self.device_id)
            .field("device_name", &self.device_name)
            .field("can_add_devices", &self.can_add_devices)
            .field("token", &"[REDACTED]")
            .field("key", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub enum PairingLink {
    V1(PairingConfig),
    V2 {
        server_url: String,
        ws_url: String,
        code: String,
        key_base64url: String,
        key_bytes: [u8; 32],
        device_name: String,
    },
}

impl PairingLink {
    pub fn server_url(&self) -> &str {
        match self {
            PairingLink::V1(c) => &c.server_url,
            PairingLink::V2 { server_url, .. } => server_url,
        }
    }

    pub fn key_bytes(&self) -> &[u8; 32] {
        match self {
            PairingLink::V1(c) => &c.key_bytes,
            PairingLink::V2 { key_bytes, .. } => key_bytes,
        }
    }
}

impl fmt::Debug for PairingLink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PairingLink::V1(c) => f.debug_tuple("V1").field(c).finish(),
            PairingLink::V2 {
                server_url,
                ws_url,
                device_name,
                ..
            } => f
                .debug_struct("V2")
                .field("server_url", server_url)
                .field("ws_url", ws_url)
                .field("device_name", device_name)
                .field("code", &"[REDACTED]")
                .field("key", &"[REDACTED]")
                .finish(),
        }
    }
}

fn is_valid_pairing_code(code: &str) -> bool {
    let Some(rest) = code.strip_prefix("pc_") else {
        return false;
    };
    rest.len() == 22
        && rest
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

pub fn parse_pairing_link(raw: &str) -> Result<PairingLink, CryptoError> {
    let trimmed = raw.trim();
    let parsed = Url::parse(trimmed)
        .map_err(|e| CryptoError::InvalidPairingUri(format!("malformed uri: {e}")))?;

    if parsed.scheme() != "allnotify" {
        return Err(CryptoError::InvalidPairingUri(
            "scheme must be allnotify".into(),
        ));
    }
    if parsed.host_str() != Some("pair") {
        return Err(CryptoError::InvalidPairingUri("host must be pair".into()));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(CryptoError::InvalidPairingUri(
            "pairing uri must not contain userinfo".into(),
        ));
    }
    if parsed.fragment().is_some() {
        return Err(CryptoError::InvalidPairingUri(
            "pairing uri must not contain fragment".into(),
        ));
    }
    let path = parsed.path();
    if !path.is_empty() && path != "/" {
        return Err(CryptoError::InvalidPairingUri(
            "pairing uri must not include a non-empty path".into(),
        ));
    }

    let mut params: HashMap<String, String> = HashMap::new();
    for (k, v) in parsed.query_pairs() {
        params.entry(k.into_owned()).or_insert_with(|| v.into_owned());
    }

    let v_str = params
        .get("v")
        .filter(|s| !s.is_empty())
        .ok_or_else(|| CryptoError::InvalidPairingUri("v parameter is required".into()))?;
    let version: u32 = v_str
        .parse()
        .map_err(|_| CryptoError::InvalidPairingUri("invalid v parameter".into()))?;
    if version != 1 && version != 2 {
        return Err(CryptoError::InvalidPairingUri(
            "only protocol versions 1 and 2 are supported".into(),
        ));
    }

    let raw_server_url = params
        .get("url")
        .filter(|s| !s.is_empty())
        .ok_or_else(|| CryptoError::InvalidPairingUri("url parameter is required".into()))?;
    let server_parsed = Url::parse(raw_server_url)
        .map_err(|_| CryptoError::InvalidPairingUri("server url is invalid".into()))?;
    if server_parsed.scheme() != "https" {
        return Err(CryptoError::InvalidPairingUri(
            "server url must use https".into(),
        ));
    }
    if server_parsed.host_str().map(|h| h.is_empty()).unwrap_or(true) {
        return Err(CryptoError::InvalidPairingUri(
            "server url must have a host".into(),
        ));
    }
    if !server_parsed.username().is_empty() || server_parsed.password().is_some() {
        return Err(CryptoError::InvalidPairingUri(
            "server url must not contain userinfo".into(),
        ));
    }
    if server_parsed.query().is_some() {
        return Err(CryptoError::InvalidPairingUri(
            "server url must not contain query parameters".into(),
        ));
    }
    if server_parsed.fragment().is_some() {
        return Err(CryptoError::InvalidPairingUri(
            "server url must not contain a fragment".into(),
        ));
    }

    let server_url = server_parsed.as_str().trim_end_matches('/').to_string();
    let ws_url = format!(
        "wss://{}/v1/ws",
        server_url.strip_prefix("https://").unwrap_or(&server_url)
    );

    let device_name = params
        .get("name")
        .filter(|s| !s.is_empty())
        .ok_or_else(|| CryptoError::InvalidPairingUri("name parameter is required".into()))?
        .clone();
    if device_name.chars().count() > 128 || device_name.chars().any(|c| c.is_control()) {
        return Err(CryptoError::InvalidPairingUri(
            "name must be at most 128 printable characters".into(),
        ));
    }

    let key_b64 = params
        .get("key")
        .filter(|s| !s.is_empty())
        .ok_or_else(|| CryptoError::InvalidPairingUri("key parameter is required".into()))?;
    let key_bytes = decode_master_key_b64url(key_b64)?;

    if version == 1 {
        let token = params
            .get("token")
            .filter(|s| !s.is_empty())
            .ok_or_else(|| CryptoError::InvalidPairingUri("token parameter is required".into()))?
            .clone();
        if token
            .bytes()
            .any(|b| b.is_ascii_control() || b.is_ascii_whitespace())
        {
            return Err(CryptoError::InvalidPairingUri(
                "token parameter contains invalid whitespace or control characters".into(),
            ));
        }
        let device_id = params
            .get("device_id")
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                CryptoError::InvalidPairingUri("device_id parameter is required".into())
            })?
            .clone();
        if device_id.len() > 128
            || !device_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        {
            return Err(CryptoError::InvalidPairingUri(
                "device_id must be 1..=128 ASCII alphanumeric, '_' or '-' characters".into(),
            ));
        }
        Ok(PairingLink::V1(PairingConfig {
            version,
            server_url,
            ws_url,
            token,
            key_base64url: key_b64.clone(),
            key_bytes,
            device_id,
            device_name,
            can_add_devices: false,
        }))
    } else {
        if params.contains_key("token") || params.contains_key("device_id") {
            return Err(CryptoError::InvalidPairingUri(
                "v2 pairing uri must not contain token or device_id".into(),
            ));
        }
        let code = params
            .get("code")
            .filter(|s| !s.is_empty())
            .ok_or_else(|| CryptoError::InvalidPairingUri("code parameter is required".into()))?
            .clone();
        if !is_valid_pairing_code(&code) {
            return Err(CryptoError::InvalidPairingUri(
                "code must match ^pc_[A-Za-z0-9_-]{22}$".into(),
            ));
        }
        Ok(PairingLink::V2 {
            server_url,
            ws_url,
            code,
            key_base64url: key_b64.clone(),
            key_bytes,
            device_name,
        })
    }
}

pub fn parse_pairing_uri(raw: &str) -> Result<PairingConfig, CryptoError> {
    match parse_pairing_link(raw)? {
        PairingLink::V1(cfg) => Ok(cfg),
        PairingLink::V2 { .. } => Err(CryptoError::InvalidPairingUri(
            "v2 pairing link must be claimed via POST /v1/pair/claim".into(),
        )),
    }
}

pub fn build_pairing_uri_v2(
    server_url: &str,
    code: &str,
    key_b64url: &str,
    device_name: &str,
) -> String {
    let mut u = Url::parse("allnotify://pair").expect("static pairing url");
    u.query_pairs_mut()
        .append_pair("v", "2")
        .append_pair("url", server_url.trim_end_matches('/'))
        .append_pair("code", code)
        .append_pair("key", key_b64url)
        .append_pair("name", device_name);
    u.to_string()
}

pub fn render_qr_svg(content: &str) -> Result<String, CryptoError> {
    let code = qrcode::QrCode::new(content.as_bytes())
        .map_err(|e| CryptoError::QrDecodeFailed(format!("qr encode failed: {e}")))?;
    Ok(code
        .render::<qrcode::render::svg::Color<'_>>()
        .min_dimensions(220, 220)
        .dark_color(qrcode::render::svg::Color("#000000"))
        .light_color(qrcode::render::svg::Color("#ffffff"))
        .build())
}

pub fn decode_master_key_b64url(key_b64: &str) -> Result<[u8; 32], CryptoError> {
    if key_b64.contains('=') {
        return Err(CryptoError::InvalidPairingUri(
            "key must be unpadded base64url".into(),
        ));
    }
    if !key_b64
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(CryptoError::InvalidPairingUri(
            "key must use base64url alphabet (- and _)".into(),
        ));
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(key_b64)
        .map_err(|_| CryptoError::InvalidPairingUri("key is not valid base64url".into()))?;
    let key_bytes: [u8; 32] = decoded.try_into().map_err(|_| {
        CryptoError::InvalidPairingUri("decoded key must be exactly 32 bytes".into())
    })?;
    if URL_SAFE_NO_PAD.encode(key_bytes) != key_b64 {
        return Err(CryptoError::InvalidPairingUri(
            "key is not canonical unpadded base64url".into(),
        ));
    }
    Ok(key_bytes)
}

/// Generates a 26-character Crockford Base32 ULID (matches `^[A-Za-z0-9_-]+$`).
pub fn generate_ulid() -> String {
    const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    let mut rand_bytes = [0u8; 10];
    rand::rngs::OsRng.fill_bytes(&mut rand_bytes);

    let mut out = [0u8; 26];
    let mut ts = now_ms;
    for i in (0..10).rev() {
        out[i] = ALPHABET[(ts & 0x1f) as usize];
        ts >>= 5;
    }

    // Encode 80 random bits into 16 5-bit chars.
    let mut bit_buf: u16 = 0;
    let mut bit_count: u8 = 0;
    let mut out_idx = 10;
    for byte in rand_bytes {
        bit_buf = (bit_buf << 8) | (byte as u16);
        bit_count += 8;
        while bit_count >= 5 {
            bit_count -= 5;
            let idx = ((bit_buf >> bit_count) & 0x1f) as usize;
            out[out_idx] = ALPHABET[idx];
            out_idx += 1;
        }
    }

    String::from_utf8(out.to_vec()).expect("valid ascii ulid")
}

/// Decodes a pairing QR code from an uploaded/dropped image (PNG, JPEG, or WebP).
pub fn decode_qr_from_image_bytes(bytes: &[u8]) -> Result<String, CryptoError> {
    if bytes.is_empty() {
        return Err(CryptoError::QrDecodeFailed("empty image file".into()));
    }
    if bytes.len() > MAX_QR_IMAGE_BYTES {
        return Err(CryptoError::QrDecodeFailed(
            "image file exceeds 10 MB limit".into(),
        ));
    }
    let img = image::load_from_memory(bytes)
        .map_err(|e| CryptoError::QrDecodeFailed(format!("unsupported or invalid image: {e}")))?
        .to_luma8();
    let mut prepared = rqrr::PreparedImage::prepare(img);
    let grids = prepared.detect_grids();
    for grid in grids {
        if let Ok((_meta, content)) = grid.decode() {
            let trimmed = content.trim().to_string();
            if !trimmed.is_empty() {
                return Ok(trimmed);
            }
        }
    }
    Err(CryptoError::QrDecodeFailed(
        "no readable QR code found in image".into(),
    ))
}

/// Abstraction over OS Keychain / Windows Credential Manager for testable secret storage.
pub trait SecretStore: Send + Sync {
    fn set_secret(&self, account: &str, value: &str) -> Result<(), CryptoError>;
    fn get_secret(&self, account: &str) -> Result<Option<String>, CryptoError>;
    fn delete_secret(&self, account: &str) -> Result<(), CryptoError>;
}

pub struct KeyringSecretStore {
    service: String,
}

impl Default for KeyringSecretStore {
    fn default() -> Self {
        Self {
            service: KEYRING_SERVICE.to_string(),
        }
    }
}

impl SecretStore for KeyringSecretStore {
    fn set_secret(&self, account: &str, value: &str) -> Result<(), CryptoError> {
        let entry = keyring::Entry::new(&self.service, account)
            .map_err(|e| CryptoError::SecretStore(e.to_string()))?;
        entry
            .set_password(value)
            .map_err(|e| CryptoError::SecretStore(e.to_string()))
    }

    fn get_secret(&self, account: &str) -> Result<Option<String>, CryptoError> {
        let entry = keyring::Entry::new(&self.service, account)
            .map_err(|e| CryptoError::SecretStore(e.to_string()))?;
        match entry.get_password() {
            Ok(v) => Ok(Some(v)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(CryptoError::SecretStore(e.to_string())),
        }
    }

    fn delete_secret(&self, account: &str) -> Result<(), CryptoError> {
        let entry = keyring::Entry::new(&self.service, account)
            .map_err(|e| CryptoError::SecretStore(e.to_string()))?;
        match entry.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(CryptoError::SecretStore(e.to_string())),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PairingMetadata {
    version: u32,
    server_url: String,
    ws_url: String,
    device_id: String,
    device_name: String,
    #[serde(default)]
    can_add_devices: bool,
}

/// Persists non-secret pairing metadata on disk and secrets (`K_master`, `device_token`) in OS Keychain.
pub struct CredentialManager {
    meta_path: PathBuf,
    secrets: Box<dyn SecretStore>,
}

impl CredentialManager {
    pub fn new(data_dir: &Path, secrets: Box<dyn SecretStore>) -> Self {
        Self {
            meta_path: data_dir.join("pairing.json"),
            secrets,
        }
    }

    pub fn save(&self, config: &PairingConfig) -> Result<(), CryptoError> {
        if let Some(parent) = self.meta_path.parent() {
            fs::create_dir_all(parent).map_err(|e| CryptoError::SecretStore(e.to_string()))?;
        }
        self.secrets
            .set_secret(KEYRING_MASTER_KEY_USER, &config.key_base64url)?;
        self.secrets
            .set_secret(KEYRING_DEVICE_TOKEN_USER, &config.token)?;

        let meta = PairingMetadata {
            version: config.version,
            server_url: config.server_url.clone(),
            ws_url: config.ws_url.clone(),
            device_id: config.device_id.clone(),
            device_name: config.device_name.clone(),
            can_add_devices: config.can_add_devices,
        };
        let bytes =
            serde_json::to_vec_pretty(&meta).map_err(|e| CryptoError::SecretStore(e.to_string()))?;
        let tmp = self.meta_path.with_extension("json.tmp");
        fs::write(&tmp, &bytes).map_err(|e| CryptoError::SecretStore(e.to_string()))?;
        fs::rename(&tmp, &self.meta_path).map_err(|e| CryptoError::SecretStore(e.to_string()))?;
        Ok(())
    }

    pub fn load(&self) -> Result<Option<PairingConfig>, CryptoError> {
        if !self.meta_path.exists() {
            return Ok(None);
        }
        let raw =
            fs::read(&self.meta_path).map_err(|e| CryptoError::SecretStore(e.to_string()))?;
        let meta: PairingMetadata =
            serde_json::from_slice(&raw).map_err(|e| CryptoError::SecretStore(e.to_string()))?;
        let Some(key_b64) = self.secrets.get_secret(KEYRING_MASTER_KEY_USER)? else {
            return Ok(None);
        };
        let Some(token) = self.secrets.get_secret(KEYRING_DEVICE_TOKEN_USER)? else {
            return Ok(None);
        };
        let key_bytes = decode_master_key_b64url(&key_b64)?;
        Ok(Some(PairingConfig {
            version: meta.version,
            server_url: meta.server_url,
            ws_url: meta.ws_url,
            token,
            key_base64url: key_b64,
            key_bytes,
            device_id: meta.device_id,
            device_name: meta.device_name,
            can_add_devices: meta.can_add_devices,
        }))
    }

    pub fn clear(&self) -> Result<(), CryptoError> {
        self.secrets.delete_secret(KEYRING_MASTER_KEY_USER)?;
        self.secrets.delete_secret(KEYRING_DEVICE_TOKEN_USER)?;
        if self.meta_path.exists() {
            fs::remove_file(&self.meta_path)
                .map_err(|e| CryptoError::SecretStore(e.to_string()))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[derive(Deserialize)]
    struct TestVectors {
        protocol_version: u32,
        kdf: KdfVector,
        event_vectors: Vec<EventVector>,
        blob_vectors: Vec<BlobVector>,
        pairing_uri_vectors: PairingVectors,
    }

    #[derive(Deserialize)]
    struct KdfVector {
        k_master_hex: String,
        k_master_base64url: String,
        kcv_info: String,
        k_event_hex: String,
        k_blob_hex: String,
        kcv_hex: String,
    }

    #[derive(Deserialize)]
    struct EventVector {
        name: String,
        event_id: String,
        sender_device_id: String,
        aad: String,
        nonce_hex: String,
        plaintext_utf8: String,
        ciphertext_base64url: String,
        ciphertext_hex: String,
    }

    #[derive(Deserialize)]
    struct BlobVector {
        name: String,
        blob_id: String,
        aad: String,
        nonce_hex: String,
        plaintext_hex: String,
        ciphertext_hex: String,
    }

    #[derive(Deserialize)]
    struct PairingVectors {
        valid: Vec<ValidPairingVector>,
        invalid: Vec<InvalidPairingVector>,
    }

    #[derive(Deserialize)]
    struct ValidPairingVector {
        name: String,
        uri: String,
        expected: ExpectedPairing,
    }

    #[derive(Deserialize)]
    struct ExpectedPairing {
        v: u32,
        url: String,
        ws_url: String,
        #[serde(default)]
        token: String,
        #[serde(default)]
        code: String,
        key_base64url: String,
        key_hex: String,
        #[serde(default)]
        device_id: String,
        device_name: String,
    }

    #[derive(Deserialize)]
    struct InvalidPairingVector {
        name: String,
        uri: String,
    }

    fn load_vectors() -> TestVectors {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../protocol/test_vectors.json");
        let raw = fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
        serde_json::from_str(&raw).expect("parse test_vectors.json")
    }

    #[test]
    fn shared_protocol_test_vectors_kdf_events_blobs() {
        let tv = load_vectors();
        assert_eq!(tv.protocol_version, 1);

        let k_master: [u8; 32] = hex::decode(&tv.kdf.k_master_hex)
            .unwrap()
            .try_into()
            .unwrap();
        assert_eq!(
            decode_master_key_b64url(&tv.kdf.k_master_base64url).unwrap(),
            k_master
        );

        let engine = CryptoEngine::new(&k_master).unwrap();
        assert_eq!(hex::encode(engine.keys().k_event), tv.kdf.k_event_hex);
        assert_eq!(hex::encode(engine.keys().k_blob), tv.kdf.k_blob_hex);
        assert_eq!(tv.kdf.kcv_info, "all-notify:v1:kcv");
        assert_eq!(compute_kcv(&k_master).unwrap(), tv.kdf.kcv_hex);

        for ev in &tv.event_vectors {
            assert_eq!(
                String::from_utf8(CryptoEngine::event_aad(&ev.event_id, &ev.sender_device_id))
                    .unwrap(),
                ev.aad,
                "AAD mismatch for {}",
                ev.name
            );
            let nonce: [u8; 24] = hex::decode(&ev.nonce_hex).unwrap().try_into().unwrap();
            let ct_b64 = engine
                .encrypt_event_with_nonce(
                    &ev.event_id,
                    &ev.sender_device_id,
                    &nonce,
                    ev.plaintext_utf8.as_bytes(),
                )
                .unwrap();
            assert_eq!(ct_b64, ev.ciphertext_base64url, "ct b64 mismatch: {}", ev.name);
            let ct_raw = URL_SAFE_NO_PAD.decode(&ct_b64).unwrap();
            assert_eq!(hex::encode(&ct_raw), ev.ciphertext_hex, "ct hex mismatch: {}", ev.name);

            let pt = engine
                .decrypt_event(&ev.event_id, &ev.sender_device_id, &ev.ciphertext_base64url)
                .unwrap();
            assert_eq!(
                String::from_utf8(pt).unwrap(),
                ev.plaintext_utf8,
                "decrypt mismatch: {}",
                ev.name
            );

            // Tampered AAD must fail authentication.
            assert!(engine
                .decrypt_event(&ev.event_id, "dev_tampered", &ev.ciphertext_base64url)
                .is_err());
        }

        for bv in &tv.blob_vectors {
            assert_eq!(
                String::from_utf8(CryptoEngine::blob_aad(&bv.blob_id)).unwrap(),
                bv.aad,
                "blob AAD mismatch for {}",
                bv.name
            );
            let nonce: [u8; 24] = hex::decode(&bv.nonce_hex).unwrap().try_into().unwrap();
            let pt = hex::decode(&bv.plaintext_hex).unwrap();
            let ct = engine
                .encrypt_blob_with_nonce(&bv.blob_id, &nonce, &pt)
                .unwrap();
            assert_eq!(hex::encode(&ct), bv.ciphertext_hex, "blob ct mismatch: {}", bv.name);

            let dec = engine.decrypt_blob(&bv.blob_id, &ct).unwrap();
            assert_eq!(dec, pt, "blob decrypt mismatch: {}", bv.name);

            // Tampered blob_id AAD must fail authentication.
            assert!(engine.decrypt_blob("icon_tampered0000", &ct).is_err());
        }
    }

    #[test]
    fn shared_protocol_pairing_uri_vectors() {
        let tv = load_vectors();

        for v in &tv.pairing_uri_vectors.valid {
            let link = parse_pairing_link(&v.uri)
                .unwrap_or_else(|e| panic!("expected valid pairing uri {}: {e}", v.name));
            let dbg = format!("{link:?}");
            match &link {
                PairingLink::V1(cfg) => {
                    assert_eq!(cfg.version, v.expected.v);
                    assert_eq!(cfg.server_url, v.expected.url);
                    assert_eq!(cfg.ws_url, v.expected.ws_url);
                    assert_eq!(cfg.token, v.expected.token);
                    assert_eq!(cfg.key_base64url, v.expected.key_base64url);
                    assert_eq!(hex::encode(cfg.key_bytes), v.expected.key_hex);
                    assert_eq!(cfg.device_id, v.expected.device_id);
                    assert_eq!(cfg.device_name, v.expected.device_name);
                    assert!(!dbg.contains(&cfg.token), "Debug leaked token!");
                    assert!(!dbg.contains(&cfg.key_base64url), "Debug leaked K_master!");
                }
                PairingLink::V2 {
                    server_url,
                    ws_url,
                    code,
                    key_base64url,
                    key_bytes,
                    device_name,
                } => {
                    assert_eq!(2, v.expected.v);
                    assert_eq!(server_url, &v.expected.url);
                    assert_eq!(ws_url, &v.expected.ws_url);
                    assert_eq!(code, &v.expected.code);
                    assert_eq!(key_base64url, &v.expected.key_base64url);
                    assert_eq!(hex::encode(key_bytes), v.expected.key_hex);
                    assert_eq!(device_name, &v.expected.device_name);
                    assert!(!dbg.contains(code), "Debug leaked code!");
                    assert!(!dbg.contains(key_base64url), "Debug leaked K_master!");

                    let rebuilt = build_pairing_uri_v2(server_url, code, key_base64url, device_name);
                    assert_eq!(parse_pairing_link(&rebuilt).unwrap(), link);
                    let svg = render_qr_svg(&rebuilt).unwrap();
                    assert!(svg.contains("<svg") && svg.contains("</svg>"));
                }
            }
        }

        for inv in &tv.pairing_uri_vectors.invalid {
            assert!(
                parse_pairing_link(&inv.uri).is_err(),
                "expected invalid pairing uri {} to fail",
                inv.name
            );
        }
    }

    #[test]
    fn ulid_is_valid_26_char_id() {
        let a = generate_ulid();
        let b = generate_ulid();
        assert_eq!(a.len(), 26);
        assert_eq!(b.len(), 26);
        assert_ne!(a, b);
        assert!(a.bytes().all(|c| c.is_ascii_alphanumeric()));
    }

    #[test]
    fn qr_image_round_trip() {
        use image::{ImageFormat, Luma};
        use qrcode::QrCode;
        use std::io::Cursor;

        let uri = "allnotify://pair?v=1&url=https%3A%2F%2Fnotify.example.com&token=tok_01&key=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8&device_id=dev_01&name=MacBook";
        let code = QrCode::new(uri.as_bytes()).unwrap();
        let img = code.render::<Luma<u8>>().min_dimensions(256, 256).build();
        let mut png_bytes = Vec::new();
        image::DynamicImage::ImageLuma8(img)
            .write_to(&mut Cursor::new(&mut png_bytes), ImageFormat::Png)
            .unwrap();

        let decoded = decode_qr_from_image_bytes(&png_bytes).unwrap();
        assert_eq!(decoded, uri);
        assert!(parse_pairing_uri(&decoded).is_ok());

        // Non-image bytes fail cleanly.
        assert!(decode_qr_from_image_bytes(b"not an image").is_err());
    }

    struct MemSecrets(Mutex<HashMap<String, String>>);

    impl SecretStore for MemSecrets {
        fn set_secret(&self, account: &str, value: &str) -> Result<(), CryptoError> {
            self.0
                .lock()
                .unwrap()
                .insert(account.to_string(), value.to_string());
            Ok(())
        }
        fn get_secret(&self, account: &str) -> Result<Option<String>, CryptoError> {
            Ok(self.0.lock().unwrap().get(account).cloned())
        }
        fn delete_secret(&self, account: &str) -> Result<(), CryptoError> {
            self.0.lock().unwrap().remove(account);
            Ok(())
        }
    }

    #[test]
    fn credential_manager_stores_secrets_outside_disk_json() {
        let dir = tempfile::tempdir().unwrap();
        let mgr = CredentialManager::new(dir.path(), Box::new(MemSecrets(Mutex::new(HashMap::new()))));
        let uri = "allnotify://pair?v=1&url=https%3A%2F%2Fnotify.example.com&token=super_secret_tok&key=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8&device_id=dev_01&name=MacBook";
        let cfg = parse_pairing_uri(uri).unwrap();

        mgr.save(&cfg).unwrap();
        let disk_json = fs::read_to_string(dir.path().join("pairing.json")).unwrap();
        assert!(!disk_json.contains("super_secret_tok"));
        assert!(!disk_json.contains(&cfg.key_base64url));

        let loaded = mgr.load().unwrap().unwrap();
        assert_eq!(loaded, cfg);

        mgr.clear().unwrap();
        assert!(mgr.load().unwrap().is_none());
    }

    #[test]
    fn pairing_uri_and_qr_reject_header_injection_and_oversized_images() {
        let base = "allnotify://pair?v=1&url=https%3A%2F%2Fnotify.example.com&key=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
        // Token with CR/LF (HTTP header injection) must be rejected.
        assert!(parse_pairing_uri(&format!("{base}&token=tok%0D%0AX-Evil%3A1&device_id=dev_1&name=Mac")).is_err());
        // Token with spaces must be rejected.
        assert!(parse_pairing_uri(&format!("{base}&token=tok%20space&device_id=dev_1&name=Mac")).is_err());
        // device_id with illegal characters must be rejected.
        assert!(parse_pairing_uri(&format!("{base}&token=tok_1&device_id=dev%2F1&name=Mac")).is_err());
        // name with control character must be rejected.
        assert!(parse_pairing_uri(&format!("{base}&token=tok_1&device_id=dev_1&name=Mac%00Book")).is_err());

        // Empty and >10 MiB QR payloads must be rejected before image decoding.
        assert!(decode_qr_from_image_bytes(&[]).is_err());
        let huge = vec![0u8; MAX_QR_IMAGE_BYTES + 1];
        assert!(decode_qr_from_image_bytes(&huge).is_err());
    }
}
