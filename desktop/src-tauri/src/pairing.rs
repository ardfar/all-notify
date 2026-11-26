use std::time::Duration;

use serde::{Deserialize, Serialize};

const HTTP_TIMEOUT: Duration = Duration::from_secs(12);

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ClaimResponse {
    pub device_id: String,
    pub token: String,
    pub name: String,
    pub platform: String,
    #[serde(default)]
    pub can_add_devices: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DeviceMe {
    pub device_id: String,
    pub name: String,
    pub platform: String,
    #[serde(default)]
    pub can_add_devices: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CreatedPairingCode {
    pub code_id: String,
    pub code: String,
    pub name: String,
    pub platform: String,
    #[serde(default)]
    pub can_add_devices: bool,
    pub expires_at: i64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PairingCodeSummary {
    pub code_id: String,
    pub name: String,
    pub platform: String,
    #[serde(default)]
    pub can_add_devices: bool,
    pub status: String,
    pub claimed_device_id: Option<String>,
    #[serde(default)]
    pub created_at: i64,
    pub expires_at: i64,
}

#[derive(Deserialize)]
struct ApiErrorEnvelope {
    error: Option<ApiErrorBody>,
}

#[derive(Deserialize)]
struct ApiErrorBody {
    #[serde(default)]
    code: String,
    #[serde(default)]
    message: String,
}

#[derive(Debug, Clone)]
pub struct PairingApiError {
    pub status: u16,
    pub code: String,
    pub message: String,
}

impl std::fmt::Display for PairingApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for PairingApiError {}

pub fn current_desktop_platform() -> &'static str {
    #[cfg(target_os = "windows")]
    {
        "windows"
    }
    #[cfg(not(target_os = "windows"))]
    {
        "macos"
    }
}

pub fn build_http_client() -> Result<reqwest::Client, PairingApiError> {
    reqwest::Client::builder()
        .timeout(HTTP_TIMEOUT)
        .build()
        .map_err(|e| PairingApiError {
            status: 0,
            code: "HTTP_CLIENT_ERROR".into(),
            message: format!("failed to build http client: {e}"),
        })
}

fn parse_error(status: u16, body: &str) -> PairingApiError {
    let parsed = serde_json::from_str::<ApiErrorEnvelope>(body)
        .ok()
        .and_then(|e| e.error);
    let code = parsed
        .as_ref()
        .map(|e| e.code.clone())
        .filter(|c| !c.is_empty())
        .unwrap_or_else(|| format!("HTTP_{status}"));
    let message = if status == 404
        || status == 410
        || code == "CODE_NOT_FOUND"
        || code == "CODE_EXPIRED_OR_USED"
    {
        "This pairing code expired or was already used — create a new one.".to_string()
    } else if let Some(msg) = parsed.map(|e| e.message).filter(|m| !m.is_empty()) {
        msg
    } else {
        format!("Request failed (HTTP {status})")
    };
    PairingApiError {
        status,
        code,
        message,
    }
}

pub async fn claim_pairing_code(
    client: &reqwest::Client,
    server_url: &str,
    code: &str,
    platform: &str,
) -> Result<ClaimResponse, PairingApiError> {
    #[derive(Serialize)]
    struct Req<'a> {
        code: &'a str,
        platform: &'a str,
    }
    let body = serde_json::to_vec(&Req { code, platform }).expect("serialize claim request");
    let url = format!("{}/v1/pair/claim", server_url.trim_end_matches('/'));
    let resp = client
        .post(&url)
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await
        .map_err(|e| PairingApiError {
            status: 0,
            code: "NETWORK_ERROR".into(),
            message: format!("failed to reach relay server: {e}"),
        })?;
    let status = resp.status().as_u16();
    let text = resp.text().await.unwrap_or_default();
    if !(200..300).contains(&status) {
        return Err(parse_error(status, &text));
    }
    serde_json::from_str(&text).map_err(|e| PairingApiError {
        status,
        code: "INVALID_RESPONSE".into(),
        message: format!("invalid server response: {e}"),
    })
}

pub async fn fetch_device_me(
    client: &reqwest::Client,
    server_url: &str,
    token: &str,
) -> Result<DeviceMe, PairingApiError> {
    let url = format!("{}/v1/me", server_url.trim_end_matches('/'));
    let resp = client
        .get(&url)
        .header("authorization", format!("Bearer {token}"))
        .send()
        .await
        .map_err(|e| PairingApiError {
            status: 0,
            code: "NETWORK_ERROR".into(),
            message: format!("failed to reach relay server: {e}"),
        })?;
    let status = resp.status().as_u16();
    let text = resp.text().await.unwrap_or_default();
    if !(200..300).contains(&status) {
        return Err(parse_error(status, &text));
    }
    serde_json::from_str(&text).map_err(|e| PairingApiError {
        status,
        code: "INVALID_RESPONSE".into(),
        message: format!("invalid server response: {e}"),
    })
}

pub async fn create_pairing_code(
    client: &reqwest::Client,
    server_url: &str,
    token: &str,
    name: &str,
    platform: &str,
) -> Result<CreatedPairingCode, PairingApiError> {
    #[derive(Serialize)]
    struct Req<'a> {
        name: &'a str,
        platform: &'a str,
    }
    let body = serde_json::to_vec(&Req { name, platform }).expect("serialize create code request");
    let url = format!("{}/v1/pairing-codes", server_url.trim_end_matches('/'));
    let resp = client
        .post(&url)
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await
        .map_err(|e| PairingApiError {
            status: 0,
            code: "NETWORK_ERROR".into(),
            message: format!("failed to reach relay server: {e}"),
        })?;
    let status = resp.status().as_u16();
    let text = resp.text().await.unwrap_or_default();
    if !(200..300).contains(&status) {
        return Err(parse_error(status, &text));
    }
    serde_json::from_str(&text).map_err(|e| PairingApiError {
        status,
        code: "INVALID_RESPONSE".into(),
        message: format!("invalid server response: {e}"),
    })
}

pub async fn list_pairing_codes(
    client: &reqwest::Client,
    server_url: &str,
    token: &str,
) -> Result<Vec<PairingCodeSummary>, PairingApiError> {
    let url = format!("{}/v1/pairing-codes", server_url.trim_end_matches('/'));
    let resp = client
        .get(&url)
        .header("authorization", format!("Bearer {token}"))
        .send()
        .await
        .map_err(|e| PairingApiError {
            status: 0,
            code: "NETWORK_ERROR".into(),
            message: format!("failed to reach relay server: {e}"),
        })?;
    let status = resp.status().as_u16();
    let text = resp.text().await.unwrap_or_default();
    if !(200..300).contains(&status) {
        return Err(parse_error(status, &text));
    }
    serde_json::from_str(&text).map_err(|e| PairingApiError {
        status,
        code: "INVALID_RESPONSE".into(),
        message: format!("invalid server response: {e}"),
    })
}
