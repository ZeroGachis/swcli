use anyhow::{Context, Result, anyhow, bail};
use ini::Ini;
use serde::Deserialize;
use std::{env, fs, path::PathBuf};

pub struct SsoConfig {
    pub sso_region: String,
    pub sso_account_id: String,
    pub sso_role_name: String,
    pub region: String, // Target region for resources and operations
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Credentials {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: String,
}

// 2. Define a wrapper struct to match the root of the JSON
#[derive(Deserialize, Debug)]
struct TempCredentialsResponse {
    #[serde(rename = "roleCredentials")]
    temp_credentials: Credentials,
}

fn get_aws_directory() -> Result<PathBuf> {
    let mut dir = dirs::home_dir().context("Could not find home directory")?;
    dir.push(".aws");
    Ok(dir)
}

pub fn get_config_from_profile() -> Result<SsoConfig> {
    let profile = env::var("AWS_PROFILE").unwrap_or_else(|_| "default".to_string());
    log::debug!("Searching SSO configuration for profile '{}'...", profile);

    let config_path = get_aws_directory()?.join("config");
    let conf = Ini::load_from_file(&config_path).context("Failed to read ~/.aws/config")?;

    let section_name = if profile == "default" {
        "default".to_string()
    } else {
        format!("profile {}", profile)
    };

    let profile_section = conf
        .section(Some(&section_name))
        .with_context(|| format!("Profile '{}' not found in config", profile))?;

    let sso_session_name = profile_section
        .get("sso_session")
        .with_context(|| format!("Profile '{}' does not specify a sso_session", profile))?;

    let sso_session_section = conf
        .section(Some(format!("sso-session {}", sso_session_name)))
        .with_context(|| format!("sso-section '{}' not found in config", sso_session_name))?;

    let sso_region = sso_session_section
        .get("sso_region")
        .with_context(|| format!("sso-section '{}' has no sso_region", sso_session_name))?;

    let sso_account_id = profile_section
        .get("sso_account_id")
        .context("Missing sso_account_id")?;
    let sso_role_name = profile_section
        .get("sso_role_name")
        .context("Missing sso_role_name")?;
    let region = profile_section.get("region").unwrap_or(sso_region);

    Ok(SsoConfig {
        sso_region: sso_region.to_string(),
        sso_account_id: sso_account_id.to_string(),
        sso_role_name: sso_role_name.to_string(),
        region: region.to_string(),
    })
}

pub fn get_bearer_token() -> Result<String> {
    let cache_dir = get_aws_directory()?.join("sso").join("cache");
    let entries = fs::read_dir(&cache_dir)
        .context("SSO cache dir not found. Did you run 'aws sso login'?")?;

    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("json")
            && let Ok(content) = fs::read_to_string(&path)
            && let Ok(json) = serde_json::from_str::<serde_json::Value>(&content)
            && let Some(token) = json.get("accessToken").and_then(|v| v.as_str())
        {
            return Ok(token.to_string());
        }
    }
    bail!("Could not find a valid SSO accessToken in the cache.")
}

pub fn request_temp_credentials(config: &SsoConfig, bearer_token: &str) -> Result<Credentials> {
    let role_encoded = urlencoding::encode(&config.sso_role_name);
    let url = format!(
        "https://portal.sso.{}.amazonaws.com/federation/credentials?account_id={}&role_name={}",
        config.sso_region, config.sso_account_id, role_encoded
    );

    let mut response = ureq::get(&url)
        .header("x-amz-sso_bearer_token", bearer_token)
        .call()
        .map_err(|e| anyhow!("Failed to fetch credentials: {}", e))?;

    let TempCredentialsResponse { temp_credentials } = response
        .body_mut()
        .read_json::<TempCredentialsResponse>()
        .map_err(|e| anyhow!("Failed to parse payload: {}", e))?;

    Ok(Credentials {
        access_key_id: temp_credentials.access_key_id,
        secret_access_key: temp_credentials.secret_access_key,
        session_token: temp_credentials.session_token,
    })
}

pub fn get_credentials_from_env() -> Option<Credentials> {
    let aws_access_key_id = env::var("AWS_ACCESS_KEY_ID").ok();
    let aws_secret_access_key = env::var("AWS_SECRET_ACCESS_KEY").ok();
    let aws_session_token = env::var("AWS_SESSION_TOKEN").ok();

    if let Some(aws_access_key_id) = aws_access_key_id
        && let Some(aws_secret_access_key) = aws_secret_access_key
        && let Some(aws_session_token) = aws_session_token
    {
        log::debug!(
            "Use credentials provided with 'AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY' & 'AWS_SESSION_TOKEN' env variables"
        );
        return Some(Credentials {
            access_key_id: aws_access_key_id,
            secret_access_key: aws_secret_access_key,
            session_token: aws_session_token,
        });
    }

    None
}

pub fn get_temp_credentials(sso_config: &SsoConfig) -> Result<Credentials> {
    log::debug!("Finding SSO Bearer token in cache");
    let bearer_token = get_bearer_token().context("Failed to get SSO Token")?;

    log::debug!("Fetching temporary AWS credentials with bearer token");

    request_temp_credentials(sso_config, &bearer_token).context("Failed to fetch temp creds")
}
