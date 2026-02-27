use anyhow::{Context, Result, anyhow, bail};
use chrono::Utc;
use hmac::{Hmac, Mac};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;

const DOMAIN: &str = "smartway";
const DOMAIN_OWNER: &str = "007065811408";

type HmacSha256 = Hmac<Sha256>;

struct SsoConfig {
    sso_region: String,
    sso_account_id: String,
    sso_role_name: String,
    region: String,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct TempCredentials {
    access_key_id: String,
    secret_access_key: String,
    session_token: String,
}

// 2. Define a wrapper struct to match the root of the JSON
#[derive(Deserialize, Debug)]
struct TempCredentialsResponse {
    #[serde(rename = "roleCredentials")]
    temp_credentials: TempCredentials,
}

fn get_aws_directory() -> Result<PathBuf> {
    let mut dir = dirs::home_dir().context("Could not find home directory")?;
    dir.push(".aws");
    Ok(dir)
}

fn get_sso_bearer_token() -> Result<String> {
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

fn get_temp_credentials(config: &SsoConfig, bearer_token: &str) -> Result<TempCredentials> {
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

    Ok(TempCredentials {
        access_key_id: temp_credentials.access_key_id,
        secret_access_key: temp_credentials.secret_access_key,
        session_token: temp_credentials.session_token,
    })
}

fn sign(key: &[u8], msg: &str) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).unwrap();
    mac.update(msg.as_bytes());
    mac.finalize().into_bytes().to_vec()
}

fn get_codeartifact_token(
    creds: &TempCredentials,
    region: &str,
    domain: &str,
    domain_owner: &str,
) -> Result<String> {
    let host = format!("codeartifact.{}.amazonaws.com", region);
    let endpoint = format!("https://{}/v1/authorization-token", host);

    let query_string = format!(
        "domain={}&domain-owner={}",
        urlencoding::encode(domain),
        domain_owner
    );
    let url = format!("{}?{}", endpoint, query_string);

    // SigV4 Timestamps
    let now = Utc::now();
    let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
    let date_stamp = now.format("%Y%m%d").to_string();

    // 1. Canonical Request
    let canonical_uri = "/v1/authorization-token";
    let canonical_headers = format!(
        "host:{}\nx-amz-date:{}\nx-amz-security-token:{}\n",
        host, amz_date, creds.session_token
    );
    let signed_headers = "host;x-amz-date;x-amz-security-token";
    let payload_hash = hex::encode(Sha256::digest(b""));

    let canonical_request = format!(
        "POST\n{}\n{}\n{}\n{}\n{}",
        canonical_uri, query_string, canonical_headers, signed_headers, payload_hash
    );

    // 2. String to Sign
    let algorithm = "AWS4-HMAC-SHA256";
    let credential_scope = format!("{}/{}/codeartifact/aws4_request", date_stamp, region);
    let hashed_canonical_request = hex::encode(Sha256::digest(canonical_request.as_bytes()));
    let string_to_sign = format!(
        "{}\n{}\n{}\n{}",
        algorithm, amz_date, credential_scope, hashed_canonical_request
    );

    // 3. Calculate Signature
    let k_secret = format!("AWS4{}", creds.secret_access_key);
    let k_date = sign(k_secret.as_bytes(), &date_stamp);
    let k_region = sign(&k_date, region);
    let k_service = sign(&k_region, "codeartifact");
    let k_signing = sign(&k_service, "aws4_request");
    let signature = hex::encode(sign(&k_signing, &string_to_sign));

    // 4. Authorization Header
    let auth_header = format!(
        "{} Credential={}/{}, SignedHeaders={}, Signature={}",
        algorithm, creds.access_key_id, credential_scope, signed_headers, signature
    );

    let mut response = ureq::post(&url)
        .header("x-amz-date", &amz_date)
        .header("x-amz-security-token", &creds.session_token)
        .header("Authorization", &auth_header)
        .send(b"")
        .map_err(|e| anyhow!("CodeArtifact Request Failed: {}", e))?;

    let json = response
        .body_mut()
        .read_json::<serde_json::Value>()
        .map_err(|e| anyhow!("Failed to parse payload: {}", e))?;

    json.get("authorizationToken")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| anyhow!("Failed to parse authorizationToken from response"))
}

fn main() -> Result<()> {
    let profile = "smartway-tools-repo-ro-007065811408";

    println!("1. Reading SSO configuration for profile '{}'...", profile);

    let sso_config = SsoConfig {
        sso_region: "eu-west-1".to_string(),
        sso_account_id: DOMAIN_OWNER.to_string(),
        sso_role_name: "smartway-tools-repo-ro".to_string(),
        region: "eu-west-3".to_string(),
    };

    println!("2. Finding SSO Bearer token in cache...");
    let bearer_token = get_sso_bearer_token().context("Failed to get SSO Token")?;

    println!(
        "3. Fetching temporary AWS credentials with {}...",
        bearer_token
    );
    let creds =
        get_temp_credentials(&sso_config, &bearer_token).context("Failed to fetch temp creds")?;

    println!(
        "4. Requesting CodeArtifact token for domain '{}'...",
        DOMAIN
    );
    let ca_token = get_codeartifact_token(&creds, &sso_config.region, DOMAIN, DOMAIN_OWNER)
        .context("Failed to get CodeArtifact token")?;

    println!("\n--- CodeArtifact Authorization Token ---");
    println!("{}", ca_token);
    println!("----------------------------------------");

    Ok(())
}
