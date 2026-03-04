use anyhow::{Result, anyhow, bail};
use chrono::Utc;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use ureq::Agent;

use crate::aws::sso;

type HmacSha256 = Hmac<Sha256>;

fn sign(key: &[u8], msg: &str) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).unwrap();
    mac.update(msg.as_bytes());
    mac.finalize().into_bytes().to_vec()
}

pub fn request_codeartifact_token(
    creds: &sso::Credentials,
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

    let config = Agent::config_builder().http_status_as_error(false).build();

    let agent: Agent = config.into();

    let mut response = agent
        .post(&url)
        .header("x-amz-date", &amz_date)
        .header("x-amz-security-token", &creds.session_token)
        .header("Authorization", &auth_header)
        .send(b"")?;

    if !response.status().is_success() {
        bail!(
            "Failed to request CodeArtifact authorization token: region={}, status={}, body={}",
            region,
            response.status(),
            response.body_mut().read_to_string()?
        )
    }
    let json = response
        .body_mut()
        .read_json::<serde_json::Value>()
        .map_err(|e| anyhow!("Failed to parse payload: {}", e))?;

    json.get("authorizationToken")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| anyhow!("Failed to parse authorizationToken from response"))
}
