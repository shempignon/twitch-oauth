use reqwest::header::AUTHORIZATION;
use reqwest::Client;
use reqwest::Url;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ValidatedToken {
    client_id: String,
    login: Option<String>,
    user_id: Option<String>,
    scopes: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct AppAccessToken {
    access_token: String,
    expires_in: usize,
    scope: Option<Vec<String>>,
    token_type: String,
}

pub async fn get_app_access_token(
    client_id: &str,
    client_secret: &str,
    scopes: Vec<String>,
) -> Result<AppAccessToken, Box<dyn std::error::Error>> {
    let joinee_scopes = scopes.join(" ");

    let mut params = HashMap::new();
    params.insert("grant_type", "client_credentials");
    params.insert("client_id", client_id);
    params.insert("client_secret", client_secret);
    params.insert("scope", joinee_scopes.as_str());

    let url = Url::parse_with_params("https://id.twitch.tv/oauth2/token", &params).unwrap();

    let resp: AppAccessToken = Client::new()
        .post(url)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;

    Ok(resp)
}

pub async fn validate_token(
    token: AppAccessToken,
) -> Result<ValidatedToken, Box<dyn std::error::Error>> {
    let auth_header = format!("OAuth {}", token.access_token);

    let resp: ValidatedToken = Client::new()
        .get("https://id.twitch.tv/oauth2/validate")
        .header(AUTHORIZATION, auth_header)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;

    Ok(resp)
}

pub async fn revoke_token(
    token: AppAccessToken,
    client_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut params = HashMap::new();
    params.insert("token", token.access_token.as_str());
    params.insert("client_id", client_id);

    let url = Url::parse_with_params("https://id.twitch.tv/oauth2/revoke", &params).unwrap();

    Client::new().post(url).send().await?.error_for_status()?;

    Ok(())
}
