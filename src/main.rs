use anyhow::{anyhow, Context, Result};
use chrono::{Duration, Utc};
use rand::{distributions::Alphanumeric, Rng};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use std::{env, fs, path::PathBuf};

const REDIRECT_URI: &str = "http://localhost:8080/callback";
const TOKEN_FILE: &str = "dexcom-token.json";

#[derive(Debug, Serialize, Deserialize)]
struct Token {
    access_token: String,
    refresh_token: String,
    expires_in: i64,
    token_type: String,
    obtained_at: i64,
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    refresh_token: String,
    expires_in: i64,
    token_type: String,
}

#[derive(Debug, Deserialize)]
struct EgvsResponse {
    records: Vec<Egv>,
}

#[derive(Debug, Deserialize)]
struct Egv {
    #[serde(rename = "systemTime")]
    system_time: String,
    #[serde(rename = "displayTime")]
    display_time: String,
    value: Option<i32>,
    status: Option<String>,
    trend: Option<String>,
    #[serde(rename = "trendRate")]
    trend_rate: Option<f64>,
    unit: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let client_id = env::var("DEXCOM_CLIENT_ID")
        .context("Missing DEXCOM_CLIENT_ID")?;
    let client_secret = env::var("DEXCOM_CLIENT_SECRET")
        .context("Missing DEXCOM_CLIENT_SECRET")?;

    let sandbox = env::var("DEXCOM_SANDBOX").unwrap_or_default() == "1";
    let base_url = if sandbox {
        "https://sandbox-api.dexcom.com"
    } else {
        "https://api.dexcom.com"
    };

    let mut token = match load_token()? {
        Some(token) => token,
        None => authorize(base_url, &client_id, &client_secret).await?,
    };

    if token_expired(&token) {
        token = refresh_token(base_url, &client_id, &client_secret, &token.refresh_token).await?;
        save_token(&token)?;
    }

    match get_latest_egvs(base_url, &token.access_token).await {
        Ok(records) => print_records(records),
        Err(err) if err.to_string().contains("401") => {
            token = refresh_token(base_url, &client_id, &client_secret, &token.refresh_token).await?;
            save_token(&token)?;

            let records = get_latest_egvs(base_url, &token.access_token).await?;
            print_records(records);
        }
        Err(err) => return Err(err),
    }

    Ok(())
}

async fn authorize(base_url: &str, client_id: &str, client_secret: &str) -> Result<Token> {
    let state = random_state();

    let auth_url = format!(
        "{base_url}/v3/oauth2/login?client_id={}&redirect_uri={}&response_type=code&scope=offline_access&state={}",
        urlencoding(client_id),
        urlencoding(REDIRECT_URI),
        urlencoding(&state),
    );

    println!("Opening Dexcom login:");
    println!("{auth_url}");

    let _ = open::that(&auth_url);

    let code = wait_for_callback(&state)?;
    let token = exchange_code(base_url, client_id, client_secret, &code).await?;
    save_token(&token)?;

    Ok(token)
}

fn wait_for_callback(expected_state: &str) -> Result<String> {
    let server = tiny_http::Server::http("127.0.0.1:8080")
        .map_err(|e| anyhow!("Failed to start callback server: {e}"))?;

    println!("Waiting for Dexcom callback on {REDIRECT_URI}");

    for request in server.incoming_requests() {
        let url = format!("http://localhost{}", request.url());
        let parsed = url::Url::parse(&url)?;

        if parsed.path() != "/callback" {
            let _ = request.respond(tiny_http::Response::from_string("Wrong callback path"));
            continue;
        }

        let code = parsed
            .query_pairs()
            .find(|(k, _)| k == "code")
            .map(|(_, v)| v.to_string());

        let state = parsed
            .query_pairs()
            .find(|(k, _)| k == "state")
            .map(|(_, v)| v.to_string());

        if state.as_deref() != Some(expected_state) {
            let _ = request.respond(tiny_http::Response::from_string("Invalid state"));
            return Err(anyhow!("OAuth state mismatch"));
        }

        if let Some(code) = code {
            let _ = request.respond(tiny_http::Response::from_string(
                "Dexcom authorization complete. You can close this tab.",
            ));
            return Ok(code);
        }

        let error = parsed
            .query_pairs()
            .find(|(k, _)| k == "error")
            .map(|(_, v)| v.to_string())
            .unwrap_or_else(|| "unknown OAuth error".to_string());

        let _ = request.respond(tiny_http::Response::from_string(format!(
            "Authorization failed: {error}"
        )));

        return Err(anyhow!("Authorization failed: {error}"));
    }

    Err(anyhow!("Callback server stopped unexpectedly"))
}

async fn exchange_code(
    base_url: &str,
    client_id: &str,
    client_secret: &str,
    code: &str,
) -> Result<Token> {
    let client = reqwest::Client::new();

    let res = client
        .post(format!("{base_url}/v3/oauth2/token"))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", REDIRECT_URI),
            ("client_id", client_id),
            ("client_secret", client_secret),
        ])
        .send()
        .await?;

    if !res.status().is_success() {
        return Err(anyhow!("Token exchange failed: {}", res.text().await?));
    }

    let token: TokenResponse = res.json().await?;

    Ok(Token {
        access_token: token.access_token,
        refresh_token: token.refresh_token,
        expires_in: token.expires_in,
        token_type: token.token_type,
        obtained_at: Utc::now().timestamp(),
    })
}

async fn refresh_token(
    base_url: &str,
    client_id: &str,
    client_secret: &str,
    refresh_token: &str,
) -> Result<Token> {
    let client = reqwest::Client::new();

    let res = client
        .post(format!("{base_url}/v3/oauth2/token"))
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
            ("client_id", client_id),
            ("client_secret", client_secret),
        ])
        .send()
        .await?;

    if !res.status().is_success() {
        return Err(anyhow!(
            "Refresh failed. Delete token file and re-authorize: {}",
            res.text().await?
        ));
    }

    let token: TokenResponse = res.json().await?;

    Ok(Token {
        access_token: token.access_token,
        refresh_token: token.refresh_token,
        expires_in: token.expires_in,
        token_type: token.token_type,
        obtained_at: Utc::now().timestamp(),
    })
}

async fn get_latest_egvs(base_url: &str, access_token: &str) -> Result<Vec<Egv>> {
    let end = Utc::now();
    let start = end - Duration::hours(3);

    let client = reqwest::Client::new();

    let res = client
        .get(format!("{base_url}/v3/users/self/egvs"))
        .bearer_auth(access_token)
        .query(&[
            ("startDate", start.format("%Y-%m-%dT%H:%M:%S").to_string()),
            ("endDate", end.format("%Y-%m-%dT%H:%M:%S").to_string()),
        ])
        .send()
        .await?;

    if res.status() == StatusCode::UNAUTHORIZED {
        return Err(anyhow!("401 unauthorized"));
    }

    if !res.status().is_success() {
        return Err(anyhow!("EGV request failed: {}", res.text().await?));
    }

    let body: EgvsResponse = res.json().await?;
    Ok(body.records)
}

fn print_records(mut records: Vec<Egv>) {
    records.sort_by(|a, b| a.system_time.cmp(&b.system_time));

    if records.is_empty() {
        println!("No glucose readings found in the last 3 hours.");
        return;
    }

    let latest = records.last().unwrap();

    println!();
    println!("Latest glucose:");
    println!(
        "{} {} | trend={} | rate={:?} | status={:?} | displayTime={}",
        latest.value.map_or("N/A".to_string(), |v| v.to_string()),
        latest.unit,
        latest.trend.as_deref().unwrap_or("unknown"),
        latest.trend_rate,
        latest.status,
        latest.display_time,
    );

    println!();
    println!("Recent readings:");
    for r in records.iter().rev().take(12) {
        println!(
            "{} | {} {} | trend={}",
            r.display_time,
            r.value.map_or("N/A".to_string(), |v| v.to_string()),
            r.unit,
            r.trend.as_deref().unwrap_or("unknown"),
        );
    }
}

fn token_expired(token: &Token) -> bool {
    let safety_margin_seconds = 120;
    Utc::now().timestamp() >= token.obtained_at + token.expires_in - safety_margin_seconds
}

fn token_path() -> Result<PathBuf> {
    let dir = dirs::config_dir()
        .ok_or_else(|| anyhow!("Could not find config directory"))?
        .join("dexcom-rust");

    fs::create_dir_all(&dir)?;
    Ok(dir.join(TOKEN_FILE))
}

fn load_token() -> Result<Option<Token>> {
    let path = token_path()?;

    if !path.exists() {
        return Ok(None);
    }

    let data = fs::read_to_string(path)?;
    Ok(Some(serde_json::from_str(&data)?))
}

fn save_token(token: &Token) -> Result<()> {
    let path = token_path()?;
    fs::write(path, serde_json::to_string_pretty(token)?)?;
    Ok(())
}

fn random_state() -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect()
}

fn urlencoding(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}
