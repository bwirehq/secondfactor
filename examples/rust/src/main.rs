//! Install existing primary-authentication middleware that inserts TrustedSession.
use axum::{
    extract::{Extension, State},
    http::StatusCode,
    routing::get,
    Router,
};
use base64::Engine;
use secondfactor_client::{Client, Identity};
use std::sync::Arc;
#[derive(Clone)]
struct TrustedSession {
    identity: Identity,
    proof: String,
}
async fn protected(
    State(client): State<Arc<Client>>,
    session: Option<Extension<TrustedSession>>,
) -> Result<&'static str, StatusCode> {
    let Some(Extension(session)) = session else {
        return Err(StatusCode::UNAUTHORIZED);
    };
    client
        .validate_proof(&session.identity, &session.proof, "access")
        .await
        .map_err(|_| StatusCode::FORBIDDEN)?;
    Ok("Primary session and MFA verified")
}
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let file =
        std::env::var("SECONDFACTOR_SEED_FILE").unwrap_or("../../secrets/application.seed".into());
    let raw = std::fs::read_to_string(file)?;
    let b = base64::engine::general_purpose::STANDARD.decode(raw.trim())?;
    let seed: [u8; 32] = b.try_into().map_err(|_| "seed must contain 32 bytes")?;
    let ca = std::env::var("SECONDFACTOR_CA_FILE")
        .ok()
        .map(std::fs::read)
        .transpose()?;
    let c = Arc::new(Client::new_with_ca(
        &std::env::var("SECONDFACTOR_URL").unwrap_or("https://localhost:8443".into()),
        "secondfactor-local",
        "demo",
        "app1",
        seed,
        ca.as_deref(),
    )?);
    let app = Router::new()
        .route("/protected", get(protected))
        .with_state(c);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:3001").await?;
    axum::serve(listener, app).await?;
    Ok(())
}
