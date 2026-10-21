//! Backend-only SecondFactor client. Retain primary authentication in your application.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{Signer, SigningKey};
use rand::RngCore;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Identity {
    pub subject: String,
    pub session: String,
    pub source: String,
}
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Proof {
    pub token: String,
    pub purpose: String,
    pub expires_at: String,
}
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Verification {
    pub access: Proof,
    pub sensitive: Proof,
}
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Enrollment {
    pub secret: String,
    pub uri: String,
    pub expires_at: String,
}
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Confirmation {
    pub recovery_codes: Vec<String>,
    pub verification: Verification,
}
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Status {
    pub enrolled: bool,
    pub recovery_pending: bool,
    pub remaining_recovery_codes: i64,
    pub version: i64,
}
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct RecoveryJob {
    pub job_id: String,
    pub state: String,
}
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Event {
    pub id: String,
    pub subject: String,
    pub kind: String,
    pub payload: serde_json::Value,
    pub delivery: Option<serde_json::Value>,
    pub lease: String,
    pub created_at: String,
}
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct Mutation {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub job_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invitation: Option<String>,
}
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct RecoveryCodes {
    pub recovery_codes: Vec<String>,
}
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct OK {
    pub ok: bool,
}
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Claims {
    pub idh: String,
    pub ver: i64,
    pub iss: String,
    pub aud: String,
    pub sub: String,
    pub sid: String,
    pub iat: i64,
    pub exp: i64,
    pub jti: String,
    pub htm: String,
    pub htu: String,
    pub bsh: String,
    pub src: String,
}
#[derive(Serialize)]
struct Header<'a> {
    alg: &'a str,
    typ: &'a str,
    kid: &'a str,
}
#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("invalid configuration or input")]
    InvalidInput,
    #[error("transport unavailable")]
    Transport,
    #[error("{code}: {message}")]
    API {
        code: String,
        message: String,
        retry_after: u64,
    },
}
pub fn body_hash(body: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(body))
}
pub fn sign_assertion(seed: &[u8; 32], kid: &str, claims: &Claims) -> Result<String, Error> {
    let key = SigningKey::from_bytes(seed);
    let h = serde_json::to_vec(&Header {
        alg: "EdDSA",
        typ: "sf-assertion+jwt",
        kid,
    })
    .map_err(|_| Error::InvalidInput)?;
    let p = serde_json::to_vec(claims).map_err(|_| Error::InvalidInput)?;
    let input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(h),
        URL_SAFE_NO_PAD.encode(p)
    );
    Ok(format!(
        "{}.{}",
        input,
        URL_SAFE_NO_PAD.encode(key.sign(input.as_bytes()).to_bytes())
    ))
}
pub struct Client {
    base: String,
    audience: String,
    application: String,
    kid: String,
    seed: [u8; 32],
    http: reqwest::Client,
}
impl Client {
    pub fn new(
        base: &str,
        audience: &str,
        application: &str,
        kid: &str,
        seed: [u8; 32],
    ) -> Result<Self, Error> {
        let u = url::Url::parse(base).map_err(|_| Error::InvalidInput)?;
        if !u.username().is_empty()
            || u.password().is_some()
            || u.query().is_some()
            || u.fragment().is_some()
            || u.path() != "/"
            || !(u.scheme() == "https"
                || (u.scheme() == "http"
                    && matches!(u.host_str(), Some("localhost" | "127.0.0.1"))))
            || audience.is_empty()
            || application.is_empty()
            || kid.is_empty()
        {
            return Err(Error::InvalidInput);
        };
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|_| Error::Transport)?;
        Ok(Self {
            base: base.trim_end_matches('/').into(),
            audience: audience.into(),
            application: application.into(),
            kid: kid.into(),
            seed,
            http,
        })
    }
    pub async fn request<T: DeserializeOwned>(
        &self,
        i: &Identity,
        method: &str,
        path: &str,
        body: Option<&serde_json::Value>,
        idempotency: Option<&str>,
    ) -> Result<T, Error> {
        if !path.starts_with("/v1/")
            || path.contains(['?', '#', '%'])
            || path.contains("//")
            || path.ends_with('/')
        {
            return Err(Error::InvalidInput);
        };
        let raw = match body {
            Some(b) => serde_json::to_vec(b).map_err(|_| Error::InvalidInput)?,
            None => vec![],
        };
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error::InvalidInput)?
            .as_secs() as i64;
        let mut nonce = [0u8; 24];
        rand::thread_rng().fill_bytes(&mut nonce);
        let c = Claims {
            idh: body_hash(idempotency.unwrap_or("").as_bytes()),
            ver: 1,
            iss: self.application.clone(),
            aud: self.audience.clone(),
            sub: i.subject.clone(),
            sid: i.session.clone(),
            iat: now,
            exp: now + 60,
            jti: URL_SAFE_NO_PAD.encode(nonce),
            htm: method.into(),
            htu: path.into(),
            bsh: body_hash(&raw),
            src: i.source.clone(),
        };
        let assertion = sign_assertion(&self.seed, &self.kid, &c)?;
        let m = reqwest::Method::from_bytes(method.as_bytes()).map_err(|_| Error::InvalidInput)?;
        let mut req = self
            .http
            .request(m, format!("{}{}", self.base, path))
            .bearer_auth(assertion)
            .header("Content-Type", "application/json")
            .body(raw);
        if let Some(k) = idempotency {
            req = req.header("Idempotency-Key", k)
        };
        let mut res = req.send().await.map_err(|_| Error::Transport)?;
        let success = res.status().is_success();
        let mut bytes = Vec::new();
        while let Some(chunk) = res.chunk().await.map_err(|_| Error::Transport)? {
            if bytes.len() + chunk.len() > 1048576 {
                return Err(Error::Transport);
            }
            bytes.extend_from_slice(&chunk)
        }
        let v: serde_json::Value = serde_json::from_slice(&bytes).map_err(|_| Error::Transport)?;
        if !success {
            let e = &v["error"];
            return Err(Error::API {
                code: e["code"].as_str().unwrap_or("unavailable").into(),
                message: e["message"].as_str().unwrap_or("Request failed").into(),
                retry_after: e["retry_after"].as_u64().unwrap_or(0),
            });
        };
        serde_json::from_value(v).map_err(|_| Error::Transport)
    }
    pub async fn status(&self, i: &Identity) -> Result<Status, Error> {
        self.request(i, "GET", "/v1/factors/status", None, None)
            .await
    }
    pub async fn begin_enrollment(
        &self,
        i: &Identity,
        b: &Mutation,
        k: &str,
    ) -> Result<Enrollment, Error> {
        self.request(
            i,
            "POST",
            "/v1/enrollments",
            Some(&serde_json::to_value(b).map_err(|_| Error::InvalidInput)?),
            Some(k),
        )
        .await
    }
    pub async fn confirm_enrollment(
        &self,
        i: &Identity,
        b: &Mutation,
        k: &str,
    ) -> Result<Confirmation, Error> {
        self.request(
            i,
            "POST",
            "/v1/enrollments/confirm",
            Some(&serde_json::to_value(b).map_err(|_| Error::InvalidInput)?),
            Some(k),
        )
        .await
    }
    pub async fn verify_totp(&self, i: &Identity, code: &str) -> Result<Verification, Error> {
        self.request(
            i,
            "POST",
            "/v1/verifications/totp",
            Some(&serde_json::json!({"code":code})),
            None,
        )
        .await
    }
    pub async fn verify_recovery_code(&self, i: &Identity, code: &str) -> Result<Proof, Error> {
        self.request(
            i,
            "POST",
            "/v1/verifications/recovery-code",
            Some(&serde_json::json!({"code":code})),
            None,
        )
        .await
    }
    pub async fn validate_proof(
        &self,
        i: &Identity,
        proof: &str,
        purpose: &str,
    ) -> Result<serde_json::Value, Error> {
        self.request(
            i,
            "POST",
            "/v1/proofs/validate",
            Some(&serde_json::json!({"proof":proof,"purpose":purpose})),
            None,
        )
        .await
    }
    pub async fn regenerate_recovery_codes(
        &self,
        i: &Identity,
        proof: &str,
        k: &str,
    ) -> Result<RecoveryCodes, Error> {
        self.request(
            i,
            "POST",
            "/v1/recovery-codes/regenerate",
            Some(&serde_json::json!({"proof":proof})),
            Some(k),
        )
        .await
    }
    pub async fn replace_factor(
        &self,
        i: &Identity,
        b: &Mutation,
        k: &str,
    ) -> Result<Enrollment, Error> {
        self.request(
            i,
            "POST",
            "/v1/factors/replace",
            Some(&serde_json::to_value(b).map_err(|_| Error::InvalidInput)?),
            Some(k),
        )
        .await
    }
    pub async fn revoke_factor(
        &self,
        i: &Identity,
        proof: &str,
        k: &str,
    ) -> Result<serde_json::Value, Error> {
        self.request(
            i,
            "DELETE",
            "/v1/factors",
            Some(&serde_json::json!({"proof":proof})),
            Some(k),
        )
        .await
    }
    pub async fn revoke_session(&self, i: &Identity, k: &str) -> Result<serde_json::Value, Error> {
        self.request(
            i,
            "POST",
            "/v1/sessions/revoke",
            Some(&serde_json::json!({})),
            Some(k),
        )
        .await
    }
    pub async fn start_assisted_recovery(
        &self,
        i: &Identity,
        b: &Mutation,
        k: &str,
    ) -> Result<RecoveryJob, Error> {
        self.request(
            i,
            "POST",
            "/v1/assisted-recovery",
            Some(&serde_json::to_value(b).map_err(|_| Error::InvalidInput)?),
            Some(k),
        )
        .await
    }
    pub async fn resume_assisted_recovery(
        &self,
        i: &Identity,
        b: &Mutation,
    ) -> Result<RecoveryJob, Error> {
        self.request(
            i,
            "POST",
            "/v1/assisted-recovery/resume",
            Some(&serde_json::to_value(b).map_err(|_| Error::InvalidInput)?),
            None,
        )
        .await
    }
    pub async fn complete_assisted_recovery(
        &self,
        i: &Identity,
        b: &Mutation,
        k: &str,
    ) -> Result<Proof, Error> {
        self.request(
            i,
            "POST",
            "/v1/assisted-recovery/complete",
            Some(&serde_json::to_value(b).map_err(|_| Error::InvalidInput)?),
            Some(k),
        )
        .await
    }
    pub async fn cancel_assisted_recovery(
        &self,
        i: &Identity,
        b: &Mutation,
        k: &str,
    ) -> Result<serde_json::Value, Error> {
        self.request(
            i,
            "POST",
            "/v1/assisted-recovery/cancel",
            Some(&serde_json::to_value(b).map_err(|_| Error::InvalidInput)?),
            Some(k),
        )
        .await
    }
    pub async fn claim_events(&self, i: &Identity) -> Result<Vec<Event>, Error> {
        self.request(
            i,
            "POST",
            "/v1/events/claim",
            Some(&serde_json::json!({})),
            None,
        )
        .await
    }
    pub async fn ack_event(
        &self,
        i: &Identity,
        id: &str,
        lease: &str,
    ) -> Result<serde_json::Value, Error> {
        self.request(
            i,
            "POST",
            "/v1/events/ack",
            Some(&serde_json::json!({"event_id":id,"lease":lease})),
            None,
        )
        .await
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn shared_vectors() {
        let v: serde_json::Value =
            serde_json::from_str(include_str!("../../../testdata/assertion_vectors.json")).unwrap();
        for row in v["valid"].as_array().unwrap() {
            let h = row["seed_hex"].as_str().unwrap();
            let mut seed = [0u8; 32];
            for j in 0..32 {
                seed[j] = u8::from_str_radix(&h[j * 2..j * 2 + 2], 16).unwrap()
            }
            let c: Claims = serde_json::from_value(row["claims"].clone()).unwrap();
            assert_eq!(
                sign_assertion(&seed, row["key_id"].as_str().unwrap(), &c).unwrap(),
                row["assertion"].as_str().unwrap()
            );
        }
    }
    #[tokio::test]
    async fn live_service() {
        let Ok(base) = std::env::var("SF_TEST_URL") else {
            return;
        };
        let c = Client::new(&base, "secondfactor-test", "test", "test", [7u8; 32]).unwrap();
        let i = Identity {
            subject: "rust-sdk-user".into(),
            session: "rust-sdk-session".into(),
            source: "rust-sdk-test".into(),
        };
        assert!(!c.status(&i).await.unwrap().enrolled);
        assert!(c.validate_proof(&i, "invalid", "access").await.is_err())
    }
}
