use crate::{
    Account, Error, Result,
    credentials::{CLAIM, CredentialClaim, NetworkMaterial},
    strict,
};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, jwk::JwkSet};
use oauth2::{AuthUrl, ClientId, EndpointNotSet, EndpointSet, RedirectUrl, TokenUrl};
use openidconnect::{
    IssuerUrl, Nonce,
    core::{CoreIdToken, CoreIdTokenVerifier, CoreJsonWebKeySet, CoreJwsSigningAlgorithm},
};
use serde_json::Value;
use std::{collections::BTreeMap, time::Duration};
use url::Url;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};
mod discovery_get;

/// Trusted deployment pins, never populated from callback, peer, or JWT.
/// Signature allowlist: RS256, ES256, ES384 (no symmetric or unsigned algorithms).
#[derive(Clone, Debug)]
pub struct AuthConfig {
    pub issuer: String,
    pub client_id: String,
    pub resource: String,
    pub product_id: String,
    pub redirect_uri: String,
    /// Administrative assertion that these client IDs are Native/public-subject clients.
    pub native_clients: BTreeMap<String, String>,
    pub offline_access: bool,
    /// Persist refresh grants only when store.durable() is true; secrets otherwise stay in RAM.
    pub persist_grant: bool,
    #[cfg(test)]
    pub(crate) test_http: bool,
}
impl AuthConfig {
    pub(crate) fn validate(&self) -> Result<()> {
        let i = Url::parse(&self.issuer).map_err(|_| Error::Configuration)?;
        let r = Url::parse(&self.resource).map_err(|_| Error::Configuration)?;
        let d = Url::parse(&self.redirect_uri).map_err(|_| Error::Configuration)?;
        let https = i.scheme() == "https";
        #[cfg(test)]
        let https =
            https || (self.test_http && i.scheme() == "http" && i.host_str() == Some("127.0.0.1"));
        if !https
            || i.as_str() != self.issuer
            || i.path() != "/oidc"
            || i.query().is_some()
            || i.fragment().is_some()
            || !i.username().is_empty()
            || i.authority().contains('@')
            || r.scheme() != "https"
            || r.fragment().is_some()
            || !r.username().is_empty()
            || r.authority().contains('@')
            || self.resource == self.client_id
            || self.client_id.is_empty()
            || self.product_id.is_empty()
            || self.native_clients.get(&self.client_id) != Some(&self.product_id)
            || d.fragment().is_some()
            || d.query().is_some()
            || !d.username().is_empty()
            || d.authority().contains('@')
            || d.as_str() != self.redirect_uri
            || (d.scheme() == "http" && !matches!(d.host_str(), Some("127.0.0.1" | "[::1]")))
        {
            return Err(Error::Configuration);
        }
        Ok(())
    }
}
#[derive(Clone, serde::Deserialize, serde::Serialize)]
pub(crate) struct Extra {
    pub id_token: Option<String>,
}
impl std::fmt::Debug for Extra {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Extra([REDACTED])")
    }
}
impl oauth2::ExtraTokenFields for Extra {}
pub(crate) type OAuthClient = oauth2::Client<
    oauth2::basic::BasicErrorResponse,
    oauth2::StandardTokenResponse<Extra, oauth2::basic::BasicTokenType>,
    oauth2::basic::BasicTokenIntrospectionResponse,
    oauth2::StandardRevocableToken,
    oauth2::basic::BasicRevocationErrorResponse,
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointSet,
>;
#[derive(Clone)]
pub(crate) struct Oidc {
    pub config: AuthConfig,
    http: reqwest::Client,
    pub client: OAuthClient,
    pub jwks_uri: String,
    pub revocation: Option<String>,
    #[cfg(test)]
    pub(crate) unavailable_before_delivery: bool,
}
impl Oidc {
    pub async fn discover(config: &AuthConfig) -> Result<Self> {
        let began = tokio::time::Instant::now();
        let deadline = began + discovery_get::BUDGET;
        config.validate().inspect_err(|_| {
            discovery_get::report(0, "configuration", 0, began, deadline);
        })?;
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(120))
            .build()
            .map_err(|_| Error::Configuration)?;
        let (raw, attempt, status) = discovery_get::get(
            &http,
            &format!("{}/.well-known/openid-configuration", config.issuer),
            began,
            deadline,
        )
        .await?;
        Self::from_discovery(config, http, &raw).inspect_err(|e| {
            let class = if *e == Error::Configuration {
                "configuration"
            } else {
                "invalid_document"
            };
            discovery_get::report(attempt, class, status, began, deadline);
        })
    }
    fn from_discovery(config: &AuthConfig, http: reqwest::Client, raw: &[u8]) -> Result<Self> {
        let v = strict::json(raw)?;
        if v["issuer"].as_str() != Some(&config.issuer)
            || !v["response_types_supported"]
                .as_array()
                .is_some_and(|a| a.iter().any(|s| s == "code"))
            || !v["code_challenge_methods_supported"]
                .as_array()
                .is_some_and(|a| a.iter().any(|s| s == "S256"))
            || !v["id_token_signing_alg_values_supported"]
                .as_array()
                .is_some_and(|a| {
                    a.iter()
                        .any(|s| matches!(s.as_str(), Some("RS256" | "ES256" | "ES384")))
                })
        {
            return Err(Error::Configuration);
        }
        let endpoint = |key: &str| -> Result<String> {
            let s = v[key].as_str().ok_or(Error::Configuration)?;
            let u = Url::parse(s).map_err(|_| Error::Configuration)?;
            let issuer = Url::parse(&config.issuer).map_err(|_| Error::Configuration)?;
            if u.origin() != issuer.origin()
                || !u.username().is_empty()
                || u.authority().contains('@')
                || u.fragment().is_some()
                || u.query().is_some()
            {
                return Err(Error::Configuration);
            }
            Ok(s.to_owned())
        };
        let client = oauth2::Client::new(ClientId::new(config.client_id.clone()))
            .set_auth_uri(
                AuthUrl::new(endpoint("authorization_endpoint")?)
                    .map_err(|_| Error::Configuration)?,
            )
            .set_token_uri(
                TokenUrl::new(endpoint("token_endpoint")?).map_err(|_| Error::Configuration)?,
            )
            .set_redirect_uri(
                RedirectUrl::new(config.redirect_uri.clone()).map_err(|_| Error::Configuration)?,
            );
        Ok(Self {
            config: config.clone(),
            #[cfg(test)]
            unavailable_before_delivery: false,
            http,
            client,
            jwks_uri: endpoint("jwks_uri")?,
            revocation: if v.get("revocation_endpoint").is_some() {
                Some(endpoint("revocation_endpoint")?)
            } else {
                None
            },
        })
    }
    /// Used by oauth2's standard grant implementation. Bodies are bounded and checked for
    /// duplicate JSON keys BEFORE the library parses them. Library errors never escape.
    pub async fn send(&self, req: oauth2::HttpRequest) -> Result<oauth2::HttpResponse> {
        #[cfg(test)]
        if self.unavailable_before_delivery {
            return Err(Error::Unavailable);
        }
        let (parts, body) = req.into_parts();
        let body = Zeroizing::new(body);
        let response = self
            .http
            .request(parts.method, parts.uri.to_string())
            .headers(parts.headers)
            .body(body.to_vec())
            .send()
            .await
            .map_err(|e| {
                if e.is_connect() {
                    Error::Unavailable
                } else {
                    Error::UnknownOutcome
                }
            })?;
        let status = response.status();
        // A server error or rate limit does not prove a rotating grant was not consumed.
        if status.is_server_error() || status.as_u16() == 429 {
            return Err(Error::UnknownOutcome);
        }
        let headers = response.headers().clone();
        let b = read(response).await?;
        if b.is_empty() {
            return Err(Error::UnknownOutcome);
        }
        if strict::json(&b).is_err() {
            return Err(Error::InvalidClaims);
        }
        let mut out = oauth2::http::Response::builder()
            .status(status)
            .body(b.to_vec())
            .map_err(|_| Error::UnknownOutcome)?;
        *out.headers_mut() = headers;
        Ok(out)
    }
    pub async fn verify(
        &self,
        t: &Tokens,
        nonce: Option<(&str, u64)>,
        now: u64,
        expected: Option<&Account>,
    ) -> Result<Verified> {
        let raw = get(&self.http, &self.jwks_uri).await?;
        let keys = strict::json(&raw)?;
        let (h, c) = strict::jwt_parts(&t.access)?;
        let alg = header(&h)?;
        let set: JwkSet = serde_json::from_value(keys.clone()).map_err(|_| Error::Configuration)?;
        let kid = h["kid"].as_str().ok_or(Error::InvalidClaims)?;
        let candidates: Vec<_> = set
            .keys
            .iter()
            .filter(|k| k.common.key_id.as_deref() == Some(kid))
            .collect();
        if candidates.len() != 1 {
            return Err(Error::InvalidClaims);
        }
        let k = candidates[0];
        if k.common
            .public_key_use
            .as_ref()
            .is_some_and(|u| *u != jsonwebtoken::jwk::PublicKeyUse::Signature)
            || k.common
                .key_algorithm
                .as_ref()
                .is_some_and(|a| format!("{a:?}") != h["alg"].as_str().unwrap_or(""))
            || k.common
                .key_operations
                .as_ref()
                .is_some_and(|ops| !ops.contains(&jsonwebtoken::jwk::KeyOperations::Verify))
        {
            return Err(Error::InvalidClaims);
        }
        let mut validation = Validation::new(alg);
        // Clock checks below use the same injectable trusted clock as the sleep-aware lease.
        validation.validate_exp = false;
        validation.validate_aud = false;
        validation.required_spec_claims.clear();
        jsonwebtoken::decode::<Value>(
            &t.access,
            &DecodingKey::from_jwk(k).map_err(|_| Error::InvalidClaims)?,
            &validation,
        )
        .map_err(|_| Error::InvalidClaims)?;
        temporal(&c, now)?;
        if c["iss"].as_str() != Some(&self.config.issuer)
            || c["aud"].as_str() != Some(&self.config.resource)
            || c["client_id"].as_str() != Some(&self.config.client_id)
            || c.get("azp")
                .is_some_and(|v| v.as_str() != Some(&self.config.client_id))
            || !c["scope"]
                .as_str()
                .is_some_and(|s| s.split_ascii_whitespace().any(|s| s == "network:join"))
            || c.get("gty").is_some_and(|v| {
                !v.as_str().is_some_and(|s| {
                    !s.split_ascii_whitespace()
                        .any(|s| s == "client_credentials")
                })
            })
            || c.get("kind").is_some_and(|v| v != "AccessToken")
        {
            return Err(Error::InvalidClaims);
        }
        let sub = c["sub"]
            .as_str()
            .filter(|s| !s.is_empty() && s.len() <= 4096)
            .ok_or(Error::InvalidClaims)?;
        let account = Account {
            issuer: self.config.issuer.clone(),
            subject: sub.into(),
            product_id: self.config.product_id.clone(),
        };
        if expected.is_some_and(|e| e != &account) {
            return Err(Error::InvalidClaims);
        }
        if let Some((nonce, began)) = nonce {
            let id = t.id.as_ref().ok_or(Error::InvalidClaims)?;
            let (ih, ic) = strict::jwt_parts(id)?;
            header(&ih)?;
            temporal(&ic, now)?;
            let auth_time = ic["auth_time"].as_u64().ok_or(Error::InvalidClaims)?;
            if auth_time < began.saturating_sub(60)
                || auth_time > now.saturating_add(60)
                || ic["sub"].as_str() != Some(sub)
                || ic
                    .get("azp")
                    .is_some_and(|v| v.as_str() != Some(&self.config.client_id))
            {
                return Err(Error::InvalidClaims);
            }
            let id: CoreIdToken = id.parse().map_err(|_| Error::InvalidClaims)?;
            let jwks: CoreJsonWebKeySet =
                serde_json::from_value(keys).map_err(|_| Error::Configuration)?;
            let verifier = CoreIdTokenVerifier::new_public_client(
                ClientId::new(self.config.client_id.clone()),
                IssuerUrl::new(self.config.issuer.clone()).map_err(|_| Error::Configuration)?,
                jwks,
            )
            .set_allowed_algs([
                CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
                CoreJwsSigningAlgorithm::EcdsaP256Sha256,
                CoreJwsSigningAlgorithm::EcdsaP384Sha384,
            ]);
            let claims = id
                .claims(&verifier, &Nonce::new(nonce.to_owned()))
                .map_err(|_| Error::InvalidClaims)?;
            if let Some(hash) = claims.access_token_hash() {
                use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
                use sha2::{Digest, Sha256, Sha384};
                use subtle::ConstantTimeEq;
                let actual = match ih["alg"].as_str() {
                    Some("ES384") => {
                        URL_SAFE_NO_PAD.encode(&Sha384::digest(t.access.as_bytes())[..24])
                    }
                    _ => URL_SAFE_NO_PAD.encode(&Sha256::digest(t.access.as_bytes())[..16]),
                };
                if !bool::from(actual.as_bytes().ct_eq(hash.as_str().as_bytes())) {
                    return Err(Error::InvalidClaims);
                }
            }
        }
        let claim: CredentialClaim =
            serde_json::from_value(c[CLAIM].clone()).map_err(|_| Error::InvalidClaims)?;
        let material = NetworkMaterial::derive(&account, &claim)?;
        Ok(Verified {
            account,
            material,
            exp: c["exp"].as_u64().ok_or(Error::InvalidClaims)?,
        })
    }
    pub async fn revoke(&self, token: &str) -> Result<()> {
        let endpoint = self.revocation.as_ref().ok_or(Error::Unsupported)?;
        let response = self
            .http
            .post(endpoint)
            .form(&[
                ("token", token),
                ("token_type_hint", "refresh_token"),
                ("client_id", &self.config.client_id),
            ])
            .send()
            .await
            .map_err(|_| Error::UnknownOutcome)?;
        if response.status().is_success() {
            Ok(())
        } else {
            Err(Error::SessionRevoked)
        }
    }
}
fn header(v: &Value) -> Result<Algorithm> {
    let alg = match v["alg"].as_str() {
        Some("RS256") => Algorithm::RS256,
        Some("ES256") => Algorithm::ES256,
        Some("ES384") => Algorithm::ES384,
        _ => return Err(Error::InvalidClaims),
    };
    if !v.is_object()
        || !v["kid"].as_str().is_some_and(|s| !s.is_empty())
        || v.get("crit").is_some()
        || v.get("b64").is_some()
        || v.get("jku").is_some()
        || v.get("jwk").is_some()
        || v.get("x5u").is_some()
        || v.get("typ").is_some_and(|v| v != "JWT" && v != "at+jwt")
    {
        return Err(Error::InvalidClaims);
    }
    Ok(alg)
}
fn temporal(c: &Value, now: u64) -> Result<()> {
    let iat = c["iat"].as_u64().ok_or(Error::InvalidClaims)?;
    let exp = c["exp"].as_u64().ok_or(Error::InvalidClaims)?;
    if iat > now.saturating_add(60)
        || exp <= now.saturating_sub(60)
        || exp <= iat
        || c.get("nbf").is_some_and(|n| {
            n.as_u64()
                .is_none_or(|n| n > now.saturating_add(60) || n >= exp)
        })
    {
        return Err(Error::InvalidClaims);
    }
    Ok(())
}
async fn get(client: &reqwest::Client, url: &str) -> Result<Zeroizing<Vec<u8>>> {
    let response = client
        .get(url)
        .send()
        .await
        .map_err(|_| Error::Unavailable)?;
    if !response.status().is_success() {
        return Err(Error::Unavailable);
    }
    read(response).await
}
async fn read(mut response: reqwest::Response) -> Result<Zeroizing<Vec<u8>>> {
    let mut b = Zeroizing::new(Vec::new());
    while let Some(c) = response.chunk().await.map_err(|_| Error::UnknownOutcome)? {
        if b.len() + c.len() > 262144 {
            return Err(Error::InvalidClaims);
        }
        b.extend_from_slice(&c);
    }
    Ok(b)
}
#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) struct Tokens {
    pub access: String,
    pub refresh: Option<String>,
    pub id: Option<String>,
}
pub(crate) struct Verified {
    pub account: Account,
    pub material: NetworkMaterial,
    pub exp: u64,
}

impl<'c> oauth2::AsyncHttpClient<'c> for Oidc {
    type Error = Error;
    type Future = std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<oauth2::HttpResponse>> + Send + 'c>,
    >;
    fn call(&'c self, req: oauth2::HttpRequest) -> Self::Future {
        Box::pin(self.send(req))
    }
}
