use super::*;
use crate::{
    credentials::{CLAIM, CredentialClaim},
    oidc::{Oidc, Tokens},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde_json::{Value, json};
use sha2::{Digest, Sha256, Sha384};
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

// Private signing keys exist only in this test process. No reusable signing
// credentials or machine-generated PEM files are distributed with the sources.
struct SigningFixture {
    es384: EncodingKey,
    es256: EncodingKey,
    rs256: EncodingKey,
    jwks: Value,
}
fn signing_fixture() -> &'static SigningFixture {
    use ring::signature::KeyPair;
    use rsa::{pkcs1::EncodeRsaPrivateKey, traits::PublicKeyParts};
    static KEYS: std::sync::OnceLock<SigningFixture> = std::sync::OnceLock::new();
    KEYS.get_or_init(|| {
        let rng = ring::rand::SystemRandom::new();
        let ec = |alg, name, curve, coordinate_len| {
            let der = ring::signature::EcdsaKeyPair::generate_pkcs8(alg, &rng).unwrap();
            let pair = ring::signature::EcdsaKeyPair::from_pkcs8(alg, der.as_ref(), &rng).unwrap();
            let public = pair.public_key().as_ref();
            let jwk = json!({"kty":"EC","crv":curve,"kid":name,"alg":name,"use":"sig",
                "x":URL_SAFE_NO_PAD.encode(&public[1..1 + coordinate_len]),
                "y":URL_SAFE_NO_PAD.encode(&public[1 + coordinate_len..])});
            (EncodingKey::from_ec_der(der.as_ref()), jwk)
        };
        let (es384, public384) = ec(&ring::signature::ECDSA_P384_SHA384_ASN1_SIGNING, "ES384", "P-384", 48usize);
        let (es256, public256) = ec(&ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING, "ES256", "P-256", 32usize);
        let rsa = rsa::RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap();
        let public_rsa = json!({"kty":"RSA","kid":"RS256","alg":"RS256","use":"sig",
            "n":URL_SAFE_NO_PAD.encode(rsa.n().to_bytes_be()),"e":URL_SAFE_NO_PAD.encode(rsa.e().to_bytes_be())});
        let rs256 = EncodingKey::from_rsa_der(rsa.to_pkcs1_der().unwrap().as_bytes());
        SigningFixture { es384, es256, rs256, jwks: json!({"keys":[public384, public256, public_rsa]}) }
    })
}

#[derive(Default)]
struct TestClock {
    elapsed: AtomicU64,
    wall: AtomicU64,
    suspend: AtomicBool,
}
impl TestClock {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            elapsed: AtomicU64::new(0),
            wall: AtomicU64::new(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            ),
            suspend: AtomicBool::new(true),
        })
    }
    fn advance(&self, n: u64) {
        self.elapsed.fetch_add(n, Ordering::SeqCst);
        self.wall.fetch_add(n, Ordering::SeqCst);
    }
}
impl Clock for TestClock {
    fn elapsed(&self) -> Duration {
        Duration::from_secs(self.elapsed.load(Ordering::SeqCst))
    }
    fn unix_seconds(&self) -> u64 {
        self.wall.load(Ordering::SeqCst)
    }
    fn includes_suspend(&self) -> bool {
        self.suspend.load(Ordering::SeqCst)
    }
}
#[derive(Default)]
struct SharedStore {
    blob: Mutex<Option<Vec<u8>>>,
    fail: AtomicBool,
}
struct TestStore(Arc<SharedStore>);
impl SecureStore for TestStore {
    fn load(&mut self) -> Result<Option<SecretBytes>> {
        Ok(self
            .0
            .blob
            .lock()
            .unwrap()
            .as_ref()
            .map(|b| SecretBytes::new(b.clone())))
    }
    fn replace(&mut self, b: &[u8]) -> Result<()> {
        if self.0.fail.load(Ordering::SeqCst) {
            return Err(Error::Storage);
        }
        *self.0.blob.lock().unwrap() = Some(b.to_vec());
        Ok(())
    }
    fn durable(&self) -> bool {
        true
    }
}
struct Fixture {
    issuer: String,
    alg: Algorithm,
    epoch: String,
    seed: String,
    nonce: String,
    challenge: String,
    token_calls: usize,
    jwks_calls: usize,
    jwks_gate: Option<Arc<tokio::sync::Semaphore>>,
    jwks_entered: Arc<tokio::sync::Notify>,
    error: Option<String>,
    bad_hash: bool,
    wrong_nonce: bool,
    seen_refresh: Vec<String>,
    delay_ms: u64,
    discovery_gate: Option<Arc<tokio::sync::Semaphore>>,
    revoke_delay_ms: u64,
    drop_response: bool,
}
impl Fixture {
    fn config(&self) -> AuthConfig {
        AuthConfig {
            issuer: self.issuer.clone(),
            client_id: "native".into(),
            resource: "https://resource.example.test".into(),
            product_id: "product".into(),
            redirect_uri: "cyberbus://callback".into(),
            native_clients: [("native".into(), "product".into())].into(),
            offline_access: true,
            persist_grant: true,
            test_http: true,
        }
    }
    fn sign(&self, c: &Value) -> String {
        let keys = signing_fixture();
        let (name, key) = match self.alg {
            Algorithm::ES384 => ("ES384", &keys.es384),
            Algorithm::ES256 => ("ES256", &keys.es256),
            _ => ("RS256", &keys.rs256),
        };
        let mut h = Header::new(self.alg);
        h.kid = Some(name.into());
        jsonwebtoken::encode(&h, c, key).unwrap()
    }
    fn claims(&self) -> Value {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        json!({"iss":self.issuer,"sub":"account","aud":"https://resource.example.test","client_id":"native","scope":"openid network:join","iat":now,"exp":now+3600,CLAIM:{"version":1,"product_id":"product","credential_epoch":self.epoch,"account_seed_secret_hex":self.seed,"max_devices":256,"virtual_cidr":"10.144.0.0/20","control_port":11000,"config_version":"1"}})
    }
    fn tokens(&self) -> Tokens {
        let access = self.sign(&self.claims());
        let mut id = self.claims();
        id.as_object_mut().unwrap().remove(CLAIM);
        id["aud"] = json!("native");
        id["nonce"] = json!(if self.wrong_nonce {
            "wrong"
        } else {
            &self.nonce
        });
        id["auth_time"] = id["iat"].clone();
        id["at_hash"] = json!(if self.bad_hash {
            "bad".into()
        } else if self.alg == Algorithm::ES384 {
            URL_SAFE_NO_PAD.encode(&Sha384::digest(access.as_bytes())[..24])
        } else {
            URL_SAFE_NO_PAD.encode(&Sha256::digest(access.as_bytes())[..16])
        });
        Tokens {
            access,
            refresh: Some(format!("refresh-{}", self.token_calls)),
            id: Some(self.sign(&id)),
        }
    }
}
async fn server() -> (Arc<Mutex<Fixture>>, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let f = Arc::new(Mutex::new(Fixture {
        issuer: format!("http://{addr}/oidc"),
        alg: Algorithm::ES384,
        epoch: "1".into(),
        seed: "11".repeat(32),
        nonce: String::new(),
        challenge: String::new(),
        token_calls: 0,
        jwks_calls: 0,
        jwks_gate: None,
        jwks_entered: Arc::new(tokio::sync::Notify::new()),
        error: None,
        bad_hash: false,
        wrong_nonce: false,
        seen_refresh: Vec::new(),
        delay_ms: 0,
        discovery_gate: None,
        revoke_delay_ms: 0,
        drop_response: false,
    }));
    let s = f.clone();
    let handle = tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            let s = s.clone();
            tokio::spawn(async move {
                let mut b = Vec::new();
                let mut buf = [0; 4096];
                let header_end;
                loop {
                    let n = stream.read(&mut buf).await.unwrap();
                    if n == 0 {
                        return;
                    }
                    b.extend_from_slice(&buf[..n]);
                    if let Some(p) = b.windows(4).position(|p| p == b"\r\n\r\n") {
                        header_end = p + 4;
                        break;
                    }
                }
                let head = String::from_utf8_lossy(&b[..header_end]);
                let path = head
                    .lines()
                    .next()
                    .unwrap()
                    .split_whitespace()
                    .nth(1)
                    .unwrap()
                    .to_string();
                let length = head
                    .lines()
                    .find_map(|l| {
                        l.to_ascii_lowercase()
                            .strip_prefix("content-length: ")
                            .and_then(|v| v.parse::<usize>().ok())
                    })
                    .unwrap_or(0);
                while b.len() < header_end + length {
                    let n = stream.read(&mut buf).await.unwrap();
                    if n == 0 {
                        return;
                    }
                    b.extend_from_slice(&buf[..n]);
                }
                let (status, body) = {
                    let mut s = s.lock().unwrap();
                    match path.as_str() {
                        "/oidc/.well-known/openid-configuration" => (
                            200,
                            json!({"issuer":s.issuer,"authorization_endpoint":format!("{}/auth",s.issuer),"token_endpoint":format!("{}/token",s.issuer),"jwks_uri":format!("{}/jwks",s.issuer),"revocation_endpoint":format!("{}/revoke",s.issuer),"response_types_supported":["code"],"code_challenge_methods_supported":["S256"],"id_token_signing_alg_values_supported":["ES384"]}),
                        ),
                        "/oidc/jwks" => {
                            s.jwks_calls += 1;
                            (200, signing_fixture().jwks.clone())
                        }
                        "/oidc/revoke" => (200, json!({})),
                        "/oidc/token" => {
                            s.token_calls += 1;
                            let fields: std::collections::BTreeMap<_, _> =
                                url::form_urlencoded::parse(&b[header_end..])
                                    .into_owned()
                                    .collect();
                            assert_eq!(
                                fields.get("resource").map(String::as_str),
                                Some("https://resource.example.test")
                            );
                            assert_eq!(fields.get("client_id").map(String::as_str), Some("native"));
                            if fields.get("grant_type").map(String::as_str)
                                == Some("authorization_code")
                            {
                                assert_eq!(
                                    URL_SAFE_NO_PAD
                                        .encode(Sha256::digest(fields["code_verifier"].as_bytes())),
                                    s.challenge
                                );
                            } else {
                                s.seen_refresh.push(fields["refresh_token"].clone());
                            }
                            if let Some(e) = &s.error {
                                (
                                    400,
                                    json!({"error":e,"error_description":"secret-must-not-escape"}),
                                )
                            } else {
                                let t = s.tokens();
                                (
                                    200,
                                    json!({"access_token":t.access,"refresh_token":t.refresh,"id_token":t.id,"token_type":"Bearer","expires_in":3600}),
                                )
                            }
                        }
                        _ => (404, json!({})),
                    }
                };
                if path == "/oidc/.well-known/openid-configuration" {
                    let gate = s.lock().unwrap().discovery_gate.clone();
                    if let Some(gate) = gate {
                        gate.acquire().await.unwrap().forget();
                    }
                }
                if path == "/oidc/revoke" {
                    let delay = s.lock().unwrap().revoke_delay_ms;
                    tokio::time::sleep(Duration::from_millis(delay)).await;
                }
                if path == "/oidc/jwks" {
                    let (gate, entered) = {
                        let s = s.lock().unwrap();
                        (s.jwks_gate.clone(), s.jwks_entered.clone())
                    };
                    if let Some(gate) = gate {
                        entered.notify_one();
                        gate.acquire().await.unwrap().forget();
                    }
                }
                if path == "/oidc/token" {
                    let (delay, drop_response) = {
                        let s = s.lock().unwrap();
                        (s.delay_ms, s.drop_response)
                    };
                    if drop_response {
                        return;
                    }
                    tokio::time::sleep(Duration::from_millis(delay)).await;
                }
                let body = serde_json::to_vec(&body).unwrap();
                let h = format!(
                    "HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                stream.write_all(h.as_bytes()).await.unwrap();
                stream.write_all(&body).await.unwrap();
            });
        }
    });
    (f, handle)
}
fn manager(
    f: &Arc<Mutex<Fixture>>,
    disk: &Arc<SharedStore>,
    clock: Arc<TestClock>,
    mode: StoreMode,
) -> AuthManager {
    AuthManager::new(
        f.lock().unwrap().config(),
        Box::new(TestStore(disk.clone())),
        mode,
        clock,
    )
    .unwrap()
}
async fn login(m: &mut AuthManager, f: &Arc<Mutex<Fixture>>) -> Result<AuthSnapshot> {
    let request = m.begin_auth(AuthMode::Login).await?;
    let u = url::Url::parse(&request.authorization_url).unwrap();
    let q: std::collections::BTreeMap<_, _> = u.query_pairs().into_owned().collect();
    {
        let mut f = f.lock().unwrap();
        f.nonce = q["nonce"].clone();
        f.challenge = q["code_challenge"].clone();
    }
    m.complete_auth(
        request.operation_id,
        &format!("cyberbus://callback?code=code&state={}", q["state"]),
    )
    .await
}

#[tokio::test]
async fn authorization_url_consent_pkce_and_registration() {
    let (fixture, server) = server().await;
    let mut states = std::collections::BTreeSet::new();
    let mut nonces = std::collections::BTreeSet::new();
    let mut challenges = std::collections::BTreeSet::new();
    for offline_access in [false, true] {
        let mut config = fixture.lock().unwrap().config();
        config.offline_access = offline_access;
        let mut manager = AuthManager::new(
            config.clone(),
            Box::new(TestStore(Arc::new(SharedStore::default()))),
            StoreMode::CreateNew,
            TestClock::new(),
        )
        .unwrap();
        for mode in [AuthMode::Login, AuthMode::Register] {
            let request = manager.begin_auth(mode).await.unwrap();
            let url = url::Url::parse(&request.authorization_url).unwrap();
            let pairs: Vec<_> = url.query_pairs().into_owned().collect();
            let query: std::collections::BTreeMap<_, _> = pairs.iter().cloned().collect();
            assert_eq!(
                pairs.len(),
                query.len(),
                "duplicate authorization parameter"
            );
            assert_eq!(
                query["prompt"],
                if offline_access {
                    "login consent"
                } else {
                    "login"
                }
            );
            assert_eq!(query["max_age"], "0");
            assert_eq!(query["response_type"], "code");
            assert_eq!(query["client_id"], config.client_id);
            assert_eq!(query["redirect_uri"], config.redirect_uri);
            assert_eq!(query["resource"], config.resource);
            assert_eq!(query["code_challenge_method"], "S256");
            assert_eq!(
                URL_SAFE_NO_PAD
                    .decode(&query["code_challenge"])
                    .unwrap()
                    .len(),
                32
            );
            assert!(challenges.insert(query["code_challenge"].clone()));
            for key in ["state", "nonce"] {
                assert_eq!(hex::decode(&query[key]).unwrap().len(), 32);
            }
            assert_ne!(query["state"], query["nonce"]);
            assert!(states.insert(query["state"].clone()));
            assert!(nonces.insert(query["nonce"].clone()));
            let scopes: std::collections::BTreeSet<_> = query["scope"].split_whitespace().collect();
            let mut expected = std::collections::BTreeSet::from(["openid", "network:join"]);
            if offline_access {
                expected.insert("offline_access");
            }
            assert_eq!(scopes, expected);
            assert_eq!(
                query.get("first_screen").map(String::as_str),
                (mode == AuthMode::Register).then_some("register")
            );
            manager.cancel_auth(request.operation_id).unwrap();
        }
    }
    assert!(states.is_disjoint(&nonces));
    server.abort();
}

#[tokio::test]
async fn pkce_es384_refresh_rotation_and_cold_restore() {
    let (f, h) = server().await;
    let d = Arc::new(SharedStore::default());
    let c = TestClock::new();
    let mut m = manager(&f, &d, c.clone(), StoreMode::CreateNew);
    assert_eq!(login(&mut m, &f).await.unwrap().phase, Phase::Authenticated);
    assert!(!m.snapshot().network_enabled);
    let material = m
        .with_network_material(|v| (v.network_name.to_owned(), v.network_secret.to_owned()))
        .unwrap();
    let boot = *m.identity().boot_id();
    let generation = m.start_network().unwrap();
    assert_ne!(boot, *m.identity().boot_id());
    m.check_gate(generation, None).unwrap();
    c.advance(100);
    m.refresh().await.unwrap();
    assert!(m.snapshot().network_enabled);
    assert_eq!(m.snapshot().lease_deadline, Some(Duration::from_secs(700)));
    assert_eq!(
        m.with_network_material(|v| (v.network_name.to_owned(), v.network_secret.to_owned()))
            .unwrap(),
        material
    );
    assert_eq!(f.lock().unwrap().seen_refresh, vec!["refresh-1"]);
    drop(m);
    let mut m = manager(&f, &d, c, StoreMode::Existing);
    assert!(m.snapshot().lease_deadline.is_none());
    assert!(m.start_network().is_err());
    m.restore_auth(OperationId([1; 16])).await.unwrap();
    assert!(!m.snapshot().network_enabled);
    assert_eq!(
        f.lock().unwrap().seen_refresh,
        vec!["refresh-1", "refresh-2"]
    );
    h.abort();
}
#[tokio::test]
async fn epoch_root_change_latch_pending_conflict_and_highwater() {
    let (f, h) = server().await;
    let d = Arc::new(SharedStore::default());
    let c = TestClock::new();
    let mut m = manager(&f, &d, c.clone(), StoreMode::CreateNew);
    login(&mut m, &f).await.unwrap();
    m.start_network().unwrap();
    f.lock().unwrap().seed = "22".repeat(32);
    assert_eq!(m.refresh().await.unwrap_err(), Error::ReauthRequired);
    assert_eq!(
        m.snapshot().reauth_reason,
        Some(ReauthReason::CredentialsChanged)
    );
    assert!(!m.snapshot().network_enabled);
    assert!(m.with_network_material(|_| ()).is_err());
    f.lock().unwrap().seed = "11".repeat(32);
    assert_eq!(login(&mut m, &f).await.unwrap_err(), Error::Conflict);
    {
        let mut s = f.lock().unwrap();
        s.epoch = "2".into();
        s.seed = "33".repeat(32);
    }
    login(&mut m, &f).await.unwrap();
    assert!(!m.snapshot().reauth_required);
    assert!(!m.snapshot().network_enabled);
    f.lock().unwrap().epoch = "1".into();
    assert_eq!(m.refresh().await.unwrap_err(), Error::Rollback);
    assert!(!m.snapshot().network_enabled);
    drop(m);
    let mut m = manager(&f, &d, c, StoreMode::Existing);
    assert_eq!(
        m.restore_auth(OperationId([2; 16])).await.unwrap_err(),
        Error::UnknownOutcome
    );
    h.abort();
}
#[tokio::test]
async fn lease_includes_sleep_wall_rollback_and_does_not_use_token_expiry() {
    let (f, h) = server().await;
    let d = Arc::new(SharedStore::default());
    let c = TestClock::new();
    let mut m = manager(&f, &d, c.clone(), StoreMode::CreateNew);
    login(&mut m, &f).await.unwrap();
    let g = m.start_network().unwrap();
    c.advance(600);
    c.wall.store(1, Ordering::SeqCst);
    assert_eq!(m.check_gate(g, None).unwrap_err(), Error::ReauthRequired);
    assert_eq!(
        m.snapshot().reauth_reason,
        Some(ReauthReason::ValidationLeaseExpired)
    );
    drop(m);
    let m = manager(&f, &d, TestClock::new(), StoreMode::Existing);
    assert!(m.snapshot().reauth_required);
    h.abort();
}
#[tokio::test]
async fn jwt_all_supported_signatures_and_security_rejections() {
    let (f, h) = server().await;
    let config = f.lock().unwrap().config();
    let oidc = Oidc::discover(&config).await.unwrap();
    let now = TestClock::new().unix_seconds();
    for alg in [Algorithm::ES384, Algorithm::ES256, Algorithm::RS256] {
        let t = {
            let mut s = f.lock().unwrap();
            s.alg = alg;
            s.nonce = "expected".into();
            s.tokens()
        };
        assert!(
            oidc.verify(&t, Some(("expected", now)), now, None)
                .await
                .is_ok()
        );
    }
    let base = f.lock().unwrap().claims();
    let patches = [
        ("iss", json!("https://evil/oidc")),
        ("aud", json!("native")),
        ("aud", json!([config.resource])),
        ("sub", json!("")),
        ("scope", json!("network:join:admin")),
        ("client_id", json!("other")),
        ("azp", json!("other")),
        ("gty", json!("client_credentials")),
        ("exp", json!(now - 100)),
        ("iat", json!(now + 61)),
        ("nbf", json!(now + 61)),
        ("sub", json!(1)),
    ];
    for (k, v) in patches {
        let mut c = base.clone();
        c[k] = v;
        let t = Tokens {
            access: f.lock().unwrap().sign(&c),
            refresh: None,
            id: None,
        };
        assert!(oidc.verify(&t, None, now, None).await.is_err(), "{k}");
    }
    for (k, v) in [
        ("credential_epoch", json!("01")),
        ("credential_epoch", json!("18446744073709551616")),
        ("version", json!(true)),
        ("max_devices", json!("256")),
        ("virtual_cidr", json!("10.144.0.0/24")),
        ("control_port", json!(0)),
        ("config_version", json!("2")),
        ("account_seed_secret_hex", json!("AA".repeat(32))),
        ("extra", json!(1)),
    ] {
        let mut c = base.clone();
        c[CLAIM][k] = v;
        let t = Tokens {
            access: f.lock().unwrap().sign(&c),
            refresh: None,
            id: None,
        };
        assert!(oidc.verify(&t, None, now, None).await.is_err(), "{k}");
    }
    {
        let mut s = f.lock().unwrap();
        s.bad_hash = true;
    }
    let t = f.lock().unwrap().tokens();
    assert!(
        oidc.verify(&t, Some(("expected", now)), now, None)
            .await
            .is_err()
    );
    {
        let mut s = f.lock().unwrap();
        s.bad_hash = false;
        s.wrong_nonce = true;
    }
    let t = f.lock().unwrap().tokens();
    assert!(
        oidc.verify(&t, Some(("expected", now)), now, None)
            .await
            .is_err()
    );
    let mut t = f.lock().unwrap().tokens();
    t.access.push('a');
    assert!(oidc.verify(&t, None, now, None).await.is_err());
    h.abort();
}
#[tokio::test]
async fn block_storage_failures_profile_cas_and_identity_persist() {
    let (f, h) = server().await;
    let d = Arc::new(SharedStore::default());
    let c = TestClock::new();
    let mut m = manager(&f, &d, c.clone(), StoreMode::CreateNew);
    let id = *m.identity().device_id();
    assert!(m.local_profile().is_none());
    assert_eq!(m.commit_local_profile(0, b"profile-1").unwrap(), 1);
    assert_eq!(m.commit_local_profile(0, b"bad"), Err(Error::Conflict));
    assert_eq!(
        m.commit_local_profile(1, &vec![0; 16385]),
        Err(Error::ResourceExhausted)
    );
    login(&mut m, &f).await.unwrap();
    let peer = [9; 32];
    let s = m.block_device(peer).unwrap();
    assert_eq!(s.revision, 2);
    assert!(s.blocked && s.persisted_blocked);
    assert_eq!(m.block_device(peer).unwrap().revision, 2);
    d.fail.store(true, Ordering::SeqCst);
    assert_eq!(m.unblock_device(peer).unwrap_err(), Error::Storage);
    let s = m.block_state(peer).unwrap();
    assert!(s.blocked && s.persisted_blocked && s.persistence_pending);
    assert_eq!(s.revision, 2);
    d.fail.store(false, Ordering::SeqCst);
    m.unblock_device(peer).unwrap();
    assert!(!m.block_state(peer).unwrap().blocked);
    m.commit_address_preference("10.144.1.0".parse().unwrap())
        .unwrap();
    assert!(
        m.commit_address_preference("10.144.15.255".parse().unwrap())
            .is_err()
    );
    let r = m.logout(LogoutPolicy::LocalOnly).await;
    assert!(r.local_closed);
    drop(m);
    let m = manager(&f, &d, c, StoreMode::Existing);
    assert_eq!(*m.identity().device_id(), id);
    assert_eq!(m.local_profile(), Some((1, b"profile-1".to_vec())));
    h.abort();
}
#[tokio::test]
async fn cancel_callback_duplicate_operation_and_error_sanitization() {
    let (f, h) = server().await;
    let d = Arc::new(SharedStore::default());
    let c = TestClock::new();
    let mut m = manager(&f, &d, c.clone(), StoreMode::CreateNew);
    let r = m.begin_auth(AuthMode::Register).await.unwrap();
    assert!(r.authorization_url.contains("first_screen=register"));
    assert!(format!("{r:?}").contains("REDACTED"));
    assert!(m.begin_auth(AuthMode::Login).await.is_err());
    assert!(
        m.complete_auth(r.operation_id, "cyberbus://callback?code=code&state=wrong")
            .await
            .is_err()
    );
    m.cancel_auth(r.operation_id).unwrap();
    m.cancel_auth(r.operation_id).unwrap();
    assert_eq!(
        m.complete_auth(r.operation_id, "cyberbus://callback")
            .await
            .unwrap_err(),
        Error::Conflict
    );
    login(&mut m, &f).await.unwrap();
    f.lock().unwrap().error = Some("invalid_grant".into());
    assert_eq!(m.refresh().await.unwrap_err(), Error::SessionRevoked);
    assert_eq!(
        m.snapshot().reauth_reason,
        Some(ReauthReason::SessionRevoked)
    );
    assert!(!format!("{m:?}").contains("secret-must-not-escape"));
    h.abort();
}
#[test]
fn derivation_independent_python_vector_and_debug_redaction() {
    let v: Value = serde_json::from_str(include_str!("../tests/fixtures/derivation.json")).unwrap();
    let a = Account {
        issuer: v["issuer"].as_str().unwrap().into(),
        subject: v["subject"].as_str().unwrap().into(),
        product_id: v["product_id"].as_str().unwrap().into(),
    };
    let c:CredentialClaim=serde_json::from_value(json!({"version":1,"product_id":a.product_id,"credential_epoch":v["epoch"],"account_seed_secret_hex":v["seed"],"max_devices":256,"virtual_cidr":"10.144.0.0/20","control_port":11000,"config_version":"1"})).unwrap();
    let m = NetworkMaterial::derive(&a, &c).unwrap();
    let n = m.view();
    assert_eq!(n.network_name, v["network_name"].as_str().unwrap());
    assert_eq!(n.network_secret, v["network_secret"].as_str().unwrap());
    assert_eq!(hex::encode(n.app_psk), v["app_psk"].as_str().unwrap());
    assert_eq!(hex::encode(n.binding_id), v["binding_id"].as_str().unwrap());
    assert_eq!(format!("{m:?}"), "NetworkMaterial([REDACTED])");
    assert!(!format!("{n:?}").contains(n.network_secret));
}
#[test]
fn recursive_duplicate_json_and_callback_rejection() {
    for s in [
        r#"{"a":1,"a":2}"#,
        r#"{"x":{"sub":"one","sub":"two"}}"#,
        r#"{"x":[{"seed":1,"seed":2}]}"#,
    ] {
        assert!(crate::strict::json(s.as_bytes()).is_err());
    }
    for u in [
        "cyberbus://evil?code=x&state=s",
        "cyberbus://callback?code=x&state=s&state=s",
        "cyberbus://callback?code=x&state=s#fragment",
        "cyberbus://callback?code=x&state=wrong",
    ] {
        assert!(crate::manager::parse_callback("cyberbus://callback", u, "s").is_err());
    }
}
#[test]
fn store_missing_existing_corruption_and_exclusive_development_file() {
    let config = AuthConfig {
        issuer: "https://example.test/oidc".into(),
        client_id: "native".into(),
        resource: "https://resource.example.test".into(),
        product_id: "product".into(),
        redirect_uri: "cyberbus://callback".into(),
        native_clients: [("native".into(), "product".into())].into(),
        offline_access: true,
        persist_grant: false,
        test_http: false,
    };
    assert!(
        AuthManager::new(
            config.clone(),
            Box::new(MemoryStore::default()),
            StoreMode::Existing,
            TestClock::new()
        )
        .is_err()
    );
    let dir = std::env::temp_dir().join(format!(
        "cyberbus-auth-{}",
        hex::encode(crate::secret::random::<16>().unwrap())
    ));
    std::fs::create_dir(&dir).unwrap();
    let p = dir.join("state.json");
    let s = DevelopmentFileStore::provision_new(&p).unwrap();
    assert!(DevelopmentFileStore::open(&p).is_err());
    let mut m = AuthManager::new(
        config.clone(),
        Box::new(s),
        StoreMode::CreateNew,
        TestClock::new(),
    )
    .unwrap();
    m.commit_local_profile(0, b"persist").unwrap();
    drop(m);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    let m = AuthManager::new(
        config.clone(),
        Box::new(DevelopmentFileStore::open(&p).unwrap()),
        StoreMode::Existing,
        TestClock::new(),
    )
    .unwrap();
    assert_eq!(m.local_profile().unwrap().0, 1);
    drop(m);
    std::fs::write(&p, b"corrupt").unwrap();
    assert!(matches!(
        DevelopmentFileStore::open(&p),
        Err(Error::Storage)
    ));
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn cancelled_caller_retains_unique_owner_and_rotated_grant() {
    let (f, h) = server().await;
    let d = Arc::new(SharedStore::default());
    let c = TestClock::new();
    let mut m = manager(&f, &d, c, StoreMode::CreateNew);
    login(&mut m, &f).await.unwrap();
    f.lock().unwrap().delay_ms = 80;
    assert!(
        tokio::time::timeout(Duration::from_millis(20), m.refresh())
            .await
            .is_err()
    );
    assert!(m.snapshot().request_in_flight);
    assert!(m.snapshot().refresh_grant_frozen);
    assert_eq!(m.refresh().await.unwrap_err(), Error::Conflict);
    m.settle_pending().await.unwrap();
    assert!(!m.snapshot().refresh_grant_frozen);
    assert_eq!(f.lock().unwrap().token_calls, 2);
    h.abort();
}

#[tokio::test]
async fn jwks_caller_cancellation_retains_login_and_refresh_for_both_stores() {
    for persist_grant in [false, true] {
        let (f, h) = server().await;
        let disk = Arc::new(SharedStore::default());
        let clock = TestClock::new();
        let mut config = f.lock().unwrap().config();
        config.persist_grant = persist_grant;
        let store: Box<dyn SecureStore> = if persist_grant {
            Box::new(TestStore(disk))
        } else {
            Box::new(MemoryStore::default())
        };
        let mut manager =
            AuthManager::new(config, store, StoreMode::CreateNew, clock.clone()).unwrap();
        let gate = Arc::new(tokio::sync::Semaphore::new(0));
        let entered = {
            let mut fixture = f.lock().unwrap();
            fixture.jwks_gate = Some(gate.clone());
            fixture.jwks_entered.clone()
        };

        // Drop the caller only after issuance succeeded and the JWKS request arrived.
        cancel_during_jwks(login(&mut manager, &f), &entered).await;
        assert!(manager.snapshot().request_in_flight);
        assert_eq!(f.lock().unwrap().token_calls, 1);
        assert_eq!(f.lock().unwrap().jwks_calls, 1);
        gate.add_permits(1);
        assert_eq!(
            manager.settle_pending().await.unwrap().phase,
            Phase::Authenticated
        );
        let generation = manager.start_network().unwrap();
        let old_deadline = manager.snapshot().lease_deadline;
        clock.advance(100);

        cancel_during_jwks(manager.refresh(), &entered).await;
        assert!(manager.snapshot().request_in_flight);
        assert!(manager.snapshot().refresh_grant_frozen);
        assert_eq!(manager.snapshot().lease_deadline, old_deadline);
        manager.check_gate(generation, None).unwrap();
        assert_eq!(manager.refresh().await.unwrap_err(), Error::Conflict);
        assert_eq!(f.lock().unwrap().token_calls, 2);
        assert_eq!(f.lock().unwrap().jwks_calls, 2);
        gate.add_permits(1);
        manager.settle_pending().await.unwrap();
        assert!(!manager.snapshot().request_in_flight);
        assert!(!manager.snapshot().refresh_grant_frozen);
        assert_eq!(
            manager.snapshot().lease_deadline,
            Some(Duration::from_secs(700))
        );
        manager.check_gate(generation, None).unwrap();

        f.lock().unwrap().jwks_gate = None;
        manager.refresh().await.unwrap();
        let fixture = f.lock().unwrap();
        assert_eq!(fixture.token_calls, 3);
        assert_eq!(fixture.jwks_calls, 3);
        assert_eq!(fixture.seen_refresh, ["refresh-1", "refresh-2"]);
        h.abort();
    }
}

async fn cancel_during_jwks(
    future: impl std::future::Future<Output = Result<AuthSnapshot>>,
    entered: &tokio::sync::Notify,
) {
    tokio::time::timeout(Duration::from_secs(2), async {
        tokio::pin!(future);
        tokio::select! {
            _ = entered.notified() => {}
            _ = &mut future => panic!("operation finished before delayed JWKS was released"),
        }
    })
    .await
    .expect("verification must reach the JWKS endpoint");
}

#[tokio::test]
async fn jwks_late_login_cannot_override_cancel_or_logout() {
    for logout in [false, true] {
        let (f, h) = server().await;
        let mut manager = manager(
            &f,
            &Arc::new(SharedStore::default()),
            TestClock::new(),
            StoreMode::CreateNew,
        );
        let request = manager.begin_auth(AuthMode::Login).await.unwrap();
        let url = url::Url::parse(&request.authorization_url).unwrap();
        let query: std::collections::BTreeMap<_, _> = url.query_pairs().into_owned().collect();
        let gate = Arc::new(tokio::sync::Semaphore::new(0));
        let entered = {
            let mut fixture = f.lock().unwrap();
            fixture.nonce = query["nonce"].clone();
            fixture.challenge = query["code_challenge"].clone();
            fixture.jwks_gate = Some(gate.clone());
            fixture.jwks_entered.clone()
        };
        let callback = format!("cyberbus://callback?code=code&state={}", query["state"]);
        cancel_during_jwks(
            manager.complete_auth(request.operation_id, &callback),
            &entered,
        )
        .await;
        assert!(manager.snapshot().request_in_flight);
        if logout {
            assert!(manager.logout(LogoutPolicy::LocalOnly).await.local_closed);
        } else {
            manager.cancel_auth(request.operation_id).unwrap();
        }
        gate.add_permits(1);
        assert_eq!(
            manager.settle_pending().await.unwrap_err(),
            Error::Cancelled
        );
        assert_eq!(manager.snapshot().phase, Phase::LoggedOut);
        assert!(!manager.snapshot().request_in_flight);
        assert!(!manager.snapshot().refresh_supported);
        assert!(manager.start_network().is_err());
        assert_eq!(f.lock().unwrap().token_calls, 1);
        h.abort();
    }
}

#[tokio::test]
async fn jwks_late_refresh_respects_expired_lease_and_stopped_generation() {
    for expire in [false, true] {
        let (f, h) = server().await;
        let clock = TestClock::new();
        let mut manager = manager(
            &f,
            &Arc::new(SharedStore::default()),
            clock.clone(),
            StoreMode::CreateNew,
        );
        login(&mut manager, &f).await.unwrap();
        let generation = manager.start_network().unwrap();
        let gate = Arc::new(tokio::sync::Semaphore::new(0));
        let entered = {
            let mut fixture = f.lock().unwrap();
            fixture.jwks_gate = Some(gate.clone());
            fixture.jwks_entered.clone()
        };
        cancel_during_jwks(manager.refresh(), &entered).await;
        if expire {
            clock.advance(600);
        } else {
            manager.stop_network();
        }
        gate.add_permits(1);
        let result = manager.settle_pending().await;
        if expire {
            assert_eq!(result.unwrap_err(), Error::ReauthRequired);
            assert_eq!(
                manager.snapshot().reauth_reason,
                Some(ReauthReason::ValidationLeaseExpired)
            );
        } else {
            assert_eq!(result.unwrap().phase, Phase::Authenticated);
        }
        assert!(!manager.snapshot().network_enabled);
        assert!(!manager.snapshot().request_in_flight);
        assert!(manager.check_gate(generation, None).is_err());
        assert_eq!(f.lock().unwrap().token_calls, 2);
        h.abort();
    }
}

#[tokio::test]
async fn lost_response_freezes_grant_across_restart_until_interactive_login() {
    let (f, h) = server().await;
    let d = Arc::new(SharedStore::default());
    let c = TestClock::new();
    let mut m = manager(&f, &d, c.clone(), StoreMode::CreateNew);
    login(&mut m, &f).await.unwrap();
    let g = m.start_network().unwrap();
    f.lock().unwrap().drop_response = true;
    assert_eq!(m.refresh().await.unwrap_err(), Error::UnknownOutcome);
    assert!(m.snapshot().refresh_grant_frozen);
    m.check_gate(g, None).unwrap();
    assert_eq!(m.refresh().await.unwrap_err(), Error::UnknownOutcome);
    assert_eq!(f.lock().unwrap().token_calls, 2);
    drop(m);
    let mut m = manager(&f, &d, c, StoreMode::Existing);
    assert_eq!(
        m.restore_auth(OperationId([5; 16])).await.unwrap_err(),
        Error::UnknownOutcome
    );
    f.lock().unwrap().drop_response = false;
    login(&mut m, &f).await.unwrap();
    assert!(!m.snapshot().refresh_grant_frozen);
    h.abort();
}

async fn next_ready(m: &mut AuthManager) -> OperationReady {
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if let Some(result) = m.poll_ready() {
                return result;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await
    .expect("owned operation did not become ready")
}
fn fixture_callback(r: &AuthRequest, f: &Arc<Mutex<Fixture>>) -> String {
    let u = url::Url::parse(&r.authorization_url).unwrap();
    let q: std::collections::BTreeMap<_, _> = u.query_pairs().into_owned().collect();
    let mut f = f.lock().unwrap();
    f.nonce = q["nonce"].clone();
    f.challenge = q["code_challenge"].clone();
    format!("cyberbus://callback?code=code&state={}", q["state"])
}
#[tokio::test]
async fn nonblocking_discovery_cancel_expiry_restore_and_single_terminal() {
    let (f, h) = server().await;
    let clock = TestClock::new();
    let mut m = manager(
        &f,
        &Arc::new(SharedStore::default()),
        clock.clone(),
        StoreMode::CreateNew,
    );
    let gate = Arc::new(tokio::sync::Semaphore::new(0));
    f.lock().unwrap().discovery_gate = Some(gate.clone());
    let id = m.submit_begin_auth(AuthMode::Login).unwrap();
    assert!(m.poll_ready().is_none());
    assert!(m.snapshot().request_in_flight);
    assert_eq!(
        m.submit_begin_auth(AuthMode::Login).unwrap_err(),
        Error::Conflict
    );
    assert_eq!(
        m.cancel_operation(id).unwrap().unwrap().stage,
        OperationStage::Cancelled
    );
    assert!(
        matches!(m.poll_ready(), Some(OperationReady::AuthFinished { operation_id, result: Err(Error::Cancelled) }) if operation_id == id)
    );
    assert!(m.cancel_operation(id).unwrap().unwrap().terminal);
    assert!(m.poll_ready().is_none());
    gate.add_permits(1);
    f.lock().unwrap().discovery_gate = None;
    let id = m.submit_begin_auth(AuthMode::Register).unwrap();
    assert!(
        matches!(next_ready(&mut m).await, OperationReady::AuthStarted(r) if r.operation_id == id)
    );
    clock.advance(600);
    assert!(
        matches!(m.poll_ready(), Some(OperationReady::AuthFinished { operation_id, result: Err(Error::DeadlineExceeded) }) if operation_id == id)
    );
    assert!(m.poll_ready().is_none());
    let restore = OperationId([91; 16]);
    m.submit_restore_auth(restore).unwrap();
    assert!(
        matches!(m.poll_ready(), Some(OperationReady::AuthFinished { operation_id, result: Err(Error::Unauthenticated) }) if operation_id == restore)
    );
    assert_eq!(m.submit_restore_auth(restore).unwrap_err(), Error::Conflict);
    h.abort();
}
#[tokio::test]
async fn nonblocking_code_jwks_cancel_and_late_refresh_keep_one_owner() {
    let (f, h) = server().await;
    let clock = TestClock::new();
    let mut m = manager(
        &f,
        &Arc::new(SharedStore::default()),
        clock.clone(),
        StoreMode::CreateNew,
    );
    let id = m.submit_begin_auth(AuthMode::Login).unwrap();
    let OperationReady::AuthStarted(request) = next_ready(&mut m).await else {
        panic!("expected auth URL");
    };
    let callback = fixture_callback(&request, &f);
    f.lock().unwrap().delay_ms = 40;
    m.submit_complete_auth(id, &callback).unwrap();
    assert!(m.poll_ready().is_none());
    assert_eq!(m.submit_complete_auth(id, &callback), Err(Error::Conflict));
    let gate = Arc::new(tokio::sync::Semaphore::new(0));
    f.lock().unwrap().jwks_gate = Some(gate.clone());
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            assert!(m.poll_ready().is_none());
            if m.operation_status(id).unwrap().stage == OperationStage::Verifying {
                break;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await
    .unwrap();
    m.cancel_operation(id).unwrap();
    assert!(matches!(
        m.poll_ready(),
        Some(OperationReady::AuthFinished {
            result: Err(Error::Cancelled),
            ..
        })
    ));
    assert_eq!(m.submit_refresh().unwrap_err(), Error::Conflict);
    gate.add_permits(1);
    tokio::time::timeout(Duration::from_secs(2), async {
        while m.snapshot().request_in_flight {
            assert!(m.poll_ready().is_none());
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await
    .unwrap();
    assert!(m.start_network().is_err());
    assert_eq!(f.lock().unwrap().token_calls, 1);
    f.lock().unwrap().jwks_gate = None;
    login(&mut m, &f).await.unwrap();
    let generation = m.start_network().unwrap();
    let id = m.submit_refresh().unwrap();
    assert!(m.poll_ready().is_none());
    m.stop_network();
    assert!(
        matches!(next_ready(&mut m).await, OperationReady::AuthFinished { operation_id, result: Ok(_) } if operation_id == id)
    );
    assert!(!m.snapshot().network_enabled);
    assert!(m.check_gate(generation, None).is_err());
    assert_eq!(f.lock().unwrap().token_calls, 3);
    h.abort();
}
#[tokio::test]
async fn sync_gate_hook_precedes_material_latch_persistence_and_cloud_budget() {
    let (f, h) = server().await;
    let disk = Arc::new(SharedStore::default());
    let mut m = manager(&f, &disk, TestClock::new(), StoreMode::CreateNew);
    login(&mut m, &f).await.unwrap();
    let open = Arc::new(AtomicU64::new(0));
    let deny = open.clone();
    m.set_gate_close_hook(Arc::new(move || {
        deny.store(0, Ordering::SeqCst);
    }));
    m.start_network().unwrap();
    open.store(1, Ordering::SeqCst);
    // The store callback inspects the real admission flag at the write boundary, before returning.
    struct GateStore {
        disk: Arc<SharedStore>,
        open: Arc<AtomicU64>,
    }
    impl SecureStore for GateStore {
        fn load(&mut self) -> Result<Option<SecretBytes>> {
            TestStore(self.disk.clone()).load()
        }
        fn replace(&mut self, b: &[u8]) -> Result<()> {
            let v: Value = serde_json::from_slice(b).unwrap();
            if v["records"][0]["latch"] == "CredentialsChanged" {
                assert_eq!(self.open.load(Ordering::SeqCst), 0);
            }
            TestStore(self.disk.clone()).replace(b)
        }
        fn durable(&self) -> bool {
            true
        }
    }
    m.protected_store_for_test(Box::new(GateStore {
        disk,
        open: open.clone(),
    }));
    f.lock().unwrap().epoch = "2".into();
    assert_eq!(m.refresh().await.unwrap_err(), Error::ReauthRequired);
    assert_eq!(open.load(Ordering::SeqCst), 0);
    login(&mut m, &f).await.unwrap();
    m.start_network().unwrap();
    open.store(1, Ordering::SeqCst);
    f.lock().unwrap().revoke_delay_ms = 200;
    let before = std::time::Instant::now();
    let id = m
        .submit_logout(LogoutPolicy::RevokeGrant, Duration::from_millis(10))
        .unwrap();
    assert_eq!(open.load(Ordering::SeqCst), 0);
    assert_eq!(m.snapshot().phase, Phase::LoggedOut);
    let OperationReady::LogoutFinished {
        operation_id,
        result,
    } = next_ready(&mut m).await
    else {
        panic!("logout expected");
    };
    assert_eq!(operation_id, id);
    assert_eq!(result.cloud_status, CloudLogout::UnknownOutcome);
    assert!(result.local_closed);
    assert!(before.elapsed() < Duration::from_millis(150));
    assert!(m.poll_ready().is_none());
    h.abort();
}

fn disk_dir() -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "cyberbus-auth-disk-{}",
        hex::encode(crate::secret::random::<16>().unwrap())
    ));
    std::fs::create_dir(&dir).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    dir
}
fn disk_baseline(path: &std::path::Path) {
    use crate::store::{Marker, Protected, Record};
    let mut p = Protected::open(
        Box::new(DevelopmentFileStore::provision_new(path).unwrap()),
        StoreMode::CreateNew,
    )
    .unwrap();
    p.vault.records.push(Record {
        account: Account {
            issuer: "https://example.test/oidc".into(),
            subject: "account".into(),
            product_id: "product".into(),
        },
        active: Marker {
            epoch: 1,
            tag: [1; 32],
        },
        pending: None,
        highwater: 1,
        latch: None,
        blocked: [[7; 32]].into(),
        block_revision: 1,
    });
    p.vault.profile_revision = 1;
    p.vault.profile = Some(b"old".to_vec());
    p.save().unwrap();
}
fn disk_advance(p: &mut crate::store::Protected) {
    let r = &mut p.vault.records[0];
    r.highwater = 2;
    r.pending = Some(crate::store::Marker {
        epoch: 2,
        tag: [2; 32],
    });
    r.latch = Some(ReauthReason::CredentialsChanged);
    r.blocked.insert([8; 32]);
    r.block_revision = 2;
    p.vault.profile_revision = 2;
    p.vault.profile = Some(b"next".to_vec());
}
#[test]
fn disk_marker_trusted_provision_migration_missing_and_rollback() {
    use crate::store::Protected;
    let dir = disk_dir();
    let path = dir.join("state.json");
    assert!(matches!(
        DevelopmentFileStore::open(&path),
        Err(Error::Storage)
    ));
    assert!(matches!(
        DevelopmentFileStore::migrate_existing(&path),
        Err(Error::Storage)
    ));
    disk_baseline(&path);
    let old = std::fs::read(&path).unwrap();
    assert!(matches!(
        DevelopmentFileStore::provision_new(&path),
        Err(Error::Storage)
    ));
    let mut p = Protected::open(
        Box::new(DevelopmentFileStore::open(&path).unwrap()),
        StoreMode::Existing,
    )
    .unwrap();
    disk_advance(&mut p);
    p.save().unwrap();
    drop(p);
    let new = std::fs::read(&path).unwrap();
    std::fs::write(&path, &old).unwrap();
    assert!(matches!(
        DevelopmentFileStore::open(&path),
        Err(Error::Storage)
    ));
    std::fs::write(&path, &new).unwrap();
    std::fs::remove_file(&path).unwrap();
    assert!(matches!(
        DevelopmentFileStore::open(&path),
        Err(Error::Storage)
    ));
    assert!(matches!(
        DevelopmentFileStore::provision_new(&path),
        Err(Error::Storage)
    ));
    // Loss of marker with an existing vault cannot silently establish a new baseline.
    std::fs::write(&path, &new).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    std::fs::remove_file(path.with_extension("auth-install")).unwrap();
    assert!(matches!(
        DevelopmentFileStore::open(&path),
        Err(Error::Storage)
    ));
    assert!(matches!(
        DevelopmentFileStore::provision_new(&path),
        Err(Error::Storage)
    ));
    let store = DevelopmentFileStore::migrate_existing(&path).unwrap();
    let p = Protected::open(Box::new(store), StoreMode::Existing).unwrap();
    assert_eq!(p.vault.records[0].highwater, 2);
    assert_eq!(
        p.vault.records[0].latch,
        Some(ReauthReason::CredentialsChanged)
    );
    assert!(p.vault.records[0].blocked.contains(&[8; 32]));
    drop(p);
    let marker = path.with_extension("auth-install");
    let marker_bytes = std::fs::read(&marker).unwrap();
    std::fs::write(&marker, b"corrupt").unwrap();
    assert!(matches!(
        DevelopmentFileStore::open(&path),
        Err(Error::Storage)
    ));
    assert!(matches!(
        DevelopmentFileStore::provision_new(&path),
        Err(Error::Storage)
    ));
    std::fs::write(&marker, marker_bytes).unwrap();
    // A crash after durable provisioning but before initial vault cannot become first use again.
    let other = dir.join("interrupted.json");
    drop(DevelopmentFileStore::provision_new(&other).unwrap());
    assert!(matches!(
        DevelopmentFileStore::open(&other),
        Err(Error::Storage)
    ));
    assert!(matches!(
        DevelopmentFileStore::provision_new(&other),
        Err(Error::Storage)
    ));
    std::fs::remove_dir_all(dir).unwrap();
}
#[test]
fn disk_failure_boundaries_preserve_complete_security_records() {
    use crate::store::Protected;
    for stage in [
        "intent",
        "written",
        "synced",
        "renamed",
        "directory-synced",
        "before-finalize",
        "committed",
    ] {
        let dir = disk_dir();
        let path = dir.join("state.json");
        disk_baseline(&path);
        let mut store = DevelopmentFileStore::open(&path).unwrap();
        store.inject_failure(stage);
        let mut p = Protected::open(Box::new(store), StoreMode::Existing).unwrap();
        disk_advance(&mut p);
        assert_eq!(p.save(), Err(Error::Storage), "{stage}");
        assert!(p.pending);
        drop(p);
        let p = Protected::open(
            Box::new(DevelopmentFileStore::open(&path).unwrap()),
            StoreMode::Existing,
        )
        .unwrap();
        let committed = matches!(
            stage,
            "renamed" | "directory-synced" | "before-finalize" | "committed"
        );
        assert_eq!(
            p.vault.profile_revision,
            if committed { 2 } else { 1 },
            "{stage}"
        );
        assert_eq!(p.vault.records[0].highwater, if committed { 2 } else { 1 });
        assert_eq!(p.vault.records[0].latch.is_some(), committed);
        assert_eq!(
            p.vault.records[0].block_revision,
            if committed { 2 } else { 1 }
        );
        assert_eq!(p.vault.records[0].blocked.contains(&[8; 32]), committed);
        assert!(p.vault.records[0].blocked.contains(&[7; 32]));
        assert_eq!(p.vault.records[0].pending.is_some(), committed);
        drop(p);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
#[test]
#[ignore = "subprocess entry; exercised by disk_process_crash_boundaries_recover_and_release_exclusive_lock"]
fn disk_crash_child() {
    let path = std::env::var("CYBERBUS_AUTH_CRASH_PATH").unwrap();
    if std::env::var("CYBERBUS_AUTH_LOCK_PROBE").is_ok() {
        assert!(matches!(
            DevelopmentFileStore::open(path),
            Err(Error::Conflict)
        ));
        std::process::exit(82);
    }
    let mut p = crate::store::Protected::open(
        Box::new(DevelopmentFileStore::open(path).unwrap()),
        StoreMode::Existing,
    )
    .unwrap();
    disk_advance(&mut p);
    p.save().unwrap();
    panic!("crash checkpoint was not reached");
}
#[test]
fn disk_process_crash_boundaries_recover_and_release_exclusive_lock() {
    for stage in [
        "intent",
        "written",
        "synced",
        "renamed",
        "directory-synced",
        "before-finalize",
        "committed",
    ] {
        let dir = disk_dir();
        let path = dir.join("state.json");
        disk_baseline(&path);
        let result = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "tests::disk_crash_child",
                "--nocapture",
                "--ignored",
            ])
            .env("CYBERBUS_AUTH_CRASH_PATH", &path)
            .env("CYBERBUS_AUTH_CRASH_STAGE", stage)
            .output()
            .unwrap();
        assert_eq!(
            result.status.code(),
            Some(81),
            "{stage}: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        let store = DevelopmentFileStore::open(&path).unwrap();
        assert!(matches!(
            DevelopmentFileStore::open(&path),
            Err(Error::Conflict)
        ));
        if stage == "intent" {
            let probe = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "tests::disk_crash_child", "--ignored"])
                .env("CYBERBUS_AUTH_CRASH_PATH", &path)
                .env("CYBERBUS_AUTH_LOCK_PROBE", "1")
                .output()
                .unwrap();
            assert_eq!(probe.status.code(), Some(82));
        }
        let p = crate::store::Protected::open(Box::new(store), StoreMode::Existing).unwrap();
        let committed = matches!(
            stage,
            "renamed" | "directory-synced" | "before-finalize" | "committed"
        );
        let r = &p.vault.records[0];
        assert_eq!(r.highwater, if committed { 2 } else { 1 }, "{stage}");
        assert_eq!(r.pending.is_some(), committed);
        assert_eq!(r.latch.is_some(), committed);
        assert_eq!(r.block_revision, if committed { 2 } else { 1 });
        assert_eq!(r.blocked.contains(&[8; 32]), committed);
        assert!(r.blocked.contains(&[7; 32]));
        assert_eq!(p.vault.profile_revision, if committed { 2 } else { 1 });
        drop(p);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
#[cfg(unix)]
#[test]
fn disk_rejects_symlink_hardlink_public_permissions_and_real_rename_failure() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let dir = disk_dir();
    let path = dir.join("state.json");
    disk_baseline(&path);
    let target = dir.join("copy.json");
    std::fs::rename(&path, &target).unwrap();
    symlink(&target, &path).unwrap();
    assert!(matches!(
        DevelopmentFileStore::open(&path),
        Err(Error::Storage)
    ));
    std::fs::remove_file(&path).unwrap();
    std::fs::hard_link(&target, &path).unwrap();
    assert!(matches!(
        DevelopmentFileStore::open(&path),
        Err(Error::Storage)
    ));
    std::fs::remove_file(&path).unwrap();
    std::fs::rename(&target, &path).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(matches!(
        DevelopmentFileStore::open(&path),
        Err(Error::Storage)
    ));
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    // Rename the parent out from under an existing owner: actual OS I/O failure, not an in-memory mock.
    let mut store = DevelopmentFileStore::open(&path).unwrap();
    let blob = store.load().unwrap().unwrap();
    let moved = dir.with_extension("moved");
    std::fs::rename(&dir, &moved).unwrap();
    assert_eq!(store.replace(blob.expose()), Err(Error::Storage));
    drop(store);
    std::fs::rename(&moved, &dir).unwrap();
    assert!(DevelopmentFileStore::open(&path).is_ok());
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn unavailable_retry_is_bounded_and_does_not_consume_or_extend_lease() {
    let (f, h) = server().await;
    let clock = TestClock::new();
    let mut m = manager(
        &f,
        &Arc::new(SharedStore::default()),
        clock.clone(),
        StoreMode::CreateNew,
    );
    login(&mut m, &f).await.unwrap();
    let generation = m.start_network().unwrap();
    clock.advance(300);
    let old_lease = m.snapshot().lease_deadline;
    // The local network environment maps a closed listener to HTTP 502 (UnknownOutcome).
    // Inject a failure at the adapter boundary before delivery instead of weakening 5xx handling.
    m.fail_before_delivery_for_test();
    for _ in 0..3 {
        let id = m.submit_refresh().unwrap();
        let outcome = next_ready(&mut m).await;
        assert!(
            matches!(outcome, OperationReady::AuthFinished { operation_id, result: Err(Error::Unavailable) } if operation_id == id),
            "{outcome:?}"
        );
        assert!(!m.snapshot().refresh_grant_frozen);
        assert_eq!(m.snapshot().lease_deadline, old_lease);
        m.check_gate(generation, None).unwrap();
        let until = m
            .snapshot()
            .next_validation
            .unwrap()
            .saturating_sub(clock.elapsed())
            .as_secs();
        assert!((5..=60).contains(&until));
        assert_eq!(m.submit_refresh().unwrap_err(), Error::Unavailable);
        assert!(!m.on_resume().unwrap());
        clock.advance(until);
        assert!(m.on_resume().unwrap());
    }
    assert_eq!(f.lock().unwrap().token_calls, 1);
    h.abort();
}
#[tokio::test]
async fn oauth_denial_and_expired_callback_settle_the_original_operation_once() {
    let (f, h) = server().await;
    let clock = TestClock::new();
    let mut m = manager(
        &f,
        &Arc::new(SharedStore::default()),
        clock.clone(),
        StoreMode::CreateNew,
    );
    let request = m.begin_auth(AuthMode::Login).await.unwrap();
    let u = url::Url::parse(&request.authorization_url).unwrap();
    let state = u
        .query_pairs()
        .find(|(k, _)| k == "state")
        .unwrap()
        .1
        .into_owned();
    let callback = format!("cyberbus://callback?error=access_denied&state={state}");
    m.submit_complete_auth(request.operation_id, &callback)
        .unwrap();
    assert!(
        matches!(m.poll_ready(), Some(OperationReady::AuthFinished { operation_id, result: Err(Error::Cancelled) }) if operation_id == request.operation_id)
    );
    assert!(m.poll_ready().is_none());
    let request = m.begin_auth(AuthMode::Login).await.unwrap();
    clock.advance(600);
    assert_eq!(
        m.submit_complete_auth(request.operation_id, "cyberbus://callback"),
        Err(Error::DeadlineExceeded)
    );
    assert!(
        matches!(m.poll_ready(), Some(OperationReady::AuthFinished { operation_id, result: Err(Error::DeadlineExceeded) }) if operation_id == request.operation_id)
    );
    assert!(m.poll_ready().is_none());
    h.abort();
}

#[tokio::test]
async fn restore_discovery_cancel_and_late_budget_keep_original_owned_request() {
    let (f, h) = server().await;
    let clock = TestClock::new();
    let disk = Arc::new(SharedStore::default());
    let mut m = manager(&f, &disk, clock.clone(), StoreMode::CreateNew);
    login(&mut m, &f).await.unwrap();
    drop(m);
    let mut m = manager(&f, &disk, clock.clone(), StoreMode::Existing);
    let discovery_gate = Arc::new(tokio::sync::Semaphore::new(0));
    f.lock().unwrap().discovery_gate = Some(discovery_gate.clone());
    let restore = OperationId([92; 16]);
    m.submit_restore_auth(restore).unwrap();
    assert!(m.poll_ready().is_none());
    assert_eq!(
        m.operation_status(restore).unwrap().stage,
        OperationStage::Discovering
    );
    m.cancel_operation(restore).unwrap();
    assert!(
        matches!(m.poll_ready(), Some(OperationReady::AuthFinished { operation_id, result: Err(Error::Cancelled) }) if operation_id == restore)
    );
    assert_eq!(f.lock().unwrap().token_calls, 1);
    discovery_gate.add_permits(1);
    f.lock().unwrap().discovery_gate = None;
    let restore = OperationId([93; 16]);
    m.submit_restore_auth(restore).unwrap();
    assert!(
        matches!(next_ready(&mut m).await, OperationReady::AuthFinished { operation_id, result: Ok(_) } if operation_id == restore)
    );
    m.start_network().unwrap();
    clock.advance(100);
    let gate = Arc::new(tokio::sync::Semaphore::new(0));
    f.lock().unwrap().jwks_gate = Some(gate.clone());
    let id = m.submit_refresh().unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            assert!(m.poll_ready().is_none());
            if m.operation_status(id).unwrap().stage == OperationStage::Verifying {
                break;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await
    .unwrap();
    let old_deadline = m.snapshot().lease_deadline;
    clock.advance(31);
    assert!(m.poll_ready().is_none());
    assert!(m.operation_status(id).unwrap().budget_exceeded);
    assert_eq!(m.snapshot().last_error, Some(Error::UnknownOutcome));
    assert!(m.snapshot().refresh_grant_frozen);
    assert_eq!(m.snapshot().lease_deadline, old_deadline);
    assert_eq!(m.submit_refresh().unwrap_err(), Error::Conflict);
    gate.add_permits(1);
    assert!(
        matches!(next_ready(&mut m).await, OperationReady::AuthFinished { operation_id, result: Ok(_) } if operation_id == id)
    );
    assert_eq!(m.snapshot().lease_deadline, Some(Duration::from_secs(700)));
    assert!(m.poll_ready().is_none());
    assert_eq!(f.lock().unwrap().token_calls, 3);
    h.abort();
}

#[tokio::test]
async fn cancelled_new_login_does_not_replace_the_previous_accounts_grant() {
    let (f, h) = server().await;
    let mut m = manager(
        &f,
        &Arc::new(SharedStore::default()),
        TestClock::new(),
        StoreMode::CreateNew,
    );
    login(&mut m, &f).await.unwrap();
    let request = m.begin_auth(AuthMode::Login).await.unwrap();
    let callback = fixture_callback(&request, &f);
    let gate = Arc::new(tokio::sync::Semaphore::new(0));
    f.lock().unwrap().jwks_gate = Some(gate.clone());
    m.submit_complete_auth(request.operation_id, &callback)
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            assert!(m.poll_ready().is_none());
            if m.operation_status(request.operation_id).unwrap().stage == OperationStage::Verifying
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await
    .unwrap();
    m.cancel_auth(request.operation_id).unwrap();
    gate.add_permits(1);
    assert_eq!(m.settle_pending().await.unwrap_err(), Error::Cancelled);
    f.lock().unwrap().jwks_gate = None;
    m.refresh().await.unwrap();
    assert_eq!(f.lock().unwrap().seen_refresh, ["refresh-1"]);
    h.abort();
}
#[tokio::test]
async fn cold_cloud_logout_owns_discovery_within_cloud_budget() {
    let (f, h) = server().await;
    let disk = Arc::new(SharedStore::default());
    let clock = TestClock::new();
    let mut m = manager(&f, &disk, clock.clone(), StoreMode::CreateNew);
    login(&mut m, &f).await.unwrap();
    drop(m);
    let mut m = manager(&f, &disk, clock, StoreMode::Existing);
    let gate = Arc::new(tokio::sync::Semaphore::new(0));
    f.lock().unwrap().discovery_gate = Some(gate.clone());
    let id = m
        .submit_logout(LogoutPolicy::RevokeGrant, Duration::from_millis(10))
        .unwrap();
    assert_eq!(m.snapshot().phase, Phase::LoggedOut);
    assert!(m.snapshot().request_in_flight);
    assert!(
        matches!(next_ready(&mut m).await, OperationReady::LogoutFinished { operation_id, result: LogoutResult { local_closed: true, cloud_status: CloudLogout::UnknownOutcome, .. } } if operation_id == id)
    );
    assert!(!m.snapshot().refresh_supported);
    gate.add_permits(1);
    h.abort();
}

#[tokio::test]
async fn boot_is_fresh_per_sdk_and_network_run_without_rotating_identity_or_profile() {
    let (f, h) = server().await;
    let disk = Arc::new(SharedStore::default());
    let clock = TestClock::new();
    let mut m = manager(&f, &disk, clock.clone(), StoreMode::CreateNew);
    let constructed_boot = *m.identity().boot_id();
    let public = *m.identity().public_key();
    let device = *m.identity().device_id();
    m.commit_local_profile(0, b"stable-profile").unwrap();
    login(&mut m, &f).await.unwrap();
    let first_generation = m.start_network().unwrap();
    let first_boot = *m.identity().boot_id();
    assert_ne!(constructed_boot, first_boot);
    assert_eq!(m.start_network().unwrap(), first_generation);
    assert_eq!(*m.identity().boot_id(), first_boot);
    m.stop_network();
    assert_ne!(m.start_network().unwrap(), first_generation);
    assert_ne!(*m.identity().boot_id(), first_boot);
    assert_eq!(*m.identity().public_key(), public);
    assert_eq!(*m.identity().device_id(), device);
    assert_eq!(m.local_profile(), Some((1, b"stable-profile".to_vec())));
    let last_boot = *m.identity().boot_id();
    drop(m);
    let m = manager(&f, &disk, clock, StoreMode::Existing);
    assert_ne!(*m.identity().boot_id(), last_boot);
    assert_eq!(*m.identity().public_key(), public);
    assert_eq!(*m.identity().device_id(), device);
    assert_eq!(m.local_profile(), Some((1, b"stable-profile".to_vec())));
    h.abort();
}

#[tokio::test]
async fn close_owner_preserves_selected_grant_for_real_restore_and_logout_erases_it() {
    let (f, h) = server().await;
    let disk = Arc::new(SharedStore::default());
    let clock = TestClock::new();
    let mut m = manager(&f, &disk, clock.clone(), StoreMode::CreateNew);
    login(&mut m, &f).await.unwrap();
    m.start_network().unwrap();
    m.close_owner().unwrap();
    m.close_owner().unwrap();
    assert!(!m.snapshot().network_enabled);
    assert!(m.snapshot().lease_deadline.is_none());
    assert_eq!(m.start_network(), Err(Error::Cancelled));
    assert_eq!(
        m.submit_begin_auth(AuthMode::Login).unwrap_err(),
        Error::Cancelled
    );
    drop(m);
    let mut m = manager(&f, &disk, clock.clone(), StoreMode::Existing);
    assert!(m.snapshot().lease_deadline.is_none());
    m.restore_auth(OperationId([94; 16])).await.unwrap();
    assert!(!m.snapshot().network_enabled);
    m.start_network().unwrap();
    assert_eq!(f.lock().unwrap().seen_refresh, ["refresh-1"]);
    assert!(m.logout(LogoutPolicy::LocalOnly).await.local_closed);
    m.close_owner().unwrap();
    drop(m);
    let mut m = manager(&f, &disk, clock, StoreMode::Existing);
    assert_eq!(
        m.restore_auth(OperationId([95; 16])).await.unwrap_err(),
        Error::Unauthenticated
    );
    h.abort();
}
#[tokio::test]
async fn close_owner_keeps_late_refresh_rotation_frozen_and_owned() {
    let (f, h) = server().await;
    let disk = Arc::new(SharedStore::default());
    let clock = TestClock::new();
    let mut m = manager(&f, &disk, clock.clone(), StoreMode::CreateNew);
    login(&mut m, &f).await.unwrap();
    f.lock().unwrap().delay_ms = 80;
    let id = m.submit_refresh().unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        while f.lock().unwrap().token_calls < 2 {
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await
    .unwrap();
    m.close_owner().unwrap();
    assert!(
        matches!(m.poll_ready(), Some(OperationReady::AuthFinished { operation_id, result: Err(Error::Cancelled) }) if operation_id == id)
    );
    assert!(m.snapshot().request_in_flight);
    tokio::time::timeout(Duration::from_secs(2), async {
        while m.snapshot().request_in_flight {
            assert!(m.poll_ready().is_none());
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(f.lock().unwrap().token_calls, 2);
    drop(m);
    let blob = disk.blob.lock().unwrap();
    let vault: Value = serde_json::from_slice(blob.as_ref().unwrap()).unwrap();
    assert_eq!(vault["grant"]["refresh"], "refresh-2");
    assert_eq!(vault["grant"]["frozen"], true);
    drop(blob);
    let mut m = manager(&f, &disk, clock, StoreMode::Existing);
    assert_eq!(
        m.restore_auth(OperationId([96; 16])).await.unwrap_err(),
        Error::UnknownOutcome
    );
    h.abort();
}
