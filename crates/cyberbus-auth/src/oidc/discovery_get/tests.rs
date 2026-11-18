use super::*;
use crate::oidc::{AuthConfig, Oidc, Tokens};
use serde_json::json;
use std::{
    collections::{BTreeMap, VecDeque},
    sync::{Arc, Mutex},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::Semaphore,
};

enum Action {
    Document,
    Status(u16, Option<&'static str>),
    Body(Vec<u8>, Option<usize>),
    Hold(bool), // true: send headers and one body byte, then hold the response
}
struct Server {
    issuer: String,
    calls: Arc<Mutex<Vec<String>>>,
    entered: Arc<Semaphore>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Server {
    async fn new(actions: Vec<Action>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let issuer = format!("{origin}/oidc");
        let calls = Arc::new(Mutex::new(Vec::new()));
        let queue = Arc::new(Mutex::new(VecDeque::from(actions)));
        let entered = Arc::new(Semaphore::new(0));
        let (record, arrived) = (calls.clone(), entered.clone());
        let document = serde_json::to_vec(&json!({
            "issuer":issuer,"authorization_endpoint":format!("{issuer}/auth"),
            "token_endpoint":format!("{issuer}/token"),"jwks_uri":format!("{issuer}/jwks"),
            "response_types_supported":["code"],"code_challenge_methods_supported":["S256"],
            "id_token_signing_alg_values_supported":["ES384"]
        }))
        .unwrap();
        let task = tokio::spawn(async move {
            let mut tasks = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let (mut io, _) = accepted.unwrap();
                        let (record, arrived, queue, document) =
                            (record.clone(), arrived.clone(), queue.clone(), document.clone());
                        tasks.spawn(async move {
                            let mut head = Vec::new();
                            let mut byte = [0];
                            while !head.ends_with(b"\r\n\r\n") {
                                if io.read(&mut byte).await.unwrap_or(0) == 0 { return; }
                                head.push(byte[0]);
                                assert!(head.len() < 16384);
                            }
                            record.lock().unwrap().push(String::from_utf8(head).unwrap().lines().next().unwrap().to_owned());
                            arrived.add_permits(1);
                            let action = queue.lock().unwrap().pop_front().unwrap_or(Action::Document);
                            let (status, body, length, extra) = match action {
                                Action::Document => (200, document, None, String::new()),
                                Action::Status(status, retry) => (status, b"unsafe-body-marker".to_vec(), None,
                                    retry.map(|s|format!("Retry-After: {s}\r\n")).unwrap_or_default()),
                                Action::Body(body,length) => (200, body, length, String::new()),
                                Action::Hold(body) => {
                                    if body { let _ = io.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\nx").await; }
                                    let mut buffer = [0;1024];
                                    while io.read(&mut buffer).await.unwrap_or(0) != 0 {}
                                    return;
                                }
                            };
                            let header = format!("HTTP/1.1 {status} unsafe-reason-marker\r\nContent-Length: {}\r\nConnection: close\r\n{extra}\r\n",length.unwrap_or(body.len()));
                            let _ = io.write_all(header.as_bytes()).await;
                            let _ = io.write_all(&body).await;
                        });
                    }
                    Some(_) = tasks.join_next() => {}
                }
            }
        });
        Self {
            issuer,
            calls,
            entered,
            task,
        }
    }
    fn config(&self) -> AuthConfig {
        AuthConfig {
            issuer: self.issuer.clone(),
            client_id: "native".into(),
            resource: "https://resource.example.test".into(),
            product_id: "product".into(),
            redirect_uri: "http://127.0.0.1/callback".into(),
            native_clients: BTreeMap::from([("native".into(), "product".into())]),
            offline_access: true,
            persist_grant: false,
            test_http: true,
        }
    }
    fn count(&self) -> usize {
        self.calls.lock().unwrap().len()
    }
}
fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(120))
        .build()
        .unwrap()
}

#[tokio::test]
async fn discovery_recovers_each_allowed_transient_status_and_partial_body() {
    for status in [408, 429, 500, 502, 503, 504] {
        let server = Server::new(vec![Action::Status(status, None), Action::Document]).await;
        assert!(
            Oidc::discover(&server.config()).await.is_ok(),
            "status {status}"
        );
        assert_eq!(server.count(), 2);
        assert!(
            server
                .calls
                .lock()
                .unwrap()
                .iter()
                .all(|s| s.starts_with("GET "))
        );
    }
    let server = Server::new(vec![
        Action::Body(b"x".to_vec(), Some(100)),
        Action::Document,
    ])
    .await;
    assert!(Oidc::discover(&server.config()).await.is_ok());
    assert_eq!(server.count(), 2);
}

#[tokio::test]
async fn discovery_stops_after_three_sdk_attempts() {
    let server = Server::new(vec![
        Action::Status(503, None),
        Action::Status(500, None),
        Action::Status(504, None),
        Action::Document,
    ])
    .await;
    assert_eq!(
        Oidc::discover(&server.config()).await.err(),
        Some(Error::Unavailable)
    );
    assert_eq!(server.count(), 3);
}

#[tokio::test]
async fn discovery_retries_request_timeout_and_classifies_transient_connect_without_details() {
    let server = Server::new(vec![Action::Hold(false), Action::Document]).await;
    // Per-request fixture timeout produces a real reqwest timeout promptly; the
    // production client retains its original connect10/request120 settings.
    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_millis(100))
        .build()
        .unwrap();
    let records = Mutex::new(Vec::new());
    let began = Instant::now();
    let (_, attempt, _) = run(
        &http,
        &server.issuer,
        began,
        began + BUDGET,
        |a, c, s, b, d| records.lock().unwrap().push(line(a, c, s, b, d)),
    )
    .await
    .unwrap();
    assert_eq!(attempt, 2);
    assert_eq!(server.count(), 2);
    assert!(records.lock().unwrap()[0].contains("class=request_timeout"));

    let reserved = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = reserved.local_addr().unwrap();
    drop(reserved);
    let error = reqwest::Client::builder()
        .no_proxy()
        .build()
        .unwrap()
        .get(format!("http://{address}/unsafe-url-marker"))
        .send()
        .await
        .unwrap_err();
    let failure = Failure::transport(error, false);
    assert_eq!(failure.class, "connect_transport");
    assert!(failure.retry);
    assert_eq!(failure.error, Error::Unavailable);
    let error = client().get("://invalid").send().await.unwrap_err();
    let failure = Failure::transport(error, false);
    assert_eq!(failure.class, "configuration");
    assert!(!failure.retry);
}

#[tokio::test]
async fn discovery_does_not_retry_redirect_other_status_or_invalid_document() {
    for status in [301, 302, 307, 308, 400, 401, 403, 404, 409, 422, 501, 505] {
        let server = Server::new(vec![Action::Status(status, None), Action::Document]).await;
        assert_eq!(
            Oidc::discover(&server.config()).await.err(),
            Some(Error::Unavailable)
        );
        assert_eq!(server.count(), 1, "status {status}");
    }
    for body in [
        vec![],
        b"invalid-json".to_vec(),
        b"{\"issuer\":1,\"issuer\":2}".to_vec(),
        vec![b'x'; 262145],
    ] {
        let server = Server::new(vec![Action::Body(body, None), Action::Document]).await;
        assert_eq!(
            Oidc::discover(&server.config()).await.err(),
            Some(Error::InvalidClaims)
        );
        assert_eq!(server.count(), 1);
    }
    let server = Server::new(vec![
        Action::Body(b"{\"issuer\":\"wrong\"}".to_vec(), None),
        Action::Document,
    ])
    .await;
    assert_eq!(
        Oidc::discover(&server.config()).await.err(),
        Some(Error::Configuration)
    );
    assert_eq!(server.count(), 1);
    let mut invalid = server.config();
    invalid.native_clients.clear();
    assert_eq!(
        Oidc::discover(&invalid).await.err(),
        Some(Error::Configuration)
    );
    assert_eq!(
        server.count(),
        1,
        "invalid trusted config made a network request"
    );
}

#[tokio::test]
async fn discovery_absolute_budget_covers_headers_body_and_retry_after() {
    assert_eq!(BUDGET, Duration::from_secs(30));
    // Shorten only the supplied deadline to exercise the exact production loop
    // without spending 30 seconds per fixture; no test-only retry/timer logic.
    for action in [
        Action::Hold(false),
        Action::Hold(true),
        Action::Status(503, Some("60")),
    ] {
        let server = Server::new(vec![action, Action::Document]).await;
        let began = Instant::now();
        let records = Mutex::new(Vec::new());
        let result = run(
            &client(),
            &server.issuer,
            began,
            began + Duration::from_millis(150),
            |attempt, class, status, start, end| {
                records
                    .lock()
                    .unwrap()
                    .push(line(attempt, class, status, start, end))
            },
        )
        .await;
        assert_eq!(result.err(), Some(Error::Unavailable));
        assert!(began.elapsed() >= Duration::from_millis(150));
        assert!(began.elapsed() < Duration::from_secs(1));
        assert_eq!(server.count(), 1);
        assert!(
            records
                .lock()
                .unwrap()
                .last()
                .unwrap()
                .contains("class=budget_exhausted")
        );
    }
    // A retry's body wait gets the remainder of the original budget, never a
    // fresh budget starting after the first status/backoff.
    let server = Server::new(vec![Action::Status(503, None), Action::Hold(true)]).await;
    let began = Instant::now();
    assert_eq!(
        get(
            &client(),
            &server.issuer,
            began,
            began + Duration::from_millis(450)
        )
        .await
        .err(),
        Some(Error::Unavailable)
    );
    assert_eq!(server.count(), 2);
    assert!(began.elapsed() < Duration::from_millis(800));
}

#[tokio::test]
async fn dropping_discovery_future_stops_held_request_and_retry_backoff() {
    let server = Server::new(vec![Action::Hold(true), Action::Document]).await;
    let http = client();
    let began = Instant::now();
    let owner = Arc::new(());
    let retained = Arc::downgrade(&owner);
    let mut future = Box::pin(run(
        &http,
        &server.issuer,
        began,
        began + BUDGET,
        move |_, _, _, _, _| {
            let _ = &owner;
        },
    ));
    tokio::select! {
        _ = &mut future => panic!("held body unexpectedly completed"),
        permit = server.entered.acquire() => permit.unwrap().forget(),
    }
    drop(future);
    // The SDK future must release its owned state immediately, without a
    // detached retry worker. reqwest may independently drain/recycle sockets;
    // server-side EOF is not a reliable assertion of SDK future cancellation.
    assert!(retained.upgrade().is_none());
    assert!(
        tokio::time::timeout(Duration::from_millis(450), server.entered.acquire())
            .await
            .is_err()
    );
    assert_eq!(server.count(), 1);

    let server = Server::new(vec![Action::Status(503, None), Action::Document]).await;
    let observed = Semaphore::new(0);
    let mut future = Box::pin(run(
        &http,
        &server.issuer,
        began,
        began + BUDGET,
        |_, class, _, _, _| {
            assert_eq!(class, "http_status");
            observed.add_permits(1);
        },
    ));
    tokio::select! {
        _ = &mut future => panic!("retrying request unexpectedly completed"),
        permit = observed.acquire() => permit.unwrap().forget(),
    }
    drop(future);
    server.entered.acquire().await.unwrap().forget();
    // Longer than the first retry's 100..=300ms jitter. A detached retry would
    // produce a second real HTTP request and make this assertion fail.
    assert!(
        tokio::time::timeout(Duration::from_millis(450), server.entered.acquire())
            .await
            .is_err()
    );
    assert_eq!(server.count(), 1);
}

#[tokio::test]
async fn discovery_retry_policy_does_not_replay_grant_posts_or_jwks() {
    for grant in ["authorization_code", "refresh_token"] {
        for status in [429, 503] {
            let server = Server::new(vec![
                Action::Document,
                Action::Status(status, None),
                Action::Document,
            ])
            .await;
            let oidc = Oidc::discover(&server.config()).await.unwrap();
            let request = oauth2::http::Request::builder()
                .method("POST")
                .uri(format!("{}/token", server.issuer))
                .body(format!("grant_type={grant}").into_bytes())
                .unwrap();
            assert_eq!(oidc.send(request).await.err(), Some(Error::UnknownOutcome));
            assert_eq!(server.count(), 2);
            assert!(server.calls.lock().unwrap()[1].starts_with("POST "));
        }
    }
    let server = Server::new(vec![
        Action::Document,
        Action::Status(503, None),
        Action::Document,
    ])
    .await;
    let oidc = Oidc::discover(&server.config()).await.unwrap();
    let tokens = Tokens {
        access: "unused".into(),
        refresh: None,
        id: None,
    };
    assert_eq!(
        oidc.verify(&tokens, None, 0, None).await.err(),
        Some(Error::Unavailable)
    );
    assert_eq!(server.count(), 2, "JWKS inherited discovery retry policy");
}

#[tokio::test]
async fn discovery_diagnostics_only_contain_whitelisted_fields() {
    let server = Server::new(vec![Action::Status(503, None), Action::Document]).await;
    let began = Instant::now();
    let records = Mutex::new(Vec::new());
    get_with_records(
        &client(),
        &format!(
            "{}/unsafe-url-marker?token=unsafe-query-marker",
            server.issuer
        ),
        began,
        &records,
    )
    .await;
    let records = records.lock().unwrap();
    assert_eq!(records.len(), 1);
    let fields: Vec<_> = records[0].split_whitespace().collect();
    assert_eq!(fields[0], "CYBERBUS_AUTH_GET");
    assert_eq!(fields.len(), 7);
    assert_eq!(fields[1], "stage=discovery");
    assert_eq!(fields[2], "attempt=1");
    assert_eq!(fields[3], "class=http_status");
    assert_eq!(fields[4], "status=503");
    assert!(
        fields[5]
            .strip_prefix("elapsed_ms=")
            .unwrap()
            .parse::<u128>()
            .is_ok()
    );
    assert!(
        fields[6]
            .strip_prefix("remaining_ms=")
            .unwrap()
            .parse::<u128>()
            .is_ok()
    );
    assert!(!records[0].contains("unsafe"));
    assert!(!records[0].contains("://"));
}
async fn get_with_records(
    http: &reqwest::Client,
    url: &str,
    began: Instant,
    records: &Mutex<Vec<String>>,
) {
    assert!(
        run(http, url, began, began + BUDGET, |a, c, s, b, d| records
            .lock()
            .unwrap()
            .push(line(a, c, s, b, d)))
        .await
        .is_ok()
    );
}
