mod auth_adapter;
mod public_config;
mod rpc_adapter;
use cyberbus::{example, pb, Client, ClientConfig, StoreMode};
use cyberbus_auth::DevelopmentFileStore;
use cyberbus_protocol::noise;
use prost::Message;
use sha2::{Digest, Sha256};
use std::{
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};
const REQUEST: &str = "type.googleapis.com/cyberbus.example.v1.EchoRequest";
const RESPONSE: &str = "type.googleapis.com/cyberbus.example.v1.EchoReply";
static IDS: AtomicU64 = AtomicU64::new(1);
fn id() -> Vec<u8> {
    let mut bytes = noise::random_bytes::<16>().unwrap_or([1; 16]);
    bytes[..8].copy_from_slice(&IDS.fetch_add(1, Ordering::Relaxed).to_be_bytes());
    bytes.to_vec()
}
fn local_error(code: pb::ErrorCode, message: &str) -> pb::ProtocolError {
    pb::ProtocolError {
        code: code as i32,
        message: message.into(),
        ..Default::default()
    }
}
fn protocol_error(e: &pb::ProtocolError) -> String {
    format!(
        "{:?}: {}",
        pb::ErrorCode::try_from(e.code).unwrap_or(pb::ErrorCode::Internal),
        e.message
    )
}
async fn execute(
    client: &Client,
    body: pb::sdk_command::Body,
) -> Result<pb::sdk_result::Body, String> {
    let result = client
        .execute(pb::SdkCommand {
            command_id: id(),
            body: Some(body),
        })
        .await;
    match result.body {
        Some(pb::sdk_result::Body::Error(e)) => Err(protocol_error(&e)),
        Some(body) => Ok(body),
        None => Err("missing result".into()),
    }
}
fn fragment(type_url: &str, bytes: Vec<u8>) -> pb::PayloadFragment {
    pb::PayloadFragment {
        application_type_url: type_url.into(),
        encoding: pb::PayloadEncoding::ProtobufMessage as i32,
        total_size: bytes.len() as u32,
        offset: 0,
        protobuf_bytes: bytes,
    }
}
fn peer(raw: &str) -> Result<Vec<u8>, String> {
    let v = hex::decode(raw).map_err(|_| "device ID must be hexadecimal".to_string())?;
    if v.len() != 32 {
        return Err("device ID must have 64 hex characters".into());
    }
    Ok(v)
}
fn private_write(path: &Path, value: &[u8]) -> Result<(), String> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut f = options
        .open(path)
        .map_err(|_| "cannot create private authorization file".to_string())?;
    f.write_all(value)
        .and_then(|_| f.sync_all())
        .map_err(|_| "cannot write private authorization file".into())
}
async fn login(
    client: &Client,
    auth: &auth_adapter::Observer,
    register: bool,
    authorization_file: Option<&Path>,
    no_browser: bool,
) -> Result<(), String> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:18765")
        .await
        .map_err(|_| "loopback callback port unavailable".to_string())?;
    let result = execute(
        client,
        pb::sdk_command::Body::AuthStart(pb::AuthStart {
            intent: if register {
                pb::AuthIntent::Register
            } else {
                pb::AuthIntent::Login
            } as i32,
        }),
    )
    .await?;
    let pb::sdk_result::Body::AuthStarted(start) = result else {
        return Err("auth did not return browser operation".into());
    };
    let waiter = auth.register(&start.operation_id)?;
    let mut wrote_authorization_file = false;
    let callback_flow = async {
        if let Some(path) = authorization_file {
            private_write(path, start.authorization_uri.as_bytes())?;
            wrote_authorization_file = true;
            println!("AUTH_BROWSER_READY private authorization file saved");
        }
        if !no_browser {
            #[cfg(target_os = "macos")]
            let mut browser = tokio::process::Command::new("open");
            #[cfg(target_os = "linux")]
            let mut browser = tokio::process::Command::new("xdg-open");
            #[cfg(target_os = "windows")]
            let mut browser = {
                let mut c = tokio::process::Command::new("rundll32");
                c.arg("url.dll,FileProtocolHandler");
                c
            };
            browser
                .arg(&start.authorization_uri)
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .map_err(|_| "cannot launch system browser".to_string())?;
            println!("Complete authentication in the system browser");
        }
        let callback = async {
            loop {
                let (mut stream, _) = listener
                    .accept()
                    .await
                    .map_err(|_| "loopback accept failed".to_string())?;
                let mut bytes = vec![0; 16384];
                let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut bytes))
                    .await
                    .map_err(|_| "callback request timed out".to_string())?
                    .map_err(|_| "callback read failed".to_string())?;
                let first = std::str::from_utf8(&bytes[..n])
                    .ok()
                    .and_then(|s| s.lines().next())
                    .unwrap_or("");
                let mut fields = first.split_whitespace();
                let method = fields.next();
                let path = fields.next().unwrap_or("");
                if method != Some("GET") || !path.starts_with("/callback?") || path.len() > 15000 {
                    let _ = stream
                    .write_all(
                        b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    )
                    .await;
                    continue;
                }
                let response = b"Authentication received. You may close this browser window.";
                let header=format!("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",response.len());
                let _ = stream.write_all(header.as_bytes()).await;
                let _ = stream.write_all(response).await;
                return Ok::<_, String>(format!("http://127.0.0.1:18765{path}"));
            }
        };
        let callback = callback.await?;
        execute(
            client,
            pb::sdk_command::Body::AuthCallback(pb::AuthCallback {
                operation_id: start.operation_id.clone(),
                callback_uri: callback,
            }),
        )
        .await?;
        Ok(())
    };
    let result = tokio::time::timeout(
        Duration::from_secs(600),
        auth_adapter::finish(waiter, callback_flow),
    )
    .await
    .unwrap_or_else(|_| Err("DeadlineExceeded: login timed out".into()));
    if wrote_authorization_file {
        if let Some(path) = authorization_file {
            let _ = std::fs::remove_file(path);
        }
    }
    if result.is_err() {
        // Reclaim a still-pending SDK operation after browser/local timeout errors.
        // Its cleanup result cannot turn the original login error into success.
        let _ = execute(
            client,
            pb::sdk_command::Body::AuthCancel(pb::AuthCancel {
                operation_id: start.operation_id,
            }),
        )
        .await;
    }
    result?;
    println!("LOGIN_COMPLETE");
    Ok(())
}
async fn set_name(
    client: &Client,
    name: String,
    revision: &mut u64,
    public: &public_config::Profile,
) -> Result<(), String> {
    let p = pb::PublicProfile {
        device_name: name,
        public_config: Some(prost_types::Any {
            type_url: "type.googleapis.com/cyberbus.example.v1.PublicConfig".into(),
            value: example::PublicConfig {
                application_version: "0.2.0".into(),
            }
            .encode_to_vec(),
        }),
        config_semantic_version: "1.0.0".into(),
        capabilities: vec![],
        config_revision: 0,
    };
    if let pb::sdk_result::Body::PublicProfile(p) = execute(
        client,
        pb::sdk_command::Body::UpdatePublicProfile(pb::UpdatePublicProfile {
            profile: Some(p),
            expected_revision: *revision,
            update_mask: Some(prost_types::FieldMask {
                paths: vec![
                    "device_name".into(),
                    "public_config".into(),
                    "config_semantic_version".into(),
                ],
            }),
        }),
    )
    .await?
    {
        public_config::accept(p, public, revision)?;
    } else {
        return Err("profile update did not return public profile".into());
    }
    Ok(())
}
async fn register(
    client: &Client,
    rpc: &rpc_adapter::Adapter,
    public: &public_config::Profile,
) -> Result<u64, String> {
    let mut revision = 0;
    for (method, streaming, request_type, response_type) in [
        (
            "cyberbus.example.v1.Echo/Unary",
            pb::RpcStreaming::Unary,
            REQUEST,
            RESPONSE,
        ),
        (
            "cyberbus.example.v1.Echo/Chat",
            pb::RpcStreaming::Bidi,
            REQUEST,
            RESPONSE,
        ),
        (
            public_config::METHOD,
            pb::RpcStreaming::Unary,
            public_config::REQUEST,
            public_config::RESPONSE,
        ),
    ] {
        let handler_id = id();
        if method == public_config::METHOD {
            rpc.register_public_config(handler_id.clone(), public.clone());
        } else {
            rpc.register_echo(handler_id.clone());
        }
        let result = execute(
            client,
            pb::sdk_command::Body::RegisterHandler(pb::RegisterHandler {
                handler_id,
                capability: Some(pb::Capability {
                    method_id: method.into(),
                    request_type_url: request_type.into(),
                    response_type_url: response_type.into(),
                    streaming: streaming as i32,
                    semantic_version: "1.0.0".into(),
                    descriptor_digest: Sha256::digest(cyberbus_protocol::FILE_DESCRIPTOR_SET)
                        .to_vec(),
                }),
                descriptor_set: cyberbus_protocol::FILE_DESCRIPTOR_SET.to_vec(),
            }),
        )
        .await?;
        if let pb::sdk_result::Body::PublicProfile(p) = result {
            public_config::accept(p, public, &mut revision)?;
        } else {
            return Err("handler registration did not return public profile".into());
        }
    }
    Ok(revision)
}
async fn events(
    client: Client,
    mut rx: cyberbus::EventReceiver,
    devices: Arc<tokio::sync::Mutex<Vec<pb::DeviceSnapshot>>>,
    rpc: rpc_adapter::Adapter,
    auth: auth_adapter::Observer,
) {
    use pb::sdk_event::Body as E;
    while let Some(event) = rx.recv().await {
        match event.body {
            Some(E::Auth(a)) => {
                auth.event(&a);
                println!(
                "AUTH {:?} revision={} reauth={} reason={} refresh={} lease_expires_at={} validated_at={}",
                pb::AuthPhase::try_from(a.phase).unwrap_or(pb::AuthPhase::Unspecified),
                a.state_revision,
                a.reauth_required,
                a.reason,
                a.refresh_supported,
                a.validation_lease_expires_at.map(|t|t.seconds).unwrap_or(0),
                a.last_online_validation_at.map(|t|t.seconds).unwrap_or(0)
                );
            }
            Some(E::Network(n)) => {
                println!("NETWORK running={} reachable={}", n.running, n.reachable)
            }
            Some(E::Devices(d)) => {
                let mut view = devices.lock().await;
                match d.body {
                    Some(pb::devices_event::Body::Snapshot(s)) => *view = s.devices,
                    Some(pb::devices_event::Body::Reset(r)) => {
                        *view = r.snapshot.map(|s| s.devices).unwrap_or_default()
                    }
                    Some(pb::devices_event::Body::Added(a)) => {
                        if let Some(d) = a.device {
                            println!(
                                "DEVICE_ADDED {} {}",
                                hex::encode(&d.device_id),
                                d.profile
                                    .as_ref()
                                    .map(|p| p.device_name.as_str())
                                    .unwrap_or("")
                            );
                            view.retain(|v| v.device_id != d.device_id);
                            view.push(d);
                        }
                    }
                    Some(pb::devices_event::Body::Updated(u)) => {
                        if let Some(d) = u.device {
                            view.retain(|v| v.device_id != d.device_id);
                            view.push(d);
                        }
                    }
                    Some(pb::devices_event::Body::Removed(r)) => {
                        view.retain(|v| v.device_id != r.device_id)
                    }
                    _ => {}
                }
            }
            Some(E::DevicesQuery(q)) => {
                if let Some(pb::devices_query_result::Result::Snapshot(s)) = q.result {
                    for d in s.devices {
                        println!(
                            "DEVICE {} local={} online={} name={}",
                            hex::encode(d.device_id),
                            d.is_local,
                            d.presence == 1,
                            d.profile.map(|p| p.device_name).unwrap_or_default()
                        );
                    }
                }
            }
            Some(E::RefreshDevices(r)) => println!(
                "REFRESH verified={} attempted={} partial={}",
                r.verified, r.attempted, r.partial
            ),
            Some(E::DataReceived(d)) => {
                if let Some(m) = d.message {
                    let f = m.fragment.as_ref();
                    let text = f
                        .and_then(|f| {
                            example::EchoRequest::decode(f.protobuf_bytes.as_slice()).ok()
                        })
                        .map(|e| e.text);
                    if let Some(text) = text {
                        println!("RECEIVED {} {}", hex::encode(&d.peer_device_id), text);
                        let _ = execute(
                            &client,
                            pb::sdk_command::Body::CompleteData(pb::CompleteData {
                                peer_device_id: d.peer_device_id,
                                message_id: m.message_id,
                                result: Some(pb::complete_data::Result::Stage(
                                    pb::AckStage::Processed as i32,
                                )),
                            }),
                        )
                        .await;
                    }
                }
            }
            Some(E::DataStatus(s)) => match s.result {
                Some(pb::data_status::Result::Stage(a)) => println!(
                    "ACK {} {:?}",
                    hex::encode(s.message_id),
                    pb::AckStage::try_from(a).unwrap_or(pb::AckStage::Unspecified)
                ),
                Some(pb::data_status::Result::Error(e)) => {
                    println!("DATA_ERROR {}", protocol_error(&e))
                }
                _ => {}
            },
            Some(E::Rpc(r)) => rpc.event(&client, r).await,
            Some(E::DeviceBlockChanged(b)) => {
                if let Some(s) = b.state {
                    println!(
                        "BLOCK {} blocked={} persisted={}",
                        hex::encode(s.device_id),
                        s.blocked,
                        s.persisted_blocked
                    );
                }
            }
            Some(E::Descriptor(d)) => println!(
                "SCHEMA {} bytes={}",
                hex::encode(d.digest),
                match d.result {
                    Some(pb::descriptor_result::Result::DescriptorSet(v)) => v.len(),
                    _ => 0,
                }
            ),
            _ => {}
        }
    }
    auth.close();
}
#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("ERROR {e}");
        std::process::exit(1);
    }
}
async fn run() -> Result<(), String> {
    let mut config_path = None;
    let mut store_path = None;
    let mut create = false;
    let mut migrate = false;
    let mut authorization_file = None;
    let mut no_browser = false;
    let mut name = "CyberBus CLI".to_string();
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--config" => config_path = args.next().map(PathBuf::from),
            "--store" => store_path = args.next().map(PathBuf::from),
            "--create-store" => create = true,
            "--migrate-store" => migrate = true,
            "--authorization-file" => authorization_file = args.next().map(PathBuf::from),
            "--no-browser" => no_browser = true,
            "--name" => name = args.next().ok_or("missing name")?,
            "--help" => {
                println!("cyberbus-cli --config public.json --store private/state.json [--create-store | --migrate-store] [--name NAME] [--no-browser --authorization-file private/url]\nCommands: login register name start stop devices refresh send rpc stream rpc-large stream-large rpc-cancel rpc-deadline config <device-id|@peer> schema block unblock auth logout sleep wait-devices quit");
                return Ok(());
            }
            _ => return Err("unknown startup option".into()),
        }
    }
    let config = ClientConfig::from_json(
        &std::fs::read_to_string(config_path.ok_or("--config is required")?)
            .map_err(|_| "cannot read public config")?,
    )
    .map_err(|e| protocol_error(&e))?;
    if config.redirect_uri != "http://127.0.0.1:18765/callback" {
        return Err("desktop requires registered loopback redirect".into());
    }
    if create && migrate {
        return Err("--create-store and --migrate-store are mutually exclusive".into());
    }
    let store_path = store_path.ok_or("--store is required")?;
    let store = if create {
        DevelopmentFileStore::provision_new(&store_path)
    } else if migrate {
        DevelopmentFileStore::migrate_existing(&store_path)
    } else {
        DevelopmentFileStore::open(&store_path)
    }
    .map_err(|e| e.to_string())?;
    let client = Client::new(
        config,
        Box::new(store),
        if create {
            StoreMode::CreateNew
        } else {
            StoreMode::Existing
        },
    )
    .await
    .map_err(|e| protocol_error(&e))?;
    execute(
        &client,
        pb::sdk_command::Body::WatchDevices(pb::WatchDevices { watch_id: id() }),
    )
    .await?;
    let first = client
        .poll_event(Duration::from_secs(2))
        .await
        .ok_or("initial self snapshot missing")?;
    let initial = match first.body {
        Some(pb::sdk_event::Body::Devices(d)) => match d.body {
            Some(pb::devices_event::Body::Snapshot(s)) => s.devices,
            _ => return Err("initial snapshot missing".into()),
        },
        _ => return Err("initial snapshot missing".into()),
    };
    let mut revision = initial
        .iter()
        .find(|d| d.is_local)
        .and_then(|d| d.profile.as_ref())
        .map(|p| p.config_revision)
        .unwrap_or(0);
    let devices = Arc::new(tokio::sync::Mutex::new(initial));
    let rpc = rpc_adapter::Adapter::default();
    let auth = auth_adapter::Observer::default();
    let event_task = tokio::spawn(events(
        client.clone(),
        client.take_event_receiver().await.unwrap(),
        devices.clone(),
        rpc.clone(),
        auth.clone(),
    ));
    let public = public_config::Profile::default();
    set_name(&client, name, &mut revision, &public).await?;
    revision = register(&client, &rpc, &public).await?;
    execute(
        &client,
        pb::sdk_command::Body::SubscribeData(pb::SubscribeData {
            subscription_id: id(),
            type_urls: vec![REQUEST.into(), RESPONSE.into()],
        }),
    )
    .await?;
    println!("READY development file identity; OAuth grants stay in memory");
    let mut input = tokio::io::BufReader::new(tokio::io::stdin()).lines();
    let mut command_failed = false;
    while let Some(line) = input.next_line().await.map_err(|_| "stdin failed")? {
        let mut words = line.splitn(2, ' ');
        let cmd = words.next().unwrap_or("");
        let rest = words.next().unwrap_or("").trim();
        let result: Result<(), String> = async {
            match cmd {
                "" => {}
                "login" | "register" => {
                    login(
                        &client,
                        &auth,
                        cmd == "register",
                        authorization_file.as_deref(),
                        no_browser,
                    )
                    .await?
                }
                "name" => set_name(&client, rest.to_owned(), &mut revision, &public).await?,
                "start" => {
                    execute(
                        &client,
                        pb::sdk_command::Body::NetworkStart(pb::NetworkStart {
                            private_config: None,
                        }),
                    )
                    .await?;
                }
                "stop" => {
                    execute(
                        &client,
                        pb::sdk_command::Body::NetworkStop(pb::NetworkStop {}),
                    )
                    .await?;
                }
                "devices" => {
                    execute(
                        &client,
                        pb::sdk_command::Body::GetDevices(pb::GetDevices { query_id: id() }),
                    )
                    .await?;
                }
                "refresh" => {
                    execute(
                        &client,
                        pb::sdk_command::Body::RefreshDevices(pb::RefreshDevices {
                            query_id: id(),
                            budget: None,
                        }),
                    )
                    .await?;
                }
                "auth" => {
                    if let pb::sdk_result::Body::AuthState(a) = execute(
                        &client,
                        pb::sdk_command::Body::GetAuthState(pb::GetAuthState {}),
                    )
                    .await?
                    {
                        println!(
                            "AUTH_STATE phase={} revision={} refresh={} reauth={} lease_expires_at={} validated_at={}",
                            a.phase, a.state_revision, a.refresh_supported, a.reauth_required,
                            a.validation_lease_expires_at.map(|t|t.seconds).unwrap_or(0),
                            a.last_online_validation_at.map(|t|t.seconds).unwrap_or(0)
                        );
                    }
                }
                "block" | "unblock" => {
                    let peer_device_id = peer(rest)?;
                    execute(
                        &client,
                        if cmd == "block" {
                            pb::sdk_command::Body::BlockDevice(pb::BlockDevice { peer_device_id })
                        } else {
                            pb::sdk_command::Body::UnblockDevice(pb::UnblockDevice {
                                peer_device_id,
                            })
                        },
                    )
                    .await?;
                }
                "logout" => {
                    execute(
                        &client,
                        pb::sdk_command::Body::AuthLogout(pb::AuthLogout {
                            cloud_policy: Some(1),
                            cloud_budget: None,
                        }),
                    )
                    .await?;
                }
                "sleep" => {
                    tokio::time::sleep(Duration::from_millis(
                        rest.parse().map_err(|_| "sleep takes milliseconds")?,
                    ))
                    .await
                }
                "wait-devices" => {
                    let count: usize = rest
                        .parse()
                        .map_err(|_| "wait-devices takes total device count")?;
                    tokio::time::timeout(Duration::from_secs(40), async {
                        loop {
                            if devices.lock().await.len() >= count {
                                break;
                            }
                            tokio::time::sleep(Duration::from_millis(100)).await;
                        }
                    })
                    .await
                    .map_err(|_| "authenticated device discovery timed out")?;
                }
                "send" | "rpc" | "stream" | "rpc-large" | "stream-large" | "rpc-cancel" | "rpc-deadline" | "config" => {
                    let mut v = rest.splitn(2, ' ');
                    let raw = v.next().unwrap_or("");
                    let text = v.next().unwrap_or("");
                    let peer_device_id = if raw == "@peer" {
                        devices
                            .lock()
                            .await
                            .iter()
                            .find(|d| !d.is_local)
                            .map(|d| d.device_id.clone())
                            .ok_or("no authenticated peer")?
                    } else {
                        peer(raw)?
                    };
                    if cmd == "config" {
                        if !text.is_empty() { return Err("config takes one device ID or @peer".into()); }
                        rpc.public_config(&client, peer_device_id).await?;
                    } else if cmd == "send" {
                        let message = pb::DataMessage {
                            message_id: id(),
                            in_reply_to: vec![],
                            requested_ack: pb::AckStage::Processed as i32,
                            timeout: Some(prost_types::Duration {
                                seconds: 30,
                                nanos: 0,
                            }),
                            fragment: Some(fragment(
                                REQUEST,
                                example::EchoRequest { text: text.into() }.encode_to_vec(),
                            )),
                        };
                        execute(
                            &client,
                            pb::sdk_command::Body::Send(pb::Send {
                                peer_device_id,
                                message: Some(message),
                            }),
                        )
                        .await?;
                    } else {
                        if matches!(cmd,"rpc-cancel"|"rpc-deadline") {
                            rpc.cancellation(&client,peer_device_id,cmd=="rpc-deadline").await?;
                        } else {
                            rpc.echo(&client,peer_device_id,text.into(),matches!(cmd,"stream"|"stream-large"),matches!(cmd,"rpc-large"|"stream-large")).await?;
                        }
                    }
                }
                "schema" => {
                    let peer_device_id = peer(rest)?;
                    execute(
                        &client,
                        pb::sdk_command::Body::PullDescriptor(pb::PullDescriptor {
                            query_id: id(),
                            peer_device_id,
                            digest: Sha256::digest(cyberbus_protocol::FILE_DESCRIPTOR_SET).to_vec(),
                            timeout: Some(prost_types::Duration {
                                seconds: 30,
                                nanos: 0,
                            }),
                        }),
                    )
                    .await?;
                }
                "quit" => {}
                _ => return Err("unknown command".into()),
            }
            Ok(())
        }
        .await;
        if let Err(e) = result {
            command_failed = true;
            eprintln!("ERROR {e}");
        } else {
            println!("OK {cmd}");
        }
        if cmd == "quit" {
            break;
        }
    }
    let close_result =
        match execute(&client, pb::sdk_command::Body::SdkClose(pb::SdkClose {})).await {
            Ok(pb::sdk_result::Body::SdkClosed(closed)) => match closed.cleanup_error {
                Some(e) => Err(format!("SDK cleanup failed: {}", protocol_error(&e))),
                None if closed.closed => Ok(()),
                None => Err("SDK did not close".into()),
            },
            Ok(_) => Err("unexpected SDK close result".into()),
            Err(e) => Err(format!("SDK close failed: {e}")),
        };
    // Drain events even when close reports a cleanup failure.
    let join_result = event_task
        .await
        .map_err(|e| format!("event task failed: {e}"));
    close_result?;
    join_result?;
    if command_failed || rpc.failed() {
        Err("one or more commands or background RPC cancellations failed".into())
    } else {
        Ok(())
    }
}
