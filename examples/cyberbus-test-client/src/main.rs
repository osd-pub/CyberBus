//! Private JSONL harness for the real SDK. Never connect stdout to a public log:
//! AuthStarted contains the SDK-owned authorization URI.
use base64::{engine::general_purpose::STANDARD, Engine};
use cyberbus::{pb, Client, ClientConfig, StoreMode};
use cyberbus_auth::DevelopmentFileStore;
use prost::Message;
use prost_reflect::{DescriptorPool, DynamicMessage};
use serde_json::{json, Value};
use std::{
    path::PathBuf,
    sync::{Arc, OnceLock},
    time::Duration,
};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
type Output = Arc<tokio::sync::Mutex<tokio::io::Stdout>>;

fn pool() -> &'static DescriptorPool {
    static POOL: OnceLock<DescriptorPool> = OnceLock::new();
    POOL.get_or_init(|| {
        DescriptorPool::decode(cyberbus_protocol::FILE_DESCRIPTOR_SET)
            .expect("compiled descriptors")
    })
}
fn encode_json<T: Message>(name: &str, message: &T) -> Value {
    let descriptor = pool()
        .get_message_by_name(&format!("cyberbus.easytier.v1.{name}"))
        .unwrap();
    let dynamic = DynamicMessage::decode(descriptor, message.encode_to_vec().as_slice()).unwrap();
    serde_json::to_value(dynamic).unwrap()
}
fn command(value: &Value) -> Result<pb::SdkCommand, &'static str> {
    let descriptor = pool()
        .get_message_by_name("cyberbus.easytier.v1.SdkCommand")
        .unwrap();
    let text = value.to_string();
    let mut deserializer = serde_json::Deserializer::from_str(&text);
    let dynamic = DynamicMessage::deserialize(descriptor, &mut deserializer)
        .map_err(|_| "invalid protobuf JSON command")?;
    pb::SdkCommand::decode(dynamic.encode_to_vec().as_slice()).map_err(|_| "invalid command")
}
fn valid_json(name: &str, value: &Value) -> bool {
    let full = format!("cyberbus.easytier.v1.{name}");
    let descriptor = pool().get_message_by_name(&full).unwrap();
    let text = value.to_string();
    let mut deserializer = serde_json::Deserializer::from_str(&text);
    DynamicMessage::deserialize(descriptor, &mut deserializer)
        .ok()
        .is_some_and(|message| {
            cyberbus_protocol::validation::validate(&message.encode_to_vec(), &full).is_ok()
        })
}
async fn output(out: &Output, value: Value) -> Result<(), &'static str> {
    let mut bytes = serde_json::to_vec(&value).map_err(|_| "JSON serialization failed")?;
    bytes.push(b'\n');
    let mut writer = out.lock().await;
    writer
        .write_all(&bytes)
        .await
        .map_err(|_| "stdout closed")?;
    writer.flush().await.map_err(|_| "stdout closed")
}
fn describe() -> Value {
    let pool = pool();
    let mut shapes = serde_json::Map::new();
    for name in ["SdkCommand", "SdkResult", "SdkEvent"] {
        let descriptor = pool
            .get_message_by_name(&format!("cyberbus.easytier.v1.{name}"))
            .unwrap();
        shapes.insert(
            name.into(),
            json!(descriptor
                .oneofs()
                .flat_map(|o| o
                    .fields()
                    .map(|f| f.json_name().to_owned())
                    .collect::<Vec<_>>())
                .collect::<Vec<_>>()),
        );
    }
    json!({"protocol":"cyberbus-test-client/1", "shapes":shapes,
        "descriptorSet":STANDARD.encode(cyberbus_protocol::FILE_DESCRIPTOR_SET),
        "clientApi":["new","execute","execute_bytes","poll_event","take_event_receiver","on_resume"]})
}
#[tokio::main(worker_threads = 2)]
async fn main() {
    if let Err(error) = run().await {
        // Only fixed harness errors: no third-party diagnostic can leak OAuth material.
        eprintln!("test-client: {error}");
        std::process::exit(1);
    }
}
async fn run() -> Result<(), &'static str> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args == ["--relay"] {
        return relay().await;
    }
    if args == ["--describe"] {
        println!("{}", describe());
        return Ok(());
    }
    let mut config = None;
    let mut state = None;
    let mut polling = false;
    let mut store_mode = None;
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--config" => config = args.next().map(PathBuf::from),
            "--state-dir" => state = args.next().map(PathBuf::from),
            "--store-mode" => {
                if store_mode.is_some() { return Err("duplicate store mode"); }
                store_mode = Some(args.next().ok_or("missing store mode")?.as_str().to_owned());
            }
            "--events" => {
                polling = match args.next().map(String::as_str) {
                    Some("poll") => true,
                    Some("receiver") => false,
                    _ => return Err("invalid event mode"),
                }
            }
            _ => {
                return Err(
                    "expected --config FILE --state-dir PRIVATE_DIR [--store-mode open|provision|migrate] [--events receiver|poll]",
                )
            }
        }
    }
    let config = ClientConfig::from_json(
        &std::fs::read_to_string(config.ok_or("missing config")?)
            .map_err(|_| "cannot read public config")?,
    )
    .map_err(|_| "invalid public config")?;
    // Trusted caller intent, never inferred from a missing vault or a failed open.
    // The explicit environment option also works through existing Linux/SSH launch wrappers.
    let store_mode = match store_mode {
        Some(mode) => mode,
        None => match std::env::var("CYBERBUS_DEVELOPMENT_STORE_MODE") {
            Ok(mode) => mode,
            Err(std::env::VarError::NotPresent) => "open".to_owned(),
            Err(_) => return Err("invalid store mode"),
        },
    };
    if !matches!(store_mode.as_str(), "open" | "provision" | "migrate") {
        return Err("invalid store mode");
    }
    let state = state.ok_or("missing state directory")?;
    if store_mode == "provision" {
        std::fs::create_dir_all(&state).map_err(|_| "cannot create state directory")?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if store_mode == "provision" {
            std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700))
                .map_err(|_| "cannot restrict state directory")?;
        }
        let metadata =
            std::fs::symlink_metadata(&state).map_err(|_| "cannot open state directory")?;
        if !metadata.is_dir() || metadata.permissions().mode() & 0o077 != 0 {
            return Err("private state directory required");
        }
    }
    let path = state.join("identity");
    let (store, mode) = match store_mode.as_str() {
        "provision" => (
            DevelopmentFileStore::provision_new(path),
            StoreMode::CreateNew,
        ),
        "migrate" => (
            DevelopmentFileStore::migrate_existing(path),
            StoreMode::Existing,
        ),
        _ => (DevelopmentFileStore::open(path), StoreMode::Existing),
    };
    let store = store.map_err(|_| "cannot open identity store for requested mode")?;
    let client = Client::new(config, Box::new(store), mode)
        .await
        .map_err(|_| "SDK creation failed")?;
    let out = Arc::new(tokio::sync::Mutex::new(tokio::io::stdout()));
    output(&out, json!({"ready":true,"protocol":"cyberbus-test-client/1","events":if polling {"poll"} else {"receiver"}})).await?;
    let events = if polling {
        None
    } else {
        let mut rx = client
            .take_event_receiver()
            .await
            .ok_or("receiver unavailable")?;
        let out = out.clone();
        Some(tokio::spawn(async move {
            while let Some(event) = rx.recv().await {
                if output(&out, json!({"event":encode_json("SdkEvent", &event),"sdkValid":cyberbus_protocol::codec::encode(&event).is_ok()}))
                    .await
                    .is_err()
                {
                    return;
                }
            }
            let _ = output(&out, json!({"eventsClosed":true})).await;
        }))
    };
    let mut lines = tokio::io::BufReader::new(tokio::io::stdin()).lines();
    while let Some(line) = lines.next_line().await.map_err(|_| "stdin failed")? {
        if line.len() > 8 * 1024 * 1024 {
            return Err("request too large");
        }
        let request: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(_) => {
                output(&out, json!({"id":null,"ok":false,"error":"invalid JSON"})).await?;
                continue;
            }
        };
        let id = request.get("id").cloned().unwrap_or(Value::Null);
        let op = request["op"].as_str().unwrap_or("");
        let result: Result<Value, &'static str> = match op {
            "describe" => Ok(describe()),
            "execute" => match command(&request["command"]) {
                Ok(c) => Ok(encode_json("SdkResult", &client.execute(c).await)),
                Err(e) => Err(e),
            },
            "execute_bytes" => match request["bytes"]
                .as_str()
                .and_then(|s| STANDARD.decode(s).ok())
            {
                Some(bytes) => {
                    let bytes = client.execute_bytes(&bytes).await;
                    let result = pb::SdkResult::decode(bytes.as_slice())
                        .map_err(|_| "SDK result decoding failed")?;
                    Ok(
                        json!({"bytes":STANDARD.encode(bytes),"result":encode_json("SdkResult", &result)}),
                    )
                }
                None => Err("invalid base64 bytes"),
            },
            "on_resume" => Ok(match client.on_resume().await {
                Ok(()) => json!({}),
                Err(e) => json!({"error":encode_json("ProtocolError", &e)}),
            }),
            "take_event_receiver" => match client.take_event_receiver().await {
                None => Ok(json!({"taken":false})),
                Some(mut rx) => {
                    let out = out.clone();
                    tokio::spawn(async move {
                        while let Some(event) = rx.recv().await {
                            if output(&out, json!({"event":encode_json("SdkEvent", &event),"sdkValid":cyberbus_protocol::codec::encode(&event).is_ok()}))
                                .await
                                .is_err()
                            {
                                return;
                            }
                        }
                        let _ = output(&out, json!({"eventsClosed":true})).await;
                    });
                    Ok(json!({"taken":true}))
                }
            },
            "poll_event" => {
                let millis = request["timeoutMs"].as_u64().unwrap_or(0).min(30_000);
                Ok(
                    match client.poll_event(Duration::from_millis(millis)).await {
                        Some(event) => {
                            json!({"event":encode_json("SdkEvent", &event),"sdkValid":cyberbus_protocol::codec::encode(&event).is_ok()})
                        }
                        None => Value::Null,
                    },
                )
            }
            "close" | "shutdown" => Ok(encode_json(
                "SdkResult",
                &client
                    .execute(pb::SdkCommand {
                        command_id: vec![255; 16],
                        body: Some(pb::sdk_command::Body::SdkClose(pb::SdkClose {})),
                    })
                    .await,
            )),
            _ => Err("unknown operation"),
        };
        output(
            &out,
            match result {
                Ok(value) => {
                    let validity = if matches!(op, "execute" | "close" | "shutdown") {
                        Some(valid_json("SdkResult", &value))
                    } else if op == "execute_bytes" {
                        Some(valid_json("SdkResult", &value["result"]))
                    } else if op == "poll_event" && !value.is_null() {
                        Some(valid_json("SdkEvent", &value["event"]))
                    } else {
                        None
                    };
                    json!({"id":id,"ok":true,"result":value,"sdkValid":validity})
                }
                Err(error) => json!({"id":id,"ok":false,"error":error}),
            },
        )
        .await?;
        if op == "shutdown" {
            break;
        }
    }
    let closed = client
        .execute(pb::SdkCommand {
            command_id: vec![254; 16],
            body: Some(pb::sdk_command::Body::SdkClose(pb::SdkClose {})),
        })
        .await;
    if let Some(task) = events {
        let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
    }
    match closed.body {
        Some(pb::sdk_result::Body::SdkClosed(c)) if c.closed && c.cleanup_error.is_none() => Ok(()),
        Some(pb::sdk_result::Body::Error(e))
            if matches!(
                pb::ErrorCode::try_from(e.code),
                Ok(pb::ErrorCode::Closed | pb::ErrorCode::Cancelled)
            ) =>
        {
            Ok(())
        }
        _ => Err("SDK cleanup failed"),
    }
}

/// Standalone EasyTier bootstrap/relay. It has no account identity or SDK grant.
/// Foreign account traffic retains its SDK-derived network and Noise encryption.
async fn relay() -> Result<(), &'static str> {
    use easytier::instance::factory::create_native_dataplane_instance;
    use easytier_core::config::toml::{ConfigLoader, NetworkIdentity, TomlConfig};
    let config = TomlConfig::default();
    config.set_network_identity(NetworkIdentity {
        network_name: "cyberbus-local-test-relay".into(),
        network_secret: Some("public-test-relay-only".into()),
        network_secret_digest: None,
    });
    config.set_listeners(vec!["tcp://127.0.0.1:0".parse().unwrap()]);
    config.set_dhcp(false);
    let mut flags = config.get_flags();
    flags.no_tun = true;
    flags.use_smoltcp = true;
    flags.enable_ipv6 = false;
    flags.disable_upnp = true;
    flags.disable_p2p = true;
    flags.disable_udp_hole_punching = true;
    flags.disable_tcp_hole_punching = true;
    flags.relay_network_whitelist = "*".into();
    flags.encryption_algorithm = "aes-gcm".into();
    flags.multi_thread = true;
    flags.multi_thread_count = 2;
    config.set_flags(flags);
    config.set_stun_servers(Some(vec![]));
    config.set_stun_servers_v6(Some(vec![]));
    config.set_tcp_stun_servers(Some(vec![]));
    let native = create_native_dataplane_instance(config).map_err(|_| "relay creation failed")?;
    native.start().await.map_err(|_| "relay startup failed")?;
    let endpoint = native
        .running_listeners()
        .into_iter()
        .find(|u| u.scheme() == "tcp")
        .ok_or("relay TCP listener missing")?
        .to_string();
    let out = Arc::new(tokio::sync::Mutex::new(tokio::io::stdout()));
    output(&out, json!({"ready":true,"relayEndpoint":endpoint})).await?;
    let mut lines = tokio::io::BufReader::new(tokio::io::stdin()).lines();
    // One request or stdin EOF shuts down the relay; never detach an unowned daemon.
    let _ = lines.next_line().await;
    native.stop().await;
    output(&out, json!({"relayClosed":true})).await
}
