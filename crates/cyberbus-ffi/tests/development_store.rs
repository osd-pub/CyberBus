//! Actual C entry-point coverage. No OAuth, tokens, or network are supplied by this test.
use cyberbus::{pb, ClientConfig};
use cyberbus_ffi::*;
use prost::Message;
use std::{
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

type Create = unsafe extern "C" fn(*const u8, usize, *const u8, usize) -> CyberbusResponse;
fn config() -> Vec<u8> {
    serde_json::json!({"issuer":"https://example.test/oidc","client_id":"native",
        "resource":"https://resource.example.test","product_id":"product",
        "native_clients":{"native":"product"},"redirect_uri":"cyberbus://callback",
        "bootstrap_peers":[],"offline_access":true,"enable_p2p":false})
    .to_string()
    .into_bytes()
}
fn take(response: CyberbusResponse) -> Vec<u8> {
    let bytes = if response.buffer.len == 0 {
        vec![]
    } else {
        unsafe { std::slice::from_raw_parts(response.buffer.data, response.buffer.len) }.to_vec()
    };
    assert_eq!(cyberbus_buffer_free(response.buffer), CYBERBUS_OK);
    bytes
}
fn call(create: Create, config: &[u8], path: &Path) -> CyberbusResponse {
    let path = path.to_str().unwrap().as_bytes();
    unsafe { create(config.as_ptr(), config.len(), path.as_ptr(), path.len()) }
}
fn rejected(create: Create, config: &[u8], path: &Path) {
    let response = call(create, config, path);
    assert_eq!(response.status, CYBERBUS_ERROR);
    assert_eq!(response.handle, 0);
    let error = pb::ProtocolError::decode(take(response).as_slice()).unwrap();
    assert_ne!(error.code, 0);
}
fn created(create: Create, config: &[u8], path: &Path) -> u64 {
    let response = call(create, config, path);
    assert_eq!(response.status, CYBERBUS_OK);
    let handle = response.handle;
    assert_ne!(handle, 0);
    take(response);
    handle
}
fn reopen(config: &[u8], path: &Path) -> u64 {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let response = call(cyberbus_create_development, config, path);
        let status = response.status;
        let handle = response.handle;
        take(response);
        if status == CYBERBUS_OK {
            return handle;
        }
        assert!(
            Instant::now() < deadline,
            "installed store did not release its lock"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}
fn close(handle: u64) {
    let response = cyberbus_close(handle);
    assert_eq!(response.status, CYBERBUS_OK);
    take(response);
}
fn identity(handle: u64) -> Vec<u8> {
    let bytes = pb::SdkCommand {
        command_id: vec![51; 16],
        body: Some(pb::sdk_command::Body::WatchDevices(pb::WatchDevices {
            watch_id: vec![52; 16],
        })),
    }
    .encode_to_vec();
    let response = unsafe { cyberbus_execute(handle, bytes.as_ptr(), bytes.len()) };
    assert_eq!(response.status, CYBERBUS_OK);
    let result = pb::SdkResult::decode(take(response).as_slice()).unwrap();
    assert!(matches!(result.body, Some(pb::sdk_result::Body::Ok(_))));
    let response = cyberbus_poll(handle, 2000);
    assert_eq!(response.status, CYBERBUS_OK);
    let event = pb::SdkEvent::decode(take(response).as_slice()).unwrap();
    let Some(pb::sdk_event::Body::Devices(devices)) = event.body else {
        panic!("watch snapshot missing");
    };
    let Some(pb::devices_event::Body::Snapshot(snapshot)) = devices.body else {
        panic!("snapshot missing");
    };
    assert_eq!(snapshot.devices.len(), 1);
    assert!(snapshot.devices[0].is_local);
    snapshot.devices[0].device_id.clone()
}
struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let seq = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "cyberbus-dev-abi-{}-{}-{seq}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&path).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        Self(path)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn explicit_c_provision_reopen_and_loss_fail_closed_without_identity_reset() {
    let config = config();
    ClientConfig::from_json(std::str::from_utf8(&config).unwrap()).unwrap();
    let dir = Directory::new();
    let path = dir.0.join("identity.json");
    rejected(cyberbus_create_development, &config, &path);
    assert!(!path.exists());
    assert!(!path.with_extension("auth-install").exists());
    let handle = created(cyberbus_create_development_new, &config, &path);
    let first = identity(handle);
    close(handle);
    let handle = reopen(&config, &path);
    assert_eq!(identity(handle), first);
    close(handle);
    let handle = reopen(&config, &path); // wait for the prior actor before examining disk
    close(handle);
    let deadline = Instant::now() + Duration::from_secs(3);
    // OS lock release is asynchronous; acquire the same store, never reprovision it.
    loop {
        if cyberbus_auth::DevelopmentFileStore::open(&path).is_ok() {
            break;
        }
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(10));
    }
    rejected(cyberbus_create_development_new, &config, &path);
    std::fs::remove_file(&path).unwrap();
    for create in [
        cyberbus_create_development as Create,
        cyberbus_create_development_new,
        cyberbus_create_development_migrate,
    ] {
        rejected(create, &config, &path);
        assert!(
            !path.exists(),
            "deleted installed vault was silently recreated"
        );
    }
}
#[test]
fn explicit_c_legacy_migration_preserves_identity_and_missing_marker_never_opens() {
    let config = config();
    let dir = Directory::new();
    let path = dir.0.join("identity.json");
    let handle = created(cyberbus_create_development_new, &config, &path);
    let first = identity(handle);
    close(handle);
    let handle = reopen(&config, &path);
    close(handle);
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if cyberbus_auth::DevelopmentFileStore::open(&path).is_ok() {
            break;
        }
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(10));
    }
    let before = std::fs::read(&path).unwrap();
    std::fs::remove_file(path.with_extension("auth-install")).unwrap();
    rejected(cyberbus_create_development, &config, &path);
    rejected(cyberbus_create_development_new, &config, &path);
    assert!(
        std::fs::read(&path).unwrap() == before,
        "legacy vault changed before explicit migration"
    );
    let handle = created(cyberbus_create_development_migrate, &config, &path);
    assert_eq!(identity(handle), first);
    close(handle);
    let handle = reopen(&config, &path);
    assert_eq!(identity(handle), first);
    close(handle);
}
#[test]
fn invalid_public_config_does_not_start_a_trusted_installation() {
    let dir = Directory::new();
    let path = dir.0.join("identity.json");
    let response = call(cyberbus_create_development_new, b"{}", &path);
    assert_ne!(response.status, CYBERBUS_OK);
    assert_eq!(response.handle, 0);
    take(response);
    assert!(!path.exists());
    assert!(!path.with_extension("auth-install").exists());
}
