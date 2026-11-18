use cyberbus::{pb, ClientConfig};
use cyberbus_ffi::*;
use prost::Message;
use std::{
    ffi::c_void,
    ptr,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};

// Only the ABI test callback is volatile. Shipped sample always uses its development file store.
struct TestStore {
    blob: Option<Vec<u8>>,
    destroyed: Arc<AtomicUsize>,
    fail_load: bool,
    fail_save: bool,
}
unsafe extern "C" fn load(context: *mut c_void, bytes: *mut *const u8, len: *mut usize) -> i32 {
    let store = unsafe { &*(context as *const TestStore) };
    if store.fail_load {
        return -1;
    }
    if let Some(blob) = &store.blob {
        unsafe {
            *bytes = blob.as_ptr();
            *len = blob.len();
        }
        0
    } else {
        1
    }
}
unsafe extern "C" fn save(context: *mut c_void, bytes: *const u8, len: usize) -> i32 {
    let store = unsafe { &mut *(context as *mut TestStore) };
    if store.fail_save {
        return -1;
    }
    store.blob = Some(unsafe { std::slice::from_raw_parts(bytes, len) }.to_vec());
    0
}
unsafe extern "C" fn release(_: *mut c_void, _: *const u8, _: usize) {}
unsafe extern "C" fn destroy(context: *mut c_void) {
    let store = unsafe { Box::from_raw(context as *mut TestStore) };
    store.destroyed.fetch_add(1, Ordering::SeqCst);
}
fn callbacks(
    blob: Option<Vec<u8>>,
    fail_load: bool,
    fail_save: bool,
) -> (CyberbusStore, Arc<AtomicUsize>) {
    let destroyed = Arc::new(AtomicUsize::new(0));
    (
        CyberbusStore {
            context: Box::into_raw(Box::new(TestStore {
                blob,
                destroyed: destroyed.clone(),
                fail_load,
                fail_save,
            })) as *mut c_void,
            load: Some(load),
            replace: Some(save),
            release: Some(release),
            destroy: Some(destroy),
        },
        destroyed,
    )
}
fn config() -> Vec<u8> {
    serde_json::json!({
        "issuer":"https://auth.example.com/oidc", "client_id":"example-native-client",
        "resource":"https://cyberbus.example/api", "product_id":"cyberbus",
        "native_clients":{"example-native-client":"cyberbus"},
        "redirect_uri":"http://127.0.0.1:18765/callback", "bootstrap_peers":[],
        "offline_access":true, "enable_p2p":true,
    })
    .to_string()
    .into_bytes()
}
fn bytes(response: CyberbusResponse) -> Vec<u8> {
    let result = if response.buffer.len == 0 {
        vec![]
    } else {
        unsafe { std::slice::from_raw_parts(response.buffer.data, response.buffer.len) }.to_vec()
    };
    assert_eq!(cyberbus_buffer_free(response.buffer), CYBERBUS_OK);
    result
}
fn command(handle: u64, seq: u8, body: pb::sdk_command::Body) -> pb::SdkResult {
    let request = pb::SdkCommand {
        command_id: vec![seq; 16],
        body: Some(body),
    }
    .encode_to_vec();
    let response = unsafe { cyberbus_execute(handle, request.as_ptr(), request.len()) };
    assert_eq!(response.status, CYBERBUS_OK);
    let result = pb::SdkResult::decode(bytes(response).as_slice()).unwrap();
    assert_eq!(result.command_id, vec![seq; 16]);
    result
}
#[test]
fn real_client_offline_snapshot_close_and_buffer_ownership() {
    assert_eq!(cyberbus_abi_version(), 1);
    ClientConfig::from_json(std::str::from_utf8(&config()).unwrap()).unwrap();
    let (store, _destroyed) = callbacks(None, false, false);
    let config = config();
    let response = unsafe { cyberbus_create(config.as_ptr(), config.len(), &store) };
    assert_eq!(response.status, CYBERBUS_OK);
    let handle = response.handle;
    assert_ne!(handle, 0);
    bytes(response);
    let response = cyberbus_poll(handle, 0);
    assert_eq!(response.status, CYBERBUS_TIMEOUT);
    bytes(response);
    assert_eq!(cyberbus_on_resume(handle).status, CYBERBUS_OK);
    let result = command(
        handle,
        1,
        pb::sdk_command::Body::WatchDevices(pb::WatchDevices {
            watch_id: vec![2; 16],
        }),
    );
    assert!(matches!(result.body, Some(pb::sdk_result::Body::Ok(_))));
    let response = cyberbus_poll(handle, 2000);
    assert_eq!(response.status, CYBERBUS_OK);
    let event = pb::SdkEvent::decode(bytes(response).as_slice()).unwrap();
    let Some(pb::sdk_event::Body::Devices(devices)) = event.body else {
        panic!("expected real watch snapshot")
    };
    let Some(pb::devices_event::Body::Snapshot(snapshot)) = devices.body else {
        panic!("expected snapshot")
    };
    assert_eq!(snapshot.devices.len(), 1);
    assert!(snapshot.devices[0].is_local);
    assert_eq!(
        snapshot.devices[0].presence,
        pb::DevicePresence::Offline as i32
    );
    assert_eq!(snapshot.devices[0].device_id.len(), 32);
    let result = command(
        handle,
        3,
        pb::sdk_command::Body::GetAuthState(pb::GetAuthState {}),
    );
    assert!(
        matches!(result.body, Some(pb::sdk_result::Body::AuthState(pb::AuthEvent { phase, .. })) if phase == pb::AuthPhase::LoggedOut as i32)
    );
    let result = command(handle, 4, pb::sdk_command::Body::SdkClose(pb::SdkClose {}));
    assert!(matches!(
        result.body,
        Some(pb::sdk_result::Body::SdkClosed(pb::SdkClosed {
            closed: true,
            ..
        }))
    ));
    for _ in 0..32 {
        let response = cyberbus_poll(handle, 1000);
        let status = response.status;
        bytes(response);
        if status == CYBERBUS_EOF {
            break;
        }
        assert_eq!(status, CYBERBUS_OK);
    }
    let response = cyberbus_close(handle);
    assert_eq!(response.status, CYBERBUS_OK);
    bytes(response);
    let response = cyberbus_poll(handle, 0);
    assert_eq!(response.status, CYBERBUS_INVALID_HANDLE);
    let first = response.buffer;
    let wrong = CyberbusBuffer {
        len: first.len + 1,
        ..first
    };
    assert_eq!(cyberbus_buffer_free(wrong), CYBERBUS_INVALID_ARGUMENT);
    assert_eq!(cyberbus_buffer_free(first), CYBERBUS_OK);
    assert_eq!(cyberbus_buffer_free(first), CYBERBUS_INVALID_ARGUMENT);
    let response = cyberbus_close(handle);
    assert_eq!(response.status, CYBERBUS_INVALID_HANDLE);
    bytes(response);
}
#[test]
fn failed_or_corrupt_storage_never_provisions_fresh_identity() {
    let config = config();
    for (blob, fail_load, fail_save) in [
        (Some(b"invalid opaque state".to_vec()), false, false),
        (None, true, false),
        (None, false, true),
    ] {
        let (store, destroyed) = callbacks(blob, fail_load, fail_save);
        let response = unsafe { cyberbus_create(config.as_ptr(), config.len(), &store) };
        assert_eq!(response.status, CYBERBUS_ERROR);
        assert_eq!(response.handle, 0);
        let error = pb::ProtocolError::decode(bytes(response).as_slice()).unwrap();
        assert_ne!(error.code, 0);
        assert!(!error.message.contains("opaque"));
        assert_eq!(destroyed.load(Ordering::SeqCst), 1);
    }
}
#[test]
fn invalid_arguments_are_rejected_without_allocating_a_handle() {
    let response = unsafe { cyberbus_execute(0, ptr::null(), 1) };
    assert_eq!(response.status, CYBERBUS_INVALID_ARGUMENT);
    bytes(response);
    let response = cyberbus_poll(u64::MAX, 0);
    assert_eq!(response.status, CYBERBUS_INVALID_HANDLE);
    bytes(response);
    let response = cyberbus_poll(1, 30_001);
    assert_eq!(response.status, CYBERBUS_INVALID_ARGUMENT);
    bytes(response);
    let response = unsafe { cyberbus_create(ptr::null(), 0, ptr::null()) };
    assert_eq!(response.status, CYBERBUS_INVALID_ARGUMENT);
    bytes(response);
    assert_eq!(
        cyberbus_buffer_free(CyberbusBuffer {
            data: ptr::null(),
            len: 0
        }),
        CYBERBUS_OK
    );
}
