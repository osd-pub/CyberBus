use super::*;
use crate::store::{CallbackStore, CyberbusStore};
use std::{ptr, slice};

pub const CYBERBUS_OK: i32 = 0;
pub const CYBERBUS_TIMEOUT: i32 = 1;
pub const CYBERBUS_EOF: i32 = 2;
pub const CYBERBUS_INVALID_ARGUMENT: i32 = 3;
pub const CYBERBUS_INVALID_HANDLE: i32 = 4;
pub const CYBERBUS_ERROR: i32 = 5;
pub const CYBERBUS_PANIC: i32 = 6;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct CyberbusBuffer {
    pub data: *const u8,
    pub len: usize,
}
impl Default for CyberbusBuffer {
    fn default() -> Self {
        Self {
            data: ptr::null(),
            len: 0,
        }
    }
}
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct CyberbusResponse {
    pub status: i32,
    pub handle: u64,
    pub buffer: CyberbusBuffer,
}
fn buffers() -> &'static Mutex<HashMap<usize, Box<[u8]>>> {
    static BUFFERS: OnceLock<Mutex<HashMap<usize, Box<[u8]>>>> = OnceLock::new();
    BUFFERS.get_or_init(|| Mutex::new(HashMap::new()))
}
fn owned(bytes: Vec<u8>) -> CyberbusBuffer {
    if bytes.is_empty() {
        return CyberbusBuffer::default();
    }
    let bytes = bytes.into_boxed_slice();
    let buffer = CyberbusBuffer {
        data: bytes.as_ptr(),
        len: bytes.len(),
    };
    // Recover ownership table after a caught panic rather than freeing arbitrary memory.
    buffers()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(buffer.data as usize, bytes);
    buffer
}
fn response(result: Outcome<(i32, u64, Vec<u8>)>) -> CyberbusResponse {
    match result {
        Ok((status, handle, bytes)) => CyberbusResponse {
            status,
            handle,
            buffer: owned(bytes),
        },
        Err(failure) => CyberbusResponse {
            status: failure.status,
            handle: 0,
            buffer: owned(failure.bytes()),
        },
    }
}
/// # Safety
/// ptr must point to len readable bytes for the duration of the call. Null is allowed only at len=0.
unsafe fn input<'a>(ptr: *const u8, len: usize, max: usize) -> Outcome<&'a [u8]> {
    if len > max || (ptr.is_null() && len != 0) {
        return Err(Failure::argument());
    }
    if len == 0 {
        return Ok(&[]);
    }
    Ok(unsafe { slice::from_raw_parts(ptr, len) })
}

#[no_mangle]
pub extern "C" fn cyberbus_abi_version() -> u32 {
    1
}

/// # Safety
/// Config bytes and store pointer must be valid for this call. A valid callback store transfers
/// ownership (including destroy on failure). Callbacks must follow include/cyberbus.h.
#[no_mangle]
pub unsafe extern "C" fn cyberbus_create(
    config: *const u8,
    len: usize,
    store: *const CyberbusStore,
) -> CyberbusResponse {
    response(protect(|| {
        if store.is_null() {
            return Err(Failure::argument());
        }
        let store = CallbackStore::new(unsafe { *store })?;
        let config = std::str::from_utf8(unsafe { input(config, len, MAX_CONFIG)? })
            .map_err(|_| Failure::argument())?;
        Ok((CYBERBUS_OK, create(config, Box::new(store))?, vec![]))
    }))
}
enum DevelopmentIntent {
    Open,
    Provision,
    Migrate,
}

unsafe fn create_development(
    config: *const u8,
    len: usize,
    path: *const u8,
    path_len: usize,
    intent: DevelopmentIntent,
) -> CyberbusResponse {
    response(protect(|| {
        let config = std::str::from_utf8(unsafe { input(config, len, MAX_CONFIG)? })
            .map_err(|_| Failure::argument())?;
        let path = std::str::from_utf8(unsafe { input(path, path_len, 16384)? })
            .map_err(|_| Failure::argument())?;
        if path.is_empty() || path.contains('\0') {
            return Err(Failure::argument());
        }
        // Validate public configuration before provisioning a durable first-install marker.
        ClientConfig::from_json(config).map_err(Failure::protocol)?;
        let store = match intent {
            DevelopmentIntent::Open => cyberbus_auth::DevelopmentFileStore::open(path),
            DevelopmentIntent::Provision => {
                cyberbus_auth::DevelopmentFileStore::provision_new(path)
            }
            DevelopmentIntent::Migrate => {
                cyberbus_auth::DevelopmentFileStore::migrate_existing(path)
            }
        }
        .map_err(|_| Failure::storage())?;
        // Only a newly provisioned owner can return reliably absent to create().
        // Open/migrate are already validated installed records; there is no error fallback.
        Ok((CYBERBUS_OK, create(config, Box::new(store))?, vec![]))
    }))
}
/// Open an already installed plaintext development store. Missing vault/marker fails closed.
/// # Safety
/// Config and UTF-8 path spans must be readable. Path must be in a trusted private directory.
#[no_mangle]
pub unsafe extern "C" fn cyberbus_create_development(
    config: *const u8,
    len: usize,
    path: *const u8,
    path_len: usize,
) -> CyberbusResponse {
    unsafe { create_development(config, len, path, path_len, DevelopmentIntent::Open) }
}
/// Explicit trusted first installation. Refuses an existing vault OR installation marker.
/// Never call this as a fallback from open failure.
/// # Safety
/// Same input/private directory requirements as cyberbus_create_development.
#[no_mangle]
pub unsafe extern "C" fn cyberbus_create_development_new(
    config: *const u8,
    len: usize,
    path: *const u8,
    path_len: usize,
) -> CyberbusResponse {
    unsafe { create_development(config, len, path, path_len, DevelopmentIntent::Provision) }
}
/// Explicit trusted legacy upgrade: requires a valid complete vault and no marker.
/// Never infer migration authorization from an absent marker or failed open.
/// # Safety
/// Same input/private directory requirements as cyberbus_create_development.
#[no_mangle]
pub unsafe extern "C" fn cyberbus_create_development_migrate(
    config: *const u8,
    len: usize,
    path: *const u8,
    path_len: usize,
) -> CyberbusResponse {
    unsafe { create_development(config, len, path, path_len, DevelopmentIntent::Migrate) }
}
/// # Safety
/// command must point to len readable bytes for the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn cyberbus_execute(
    handle: u64,
    command: *const u8,
    len: usize,
) -> CyberbusResponse {
    response(protect(|| {
        Ok((
            CYBERBUS_OK,
            handle,
            execute(handle, unsafe { input(command, len, MAX_COMMAND)? })?,
        ))
    }))
}
#[no_mangle]
pub extern "C" fn cyberbus_poll(handle: u64, timeout_ms: u32) -> CyberbusResponse {
    response(protect(|| {
        Ok(match poll(handle, timeout_ms)? {
            Poll::Event(bytes) => (CYBERBUS_OK, handle, bytes),
            Poll::Timeout => (CYBERBUS_TIMEOUT, handle, vec![]),
            Poll::Eof => (CYBERBUS_EOF, handle, vec![]),
        })
    }))
}
#[no_mangle]
pub extern "C" fn cyberbus_on_resume(handle: u64) -> CyberbusResponse {
    response(protect(|| {
        resume(handle)?;
        Ok((CYBERBUS_OK, handle, vec![]))
    }))
}
#[no_mangle]
pub extern "C" fn cyberbus_close(handle: u64) -> CyberbusResponse {
    response(protect(|| Ok((CYBERBUS_OK, handle, close(handle)?))))
}
#[no_mangle]
pub extern "C" fn cyberbus_buffer_free(buffer: CyberbusBuffer) -> i32 {
    protect(|| {
        if buffer.data.is_null() && buffer.len == 0 {
            return Ok(CYBERBUS_OK);
        }
        let mut table = buffers().lock().map_err(|_| Failure::unavailable())?;
        let valid = table
            .get(&(buffer.data as usize))
            .is_some_and(|bytes| bytes.len() == buffer.len);
        if !valid {
            return Err(Failure::argument());
        }
        table.remove(&(buffer.data as usize));
        Ok(CYBERBUS_OK)
    })
    .unwrap_or_else(|e| e.status)
}
