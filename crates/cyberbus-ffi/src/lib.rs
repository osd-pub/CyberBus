//! C/JNI glue only. All auth, protocol, discovery and transport stay in Client.
#[cfg(target_os = "android")]
mod android;
mod c_api;
mod store;

pub use c_api::*;
use cyberbus::{pb, Client, ClientConfig, SecureStore, StoreMode};
use prost::Message;
use std::{
    collections::HashMap,
    panic::{catch_unwind, AssertUnwindSafe},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex, OnceLock,
    },
    time::Duration,
};
pub use store::CyberbusStore;
use tokio::{
    runtime::Runtime,
    sync::{mpsc, Mutex as AsyncMutex},
};

const MAX_CONFIG: usize = 65536;
// Match the protocol's local SDK object limit; schema/data commands can exceed 64 KiB.
const MAX_COMMAND: usize = 5 * 1024 * 1024;
const MAX_STORE: usize = 8 * 1024 * 1024;
const MAX_POLL_MS: u32 = 30_000;

#[derive(Clone, Copy, Debug)]
struct Failure {
    status: i32,
    code: pb::ErrorCode,
    message: &'static str,
}
type Outcome<T> = Result<T, Failure>;
impl Failure {
    fn argument() -> Self {
        Self {
            status: CYBERBUS_INVALID_ARGUMENT,
            code: pb::ErrorCode::InvalidArgument,
            message: "invalid native argument",
        }
    }
    fn invalid_handle() -> Self {
        Self {
            status: CYBERBUS_INVALID_HANDLE,
            code: pb::ErrorCode::Closed,
            message: "invalid or released native handle",
        }
    }
    fn storage() -> Self {
        Self {
            status: CYBERBUS_ERROR,
            code: pb::ErrorCode::Internal,
            message: "development local storage unavailable",
        }
    }
    fn unavailable() -> Self {
        Self {
            status: CYBERBUS_ERROR,
            code: pb::ErrorCode::Unavailable,
            message: "native runtime unavailable",
        }
    }
    fn panic() -> Self {
        Self {
            status: CYBERBUS_PANIC,
            code: pb::ErrorCode::Internal,
            message: "native operation failed",
        }
    }
    fn protocol(error: pb::ProtocolError) -> Self {
        Self {
            status: CYBERBUS_ERROR,
            code: pb::ErrorCode::try_from(error.code).unwrap_or(pb::ErrorCode::Internal),
            message: "native SDK rejected operation",
        }
    }
    fn bytes(self) -> Vec<u8> {
        pb::ProtocolError {
            code: self.code as i32,
            message: self.message.into(),
            retryable: false,
            retry_after: None,
        }
        .encode_to_vec()
    }
}
fn protect<T>(f: impl FnOnce() -> Outcome<T>) -> Outcome<T> {
    catch_unwind(AssertUnwindSafe(f)).unwrap_or_else(|_| Err(Failure::panic()))
}
fn executor() -> Outcome<&'static Runtime> {
    static EXECUTOR: OnceLock<Result<Runtime, ()>> = OnceLock::new();
    EXECUTOR
        .get_or_init(|| {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(4)
                .thread_name("cyberbus-native")
                .enable_all()
                .build()
                .map_err(|_| ())
        })
        .as_ref()
        .map_err(|_| Failure::unavailable())
}
struct Instance {
    client: Client,
    events: AsyncMutex<cyberbus::EventReceiver>,
    // One adapter event consumer; overlapping Poll is an error rather than two readers.
    polling: AtomicBool,
    close_requested: AtomicBool,
}
fn handles() -> &'static Mutex<HashMap<u64, Arc<Instance>>> {
    static HANDLES: OnceLock<Mutex<HashMap<u64, Arc<Instance>>>> = OnceLock::new();
    HANDLES.get_or_init(|| Mutex::new(HashMap::new()))
}
fn lookup(handle: u64) -> Outcome<Arc<Instance>> {
    handles()
        .lock()
        .map_err(|_| Failure::unavailable())?
        .get(&handle)
        .cloned()
        .ok_or_else(Failure::invalid_handle)
}
fn create(config: &str, mut store: Box<dyn SecureStore>) -> Outcome<u64> {
    if config.len() > MAX_CONFIG {
        return Err(Failure::argument());
    }
    let config = ClientConfig::from_json(config).map_err(Failure::protocol)?;
    let mode = match store.load().map_err(|_| Failure::storage())? {
        None => StoreMode::CreateNew,
        Some(_) => StoreMode::Existing,
    };
    let rt = executor()?;
    let (client, events) = rt.block_on(async {
        let client = Client::new(config, store, mode)
            .await
            .map_err(Failure::protocol)?;
        let events = client
            .take_event_receiver()
            .await
            .ok_or_else(Failure::unavailable)?;
        Ok::<_, Failure>((client, events))
    })?;
    static NEXT_HANDLE: AtomicU64 = AtomicU64::new(1);
    let handle = NEXT_HANDLE
        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_add(1))
        .map_err(|_| Failure::unavailable())?;
    handles()
        .lock()
        .map_err(|_| Failure::unavailable())?
        .insert(
            handle,
            Arc::new(Instance {
                client,
                events: AsyncMutex::new(events),
                polling: AtomicBool::new(false),
                close_requested: AtomicBool::new(false),
            }),
        );
    Ok(handle)
}
fn execute(handle: u64, command: &[u8]) -> Outcome<Vec<u8>> {
    if command.is_empty() || command.len() > MAX_COMMAND {
        return Err(Failure::argument());
    }
    let instance = lookup(handle)?;
    let result = executor()?.block_on(instance.client.execute_bytes(command));
    if let Ok(pb::SdkResult {
        body: Some(pb::sdk_result::Body::SdkClosed(_)),
        ..
    }) = pb::SdkResult::decode(result.as_slice())
    {
        instance.close_requested.store(true, Ordering::Release);
    }
    Ok(result)
}
enum Poll {
    Event(Vec<u8>),
    Timeout,
    Eof,
}
fn poll(handle: u64, timeout_ms: u32) -> Outcome<Poll> {
    if timeout_ms > MAX_POLL_MS {
        return Err(Failure::argument());
    }
    let instance = lookup(handle)?;
    if instance.polling.swap(true, Ordering::AcqRel) {
        return Err(Failure {
            status: CYBERBUS_ERROR,
            code: pb::ErrorCode::Conflict,
            message: "one native event consumer required",
        });
    }
    struct PollGuard<'a>(&'a AtomicBool);
    impl Drop for PollGuard<'_> {
        fn drop(&mut self) {
            self.0.store(false, Ordering::Release);
        }
    }
    let _guard = PollGuard(&instance.polling);
    executor()?.block_on(async {
        let mut events = instance.events.lock().await;
        // An immediate read makes timeout_ms=0 useful and drains EOF deterministically.
        match events.try_recv() {
            Ok(event) => return Ok(Poll::Event(event.encode_to_vec())),
            Err(mpsc::error::TryRecvError::Disconnected) => return Ok(Poll::Eof),
            Err(mpsc::error::TryRecvError::Empty) => {}
        }
        if timeout_ms == 0 {
            return Ok(Poll::Timeout);
        }
        Ok(
            match tokio::time::timeout(Duration::from_millis(timeout_ms as u64), events.recv())
                .await
            {
                Ok(Some(event)) => Poll::Event(event.encode_to_vec()),
                Ok(None) => Poll::Eof,
                Err(_) => Poll::Timeout,
            },
        )
    })
}
fn resume(handle: u64) -> Outcome<()> {
    let instance = lookup(handle)?;
    executor()?
        .block_on(instance.client.on_resume())
        .map_err(Failure::protocol)
}
fn close(handle: u64) -> Outcome<Vec<u8>> {
    // Remove first: no new operation can use this handle; in-flight Arc owners remain valid.
    let instance = handles()
        .lock()
        .map_err(|_| Failure::unavailable())?
        .remove(&handle)
        .ok_or_else(Failure::invalid_handle)?;
    let result = if !instance.close_requested.swap(true, Ordering::AcqRel) {
        let mut command_id = vec![0u8; 16];
        command_id[..8].copy_from_slice(&handle.to_be_bytes());
        command_id[8..].copy_from_slice(&u64::MAX.to_be_bytes());
        let command = pb::SdkCommand {
            command_id,
            body: Some(pb::sdk_command::Body::SdkClose(pb::SdkClose {})),
        };
        Some(
            executor()?
                .block_on(instance.client.execute(command))
                .encode_to_vec(),
        )
    } else {
        None
    };
    Ok(result.unwrap_or_default())
}
