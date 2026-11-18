use super::*;
use cyberbus_auth::{Error, Result as StoreResult, SecretBytes};
use jni::{
    objects::{GlobalRef, JByteArray, JClass, JObject, JString, JValue},
    sys::{jboolean, jbyteArray, jint, jlong, JNI_FALSE, JNI_TRUE},
    JNIEnv, JavaVM,
};
use std::ptr;
use zeroize::Zeroizing;
const RECORD_KEY: &str = "cyberbus-v1";

struct JvmStore {
    vm: JavaVM,
    object: Option<GlobalRef>,
}
impl JvmStore {
    fn new(env: &mut JNIEnv, object: JObject) -> Outcome<Self> {
        if object.is_null() {
            return Err(Failure::argument());
        }
        let vm = env.get_java_vm().map_err(|_| Failure::storage())?;
        let object = env.new_global_ref(object).map_err(|_| Failure::storage())?;
        Ok(Self {
            vm,
            object: Some(object),
        })
    }
}
impl Drop for JvmStore {
    fn drop(&mut self) {
        if let Ok(_guard) = self.vm.attach_current_thread() {
            drop(self.object.take());
        }
    }
}
impl SecureStore for JvmStore {
    fn load(&mut self) -> StoreResult<Option<SecretBytes>> {
        let mut env = self
            .vm
            .attach_current_thread()
            .map_err(|_| Error::Storage)?;
        let result = env.with_local_frame(8, |env| -> jni::errors::Result<_> {
            let key = JObject::from(env.new_string(RECORD_KEY)?);
            let array = env
                .call_method(
                    self.object.as_ref().unwrap().as_obj(),
                    "load",
                    "(Ljava/lang/String;)[B",
                    &[JValue::Object(&key)],
                )?
                .l()?;
            if array.is_null() {
                return Ok(None);
            }
            let array = JByteArray::from(array);
            let len = env.get_array_length(&array)? as usize;
            if len == 0 || len > MAX_STORE {
                return Err(jni::errors::Error::NullPtr("invalid local store record"));
            }
            let bytes = Zeroizing::new(env.convert_byte_array(&array)?);
            env.set_byte_array_region(&array, 0, &vec![0; len])?;
            Ok(Some(SecretBytes::new(bytes.to_vec())))
        });
        // Java exceptions from opaque store callbacks are translated, never described/logged.
        if env.exception_check().unwrap_or(true) {
            let _ = env.exception_clear();
            return Err(Error::Storage);
        }
        result.map_err(|_| Error::Storage)
    }
    fn replace(&mut self, value: &[u8]) -> StoreResult<()> {
        if value.len() > MAX_STORE {
            return Err(Error::Storage);
        }
        let mut env = self
            .vm
            .attach_current_thread()
            .map_err(|_| Error::Storage)?;
        let result = env.with_local_frame(8, |env| -> jni::errors::Result<_> {
            let key = JObject::from(env.new_string(RECORD_KEY)?);
            let array = env.byte_array_from_slice(value)?;
            let saved = env.call_method(
                self.object.as_ref().unwrap().as_obj(),
                "save",
                "(Ljava/lang/String;[B)Z",
                &[JValue::Object(&key), JValue::Object(array.as_ref())],
            );
            let threw = env.exception_check()?;
            if threw {
                env.exception_clear()?;
            }
            env.set_byte_array_region(&array, 0, &vec![0; value.len()])?;
            if threw {
                return Err(jni::errors::Error::JavaException);
            }
            Ok(saved?.z()?)
        });
        if env.exception_check().unwrap_or(true) {
            let _ = env.exception_clear();
            return Err(Error::Storage);
        }
        match result {
            Ok(true) => Ok(()),
            _ => Err(Error::Storage),
        }
    }
    fn durable(&self) -> bool {
        true
    }
}
fn throw(env: &mut JNIEnv, failure: Failure) {
    if env.exception_check().unwrap_or(false) {
        let _ = env.exception_clear();
    }
    let class = if failure.status == CYBERBUS_INVALID_ARGUMENT {
        "java/lang/IllegalArgumentException"
    } else {
        "java/lang/IllegalStateException"
    };
    let _ = env.throw_new(class, failure.message);
}
fn jhandle(handle: jlong) -> Outcome<u64> {
    if handle <= 0 {
        Err(Failure::invalid_handle())
    } else {
        Ok(handle as u64)
    }
}
fn array(env: &mut JNIEnv, result: Outcome<Vec<u8>>) -> jbyteArray {
    match result {
        Ok(bytes) => match env.byte_array_from_slice(&bytes) {
            Ok(array) => array.into_raw(),
            Err(_) => {
                throw(env, Failure::unavailable());
                ptr::null_mut()
            }
        },
        Err(error) => {
            throw(env, error);
            ptr::null_mut()
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_io_cyberbus_demo_NativeBridge_nativeCreate(
    mut env: JNIEnv,
    _class: JClass,
    config: JString,
    store: JObject,
) -> jlong {
    let result = protect(|| {
        let config: String = env
            .get_string(&config)
            .map_err(|_| Failure::argument())?
            .into();
        let store = JvmStore::new(&mut env, store)?;
        create(&config, Box::new(store))
    });
    match result {
        Ok(handle) => handle as jlong,
        Err(error) => {
            throw(&mut env, error);
            0
        }
    }
}
#[no_mangle]
pub extern "system" fn Java_io_cyberbus_demo_NativeBridge_nativeExecute(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
    command: JByteArray,
) -> jbyteArray {
    let result = protect(|| {
        let len = env
            .get_array_length(&command)
            .map_err(|_| Failure::argument())? as usize;
        if len > MAX_COMMAND {
            return Err(Failure::argument());
        }
        let bytes = env
            .convert_byte_array(&command)
            .map_err(|_| Failure::argument())?;
        execute(jhandle(handle)?, &bytes)
    });
    array(&mut env, result)
}
#[no_mangle]
pub extern "system" fn Java_io_cyberbus_demo_NativeBridge_nativePoll(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
    timeout_ms: jint,
) -> jbyteArray {
    let result = protect(|| {
        if timeout_ms < 0 {
            return Err(Failure::argument());
        }
        poll(jhandle(handle)?, timeout_ms as u32)
    });
    match result {
        Ok(Poll::Event(bytes)) => array(&mut env, Ok(bytes)),
        Ok(Poll::Timeout) => ptr::null_mut(),
        Ok(Poll::Eof) => {
            throw(
                &mut env,
                Failure {
                    status: CYBERBUS_EOF,
                    code: pb::ErrorCode::Closed,
                    message: "native event channel closed",
                },
            );
            ptr::null_mut()
        }
        Err(error) => {
            throw(&mut env, error);
            ptr::null_mut()
        }
    }
}
#[no_mangle]
pub extern "system" fn Java_io_cyberbus_demo_NativeBridge_nativeOnResume(
    env: JNIEnv,
    _class: JClass,
    handle: jlong,
) -> jboolean {
    match protect(|| resume(jhandle(handle)?)) {
        Ok(()) => JNI_TRUE,
        Err(_) => {
            if env.exception_check().unwrap_or(false) {
                let _ = env.exception_clear();
            }
            JNI_FALSE
        }
    }
}
#[no_mangle]
pub extern "system" fn Java_io_cyberbus_demo_NativeBridge_nativeClose(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
) {
    if let Err(error) = protect(|| close(jhandle(handle)?).map(|_| ())) {
        throw(&mut env, error);
    }
}

/// Public SDK package alias; delegates to the existing JNI boundary.
#[no_mangle]
pub extern "system" fn Java_io_cyberbus_sdk_NativeBridge_nativeCreate(
    env: JNIEnv,
    class: JClass,
    config: JString,
    store: JObject,
) -> jlong {
    Java_io_cyberbus_demo_NativeBridge_nativeCreate(env, class, config, store)
}

/// Public SDK package alias; delegates to the existing JNI boundary.
#[no_mangle]
pub extern "system" fn Java_io_cyberbus_sdk_NativeBridge_nativeExecute(
    env: JNIEnv,
    class: JClass,
    handle: jlong,
    command: JByteArray,
) -> jbyteArray {
    Java_io_cyberbus_demo_NativeBridge_nativeExecute(env, class, handle, command)
}

/// Public SDK package alias; delegates to the existing JNI boundary.
#[no_mangle]
pub extern "system" fn Java_io_cyberbus_sdk_NativeBridge_nativePoll(
    env: JNIEnv,
    class: JClass,
    handle: jlong,
    timeout_ms: jint,
) -> jbyteArray {
    Java_io_cyberbus_demo_NativeBridge_nativePoll(env, class, handle, timeout_ms)
}

/// Public SDK package alias; delegates to the existing JNI boundary.
#[no_mangle]
pub extern "system" fn Java_io_cyberbus_sdk_NativeBridge_nativeOnResume(
    env: JNIEnv,
    class: JClass,
    handle: jlong,
) -> jboolean {
    Java_io_cyberbus_demo_NativeBridge_nativeOnResume(env, class, handle)
}

/// Public SDK package alias; delegates to the existing JNI boundary.
#[no_mangle]
pub extern "system" fn Java_io_cyberbus_sdk_NativeBridge_nativeClose(
    env: JNIEnv,
    class: JClass,
    handle: jlong,
) {
    Java_io_cyberbus_demo_NativeBridge_nativeClose(env, class, handle)
}
