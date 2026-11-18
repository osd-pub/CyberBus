use super::*;
use cyberbus_auth::{Error, Result as StoreResult, SecretBytes};
use std::{ffi::c_void, ptr, slice};

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CyberbusStore {
    pub context: *mut c_void,
    pub load: Option<unsafe extern "C" fn(*mut c_void, *mut *const u8, *mut usize) -> i32>,
    pub replace: Option<unsafe extern "C" fn(*mut c_void, *const u8, usize) -> i32>,
    pub release: Option<unsafe extern "C" fn(*mut c_void, *const u8, usize)>,
    pub destroy: Option<unsafe extern "C" fn(*mut c_void)>,
}
pub(crate) struct CallbackStore(CyberbusStore);
// Safety: the callback ABI requires the context to be movable across native threads. Calls on a
// store are serialized by its exclusive SecureStore owner. No callback runs under registry locks.
unsafe impl Send for CallbackStore {}
impl CallbackStore {
    pub(crate) fn new(callbacks: CyberbusStore) -> Outcome<Self> {
        if callbacks.load.is_none() || callbacks.replace.is_none() || callbacks.release.is_none() {
            return Err(Failure::argument());
        }
        Ok(Self(callbacks))
    }
}
impl Drop for CallbackStore {
    fn drop(&mut self) {
        if let Some(destroy) = self.0.destroy {
            unsafe { destroy(self.0.context) }
        }
    }
}
impl SecureStore for CallbackStore {
    fn load(&mut self) -> StoreResult<Option<SecretBytes>> {
        let mut data = ptr::null();
        let mut len = 0usize;
        let status = unsafe { (self.0.load.unwrap())(self.0.context, &mut data, &mut len) };
        if status == 1 {
            if !data.is_null() || len != 0 {
                return Err(Error::Storage);
            }
            return Ok(None);
        }
        if status != 0 {
            return Err(Error::Storage);
        }
        struct Release(CyberbusStore, *const u8, usize);
        impl Drop for Release {
            fn drop(&mut self) {
                unsafe { (self.0.release.unwrap())(self.0.context, self.1, self.2) }
            }
        }
        let _release = Release(self.0, data, len);
        if data.is_null() || len == 0 || len > MAX_STORE {
            return Err(Error::Storage);
        }
        Ok(Some(SecretBytes::new(
            unsafe { slice::from_raw_parts(data, len) }.to_vec(),
        )))
    }
    fn replace(&mut self, value: &[u8]) -> StoreResult<()> {
        if value.len() > MAX_STORE {
            return Err(Error::Storage);
        }
        match unsafe { (self.0.replace.unwrap())(self.0.context, value.as_ptr(), value.len()) } {
            0 => Ok(()),
            _ => Err(Error::Storage),
        }
    }
    fn durable(&self) -> bool {
        true
    }
}
