use crate::{Account, Error, Result, SecretBytes, secret::random};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// One exclusive owner for the lifetime of this value, including across processes. Implementors
/// must protect confidentiality/integrity and atomically replace the ENTIRE blob durably. A failed
/// write may have committed: caller always fails closed. DevelopmentFileStore is explicitly plaintext.
pub trait SecureStore: Send {
    fn load(&mut self) -> Result<Option<SecretBytes>>;
    fn replace(&mut self, value: &[u8]) -> Result<()>;
    fn durable(&self) -> bool;
}
#[derive(Default)]
pub struct MemoryStore {
    blob: Option<SecretBytes>,
}
impl SecureStore for MemoryStore {
    fn load(&mut self) -> Result<Option<SecretBytes>> {
        Ok(self
            .blob
            .as_ref()
            .map(|v| SecretBytes::new(v.expose().to_vec())))
    }
    fn replace(&mut self, value: &[u8]) -> Result<()> {
        self.blob = Some(SecretBytes::new(value.to_vec()));
        Ok(())
    }
    fn durable(&self) -> bool {
        false
    }
}
/// CreateNew is an explicit trusted provisioning decision. Never choose it as a fallback when
/// Existing fails. Even CreateNew refuses to overwrite an existing or corrupt vault.
#[derive(Debug, Clone, Copy)]
pub enum StoreMode {
    Existing,
    CreateNew,
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(transparent)]
pub(crate) struct StoredSecret(pub String);
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Grant {
    pub account: Account,
    pub client: String,
    pub resource: String,
    pub refresh: StoredSecret,
    pub frozen: bool,
}
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Marker {
    pub epoch: u64,
    pub tag: [u8; 32],
}
impl Marker {
    pub fn matches(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq;
        self.epoch == other.epoch && bool::from(self.tag.ct_eq(&other.tag))
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Record {
    pub account: Account,
    pub active: Marker,
    pub pending: Option<Marker>,
    pub highwater: u64,
    pub latch: Option<crate::ReauthReason>,
    pub blocked: BTreeSet<[u8; 32]>,
    pub block_revision: u64,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AddressPreference {
    pub account: Account,
    pub epoch: u64,
    pub device_id: [u8; 32],
    pub cidr: String,
    pub ip: std::net::Ipv4Addr,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Vault {
    pub version: u32,
    pub comparison_key: [u8; 32],
    pub identity_key: [u8; 32],
    pub records: Vec<Record>,
    pub grant: Option<Grant>,
    pub profile_revision: u64,
    pub profile: Option<Vec<u8>>,
    pub addresses: Vec<AddressPreference>,
}
impl Drop for Vault {
    fn drop(&mut self) {
        self.comparison_key.zeroize();
        self.identity_key.zeroize();
        for r in &mut self.records {
            r.active.tag.zeroize();
            if let Some(p) = &mut r.pending {
                p.tag.zeroize();
            }
        }
    }
}
impl Vault {
    pub fn new() -> Result<Self> {
        Ok(Self {
            version: 1,
            comparison_key: random()?,
            identity_key: random()?,
            records: Vec::new(),
            grant: None,
            profile_revision: 0,
            profile: None,
            addresses: Vec::new(),
        })
    }
    pub fn validate(&self) -> Result<()> {
        if self.version != 1
            || self.records.len() > 1024
            || self.profile.as_ref().is_some_and(|p| p.len() > 16384)
            || self.addresses.len() > 1024
            || (self.profile.is_none() != (self.profile_revision == 0))
        {
            return Err(Error::Storage);
        }
        for (i, r) in self.records.iter().enumerate() {
            if r.account.issuer.is_empty()
                || r.account.subject.is_empty()
                || r.account.product_id.is_empty()
                || self.records[..i].iter().any(|x| x.account == r.account)
                || r.highwater < r.active.epoch
                || r.blocked.len() > 1024
                || r.block_revision == 0
                || r.pending
                    .as_ref()
                    .is_some_and(|p| p.epoch != r.highwater || r.latch.is_none())
            {
                return Err(Error::Storage);
            }
        }
        if let Some(g) = &self.grant
            && (g.refresh.0.is_empty() || !self.records.iter().any(|r| r.account == g.account))
        {
            return Err(Error::Storage);
        }
        Ok(())
    }
    pub fn index(&self, a: &Account) -> Option<usize> {
        self.records.iter().position(|r| r.account == *a)
    }
}

pub(crate) struct Protected {
    pub store: Box<dyn SecureStore>,
    pub vault: Vault,
    pub pending: bool,
}
impl Protected {
    pub fn open(mut store: Box<dyn SecureStore>, mode: StoreMode) -> Result<Self> {
        let data = store.load()?;
        let vault = match (mode, data) {
            (StoreMode::Existing, Some(b)) => {
                crate::strict::json(b.expose()).map_err(|_| Error::Storage)?;
                let v: Vault = serde_json::from_slice(b.expose()).map_err(|_| Error::Storage)?;
                v.validate()?;
                v
            }
            (StoreMode::CreateNew, None) => {
                let v = Vault::new()?;
                let b = Zeroizing::new(serde_json::to_vec(&v).map_err(|_| Error::Storage)?);
                store.replace(&b)?;
                v
            }
            _ => return Err(Error::Storage),
        };
        Ok(Self {
            store,
            vault,
            pending: false,
        })
    }
    pub fn save(&mut self) -> Result<()> {
        self.pending = true;
        self.vault.validate()?;
        let b = Zeroizing::new(serde_json::to_vec(&self.vault).map_err(|_| Error::Storage)?);
        self.store.replace(&b).map_err(|_| Error::Storage)?;
        self.pending = false;
        Ok(())
    }
}

/// Static installation identity. Only borrow private bytes inside the Noise owner.
pub struct Identity {
    private: Zeroizing<[u8; 32]>,
    public: [u8; 32],
    device: [u8; 32],
    boot: [u8; 16],
}
impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Identity([REDACTED])")
    }
}
impl Identity {
    pub(crate) fn from_key(k: [u8; 32]) -> Result<Self> {
        let secret = curve::StaticSecret::from(k);
        let public = curve::PublicKey::from(&secret).to_bytes();
        Ok(Self {
            private: Zeroizing::new(k),
            device: Sha256::digest(public).into(),
            public,
            boot: random()?,
        })
    }
    pub fn public_key(&self) -> &[u8; 32] {
        &self.public
    }
    pub fn device_id(&self) -> &[u8; 32] {
        &self.device
    }
    pub fn renew_boot_id(&mut self) -> Result<()> {
        self.boot = random()?;
        Ok(())
    }
    pub fn boot_id(&self) -> &[u8; 16] {
        &self.boot
    }
    pub fn with_private_key<T>(&self, f: impl FnOnce(&[u8; 32]) -> T) -> T {
        f(&self.private)
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockState {
    pub account: Account,
    pub device_id: [u8; 32],
    pub blocked: bool,
    pub persisted_blocked: bool,
    pub persistence_pending: bool,
    pub revision: u64,
    pub state_revision: u64,
}

/// Real macOS Keychain / Windows Credential Manager / Linux Secret Service backend.
/// `lock_path` MUST be inside an existing private, user-owned directory. The lock contains no
/// secrets. Use a unique stable service/account and the SAME lock path in every process.
/// Android/iOS hosts should implement SecureStore using Keystore-encrypted atomic files / Keychain.
#[cfg(feature = "platform-keyring")]
pub struct KeyringStore {
    entry: keyring::Entry,
    _lock: std::fs::File,
}
#[cfg(feature = "platform-keyring")]
impl KeyringStore {
    pub fn open(service: &str, account: &str, lock_path: &std::path::Path) -> Result<Self> {
        use fs2::FileExt;
        let mut opts = std::fs::OpenOptions::new();
        opts.read(true).write(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
            let parent = std::fs::symlink_metadata(lock_path.parent().ok_or(Error::Storage)?)
                .map_err(|_| Error::Storage)?;
            // SAFETY: geteuid has no arguments or memory access requirements.
            if !parent.is_dir()
                || parent.uid() != unsafe { libc::geteuid() }
                || parent.mode() & 0o077 != 0
            {
                return Err(Error::Storage);
            }
            opts.mode(0o600).custom_flags(libc::O_NOFOLLOW);
        }
        let lock = opts.open(lock_path).map_err(|_| Error::Storage)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let m = lock.metadata().map_err(|_| Error::Storage)?;
            if !m.is_file()
                || m.nlink() != 1
                || m.mode() & 0o077 != 0
                || m.uid() != unsafe { libc::geteuid() }
            {
                return Err(Error::Storage);
            }
        }
        lock.try_lock_exclusive().map_err(|_| Error::Conflict)?;
        let entry = keyring::Entry::new(service, account).map_err(|_| Error::Storage)?;
        Ok(Self { entry, _lock: lock })
    }
}
#[cfg(feature = "platform-keyring")]
impl SecureStore for KeyringStore {
    fn load(&mut self) -> Result<Option<SecretBytes>> {
        match self.entry.get_secret() {
            Ok(b) => Ok(Some(SecretBytes::new(b))),
            Err(keyring::Error::NoEntry) => Ok(None),
            _ => Err(Error::Storage),
        }
    }
    fn replace(&mut self, value: &[u8]) -> Result<()> {
        use subtle::ConstantTimeEq;
        self.entry.set_secret(value).map_err(|_| Error::Storage)?;
        let read = Zeroizing::new(self.entry.get_secret().map_err(|_| Error::Storage)?);
        if !bool::from(read.as_slice().ct_eq(value)) {
            return Err(Error::Storage);
        }
        Ok(())
    }
    fn durable(&self) -> bool {
        true
    }
}

/// JNI/FFI adapter: callbacks execute synchronously on the serialized native owner. Return None
/// only for a reliably absent blob. Decryption, corruption, permission and I/O errors are Storage.
/// Callbacks must satisfy SecureStore's exclusive ownership and atomic durable replace contract.
/// A JNI host can use Keystore AES-GCM + fsync(temp), atomic rename, fsync(directory).
pub struct CallbackStore<L, S> {
    load: L,
    save: S,
}
impl<L, S> CallbackStore<L, S> {
    pub fn new(load: L, save: S) -> Self {
        Self { load, save }
    }
}
impl<L, S> SecureStore for CallbackStore<L, S>
where
    L: FnMut() -> Result<Option<SecretBytes>> + Send,
    S: FnMut(&[u8]) -> Result<()> + Send,
{
    fn load(&mut self) -> Result<Option<SecretBytes>> {
        (self.load)()
    }
    fn replace(&mut self, value: &[u8]) -> Result<()> {
        (self.save)(value)
    }
    fn durable(&self) -> bool {
        true
    }
}

#[path = "development_store.rs"]
mod development;
pub use development::DevelopmentFileStore;
