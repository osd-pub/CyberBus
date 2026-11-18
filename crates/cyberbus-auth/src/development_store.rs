use super::*;
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Installation {
    version: u32,
    installation: [u8; 32],
    identity: Option<[u8; 32]>,
    current: Option<[u8; 32]>,
    pending: Option<[u8; 32]>,
}

/// Explicit plaintext DEVELOPMENT storage, not encrypted platform storage. The stable installation
/// marker must live with the vault in a trusted private directory. Never infer first installation
/// from missing files. Use provision_new only on a trusted first-install decision.
pub struct DevelopmentFileStore {
    path: PathBuf,
    _lock: File,
    fresh: bool,
    #[cfg(test)]
    pub(super) failure: Option<&'static str>,
}
impl DevelopmentFileStore {
    fn lock(path: &Path) -> Result<Self> {
        use fs2::FileExt;
        if path == path.with_extension("auth-install") || path == path.with_extension("auth-lock") {
            return Err(Error::Configuration);
        }
        let mut opts = private_options();
        opts.read(true).write(true).create(true).truncate(false);
        let lock = opts
            .open(path.with_extension("auth-lock"))
            .map_err(|_| Error::Storage)?;
        regular_private(&lock)?;
        lock.try_lock_exclusive().map_err(|_| Error::Conflict)?;
        Ok(Self {
            path: path.to_path_buf(),
            _lock: lock,
            fresh: false,
            #[cfg(test)]
            failure: None,
        })
    }
    /// Open an already installed record. Missing marker/vault is always Storage, never a fresh
    /// installation. An interrupted committed replacement is recovered before returning.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let mut store = Self::lock(path.as_ref())?;
        store.load()?;
        Ok(store)
    }
    /// Trusted first installation only. Refuses ANY existing vault or marker, including corrupt
    /// files. The marker is durably created before the first vault. Interrupted provisioning must
    /// be recovered explicitly by the host, never silently retried as a new installation.
    pub fn provision_new(path: impl AsRef<Path>) -> Result<Self> {
        let mut store = Self::lock(path.as_ref())?;
        if exists(&store.path)? || exists(&store.marker_path())? {
            return Err(Error::Storage);
        }
        let marker = Installation {
            version: 1,
            installation: random()?,
            identity: None,
            current: None,
            pending: None,
        };
        store.write_marker(&marker)?;
        store.fresh = true;
        Ok(store)
    }
    /// Explicit trusted migration of a complete legacy vault. Never a fallback from open failure.
    /// Existing marker, missing/corrupt vault or stale copied vault is not automatically migrated.
    pub fn migrate_existing(path: impl AsRef<Path>) -> Result<Self> {
        let store = Self::lock(path.as_ref())?;
        if exists(&store.marker_path())? {
            return Err(Error::Storage);
        }
        let blob = read_private(&store.path)?.ok_or(Error::Storage)?;
        let identity = vault_identity(blob.expose())?;
        let marker = Installation {
            version: 1,
            installation: random()?,
            identity: Some(identity),
            current: Some(digest(blob.expose())),
            pending: None,
        };
        store.write_marker(&marker)?;
        Ok(store)
    }
    fn marker_path(&self) -> PathBuf {
        self.path.with_extension("auth-install")
    }
    fn marker(&self) -> Result<Installation> {
        let blob = read_private(&self.marker_path())?.ok_or(Error::Storage)?;
        crate::strict::json(blob.expose()).map_err(|_| Error::Storage)?;
        let m: Installation = serde_json::from_slice(blob.expose()).map_err(|_| Error::Storage)?;
        if m.version != 1 || (m.identity.is_none() && (m.current.is_some() || m.pending.is_some()))
        {
            return Err(Error::Storage);
        }
        Ok(m)
    }
    fn write_marker(&self, marker: &Installation) -> Result<()> {
        let bytes = serde_json::to_vec(marker).map_err(|_| Error::Storage)?;
        atomic_write(&self.marker_path(), &bytes, |_| Ok(()))
    }
    fn checkpoint(&self, stage: &str) -> Result<()> {
        #[cfg(test)]
        {
            // Test-only process exit simulates a crash with real disk contents and OS lock release.
            if std::env::var("CYBERBUS_AUTH_CRASH_STAGE").ok().as_deref() == Some(stage) {
                std::process::exit(81);
            }
            if self.failure == Some(stage) {
                return Err(Error::Storage);
            }
        }
        let _ = stage;
        Ok(())
    }
    #[cfg(test)]
    pub(crate) fn inject_failure(&mut self, stage: &'static str) {
        self.failure = Some(stage);
    }
}
impl SecureStore for DevelopmentFileStore {
    fn load(&mut self) -> Result<Option<SecretBytes>> {
        let mut marker = self.marker()?;
        let blob = match read_private(&self.path)? {
            Some(blob) => blob,
            None if self.fresh
                && marker.current.is_none()
                && marker.pending.is_none()
                && marker.identity.is_none() =>
            {
                return Ok(None);
            }
            None => return Err(Error::Storage),
        };
        let identity = vault_identity(blob.expose())?;
        if marker.identity != Some(identity) {
            return Err(Error::Storage);
        }
        let hash = digest(blob.expose());
        if marker.pending == Some(hash) {
            // The vault rename committed. Finalize its marker without rolling security state back.
            marker.current = Some(hash);
            marker.pending = None;
            self.write_marker(&marker)?;
        } else if marker.current == Some(hash) {
            if marker.pending.take().is_some() {
                self.write_marker(&marker)?;
            }
        } else {
            return Err(Error::Storage);
        }
        self.fresh = false;
        Ok(Some(blob))
    }
    fn replace(&mut self, value: &[u8]) -> Result<()> {
        // Reconcile any previous ambiguous transaction before preparing the next one.
        self.load()?;
        self.fresh = false;
        let identity = vault_identity(value)?;
        let mut marker = self.marker()?;
        if marker.identity.is_some_and(|old| old != identity) {
            return Err(Error::Storage);
        }
        marker.identity = Some(identity);
        marker.pending = Some(digest(value));
        // Durable intent: recovery accepts exactly the last complete vault or this complete vault.
        self.write_marker(&marker)?;
        self.checkpoint("intent")?;
        atomic_write(&self.path, value, |stage| self.checkpoint(stage))?;
        marker.current = marker.pending.take();
        self.checkpoint("before-finalize")?;
        self.write_marker(&marker)?;
        self.checkpoint("committed")?;
        Ok(())
    }
    fn durable(&self) -> bool {
        true
    }
}
fn vault_identity(bytes: &[u8]) -> Result<[u8; 32]> {
    crate::strict::json(bytes).map_err(|_| Error::Storage)?;
    let v: Vault = serde_json::from_slice(bytes).map_err(|_| Error::Storage)?;
    v.validate()?;
    let mut hash = Sha256::new();
    hash.update(v.identity_key);
    hash.update(v.comparison_key);
    Ok(hash.finalize().into())
}
fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
fn exists(path: &Path) -> Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        _ => Err(Error::Storage),
    }
}
fn private_options() -> OpenOptions {
    let mut opts = OpenOptions::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // Reparse points are inspected as such, never traversed. Deny deletion while a file is open.
        opts.custom_flags(0x00200000)
            .share_mode(0x00000001 | 0x00000002);
    }
    opts
}
fn regular_private(file: &File) -> Result<()> {
    let m = file.metadata().map_err(|_| Error::Storage)?;
    if !m.is_file() || m.len() > 8 * 1024 * 1024 {
        return Err(Error::Storage);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if m.mode() & 0o077 != 0 || m.nlink() != 1 || m.uid() != unsafe { libc::geteuid() } {
            return Err(Error::Storage);
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if m.file_attributes() & 0x00000400 != 0 {
            return Err(Error::Storage);
        }
    }
    Ok(())
}
fn read_private(path: &Path) -> Result<Option<SecretBytes>> {
    let mut opts = private_options();
    opts.read(true);
    let mut file = match opts.open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        _ => return Err(Error::Storage),
    };
    regular_private(&file)?;
    let mut bytes = Zeroizing::new(Vec::new());
    (&mut file)
        .take(8 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::Storage)?;
    if bytes.len() > 8 * 1024 * 1024 {
        return Err(Error::Storage);
    }
    Ok(Some(SecretBytes::new(std::mem::take(&mut bytes))))
}
fn atomic_write(path: &Path, bytes: &[u8], checkpoint: impl Fn(&str) -> Result<()>) -> Result<()> {
    let tmp = path.with_extension(format!("auth-tmp-{}", hex::encode(random::<16>()?)));
    let result = (|| {
        let mut opts = private_options();
        opts.write(true).create_new(true);
        let mut file = opts.open(&tmp).map_err(|_| Error::Storage)?;
        file.write_all(bytes).map_err(|_| Error::Storage)?;
        checkpoint("written")?;
        file.sync_all().map_err(|_| Error::Storage)?;
        checkpoint("synced")?;
        // Windows denies deletion of open files; close the fully synced temp before replacement.
        drop(file);
        atomic_replace(&tmp, path)?;
        checkpoint("renamed")?;
        sync_parent(path)?;
        checkpoint("directory-synced")?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}
#[cfg(not(windows))]
fn atomic_replace(from: &Path, to: &Path) -> Result<()> {
    std::fs::rename(from, to).map_err(|_| Error::Storage)
}
#[cfg(windows)]
fn atomic_replace(from: &Path, to: &Path) -> Result<()> {
    use std::os::windows::ffi::OsStrExt;
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn MoveFileExW(from: *const u16, to: *const u16, flags: u32) -> i32;
    }
    let from: Vec<_> = from.as_os_str().encode_wide().chain(Some(0)).collect();
    let to: Vec<_> = to.as_os_str().encode_wide().chain(Some(0)).collect();
    if from[..from.len() - 1].contains(&0) || to[..to.len() - 1].contains(&0) {
        return Err(Error::Storage);
    }
    // MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH. Never unlink the destination first.
    if unsafe { MoveFileExW(from.as_ptr(), to.as_ptr(), 0x1 | 0x8) } == 0 {
        Err(Error::Storage)
    } else {
        Ok(())
    }
}
#[cfg(not(windows))]
fn sync_parent(path: &Path) -> Result<()> {
    File::open(
        path.parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new(".")),
    )
    .and_then(|f| f.sync_all())
    .map_err(|_| Error::Storage)
}
#[cfg(windows)]
fn sync_parent(_: &Path) -> Result<()> {
    // MoveFileExW WRITE_THROUGH supplies the native synchronous replacement boundary.
    Ok(())
}
