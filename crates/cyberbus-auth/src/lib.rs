//! Native-only authentication owner. Never expose this crate's secret borrowing APIs to UI/FFI.
//! See `README.md` for the runtime contract and storage provisioning requirements.
#![forbid(unsafe_op_in_unsafe_fn)]
mod clock;
mod credentials;
mod error;
mod manager;
mod oidc;
mod secret;
mod store;
mod strict;

pub use clock::{Clock, SystemClock};
pub use credentials::{Account, NetworkMaterial, NetworkView};
pub use error::{Error, Result};
pub use manager::{
    AuthManager, AuthMode, AuthRequest, AuthSnapshot, CloudLogout, LogoutPolicy, LogoutResult,
    OperationId, OperationReady, OperationStage, OperationStatus, Phase, ReauthReason,
};
pub use oidc::AuthConfig;
pub use secret::SecretBytes;
#[cfg(feature = "platform-keyring")]
pub use store::KeyringStore;
pub use store::{
    BlockState, CallbackStore, DevelopmentFileStore, Identity, MemoryStore, SecureStore, StoreMode,
};

#[cfg(test)]
mod tests;
