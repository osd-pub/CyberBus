/// Errors intentionally contain no remote response, URL, token, or underlying library error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("invalid trusted authentication configuration")]
    Configuration,
    #[error("invalid signed claims or signature")]
    InvalidClaims,
    #[error("authentication operation conflicts with current state")]
    Conflict,
    #[error("authentication operation expired")]
    DeadlineExceeded,
    #[error("authentication was cancelled")]
    Cancelled,
    #[error("not authenticated; interactive login required")]
    Unauthenticated,
    #[error("interactive reauthentication required")]
    ReauthRequired,
    #[error("authorization no longer valid")]
    SessionRevoked,
    #[error("request outcome unknown; grant frozen")]
    UnknownOutcome,
    #[error("service unavailable before request delivery")]
    Unavailable,
    #[error("protected storage unavailable, corrupt, or not provisioned")]
    Storage,
    #[error("credential epoch rollback rejected")]
    Rollback,
    #[error("device policy capacity exceeded")]
    ResourceExhausted,
    #[error("invalid device identity")]
    InvalidDevice,
    #[error("operation unsupported by this platform or adapter")]
    Unsupported,
}
pub type Result<T> = std::result::Result<T, Error>;
