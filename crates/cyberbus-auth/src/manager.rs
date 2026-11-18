#[path = "operations.rs"]
mod operations;
use crate::{
    Account, AuthConfig, BlockState, Clock, Error, Identity, NetworkMaterial, NetworkView, Result,
    SecureStore, StoreMode,
    oidc::{Oidc, Tokens, Verified},
    secret::random,
    store::{AddressPreference, Grant, Marker, Protected, Record, StoredSecret},
};
use oauth2::{
    AuthorizationCode, CsrfToken, PkceCodeChallenge, PkceCodeVerifier, RefreshToken, Scope,
    TokenResponse,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeSet, VecDeque},
    future::Future,
    sync::Arc,
    task::{Context, Poll, Waker},
    time::Duration,
};
use subtle::ConstantTimeEq;
use tokio::task::JoinHandle;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReauthReason {
    CredentialsChanged,
    SessionRevoked,
    ValidationLeaseExpired,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    LoggedOut,
    AuthPending,
    Authenticated,
    Degraded,
    ReauthRequired,
    ConfigurationError,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMode {
    Login,
    Register,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OperationId(pub [u8; 16]);
/// Authorization URL is intentionally redacted in Debug. Pass it only to the local browser.
pub struct AuthRequest {
    pub operation_id: OperationId,
    pub authorization_url: String,
    pub expires_at: u64,
}
impl std::fmt::Debug for AuthRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthRequest")
            .field("operation_id", &self.operation_id)
            .field("authorization_url", &"[REDACTED]")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthSnapshot {
    pub phase: Phase,
    pub state_revision: u64,
    pub generation: u64,
    pub account: Option<Account>,
    pub reauth_required: bool,
    pub reauth_reason: Option<ReauthReason>,
    pub refresh_supported: bool,
    pub refresh_grant_frozen: bool,
    pub interaction_recommended: bool,
    pub security_state_persistence_pending: bool,
    pub durable_store: bool,
    pub network_enabled: bool,
    /// Process-local monotonic deadline, suitable for scheduling only; never persist it.
    pub lease_deadline: Option<Duration>,
    pub next_validation: Option<Duration>,
    pub validation_request_started_at: Option<u64>,
    pub last_online_validation_at: Option<u64>,
    pub validation_lease_expires_at: Option<u64>,
    pub access_token_expires_at: Option<u64>,
    pub last_error: Option<Error>,
    pub request_in_flight: bool,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogoutPolicy {
    LocalOnly,
    RevokeGrant,
    EndSession,
    RevokeAndEndSession,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloudLogout {
    NotRequested,
    Succeeded,
    Failed,
    Unsupported,
    UnknownOutcome,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogoutResult {
    pub local_closed: bool,
    pub local_error: Option<Error>,
    pub cloud_status: CloudLogout,
    pub cloud_error: Option<Error>,
}

/// Observable operation progress; does not grant network admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationStage {
    Discovering,
    AwaitingCallback,
    ExchangingCode,
    Restoring,
    Refreshing,
    Verifying,
    LoggingOut,
    Succeeded,
    Failed,
    Cancelled,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OperationStatus {
    pub operation_id: OperationId,
    pub stage: OperationStage,
    pub terminal: bool,
    pub error: Option<Error>,
    /// A caller budget has elapsed. The original task remains owned until settlement.
    pub budget_exceeded: bool,
}
#[derive(Debug)]
pub enum OperationReady {
    AuthStarted(AuthRequest),
    AuthFinished {
        operation_id: OperationId,
        result: Result<AuthSnapshot>,
    },
    LogoutFinished {
        operation_id: OperationId,
        result: LogoutResult,
    },
}
struct OperationRecord {
    status: OperationStatus,
    began: Duration,
    finished: Option<Duration>,
}
enum DiscoveryAction {
    Begin(AuthMode),
    Refresh,
}
struct Discovery {
    id: OperationId,
    action: DiscoveryAction,
    task: JoinHandle<Result<Oidc>>,
    began: Duration,
}
impl Drop for Discovery {
    fn drop(&mut self) {
        self.task.abort();
    }
}
struct CloudFlight {
    id: OperationId,
    task: JoinHandle<Result<()>>,
    result: LogoutResult,
    began: Duration,
    budget: Duration,
}
impl Drop for CloudFlight {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct Pending {
    #[zeroize(skip)]
    id: OperationId,
    state: String,
    nonce: String,
    verifier: String,
    #[zeroize(skip)]
    began: Duration,
    #[zeroize(skip)]
    wall: u64,
}
enum FlightTask {
    Tokens(JoinHandle<Result<Tokens>>),
    Verification(JoinHandle<Result<(Tokens, Verified)>>),
}
struct Flight {
    id: OperationId,
    task: FlightTask,
    nonce: Option<(Zeroizing<String>, u64)>,
    expected: Option<Account>,
    start: Duration,
    wall: u64,
    cancelled: bool,
}
impl Drop for Flight {
    fn drop(&mut self) {
        match &self.task {
            FlightTask::Tokens(task) => task.abort(),
            FlightTask::Verification(task) => task.abort(),
        }
    }
}
struct Lease {
    success: Duration,
    start_wall: u64,
    success_wall: u64,
    deadline: Duration,
    expiry_wall: u64,
    token_exp: u64,
    next: Duration,
}

/// Sole serialized OAuth grant owner. Not Clone; all mutating methods require &mut self.
/// Host must retain this object after a 30s operation budget: settle_pending() continues the SAME
/// request. Dropping an awaiting caller never transfers grant ownership or permits token replay.
pub struct AuthManager {
    config: AuthConfig,
    protected: Protected,
    clock: Arc<dyn Clock>,
    identity: Identity,
    oidc: Option<Oidc>,
    discovery: Option<Discovery>,
    cloud: Option<CloudFlight>,
    operations: VecDeque<OperationRecord>,
    ready: VecDeque<OperationReady>,
    gate_close_hook: Option<Arc<dyn Fn() + Send + Sync>>,
    retry_attempt: u32,
    retry_at: Option<Duration>,
    pending: Option<Pending>,
    flight: Option<Flight>,
    grant: Option<Grant>,
    current: Option<Account>,
    material: Option<NetworkMaterial>,
    lease: Option<Lease>,
    phase: Phase,
    generation: u64,
    revision: u64,
    enabled: bool,
    suspended: bool,
    closing: bool,
    error: Option<Error>,
    block_deny: BTreeSet<[u8; 32]>,
    block_revision: u64,
    block_persisted: BTreeSet<[u8; 32]>,
    block_state_revision: u64,
}
impl std::fmt::Debug for AuthManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthManager")
            .field("snapshot", &self.snapshot())
            .finish_non_exhaustive()
    }
}
impl AuthManager {
    /// No implicit memory store and no recovery fallback. Provision CreateNew only with trusted
    /// user intent; Existing missing/corrupt/decryption failure always returns Storage.
    pub fn new(
        config: AuthConfig,
        store: Box<dyn SecureStore>,
        mode: StoreMode,
        clock: Arc<dyn Clock>,
    ) -> Result<Self> {
        config.validate()?;
        if config.persist_grant && !store.durable() {
            return Err(Error::Configuration);
        }
        let protected = Protected::open(store, mode)?;
        let identity = Identity::from_key(protected.vault.identity_key)?;
        let current = protected.vault.grant.as_ref().map(|g| g.account.clone());
        let mut m = Self {
            config,
            protected,
            clock,
            identity,
            oidc: None,
            discovery: None,
            cloud: None,
            operations: VecDeque::new(),
            ready: VecDeque::new(),
            gate_close_hook: None,
            retry_attempt: 0,
            retry_at: None,
            pending: None,
            flight: None,
            grant: None,
            current,
            material: None,
            lease: None,
            phase: Phase::LoggedOut,
            generation: 1,
            revision: 1,
            enabled: false,
            suspended: false,
            closing: false,
            error: None,
            block_deny: BTreeSet::new(),
            block_persisted: BTreeSet::new(),
            block_revision: 1,
            block_state_revision: 1,
        };
        m.load_blocks();
        if m.reason().is_some() {
            m.phase = Phase::ReauthRequired;
        }
        Ok(m)
    }
    #[cfg(test)]
    pub(crate) fn protected_store_for_test(&mut self, store: Box<dyn SecureStore>) {
        self.protected.store = store;
    }
    #[cfg(test)]
    pub(crate) fn fail_before_delivery_for_test(&mut self) {
        self.oidc.as_mut().unwrap().unavailable_before_delivery = true;
    }
    fn touch(&mut self) {
        self.revision = self
            .revision
            .checked_add(1)
            .expect("auth revision exhausted");
    }
    fn record_index(&self) -> Option<usize> {
        self.current
            .as_ref()
            .and_then(|a| self.protected.vault.index(a))
    }
    fn reason(&self) -> Option<ReauthReason> {
        self.record_index()
            .and_then(|i| self.protected.vault.records[i].latch)
    }
    /// The hook must only close admission/cancel a network token; it must not reenter this owner.
    /// It runs synchronously before state changes and durable writes. Only NetworkStart reopens.
    pub fn set_gate_close_hook(&mut self, hook: Arc<dyn Fn() + Send + Sync>) {
        hook(); // installation is fail-closed, including an already enabled manager
        self.enabled = false;
        self.gate_close_hook = Some(hook);
        self.touch();
    }
    pub fn set_close_gate_observer(&mut self, hook: Arc<dyn Fn() + Send + Sync>) {
        self.set_gate_close_hook(hook);
    }
    fn notify_closed(&self) {
        if let Some(hook) = &self.gate_close_hook {
            hook();
        }
    }
    fn close_gate(&mut self) {
        self.notify_closed();
        self.enabled = false;
        self.material = None;
        self.generation = self
            .generation
            .checked_add(1)
            .expect("generation exhausted");
        self.touch();
    }
    fn fail(&mut self, e: Error) -> Error {
        self.error = Some(e);
        self.touch();
        e
    }
    fn save(&mut self) -> Result<()> {
        if let Err(e) = self.protected.save() {
            self.close_gate();
            self.error = Some(e);
            return Err(e);
        }
        Ok(())
    }
    fn latch(&mut self, r: ReauthReason) -> Result<()> {
        self.close_gate();
        self.lease = None;
        if let Some(i) = self.record_index() {
            self.protected.vault.records[i].latch.get_or_insert(r);
        }
        self.phase = Phase::ReauthRequired;
        self.save()
    }
    fn check_lease(&mut self) -> Result<()> {
        if self
            .lease
            .as_ref()
            .is_some_and(|l| self.clock.elapsed() >= l.deadline)
        {
            self.latch(ReauthReason::ValidationLeaseExpired)?;
            return Err(Error::ReauthRequired);
        }
        if self.protected.pending {
            return Err(Error::Storage);
        }
        Ok(())
    }
    pub fn identity(&self) -> &Identity {
        &self.identity
    }
    pub fn snapshot(&self) -> AuthSnapshot {
        let grant = self.grant.as_ref().or(self.protected.vault.grant.as_ref());
        let refresh = grant.is_some();
        let frozen = grant.is_some_and(|g| g.frozen);
        let valid = self
            .lease
            .as_ref()
            .is_some_and(|l| self.clock.elapsed() < l.deadline);
        AuthSnapshot {
            phase: self.phase,
            state_revision: self.revision,
            generation: self.generation,
            account: if self.phase == Phase::Authenticated {
                self.current.clone()
            } else {
                None
            },
            reauth_required: self.reason().is_some(),
            reauth_reason: self.reason(),
            refresh_supported: refresh,
            refresh_grant_frozen: frozen,
            interaction_recommended: !refresh || frozen || self.reason().is_some(),
            security_state_persistence_pending: self.protected.pending,
            durable_store: self.protected.store.durable(),
            network_enabled: self.enabled
                && valid
                && !self.suspended
                && !self.protected.pending
                && self.reason().is_none(),
            lease_deadline: self.lease.as_ref().map(|l| l.deadline),
            next_validation: self.lease.as_ref().map(|l| l.next),
            validation_request_started_at: self.lease.as_ref().map(|l| l.start_wall),
            last_online_validation_at: self.lease.as_ref().map(|l| l.success_wall),
            validation_lease_expires_at: self.lease.as_ref().map(|l| l.expiry_wall),
            access_token_expires_at: self.lease.as_ref().map(|l| l.token_exp),
            last_error: self.error,
            request_in_flight: self.flight.is_some()
                || self.discovery.is_some()
                || self.cloud.is_some(),
        }
    }
    fn prepare_auth(&mut self, id: OperationId, mode: AuthMode) -> Result<AuthRequest> {
        let oidc = self.oidc.clone().ok_or(Error::Configuration)?;
        let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
        let state = hex::encode(random::<32>()?);
        let nonce = hex::encode(random::<32>()?);
        let mut request = oidc
            .client
            .authorize_url(|| CsrfToken::new(state.clone()))
            .add_scope(Scope::new("openid".into()))
            .add_scope(Scope::new("network:join".into()))
            .set_pkce_challenge(challenge)
            .add_extra_param("resource", &self.config.resource)
            .add_extra_param("nonce", &nonce)
            .add_extra_param(
                "prompt",
                if self.config.offline_access {
                    "login consent"
                } else {
                    "login"
                },
            )
            .add_extra_param("max_age", "0");
        if self.config.offline_access {
            request = request.add_scope(Scope::new("offline_access".into()));
        }
        // Logto's documented hosted sign-up entry; never accepts registration credentials locally.
        if mode == AuthMode::Register {
            request = request.add_extra_param("first_screen", "register");
        }
        let (url, _) = request.url();
        let wall = self.clock.unix_seconds();
        self.pending = Some(Pending {
            id,
            state,
            nonce,
            verifier: verifier.secret().clone(),
            began: self.clock.elapsed(),
            wall,
        });
        self.close_gate();
        self.lease = None;
        self.phase = Phase::AuthPending;
        self.error = None;
        self.touch();
        Ok(AuthRequest {
            operation_id: id,
            authorization_url: url.to_string(),
            expires_at: wall.saturating_add(600),
        })
    }
    fn dispatch_code(&mut self, id: OperationId, callback_uri: &str) -> Result<()> {
        if self.flight.is_some() {
            return Err(Error::Conflict);
        }
        let p = self.pending.as_ref().ok_or(Error::Conflict)?;
        if p.id != id {
            return Err(Error::Conflict);
        }
        if self.clock.elapsed().saturating_sub(p.began) >= Duration::from_secs(600) {
            self.pending = None;
            self.phase = if self.reason().is_some() {
                Phase::ReauthRequired
            } else {
                Phase::LoggedOut
            };
            return Err(self.fail(Error::DeadlineExceeded));
        }
        let code = match parse_callback(&self.config.redirect_uri, callback_uri, &p.state) {
            Ok(code) => code,
            Err(Error::Cancelled) => {
                self.pending = None;
                self.phase = if self.reason().is_some() {
                    Phase::ReauthRequired
                } else {
                    Phase::LoggedOut
                };
                return Err(self.fail(Error::Cancelled));
            }
            Err(e) => return Err(e),
        };
        let callback = url::Url::parse(callback_uri).map_err(|_| Error::InvalidClaims)?;
        if callback
            .query_pairs()
            .any(|(k, v)| k == "iss" && v != self.config.issuer)
        {
            return Err(Error::InvalidClaims);
        }
        let mut p = self.pending.take().ok_or(Error::Conflict)?;
        let o = self.oidc.clone().ok_or(Error::Configuration)?;
        let verifier = PkceCodeVerifier::new(std::mem::take(&mut p.verifier));
        let start = self.clock.elapsed();
        let wall = self.clock.unix_seconds();
        let task = tokio::spawn(async move {
            let result = o
                .client
                .exchange_code(AuthorizationCode::new(code))
                .set_pkce_verifier(verifier)
                .add_extra_param("resource", &o.config.resource)
                .request_async(&o)
                .await;
            convert(result)
        });
        self.flight = Some(Flight {
            id,
            task: FlightTask::Tokens(task),
            nonce: Some((Zeroizing::new(std::mem::take(&mut p.nonce)), p.wall)),
            expected: None,
            start,
            wall,
            cancelled: false,
        });
        self.touch();
        Ok(())
    }
    /// Idempotent cancellation. Issued grants and verification tasks remain owned for cleanup.
    pub fn cancel_auth(&mut self, id: OperationId) -> Result<()> {
        self.cancel_operation(id).map(|_| ())
    }
    fn load_restore_grant(&mut self) -> Result<()> {
        if self.protected.pending {
            return Err(Error::Storage);
        }
        if self.reason().is_some() {
            return Err(Error::ReauthRequired);
        }
        if self.grant.is_none() {
            let g = self
                .protected
                .vault
                .grant
                .as_ref()
                .ok_or(Error::Unauthenticated)?;
            if g.client != self.config.client_id
                || g.resource != self.config.resource
                || g.account.issuer != self.config.issuer
                || g.account.product_id != self.config.product_id
            {
                return Err(Error::Configuration);
            }
            self.current = Some(g.account.clone());
            self.grant = Some(copy_grant(g));
            self.load_blocks();
        }
        Ok(())
    }
    fn dispatch_refresh(&mut self, id: OperationId) -> Result<()> {
        if self.pending.is_some() || self.flight.is_some() {
            return Err(Error::Conflict);
        }
        if self.reason().is_some() {
            return Err(Error::ReauthRequired);
        }
        if self.protected.pending {
            return Err(Error::Storage);
        }
        if self.grant.as_ref().is_none_or(|g| g.frozen) {
            return Err(if self.grant.is_some() {
                Error::UnknownOutcome
            } else {
                Error::Unauthenticated
            });
        }
        let o = self.oidc.clone().ok_or(Error::Configuration)?;
        let g = self.grant.as_mut().ok_or(Error::Unauthenticated)?;
        let token = RefreshToken::new(g.refresh.0.clone());
        let expected = g.account.clone();
        g.frozen = true;
        self.sync_grant();
        self.save()?;
        let start = self.clock.elapsed();
        let wall = self.clock.unix_seconds();
        let task = tokio::spawn(async move {
            convert(
                o.client
                    .exchange_refresh_token(&token)
                    .add_extra_param("resource", &o.config.resource)
                    .request_async(&o)
                    .await,
            )
        });
        self.flight = Some(Flight {
            id,
            task: FlightTask::Tokens(task),
            nonce: None,
            expected: Some(expected),
            start,
            wall,
            cancelled: false,
        });
        self.touch();
        Ok(())
    }
    /// Compatibility wrapper. Dropping this future retains discovery, issuance and JWKS ownership.
    pub async fn settle_pending(&mut self) -> Result<AuthSnapshot> {
        let id = self
            .flight
            .as_ref()
            .map(|f| f.id)
            .or_else(|| self.discovery.as_ref().map(|d| d.id))
            .ok_or(Error::Conflict)?;
        self.wait_finished(id).await
    }
    async fn settle_owned(&mut self) -> Result<AuthSnapshot> {
        let token_result = match &mut self.flight.as_mut().ok_or(Error::Conflict)?.task {
            FlightTask::Tokens(task) => Some(
                task.await
                    .map_err(|_| Error::UnknownOutcome)
                    .and_then(|r| r),
            ),
            FlightTask::Verification(_) => None,
        };
        if let Some(result) = token_result {
            let mut f = self.flight.take().ok_or(Error::Conflict)?;
            // Expire old lease BEFORE accepting a late result. A background result can never unlatch.
            let _ = self.check_lease();
            if self.closing {
                // A closing owner keeps the dispatched task, but never installs a session.
                // Persist only the refresh rotation and retain the conservative frozen bit.
                if f.nonce.is_none() {
                    if let Some(g) = self.protected.vault.grant.as_mut()
                        && f.expected.as_ref() == Some(&g.account)
                    {
                        match result {
                            Ok(t) => {
                                if let Some(rt) = &t.refresh {
                                    g.refresh = StoredSecret(rt.clone());
                                }
                                g.frozen = true;
                            }
                            Err(Error::Unavailable) => g.frozen = false,
                            Err(_) => {}
                        }
                        self.save()?;
                    }
                }
                return Err(Error::Cancelled);
            }
            let t = match result {
                Ok(t) => t,
                Err(e) => {
                    if e == Error::Unavailable && !f.cancelled {
                        if let Some(g) = &mut self.grant {
                            g.frozen = false;
                        }
                        self.sync_grant();
                        self.save()?;
                    }
                    if f.cancelled {
                        return Err(self.fail(Error::Cancelled));
                    }
                    if e == Error::SessionRevoked {
                        self.latch(ReauthReason::SessionRevoked)?;
                    } else if matches!(e, Error::InvalidClaims | Error::Configuration) {
                        self.close_gate();
                        self.phase = Phase::ConfigurationError;
                    } else if self.reason().is_none() {
                        self.phase = Phase::Degraded;
                    }
                    return Err(self.fail(if f.cancelled { Error::Cancelled } else { e }));
                }
            };
            // Save rotated grant while still frozen BEFORE any further async verification. A caller
            // cancellation during JWKS fetch cannot replay the old refresh token in this or next process.
            if f.nonce.is_none()
                && let (Some(g), Some(rt)) = (&mut self.grant, &t.refresh)
            {
                g.refresh = StoredSecret(rt.clone());
            }
            self.sync_grant();
            self.save()?;
            if f.cancelled {
                if f.nonce.is_some() {
                    self.phase = if self.reason().is_some() {
                        Phase::ReauthRequired
                    } else {
                        Phase::LoggedOut
                    };
                }
                return Err(self.fail(Error::Cancelled));
            }
            let o = self.oidc.clone().ok_or(Error::Configuration)?;
            let nonce = f.nonce.clone();
            let expected = f.expected.clone();
            let clock = self.clock.clone();
            // No await occurs between taking the issuance result, journaling its rotated grant,
            // and retaining the verification task. Dropping the caller cannot lose the tokens.
            f.task = FlightTask::Verification(tokio::spawn(async move {
                let verified = o
                    .verify(
                        &t,
                        nonce.as_ref().map(|(n, w)| (n.as_str(), *w)),
                        clock.unix_seconds(),
                        expected.as_ref(),
                    )
                    .await?;
                Ok((t, verified))
            }));
            self.flight = Some(f);
        }
        let result = match &mut self.flight.as_mut().ok_or(Error::Conflict)?.task {
            FlightTask::Verification(task) => task
                .await
                .map_err(|_| Error::UnknownOutcome)
                .and_then(|r| r),
            FlightTask::Tokens(_) => unreachable!("issuance transitioned to verification"),
        };
        let f = self.flight.take().ok_or(Error::Conflict)?;
        let _ = self.check_lease();
        // Cancellation or logout may have happened while the owned JWKS task was running.
        if f.cancelled {
            if f.nonce.is_some() {
                self.phase = if self.reason().is_some() {
                    Phase::ReauthRequired
                } else {
                    Phase::LoggedOut
                };
            }
            return Err(self.fail(Error::Cancelled));
        }
        let (t, verified) = match result {
            Ok(result) => result,
            Err(e) => {
                self.close_gate();
                self.phase = Phase::ConfigurationError;
                return Err(self.fail(e));
            }
        };
        let interactive = f.nonce.is_some();
        if interactive {
            self.current = Some(verified.account.clone());
            self.load_blocks();
            self.grant = if self.config.offline_access {
                t.refresh.as_ref().map(|rt| Grant {
                    account: verified.account.clone(),
                    client: self.config.client_id.clone(),
                    resource: self.config.resource.clone(),
                    refresh: StoredSecret(rt.clone()),
                    frozen: true,
                })
            } else {
                None
            };
        }
        self.accept(verified, interactive, f.start, f.wall)?;
        Ok(self.snapshot())
    }
    fn sync_grant(&mut self) {
        self.protected.vault.grant = if self.config.persist_grant {
            self.grant.as_ref().map(copy_grant)
        } else {
            None
        };
    }
    fn accept(&mut self, v: Verified, interactive: bool, start: Duration, wall: u64) -> Result<()> {
        let _ = self.check_lease();
        if self.protected.pending {
            return Err(Error::Storage);
        }
        let marker = Marker {
            epoch: v.material.epoch,
            tag: v
                .material
                .tag(&v.account, &self.protected.vault.comparison_key),
        };
        let i = if let Some(i) = self.protected.vault.index(&v.account) {
            i
        } else {
            if !interactive {
                self.close_gate();
                return Err(Error::Storage);
            }
            if self.protected.vault.records.len() >= 1024 {
                self.close_gate();
                return Err(Error::ResourceExhausted);
            }
            self.protected.vault.records.push(Record {
                account: v.account.clone(),
                active: marker.clone(),
                pending: None,
                highwater: marker.epoch,
                latch: None,
                blocked: BTreeSet::new(),
                block_revision: 1,
            });
            self.protected.vault.records.len() - 1
        };
        if marker.epoch < self.protected.vault.records[i].highwater {
            self.close_gate();
            self.phase = Phase::ConfigurationError;
            return Err(self.fail(Error::Rollback));
        }
        if let Some(p) = &self.protected.vault.records[i].pending
            && marker.epoch == p.epoch
            && !p.matches(&marker)
        {
            self.close_gate();
            return Err(self.fail(Error::Conflict));
        }
        let changed = !self.protected.vault.records[i].active.matches(&marker);
        if changed {
            self.close_gate();
            let r = &mut self.protected.vault.records[i];
            if r.pending.is_none() || marker.epoch > r.highwater {
                r.pending = Some(marker.clone());
            }
            r.highwater = r.highwater.max(marker.epoch);
            r.latch.get_or_insert(ReauthReason::CredentialsChanged);
            self.phase = Phase::ReauthRequired;
        }
        if !interactive && self.protected.vault.records[i].latch.is_some() {
            self.sync_grant();
            self.save()?;
            return Err(self.fail(Error::ReauthRequired));
        }
        let refresh = self.grant.is_some();
        let mut deadline = start.saturating_add(Duration::from_secs(600));
        if !refresh {
            deadline =
                deadline.min(start.saturating_add(Duration::from_secs(v.exp.saturating_sub(wall))));
        }
        if self.clock.elapsed() >= deadline {
            self.sync_grant();
            self.latch(ReauthReason::ValidationLeaseExpired)?;
            return Err(self.fail(Error::ReauthRequired));
        }
        let old_active = self.protected.vault.records[i].active.clone();
        let old_pending = self.protected.vault.records[i].pending.clone();
        let old_latch = self.protected.vault.records[i].latch;
        // Final atomic acceptance. Failures never reopen the gate and leave a repairable dirty vault.
        if interactive {
            let r = &mut self.protected.vault.records[i];
            r.active = marker;
            r.pending = None;
            r.latch = None;
        }
        if let Some(g) = &mut self.grant {
            g.frozen = false;
        }
        self.sync_grant();
        if let Err(e) = self.save() {
            // An ambiguous commit cannot erase the running reauth latch. Repair writes this
            // conservative state; even if disk accepted the transaction, admission stays closed.
            if interactive {
                let r = &mut self.protected.vault.records[i];
                r.active = old_active;
                r.pending = old_pending;
                r.latch = old_latch;
            }
            return Err(e);
        }
        self.material = Some(v.material);
        let jitter = 240 + u16::from_be_bytes(random()?) as u64 % 121;
        self.lease = Some(Lease {
            success: self.clock.elapsed(),
            start_wall: wall,
            success_wall: self.clock.unix_seconds(),
            deadline,
            expiry_wall: wall.saturating_add(deadline.saturating_sub(start).as_secs()),
            token_exp: v.exp,
            next: self
                .clock
                .elapsed()
                .saturating_add(Duration::from_secs(jitter)),
        });
        self.suspended = false;
        self.phase = Phase::Authenticated;
        self.error = None;
        self.retry_attempt = 0;
        self.retry_at = None;
        self.touch();
        Ok(())
    }
    /// Validate credentials and lease before constructing native network adapters. Borrowed
    /// secrets are not admission permission; start_network and per-delivery check_gate still apply.
    pub fn with_network_material<T>(&mut self, f: impl FnOnce(NetworkView<'_>) -> T) -> Result<T> {
        self.check_lease()?;
        if self.reason().is_some() || self.suspended {
            return Err(Error::ReauthRequired);
        }
        Ok(f(self
            .material
            .as_ref()
            .ok_or(Error::Unauthenticated)?
            .view()))
    }
    /// Opens only local auth admission. Runtime owns actual EasyTier/Noise lifecycle and must
    /// cancel old generation work before publishing new sessions. Returns the new generation.
    pub fn start_network(&mut self) -> Result<u64> {
        if self.closing {
            return Err(Error::Cancelled);
        }
        self.check_lease()?;
        if self.reason().is_some() || self.suspended {
            return Err(Error::ReauthRequired);
        }
        if self.material.is_none() {
            return Err(Error::Unauthenticated);
        }
        if self.enabled {
            return Ok(self.generation);
        }
        self.identity.renew_boot_id()?;
        self.generation += 1;
        self.enabled = true;
        self.touch();
        Ok(self.generation)
    }
    pub fn stop_network(&mut self) {
        self.notify_closed();
        self.enabled = false;
        self.generation += 1;
        self.touch();
    }
    /// Call at the serialized send/receive/handler admission point, including queued work.
    pub fn check_gate(&mut self, generation: u64, device_id: Option<&[u8; 32]>) -> Result<()> {
        self.check_lease()?;
        if generation != self.generation
            || !self.enabled
            || self.material.is_none()
            || self.suspended
            || self.reason().is_some()
            || device_id.is_some_and(|d| self.block_deny.contains(d))
        {
            return Err(Error::ReauthRequired);
        }
        Ok(())
    }
    /// Host calls before delivering ANY resumed work. Returns true when an online check is due.
    pub fn on_resume(&mut self) -> Result<bool> {
        self.check_lease()?;
        if !self.clock.includes_suspend() {
            self.notify_closed();
            self.enabled = false;
            self.suspended = true;
            self.generation += 1;
            self.touch();
            return Ok(true);
        }
        Ok(self.retry_at.is_none_or(|at| self.clock.elapsed() >= at)
            && self.lease.as_ref().is_none_or(|l| {
                self.clock.elapsed().saturating_sub(l.success) >= Duration::from_secs(300)
            }))
    }
    /// Explicitly repair a failed durable transaction. Never opens admission or clears a latch.
    pub fn retry_storage(&mut self) -> Result<()> {
        self.save()?;
        self.load_blocks();
        self.touch();
        Ok(())
    }
    fn load_blocks(&mut self) {
        if let Some(i) = self.record_index() {
            let r = &self.protected.vault.records[i];
            self.block_deny = r.blocked.clone();
            self.block_persisted = r.blocked.clone();
            self.block_revision = r.block_revision;
        } else {
            self.block_deny.clear();
            self.block_persisted.clear();
            self.block_revision = 1;
        }
        self.block_state_revision += 1;
    }
    fn valid_device(&self, id: &[u8; 32]) -> Result<usize> {
        if id == self.identity.device_id() {
            return Err(Error::InvalidDevice);
        }
        self.record_index().ok_or(Error::Unauthenticated)
    }
    pub fn block_state(&self, id: [u8; 32]) -> Result<BlockState> {
        self.valid_device(&id)?;
        Ok(BlockState {
            account: self.current.clone().ok_or(Error::Unauthenticated)?,
            device_id: id,
            blocked: self.block_deny.contains(&id),
            persisted_blocked: self.block_persisted.contains(&id),
            persistence_pending: self.protected.pending
                || self.block_deny.contains(&id) != self.block_persisted.contains(&id),
            revision: self.block_revision,
            state_revision: self.block_state_revision,
        })
    }
    pub fn blocked_devices(&self) -> Result<Vec<BlockState>> {
        if self.current.is_none() {
            return Err(Error::Unauthenticated);
        }
        self.block_deny
            .iter()
            .map(|d| self.block_state(*d))
            .collect()
    }
    /// Runtime must use check_gate for every queued action, and cancel sessions/RPC/cache for
    /// this ID before returning block success to its application. Policy deny precedes disk I/O.
    pub fn block_device(&mut self, id: [u8; 32]) -> Result<BlockState> {
        self.set_block(id, true)
    }
    pub fn unblock_device(&mut self, id: [u8; 32]) -> Result<BlockState> {
        self.set_block(id, false)
    }
    fn set_block(&mut self, id: [u8; 32], blocked: bool) -> Result<BlockState> {
        let i = self.valid_device(&id)?;
        if !self.protected.pending && self.block_deny.contains(&id) == blocked {
            return self.block_state(id);
        }
        if blocked && !self.block_deny.contains(&id) && self.block_deny.len() >= 1024 {
            self.close_gate();
            return Err(Error::ResourceExhausted);
        }
        // Failed unblock retains deny too. Admission is restored only after a durable remove.
        self.block_deny.insert(id);
        self.block_state_revision += 1;
        self.touch();
        let r = &mut self.protected.vault.records[i];
        let changed = if blocked {
            r.blocked.insert(id)
        } else {
            r.blocked.remove(&id)
        };
        if changed {
            r.block_revision = r
                .block_revision
                .checked_add(1)
                .ok_or(Error::ResourceExhausted)?;
        }
        self.save()?;
        self.block_revision = self.protected.vault.records[i].block_revision;
        self.block_persisted = self.protected.vault.records[i].blocked.clone();
        if !blocked {
            self.block_deny.remove(&id);
        }
        self.block_state_revision += 1;
        self.block_state(id)
    }
    pub fn local_profile(&self) -> Option<(u64, Vec<u8>)> {
        self.protected
            .vault
            .profile
            .as_ref()
            .map(|p| (self.protected.vault.profile_revision, p.clone()))
    }
    pub fn commit_local_profile(
        &mut self,
        expected_revision: u64,
        serialized_profile: &[u8],
    ) -> Result<u64> {
        if self.protected.pending {
            return Err(Error::Storage);
        }
        if serialized_profile.len() > 16384 {
            return Err(Error::ResourceExhausted);
        }
        if self.protected.vault.profile_revision != expected_revision {
            return Err(Error::Conflict);
        }
        let next = expected_revision
            .checked_add(1)
            .ok_or(Error::ResourceExhausted)?;
        self.protected.vault.profile = Some(serialized_profile.to_vec());
        self.protected.vault.profile_revision = next;
        self.save()?;
        Ok(next)
    }
    pub fn address_preference(&self) -> Result<Option<std::net::Ipv4Addr>> {
        let a = self.current.as_ref().ok_or(Error::Unauthenticated)?;
        let i = self.record_index().ok_or(Error::Storage)?;
        let epoch = self.protected.vault.records[i].active.epoch;
        Ok(self
            .protected
            .vault
            .addresses
            .iter()
            .find(|p| {
                p.account == *a
                    && p.epoch == epoch
                    && p.device_id == *self.identity.device_id()
                    && p.cidr == "10.144.0.0/20"
            })
            .map(|p| p.ip))
    }
    pub fn commit_address_preference(&mut self, ip: std::net::Ipv4Addr) -> Result<()> {
        if self.protected.pending {
            return Err(Error::Storage);
        }
        let n = u32::from(ip);
        let base = u32::from(std::net::Ipv4Addr::new(10, 144, 0, 0));
        if n <= base || n >= base + 4095 {
            return Err(Error::Configuration);
        }
        let a = self.current.clone().ok_or(Error::Unauthenticated)?;
        let i = self.record_index().ok_or(Error::Storage)?;
        let epoch = self.protected.vault.records[i].active.epoch;
        if let Some(p) = self.protected.vault.addresses.iter_mut().find(|p| {
            p.account == a && p.epoch == epoch && p.device_id == *self.identity.device_id()
        }) {
            p.ip = ip;
        } else {
            if self.protected.vault.addresses.len() >= 1024 {
                return Err(Error::ResourceExhausted);
            }
            self.protected.vault.addresses.push(AddressPreference {
                account: a,
                epoch,
                device_id: *self.identity.device_id(),
                cidr: "10.144.0.0/20".into(),
                ip,
            });
        }
        self.save()
    }
}
fn copy_grant(g: &Grant) -> Grant {
    Grant {
        account: g.account.clone(),
        client: g.client.clone(),
        resource: g.resource.clone(),
        refresh: StoredSecret(g.refresh.0.clone()),
        frozen: g.frozen,
    }
}
pub(crate) fn parse_callback(redirect: &str, raw: &str, state: &str) -> Result<String> {
    if raw.len() > 16384 {
        return Err(Error::InvalidClaims);
    }
    let url = url::Url::parse(raw).map_err(|_| Error::InvalidClaims)?;
    let mut base = url.clone();
    base.set_query(None);
    if raw.split('?').next() != Some(redirect)
        || url.fragment().is_some()
        || base.as_str() != redirect
    {
        return Err(Error::InvalidClaims);
    }
    let mut fields = std::collections::BTreeMap::new();
    for (k, v) in url.query_pairs() {
        if fields.insert(k.to_string(), v.to_string()).is_some() {
            return Err(Error::InvalidClaims);
        }
    }
    let received = fields.get("state").ok_or(Error::InvalidClaims)?;
    if !bool::from(received.as_bytes().ct_eq(state.as_bytes())) {
        return Err(Error::InvalidClaims);
    }
    if fields.contains_key("error") {
        return Err(if fields.contains_key("code") {
            Error::InvalidClaims
        } else {
            Error::Cancelled
        });
    }
    fields
        .remove("code")
        .filter(|c| !c.is_empty())
        .ok_or(Error::InvalidClaims)
}
fn convert(
    result: std::result::Result<
        oauth2::StandardTokenResponse<crate::oidc::Extra, oauth2::basic::BasicTokenType>,
        oauth2::RequestTokenError<Error, oauth2::basic::BasicErrorResponse>,
    >,
) -> Result<Tokens> {
    match result {
        Ok(t) => {
            if *t.token_type() != oauth2::basic::BasicTokenType::Bearer {
                return Err(Error::InvalidClaims);
            }
            Ok(Tokens {
                access: t.access_token().secret().clone(),
                refresh: t.refresh_token().map(|t| t.secret().clone()),
                id: t.extra_fields().id_token.clone(),
            })
        }
        Err(oauth2::RequestTokenError::Request(e)) => Err(e),
        Err(oauth2::RequestTokenError::ServerResponse(e)) => match e.error().as_ref() {
            "invalid_grant" | "login_required" | "interaction_required" | "consent_required" => {
                Err(Error::SessionRevoked)
            }
            "invalid_client"
            | "invalid_scope"
            | "unauthorized_client"
            | "unsupported_grant_type" => Err(Error::Configuration),
            _ => Err(Error::UnknownOutcome),
        },
        Err(oauth2::RequestTokenError::Parse(_, _)) => Err(Error::InvalidClaims),
        _ => Err(Error::InvalidClaims),
    }
}
