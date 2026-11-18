use super::*;
use sha2::{Digest, Sha256};

// This module is a child of manager: all tasks and all grant transitions remain in AuthManager.
impl AuthManager {
    fn idle(&self) -> Result<()> {
        if self.closing {
            return Err(Error::Cancelled);
        }
        if self.pending.is_some()
            || self.flight.is_some()
            || self.discovery.is_some()
            || self.cloud.is_some()
        {
            Err(Error::Conflict)
        } else {
            Ok(())
        }
    }
    fn register_operation(&mut self, id: OperationId, stage: OperationStage) -> Result<()> {
        let now = self.clock.elapsed();
        // Never evict an undelivered outcome or an owned active task.
        let owned = self.flight.as_ref().map(|f| f.id);
        self.operations.retain(|r| {
            owned == Some(r.status.operation_id)
                || r.finished
                    .is_none_or(|at| now.saturating_sub(at) < Duration::from_secs(600))
                || self
                    .ready
                    .iter()
                    .any(|e| ready_id(e) == r.status.operation_id)
        });
        if self.operations.iter().any(|r| r.status.operation_id == id) {
            return Err(Error::Conflict);
        }
        if self.operations.len() >= 1024 || self.ready.len() >= 1024 {
            return Err(Error::ResourceExhausted);
        }
        self.operations.push_back(OperationRecord {
            status: OperationStatus {
                operation_id: id,
                stage,
                terminal: false,
                error: None,
                budget_exceeded: false,
            },
            began: now,
            finished: None,
        });
        self.touch();
        Ok(())
    }
    fn stage(&mut self, id: OperationId, stage: OperationStage) {
        if let Some(r) = self
            .operations
            .iter_mut()
            .find(|r| r.status.operation_id == id && !r.status.terminal)
            && r.status.stage != stage
        {
            r.status.stage = stage;
            self.touch();
        }
    }
    pub fn operation_status(&self, id: OperationId) -> Option<OperationStatus> {
        self.operations
            .iter()
            .find(|r| r.status.operation_id == id)
            .map(|r| r.status)
    }
    fn terminal(&mut self, id: OperationId, error: Option<Error>) -> bool {
        let Some(r) = self
            .operations
            .iter_mut()
            .find(|r| r.status.operation_id == id)
        else {
            return false;
        };
        if r.status.terminal {
            return false;
        }
        r.status.terminal = true;
        r.status.error = error;
        r.status.stage = match error {
            Some(Error::Cancelled) => OperationStage::Cancelled,
            Some(_) => OperationStage::Failed,
            None => OperationStage::Succeeded,
        };
        r.finished = Some(self.clock.elapsed());
        self.touch();
        true
    }
    fn finish_auth(&mut self, id: OperationId, result: Result<AuthSnapshot>) {
        if self.terminal(id, result.as_ref().err().copied()) {
            let result = result.map(|_| self.snapshot());
            self.ready.push_back(OperationReady::AuthFinished {
                operation_id: id,
                result,
            });
        }
    }
    fn start_discovery(&mut self, id: OperationId, action: DiscoveryAction) {
        let config = self.config.clone();
        self.discovery = Some(Discovery {
            id,
            action,
            began: self.clock.elapsed(),
            task: tokio::spawn(async move {
                tokio::time::timeout(Duration::from_secs(30), Oidc::discover(&config))
                    .await
                    .map_err(|_| Error::Unavailable)?
            }),
        });
        self.stage(id, OperationStage::Discovering);
    }
    /// Requires an entered Tokio runtime. Returns immediately; no network future borrows self.
    pub fn submit_begin_auth(&mut self, mode: AuthMode) -> Result<OperationId> {
        let _ = self.check_lease();
        self.idle()?;
        if self.protected.pending {
            return Err(Error::Storage);
        }
        let id = OperationId(random()?);
        self.register_operation(id, OperationStage::Discovering)?;
        self.close_gate();
        self.lease = None;
        self.phase = Phase::AuthPending;
        self.error = None;
        if self.oidc.is_none() {
            self.start_discovery(id, DiscoveryAction::Begin(mode));
        } else {
            self.begin_ready(id, mode);
        }
        Ok(id)
    }
    fn begin_ready(&mut self, id: OperationId, mode: AuthMode) {
        match self.prepare_auth(id, mode) {
            Ok(request) => {
                self.stage(id, OperationStage::AwaitingCallback);
                self.ready.push_back(OperationReady::AuthStarted(request));
            }
            Err(e) => {
                self.auth_failed(e);
                self.finish_auth(id, Err(e));
            }
        }
    }
    /// Invalid/duplicate callbacks are rejected synchronously and do not produce an extra outcome.
    pub fn submit_complete_auth(&mut self, id: OperationId, callback_uri: &str) -> Result<()> {
        if self.pending.as_ref().is_some_and(|p| {
            p.id == id && self.clock.elapsed().saturating_sub(p.began) >= Duration::from_secs(600)
        }) {
            self.expire_interaction();
            return Err(Error::DeadlineExceeded);
        }
        match self.dispatch_code(id, callback_uri) {
            Ok(()) => self.stage(id, OperationStage::ExchangingCode),
            // A correctly bound OAuth denial is an accepted cancellation of the original operation.
            Err(Error::Cancelled) => {
                self.auth_failed(Error::Cancelled);
                self.finish_auth(id, Err(Error::Cancelled));
            }
            Err(e) => return Err(e),
        }
        Ok(())
    }
    /// Missing/frozen grants are accepted and produce one failed outcome with the supplied ID.
    pub fn submit_restore_auth(&mut self, id: OperationId) -> Result<()> {
        self.idle()?;
        self.register_operation(id, OperationStage::Restoring)?;
        self.close_gate();
        let result = self.load_restore_grant().and_then(|_| self.check_refresh());
        match result {
            Err(e) => {
                self.auth_failed(e);
                self.finish_auth(id, Err(e));
            }
            Ok(()) if self.oidc.is_none() => self.start_discovery(id, DiscoveryAction::Refresh),
            Ok(()) => {
                if let Err(e) = self.dispatch_refresh(id) {
                    self.auth_failed(e);
                    self.finish_auth(id, Err(e));
                }
            }
        }
        Ok(())
    }
    fn check_refresh(&self) -> Result<()> {
        if self.protected.pending {
            return Err(Error::Storage);
        }
        if self.reason().is_some() {
            return Err(Error::ReauthRequired);
        }
        if self.grant.as_ref().is_none_or(|g| g.frozen) {
            return Err(if self.grant.is_some() {
                Error::UnknownOutcome
            } else {
                Error::Unauthenticated
            });
        }
        if self.retry_at.is_some_and(|at| self.clock.elapsed() < at) {
            return Err(Error::Unavailable);
        }
        Ok(())
    }
    pub fn submit_refresh(&mut self) -> Result<OperationId> {
        self.check_lease()?;
        self.idle()?;
        self.check_refresh()?;
        let id = OperationId(random()?);
        self.register_operation(id, OperationStage::Refreshing)?;
        if self.oidc.is_none() {
            self.start_discovery(id, DiscoveryAction::Refresh);
        } else if let Err(e) = self.dispatch_refresh(id) {
            self.auth_failed(e);
            self.finish_auth(id, Err(e));
        }
        Ok(id)
    }
    fn auth_failed(&mut self, e: Error) {
        self.error = Some(e);
        if self.reason().is_some() {
            self.phase = Phase::ReauthRequired;
        } else if matches!(e, Error::InvalidClaims | Error::Configuration) {
            self.close_gate();
            self.phase = Phase::ConfigurationError;
        } else if e == Error::Cancelled {
            self.phase = if self.material.is_some() && self.lease.is_some() {
                Phase::Authenticated
            } else {
                Phase::LoggedOut
            };
        } else {
            self.phase = Phase::Degraded;
        }
        if e == Error::Unavailable {
            self.retry_attempt = self.retry_attempt.saturating_add(1);
            let cap = (5u64.saturating_mul(1u64 << self.retry_attempt.min(4))).min(60);
            // 5..=cap jitter, bounded by the original lease deadline. No lease renewal.
            // Scheduling jitter needs dispersion across installations, not fresh grant entropy.
            let mut hash = Sha256::new();
            hash.update(self.identity.device_id());
            hash.update(self.retry_attempt.to_be_bytes());
            hash.update(self.clock.elapsed().as_nanos().to_be_bytes());
            hash.update(self.revision.to_be_bytes());
            let digest = hash.finalize();
            let jitter = u16::from_be_bytes([digest[0], digest[1]]) as u64;
            let at = self
                .clock
                .elapsed()
                .saturating_add(Duration::from_secs(5 + jitter % (cap - 4)));
            self.retry_at = Some(self.lease.as_ref().map_or(at, |l| at.min(l.deadline)));
            if let Some(l) = &mut self.lease {
                l.next = self.retry_at.unwrap();
            }
        }
        self.touch();
    }
    /// Unknown/terminal IDs are idempotent. Cancellation publishes exactly one terminal outcome.
    /// The returned status describes the actual terminal result; HTTP/JWKS cleanup may remain owned.
    pub fn cancel_operation(&mut self, id: OperationId) -> Result<Option<OperationStatus>> {
        let Some(status) = self.operation_status(id) else {
            return Ok(None);
        };
        if status.terminal {
            return Ok(Some(status));
        }
        if self.cloud.as_ref().is_some_and(|c| c.id == id) {
            let mut cloud = self.cloud.take().unwrap();
            cloud_error(&mut cloud.result, Error::UnknownOutcome);
            if self.terminal(id, Some(Error::Cancelled)) {
                self.ready.push_back(OperationReady::LogoutFinished {
                    operation_id: id,
                    result: cloud.result.clone(),
                });
            }
            return Ok(self.operation_status(id));
        }
        if self.discovery.as_ref().is_some_and(|d| d.id == id) {
            self.discovery = None;
        }
        if self.pending.as_ref().is_some_and(|p| p.id == id) {
            self.pending = None;
        }
        if let Some(f) = &mut self.flight
            && f.id == id
        {
            f.cancelled = true;
        }
        self.ready
            .retain(|e| !matches!(e, OperationReady::AuthStarted(r) if r.operation_id == id));
        self.auth_failed(Error::Cancelled);
        self.finish_auth(id, Err(Error::Cancelled));
        Ok(self.operation_status(id))
    }
    /// Permanently close this SDK auth owner without logging out the selected durable grant.
    /// Synchronous/nonblocking: late grant work remains owned for conservative frozen settlement.
    /// Drain cancellation outcomes before closing the event stream; continue polling owned cleanup.
    /// If the host drops the owner at its close deadline, the persisted in-flight grant stays frozen.
    pub fn close_owner(&mut self) -> Result<()> {
        if self.closing {
            return Ok(());
        }
        self.close_gate();
        let active: Vec<_> = self
            .operations
            .iter()
            .filter(|r| !r.status.terminal)
            .map(|r| r.status.operation_id)
            .collect();
        for id in active {
            self.cancel_operation(id)?;
        }
        self.closing = true;
        self.discovery = None;
        self.pending = None;
        self.grant = None;
        self.lease = None;
        self.current = None;
        self.oidc = None;
        self.block_deny.clear();
        self.block_persisted.clear();
        self.phase = Phase::LoggedOut;
        self.touch();
        Ok(())
    }
    /// Local closure and durable grant deletion occur before returning. Cloud work is budgeted
    /// independently and can never reinstall credentials. A budget must be in (0, 30 seconds].
    pub fn submit_logout(
        &mut self,
        policy: LogoutPolicy,
        cloud_budget: Duration,
    ) -> Result<OperationId> {
        if self.closing {
            return Err(Error::Cancelled);
        }
        if cloud_budget.is_zero() || cloud_budget > Duration::from_secs(30) {
            return Err(Error::Configuration);
        }
        if self.cloud.is_some() {
            return Err(Error::Conflict);
        }
        let id = OperationId(random()?);
        self.register_operation(id, OperationStage::LoggingOut)?;
        self.close_gate();
        self.lease = None;
        let active: Vec<_> = self
            .operations
            .iter()
            .filter(|r| !r.status.terminal && r.status.operation_id != id)
            .map(|r| r.status.operation_id)
            .collect();
        for op in active {
            let _ = self.cancel_operation(op);
        }
        let token = self
            .grant
            .take()
            .or_else(|| self.protected.vault.grant.take());
        self.protected.vault.grant = None;
        let local_error = self.save().err();
        self.phase = Phase::LoggedOut;
        self.current = None;
        self.block_deny.clear();
        self.block_persisted.clear();
        self.touch();
        let mut result = LogoutResult {
            local_closed: local_error.is_none(),
            local_error,
            cloud_status: CloudLogout::NotRequested,
            cloud_error: None,
        };
        match policy {
            LogoutPolicy::LocalOnly => {}
            LogoutPolicy::EndSession | LogoutPolicy::RevokeAndEndSession => {
                cloud_error(&mut result, Error::Unsupported)
            }
            LogoutPolicy::RevokeGrant => {
                // A rotating grant still in flight cannot be truthfully reported revoked.
                if self.flight.is_some() {
                    cloud_error(&mut result, Error::UnknownOutcome);
                } else if let Some(g) = token {
                    let cached = self.oidc.clone();
                    let config = self.config.clone();
                    self.cloud = Some(CloudFlight {
                        id,
                        result,
                        began: self.clock.elapsed(),
                        budget: cloud_budget,
                        task: tokio::spawn(async move {
                            tokio::time::timeout(cloud_budget, async move {
                                let o = match cached {
                                    Some(o) => o,
                                    None => Oidc::discover(&config).await?,
                                };
                                o.revoke(&g.refresh.0).await
                            })
                            .await
                            .map_err(|_| Error::UnknownOutcome)?
                        }),
                    });
                    return Ok(id);
                } else {
                    cloud_error(&mut result, Error::Unsupported);
                }
            }
        }
        self.finish_logout(id, result);
        Ok(id)
    }
    fn finish_logout(&mut self, id: OperationId, result: LogoutResult) {
        if self.terminal(id, result.local_error.or(result.cloud_error)) {
            self.ready.push_back(OperationReady::LogoutFinished {
                operation_id: id,
                result,
            });
        }
    }
    fn expire_interaction(&mut self) {
        if let Some(p) = &self.pending
            && self.clock.elapsed().saturating_sub(p.began) >= Duration::from_secs(600)
        {
            let id = p.id;
            self.pending = None;
            self.ready
                .retain(|e| !matches!(e, OperationReady::AuthStarted(r) if r.operation_id == id));
            self.auth_failed(Error::DeadlineExceeded);
            self.finish_auth(id, Err(Error::DeadlineExceeded));
        }
    }
    /// Advance only ready task results and timers. Does not await network or spawn a second grant
    /// owner. Call every 20-50ms and before/after command dispatch, even after caller cancellation.
    /// Storage commits remain synchronous and invoke the close hook before any fail-closed write.
    pub fn poll_ready(&mut self) -> Option<OperationReady> {
        let _ = self.check_lease();
        self.expire_interaction();
        if let Some(d) = &mut self.discovery {
            let result = if self.clock.elapsed().saturating_sub(d.began) >= Duration::from_secs(30)
            {
                Some(Err(Error::Unavailable))
            } else {
                poll_task(&mut d.task)
            };
            if let Some(result) = result {
                let d = self.discovery.take().unwrap();
                match result {
                    Err(e) => {
                        self.auth_failed(e);
                        self.finish_auth(d.id, Err(e));
                    }
                    Ok(o) => {
                        self.oidc = Some(o);
                        match d.action {
                            DiscoveryAction::Begin(mode) => self.begin_ready(d.id, mode),
                            DiscoveryAction::Refresh => {
                                if let Err(e) = self.dispatch_refresh(d.id) {
                                    self.auth_failed(e);
                                    self.finish_auth(d.id, Err(e));
                                }
                            }
                        }
                    }
                }
            }
        }
        if let Some(f) = &self.flight {
            let id = f.id;
            let over = self
                .operations
                .iter()
                .find(|r| r.status.operation_id == id)
                .is_some_and(|r| {
                    self.clock.elapsed().saturating_sub(r.began) >= Duration::from_secs(30)
                });
            // Browser waiting time does not consume the token request's 30s budget.
            let over =
                over && self.clock.elapsed().saturating_sub(f.start) >= Duration::from_secs(30);
            if over
                && let Some(r) = self.operations.iter_mut().find(|r| {
                    r.status.operation_id == id && !r.status.terminal && !r.status.budget_exceeded
                })
            {
                r.status.budget_exceeded = true;
                self.auth_failed(Error::UnknownOutcome);
            }
            let result = {
                let mut future = std::pin::pin!(self.settle_owned());
                match future
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                {
                    Poll::Ready(result) => Some(result),
                    Poll::Pending => None,
                }
            };
            if let Some(result) = result {
                // Never change the externally selected cancellation/logout terminal on late cleanup.
                if !self.operation_status(id).is_some_and(|s| s.terminal) {
                    if let Err(e) = result {
                        self.auth_failed(e);
                    }
                    self.finish_auth(id, result);
                }
            } else if self
                .flight
                .as_ref()
                .is_some_and(|f| matches!(f.task, FlightTask::Verification(_)))
            {
                self.stage(id, OperationStage::Verifying);
            }
        }
        if let Some(c) = &mut self.cloud {
            let result = if self.clock.elapsed().saturating_sub(c.began) >= c.budget {
                Some(Err(Error::UnknownOutcome))
            } else {
                poll_task(&mut c.task)
            };
            if let Some(result) = result {
                let mut c = self.cloud.take().unwrap();
                match result {
                    Ok(()) => c.result.cloud_status = CloudLogout::Succeeded,
                    Err(e) => cloud_error(&mut c.result, e),
                }
                self.finish_logout(c.id, c.result.clone());
            }
        }
        self.ready.pop_front()
    }
    pub async fn begin_auth(&mut self, mode: AuthMode) -> Result<AuthRequest> {
        let id = self.submit_begin_auth(mode)?;
        loop {
            if let Some(e) = self.poll_ready() {
                match e {
                    OperationReady::AuthStarted(r) if r.operation_id == id => return Ok(r),
                    OperationReady::AuthFinished {
                        operation_id,
                        result,
                    } if operation_id == id => return Err(result.err().unwrap_or(Error::Conflict)),
                    e => self.ready.push_back(e),
                }
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }
    pub async fn complete_auth(
        &mut self,
        id: OperationId,
        callback_uri: &str,
    ) -> Result<AuthSnapshot> {
        self.submit_complete_auth(id, callback_uri)?;
        self.wait_finished(id).await
    }
    pub async fn restore_auth(&mut self, id: OperationId) -> Result<AuthSnapshot> {
        self.submit_restore_auth(id)?;
        self.wait_finished(id).await
    }
    pub async fn refresh(&mut self) -> Result<AuthSnapshot> {
        let id = self.submit_refresh()?;
        self.wait_finished(id).await
    }
    pub(super) async fn wait_finished(&mut self, id: OperationId) -> Result<AuthSnapshot> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        loop {
            if let Some(e) = self.poll_ready() {
                match e {
                    OperationReady::AuthFinished {
                        operation_id,
                        result,
                    } if operation_id == id => {
                        if self.flight.as_ref().is_some_and(|f| f.id == id) {
                            self.ready.push_back(OperationReady::AuthFinished {
                                operation_id,
                                result,
                            });
                        } else {
                            return result;
                        }
                    }
                    e => self.ready.push_back(e),
                }
            }
            // After cancellation, settle_pending still waits for the original owner to clean up.
            if self.flight.as_ref().is_none_or(|f| f.id != id)
                && self.discovery.as_ref().is_none_or(|d| d.id != id)
                && let Some(s) = self.operation_status(id).filter(|s| s.terminal)
            {
                self.ready.retain(|e| ready_id(e) != id);
                return s.error.map_or_else(|| Ok(self.snapshot()), Err);
            }
            if tokio::time::Instant::now() >= deadline {
                self.auth_failed(Error::UnknownOutcome);
                return Err(Error::UnknownOutcome);
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }
    pub async fn logout(&mut self, policy: LogoutPolicy) -> LogoutResult {
        let id = match self.submit_logout(policy, Duration::from_secs(30)) {
            Ok(id) => id,
            Err(e) => {
                return LogoutResult {
                    local_closed: false,
                    local_error: Some(e),
                    cloud_status: CloudLogout::NotRequested,
                    cloud_error: None,
                };
            }
        };
        loop {
            if let Some(e) = self.poll_ready() {
                match e {
                    OperationReady::LogoutFinished {
                        operation_id,
                        result,
                    } if operation_id == id => return result,
                    e => self.ready.push_back(e),
                }
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }
}
fn ready_id(e: &OperationReady) -> OperationId {
    match e {
        OperationReady::AuthStarted(r) => r.operation_id,
        OperationReady::AuthFinished { operation_id, .. }
        | OperationReady::LogoutFinished { operation_id, .. } => *operation_id,
    }
}
fn poll_task<T>(task: &mut JoinHandle<Result<T>>) -> Option<Result<T>> {
    match std::pin::Pin::new(task).poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(r) => Some(r.map_err(|_| Error::UnknownOutcome).and_then(|r| r)),
        Poll::Pending => None,
    }
}
fn cloud_error(result: &mut LogoutResult, e: Error) {
    result.cloud_status = match e {
        Error::Unsupported => CloudLogout::Unsupported,
        Error::UnknownOutcome => CloudLogout::UnknownOutcome,
        _ => CloudLogout::Failed,
    };
    result.cloud_error = Some(e);
}
