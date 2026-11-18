//! One pending CLI login, fed only by the existing SDK event consumer.
use cyberbus::pb;
use std::{
    future::Future,
    sync::{Arc, Mutex},
};
use tokio::sync::oneshot;

type Outcome = Result<(), String>;
#[derive(Default)]
struct State {
    pending: Option<(Vec<u8>, oneshot::Sender<Outcome>)>,
    closed: bool,
}
#[derive(Clone, Default)]
pub(crate) struct Observer(Arc<Mutex<State>>);
pub(crate) struct Waiter {
    observer: Observer,
    operation_id: Vec<u8>,
    result: oneshot::Receiver<Outcome>,
}
impl Observer {
    // Register before presenting the URL or submitting AuthCallback: an event
    // may arrive before Execute returns its admission result.
    pub(crate) fn register(&self, operation_id: &[u8]) -> Result<Waiter, String> {
        let mut state = self.0.lock().unwrap();
        if state.closed {
            return Err("Closed: SDK auth event stream closed".into());
        }
        if state.pending.is_some() {
            return Err("Conflict: CLI login already pending".into());
        }
        let (tx, result) = oneshot::channel();
        state.pending = Some((operation_id.to_vec(), tx));
        Ok(Waiter {
            observer: self.clone(),
            operation_id: operation_id.to_vec(),
            result,
        })
    }
    pub(crate) fn event(&self, event: &pb::AuthEvent) {
        use pb::AuthPhase;
        let mut state = self.0.lock().unwrap();
        if !state
            .pending
            .as_ref()
            .is_some_and(|(id, _)| *id == event.operation_id)
        {
            return;
        }
        let outcome = match AuthPhase::try_from(event.phase) {
            Ok(AuthPhase::Authenticated) if event.error.is_none() => Ok(()),
            Ok(
                AuthPhase::Authenticated
                | AuthPhase::Failed
                | AuthPhase::AuthCancelled
                | AuthPhase::ReauthRequired
                | AuthPhase::ConfigurationError,
            ) => Err(event
                .error
                .as_ref()
                .map(crate::protocol_error)
                .unwrap_or_else(|| {
                    format!(
                        "{:?}: authentication did not succeed",
                        AuthPhase::try_from(event.phase).unwrap()
                    )
                })),
            _ => return,
        };
        let (_, tx) = state.pending.take().unwrap();
        let _ = tx.send(outcome);
    }
    pub(crate) fn close(&self) {
        let mut state = self.0.lock().unwrap();
        state.closed = true;
        if let Some((_, tx)) = state.pending.take() {
            let _ = tx.send(Err("Closed: SDK auth event stream closed".into()));
        }
    }
}
impl Waiter {
    async fn wait(&mut self) -> Outcome {
        (&mut self.result)
            .await
            .map_err(|_| "Closed: SDK auth event stream closed".to_string())?
    }
}
impl Drop for Waiter {
    fn drop(&mut self) {
        let mut state = self.observer.0.lock().unwrap();
        if state
            .pending
            .as_ref()
            .is_some_and(|(id, _)| *id == self.operation_id)
        {
            state.pending = None;
        }
    }
}

// A callback admission and the correlated successful terminal are both needed.
// Failure/expiry/EOF can also end the wait while the browser is still open.
pub(crate) async fn finish(mut waiter: Waiter, callback: impl Future<Output = Outcome>) -> Outcome {
    tokio::pin!(callback);
    tokio::select! {
        result = &mut callback => { result?; waiter.wait().await }
        result = waiter.wait() => { result?; callback.await }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    async fn bounded(future: impl Future<Output = Outcome>) -> Outcome {
        tokio::time::timeout(std::time::Duration::from_secs(2), future)
            .await
            .expect("CLI auth completion did not settle within fixture budget")
    }
    fn event(id: u8, phase: pb::AuthPhase, code: Option<pb::ErrorCode>) -> pb::AuthEvent {
        pb::AuthEvent {
            operation_id: vec![id; 16],
            phase: phase as i32,
            error: code.map(|c| crate::local_error(c, "injected auth outcome")),
            ..Default::default()
        }
    }
    #[tokio::test]
    async fn admission_waits_for_delayed_matching_success_and_ignores_stale_operations() {
        let observer = Observer::default();
        let waiter = observer.register(&[1; 16]).unwrap();
        let mut login = Box::pin(finish(waiter, async { Ok(()) }));
        // This polls actual completion logic after callback admission. The old
        // admission-only login returns Ready here and fails this negative check.
        assert!(
            std::future::poll_fn(|cx| std::task::Poll::Ready(login.as_mut().poll(cx).is_pending()))
                .await
        );
        observer.event(&event(2, pb::AuthPhase::Authenticated, None));
        observer.event(&event(1, pb::AuthPhase::Authorizing, None));
        assert!(
            std::future::poll_fn(|cx| std::task::Poll::Ready(login.as_mut().poll(cx).is_pending()))
                .await
        );
        observer.event(&event(1, pb::AuthPhase::Authenticated, None));
        bounded(login).await.unwrap();
    }
    #[tokio::test]
    async fn delayed_failure_cancel_and_expiry_never_complete_successfully() {
        for (phase, code) in [
            (pb::AuthPhase::Failed, pb::ErrorCode::Unauthenticated),
            (pb::AuthPhase::AuthCancelled, pb::ErrorCode::Cancelled),
            (pb::AuthPhase::Failed, pb::ErrorCode::DeadlineExceeded),
        ] {
            let observer = Observer::default();
            let waiter = observer.register(&[1; 16]).unwrap();
            let mut login = Box::pin(finish(waiter, async { Ok(()) }));
            assert!(
                std::future::poll_fn(|cx| std::task::Poll::Ready(
                    login.as_mut().poll(cx).is_pending()
                ))
                .await
            );
            observer.event(&event(1, phase, Some(code)));
            assert!(bounded(login)
                .await
                .unwrap_err()
                .starts_with(&format!("{code:?}:")));
        }
    }
    #[tokio::test]
    async fn terminal_before_admission_is_retained_but_cannot_mask_submission_error() {
        let observer = Observer::default();
        let waiter = observer.register(&[1; 16]).unwrap();
        observer.event(&event(1, pb::AuthPhase::Authenticated, None));
        assert_eq!(
            bounded(finish(waiter, async { Err("submission rejected".into()) }))
                .await
                .unwrap_err(),
            "submission rejected"
        );
        let waiter = observer.register(&[2; 16]).unwrap();
        observer.event(&event(2, pb::AuthPhase::Authenticated, None));
        bounded(finish(waiter, async { Ok(()) })).await.unwrap();
    }
    #[tokio::test]
    async fn expiry_or_eof_while_waiting_for_browser_fails_and_drop_releases_slot() {
        let observer = Observer::default();
        let waiter = observer.register(&[1; 16]).unwrap();
        observer.event(&event(
            1,
            pb::AuthPhase::Failed,
            Some(pb::ErrorCode::DeadlineExceeded),
        ));
        assert!(bounded(finish(waiter, std::future::pending()))
            .await
            .unwrap_err()
            .starts_with("DeadlineExceeded:"));
        let waiter = observer.register(&[2; 16]).unwrap();
        drop(waiter);
        let waiter = observer.register(&[3; 16]).unwrap();
        observer.close();
        assert!(bounded(finish(waiter, std::future::pending()))
            .await
            .unwrap_err()
            .starts_with("Closed:"));
        assert!(observer.register(&[4; 16]).is_err());
    }
    #[tokio::test]
    async fn real_sdk_failure_routes_through_the_existing_event_consumer() {
        let config = crate::ClientConfig::from_json(r#"{"issuer":"https://auth.invalid/oidc","client_id":"cli","resource":"https://resource.invalid/api","product_id":"cyberbus","native_clients":{"cli":"cyberbus"},"redirect_uri":"http://127.0.0.1:18765/callback"}"#).unwrap();
        let client = crate::Client::new(
            config,
            Box::new(cyberbus_auth::MemoryStore::default()),
            crate::StoreMode::CreateNew,
        )
        .await
        .unwrap();
        let observer = Observer::default();
        let waiter = observer.register(&[9; 16]).unwrap();
        let task = tokio::spawn(crate::events(
            client.clone(),
            client.take_event_receiver().await.unwrap(),
            Arc::new(tokio::sync::Mutex::new(vec![])),
            crate::rpc_adapter::Adapter::default(),
            observer,
        ));
        let admission = async {
            crate::execute(
                &client,
                pb::sdk_command::Body::AuthRestore(pb::AuthRestore {
                    operation_id: vec![9; 16],
                }),
            )
            .await?;
            Ok(())
        };
        let outcome =
            tokio::time::timeout(std::time::Duration::from_secs(2), finish(waiter, admission))
                .await
                .unwrap();
        assert!(outcome.unwrap_err().starts_with("Unauthenticated:"));
        crate::execute(&client, pb::sdk_command::Body::SdkClose(pb::SdkClose {}))
            .await
            .unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap();
    }
}
