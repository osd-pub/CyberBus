//! A bounded application adapter. Sending runs outside event delivery, so byte/item
//! windows can continue to arrive while a 1 MiB item is waiting for credit.
use crate::{example, id, pb, protocol_error, Client, REQUEST, RESPONSE};
use cyberbus_protocol::reassembly::FragmentAssembler;
use prost::Message;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, VecDeque},
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    sync::{mpsc, watch, Notify},
    time::Instant,
};
type Key = (Vec<u8>, Vec<u8>);
type Handler = Arc<dyn Fn(&[u8]) -> Result<Vec<u8>, pb::ProtocolError> + Send + Sync>;
#[derive(Clone, Debug)]
pub(super) enum Outcome {
    End(Option<pb::ProtocolError>, u64),
    Cancel(pb::ProtocolError),
    CancelRejected(pb::ProtocolError),
}
enum Output {
    Item(Vec<u8>),
    End,
}
struct Receiving {
    sequence: u64,
    assembler: FragmentAssembler,
}
struct Call {
    outbound: bool,
    output: mpsc::Sender<Output>,
    wake: Arc<Notify>,
    terminal: watch::Sender<Option<Outcome>>,
    receiving: Option<Receiving>,
    received: u64,
    expected: Vec<[u8; 32]>,
    config_request: Option<Vec<u8>>,
    request_type: String,
    response_type: String,
    handler_id: Vec<u8>,
    handler: Option<Handler>,
    fragment_size: usize,
    cancel_pending: bool,
    deferred_terminal: Option<Outcome>,
}
#[derive(Clone, Default)]
pub(super) struct Adapter {
    calls: Arc<Mutex<BTreeMap<Key, Call>>>,
    handlers: Arc<Mutex<BTreeMap<Vec<u8>, Handler>>>,
    failed: Arc<Mutex<bool>>,
    // Keep a bounded direction history for SDK terminals delivered after local
    // cooperative cancellation removed the active application call.
    roles: Arc<Mutex<VecDeque<(Key, bool)>>>,
}
impl Adapter {
    pub(super) fn register_echo(&self, id: Vec<u8>) {
        self.handlers.lock().unwrap().insert(
            id,
            Arc::new(|bytes| {
                example::EchoRequest::decode(bytes)
                    .map(|r| example::EchoReply { text: r.text }.encode_to_vec())
                    .map_err(|_| {
                        crate::local_error(pb::ErrorCode::TypeMismatch, "invalid echo request")
                    })
            }),
        );
    }
    pub(super) fn register_public_config(
        &self,
        id: Vec<u8>,
        public: crate::public_config::Profile,
    ) {
        self.handlers.lock().unwrap().insert(
            id,
            Arc::new(move |bytes| crate::public_config::reply(&public, bytes)),
        );
    }
    fn add(
        &self,
        client: Client,
        peer: Vec<u8>,
        request: pb::RpcRequest,
        outbound: bool,
        expected: Vec<[u8; 32]>,
    ) -> (mpsc::Sender<Output>, watch::Receiver<Option<Outcome>>) {
        let key = (peer, request.call_id.clone());
        {
            let mut roles = self.roles.lock().unwrap();
            if roles.len() == 128 {
                roles.pop_front();
            }
            roles.push_back((key.clone(), outbound));
        }
        let (tx, rx) = mpsc::channel(5);
        let (terminal, result) = watch::channel(None);
        let wake = Arc::new(Notify::new());
        let budget = request
            .timeout
            .as_ref()
            .map(|t| Duration::new(t.seconds.max(0) as u64, t.nanos.max(0) as u32))
            .unwrap_or(Duration::from_secs(30));
        let deadline = Instant::now() + budget;
        self.calls.lock().unwrap().insert(
            key.clone(),
            Call {
                outbound,
                output: tx.clone(),
                wake: wake.clone(),
                terminal,
                receiving: None,
                received: 0,
                expected,
                config_request: None,
                request_type: request.request_type_url.clone(),
                response_type: request.response_type_url.clone(),
                handler_id: vec![],
                handler: None,
                fragment_size: 16384,
                cancel_pending: false,
                deferred_terminal: None,
            },
        );
        let adapter = self.clone();
        tokio::spawn(async move {
            adapter
                .writer(client, key, rx, wake, deadline, outbound)
                .await;
        });
        (tx, result)
    }
    fn finish(&self, key: &Key, outcome: Outcome) {
        let mut calls = self.calls.lock().unwrap();
        if let Some(call) = calls.get_mut(key) {
            // A terminal event can precede the RpcCancel command's rejection.
            // Publish only after its result, so that rejection cannot become success.
            if call.cancel_pending {
                call.deferred_terminal.get_or_insert(outcome);
                return;
            }
        }
        if let Some(call) = calls.remove(key) {
            call.terminal.send_replace(Some(outcome));
            call.wake.notify_waiters();
        }
    }
    pub(super) fn failed(&self) -> bool {
        *self.failed.lock().unwrap()
    }
    fn correlation(key: &Key) -> String {
        format!(
            "call_id={} peer={}",
            hex::encode(&key.1),
            hex::encode(&key.0)
        )
    }
    fn role(&self, key: &Key) -> &'static str {
        // Outbound calls may also pin a local handler; handler_id does not tell
        // which endpoint originated a call. Use only an observed request.
        match self
            .roles
            .lock()
            .unwrap()
            .iter()
            .rev()
            .find(|(k, _)| k == key)
            .map(|(_, outbound)| *outbound)
        {
            Some(true) => "caller",
            Some(false) => "callee",
            None => "unknown",
        }
    }
    fn event_log(&self, key: &Key, kind: &str, error: Option<&pb::ProtocolError>) {
        let role = self.role(key);
        let code = error
            .map(|e| {
                pb::ErrorCode::try_from(e.code)
                    .map(|code| format!("{code:?}"))
                    .unwrap_or_else(|_| e.code.to_string())
            })
            .unwrap_or_else(|| "OK".into());
        println!(
            "RPC_EVENT source=sdk_event kind={kind} role={role} {} code={code}",
            Self::correlation(key)
        );
    }
    async fn execute(
        client: &Client,
        body: pb::sdk_command::Body,
    ) -> Result<(), pb::ProtocolError> {
        match client
            .execute(pb::SdkCommand {
                command_id: id(),
                body: Some(body),
            })
            .await
            .body
        {
            Some(pb::sdk_result::Body::Error(e)) => Err(e),
            Some(_) => Ok(()),
            None => Err(crate::local_error(
                pb::ErrorCode::Internal,
                "RPC result missing",
            )),
        }
    }
    fn begin_cancel(&self, key: &Key) -> bool {
        if let Some(call) = self.calls.lock().unwrap().get_mut(key) {
            if call.cancel_pending {
                return false;
            }
            call.cancel_pending = true;
        }
        true
    }
    fn complete_cancel(
        &self,
        key: &Key,
        reason: pb::ProtocolError,
        result: &Result<(), pb::ProtocolError>,
    ) {
        let mut calls = self.calls.lock().unwrap();
        if let Some(mut call) = calls.remove(key) {
            let outcome = match result {
                Err(e) => Outcome::CancelRejected(e.clone()),
                Ok(()) => call
                    .deferred_terminal
                    .take()
                    .unwrap_or(Outcome::Cancel(reason)),
            };
            call.terminal.send_replace(Some(outcome));
            call.wake.notify_waiters();
        }
        if let Err(e) = result {
            *self.failed.lock().unwrap() = true;
            eprintln!(
                "RPC_CANCEL_REJECTED {} error={}",
                Self::correlation(key),
                protocol_error(e)
            );
        } else {
            println!(
                "RPC_CANCEL_ACCEPTED confirmation=local {}",
                Self::correlation(key)
            );
        }
    }
    async fn cancel(
        &self,
        client: &Client,
        key: &Key,
        e: pb::ProtocolError,
    ) -> Result<(), pb::ProtocolError> {
        // An existing cancellation owns the result channel; its completion will
        // publish either the terminal or the SDK rejection to every waiter.
        if !self.begin_cancel(key) {
            return Ok(());
        }
        let result = Self::execute(
            client,
            pb::sdk_command::Body::RpcCancel(pb::CancelRpc {
                peer_device_id: key.0.clone(),
                cancel: Some(pb::RpcCancel {
                    call_id: key.1.clone(),
                    error: Some(e.clone()),
                }),
            }),
        )
        .await;
        self.complete_cancel(key, e, &result);
        result
    }
    async fn cancel_background(&self, client: &Client, key: &Key, e: pb::ProtocolError) {
        match self.cancel(client, key, e).await {
            Ok(()) => {}
            // complete_cancel records the rejected terminal, emits a diagnostic,
            // and marks the CLI exit as failed even for inbound/background calls.
            Err(_) => debug_assert!(self.failed()),
        }
    }
    async fn send_chunk(
        &self,
        client: &Client,
        key: &Key,
        direction: i32,
        seq: u64,
        bytes: &[u8],
        wake: &Notify,
        deadline: Instant,
    ) -> Result<(), pb::ProtocolError> {
        let ty = {
            let calls = self.calls.lock().unwrap();
            let call = calls.get(key).ok_or_else(|| {
                crate::local_error(pb::ErrorCode::Cancelled, "RPC already terminated")
            })?;
            if direction == 1 {
                call.request_type.clone()
            } else {
                call.response_type.clone()
            }
        };
        let mut offset = 0;
        let mut fragment_size = self
            .calls
            .lock()
            .unwrap()
            .get(key)
            .map_or(16384, |c| c.fragment_size);
        loop {
            let n = (bytes.len() - offset).min(fragment_size);
            // Arm notification before submitting: a concurrently delivered Window must
            // not be lost between QUEUE_FULL/credit rejection and waiting.
            let notified = wake.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if !self.calls.lock().unwrap().contains_key(key) {
                return Err(crate::local_error(
                    pb::ErrorCode::Cancelled,
                    "RPC already terminated",
                ));
            }
            let command = pb::sdk_command::Body::RpcChunk(pb::SendRpcChunk {
                peer_device_id: key.0.clone(),
                chunk: Some(pb::RpcChunk {
                    call_id: key.1.clone(),
                    direction,
                    item_sequence: seq,
                    fragment: Some(pb::PayloadFragment {
                        application_type_url: ty.clone(),
                        encoding: 1,
                        total_size: bytes.len() as u32,
                        offset: offset as u32,
                        protobuf_bytes: bytes[offset..offset + n].to_vec(),
                    }),
                }),
            });
            match Self::execute(client, command).await {
                Ok(()) => {
                    offset += n;
                    if offset == bytes.len() {
                        return Ok(());
                    }
                }
                Err(e)
                    if e.code == pb::ErrorCode::ResourceExhausted as i32
                        || e.code == pb::ErrorCode::QueueFull as i32 =>
                {
                    // The public event schema does not expose negotiated initial limits.
                    // Reduce the first fragment to discover a lower byte/fragment limit;
                    // subsequent backpressure waits for actual credit or queue drainage.
                    if n > 1 && (seq == 0 && offset == 0 || e.message.contains("fragment/item")) {
                        fragment_size = (n / 2).max(1);
                        if let Some(call) = self.calls.lock().unwrap().get_mut(key) {
                            call.fragment_size = fragment_size;
                        }
                        continue;
                    }
                    tokio::select! {_=tokio::time::sleep_until(deadline)=>return Err(crate::local_error(pb::ErrorCode::DeadlineExceeded,"RPC send deadline")),_=notified=>{},_=tokio::time::sleep(Duration::from_millis(20)),if e.code==pb::ErrorCode::QueueFull as i32=>{}}
                }
                Err(e) => return Err(e),
            }
            if Instant::now() >= deadline {
                return Err(crate::local_error(
                    pb::ErrorCode::DeadlineExceeded,
                    "RPC send deadline",
                ));
            }
        }
    }
    async fn observe_sdk_deadline(&self, key: &Key) {
        let result = self
            .calls
            .lock()
            .unwrap()
            .get(key)
            .map(|call| call.terminal.subscribe());
        let Some(mut result) = result else {
            return;
        };
        // The SDK owns RPC expiry. Its maintenance tick and event delivery may
        // follow the application's timer; cancelling here races that terminal.
        // Never turn an observation timeout into a fabricated expiry success.
        if !matches!(
            tokio::time::timeout(Duration::from_secs(2), Self::wait_outcome(&mut result)).await,
            Ok(Ok(_))
        ) {
            *self.failed.lock().unwrap() = true;
            eprintln!("RPC_SDK_TERMINAL_MISSING {}", Self::correlation(key));
            self.finish(
                key,
                Outcome::End(
                    Some(crate::local_error(
                        pb::ErrorCode::Internal,
                        "SDK deadline terminal not observed within 2s",
                    )),
                    0,
                ),
            );
        }
    }
    async fn writer(
        &self,
        client: Client,
        key: Key,
        mut rx: mpsc::Receiver<Output>,
        wake: Arc<Notify>,
        deadline: Instant,
        outbound: bool,
    ) {
        let direction = if outbound { 1 } else { 2 };
        let mut count = 0;
        loop {
            let notified = wake.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if !self.calls.lock().unwrap().contains_key(&key) {
                return;
            }
            let output = tokio::select! {
                _ = tokio::time::sleep_until(deadline) => {
                    self.observe_sdk_deadline(&key).await;
                    return;
                },
                _ = notified => continue,
                v = rx.recv() => match v { Some(v) => v, None => return },
            };
            match output {
                Output::Item(bytes) => match self
                    .send_chunk(&client, &key, direction, count, &bytes, &wake, deadline)
                    .await
                {
                    Ok(()) => {
                        count += 1;
                    }
                    Err(e) => {
                        self.cancel_background(&client, &key, e).await;
                        return;
                    }
                },
                Output::End => {
                    // End shares business ordering with chunks in the runtime outbox.
                    loop {
                        let result = Self::execute(
                            &client,
                            pb::sdk_command::Body::RpcEnd(pb::EndRpc {
                                peer_device_id: key.0.clone(),
                                end: Some(pb::RpcEnd {
                                    call_id: key.1.clone(),
                                    direction,
                                    item_count: count,
                                    error: None,
                                }),
                            }),
                        )
                        .await;
                        match result {
                            Ok(()) => {
                                if !outbound {
                                    self.finish(&key, Outcome::End(None, count));
                                }
                                return;
                            }
                            Err(e)
                                if e.code == pb::ErrorCode::QueueFull as i32
                                    && Instant::now() < deadline =>
                            {
                                tokio::time::sleep(Duration::from_millis(20)).await
                            }
                            Err(e) => {
                                self.cancel_background(&client, &key, e).await;
                                return;
                            }
                        }
                    }
                }
            }
        }
    }
    pub(super) async fn event(&self, client: &Client, event: pb::RpcEvent) {
        let peer = event.peer_device_id;
        let handler_id = event.handler_id;
        match event.body {
            Some(pb::rpc_event::Body::Request(r)) => {
                let key = (peer.clone(), r.call_id.clone());
                println!(
                    "RPC_REQUEST_RECEIVED role=callee {}",
                    Self::correlation(&key)
                );
                let callback = self.handlers.lock().unwrap().get(&handler_id).cloned();
                let Some(callback) = callback else {
                    self.cancel_background(
                        client,
                        &key,
                        crate::local_error(
                            pb::ErrorCode::MethodNotExposed,
                            "unknown original handler binding",
                        ),
                    )
                    .await;
                    return;
                };
                if !self.calls.lock().unwrap().contains_key(&key) {
                    self.add(client.clone(), peer, r, false, vec![]);
                    if let Some(call) = self.calls.lock().unwrap().get_mut(&key) {
                        call.handler_id = handler_id;
                        call.handler = Some(callback);
                    }
                }
            }
            Some(pb::rpc_event::Body::Window(w)) => {
                if let Some(c) = self.calls.lock().unwrap().get(&(peer, w.call_id)) {
                    c.wake.notify_waiters();
                }
            }
            Some(pb::rpc_event::Body::Chunk(c)) => {
                let key = (peer, c.call_id.clone());
                let result=(||->Result<Option<(Vec<u8>,bool,mpsc::Sender<Output>,Option<Handler>)>,pb::ProtocolError>{
                    let mut calls=self.calls.lock().unwrap();let call=calls.get_mut(&key).ok_or_else(||crate::local_error(pb::ErrorCode::ProtocolError,"RPC chunk without application call"))?;
                    if !call.outbound && handler_id!=call.handler_id {return Err(crate::local_error(pb::ErrorCode::ProtocolError,"changed handler binding"));}
                    let f=c.fragment.as_ref().ok_or_else(||crate::local_error(pb::ErrorCode::ProtocolError,"RPC fragment missing"))?;
                    if call.receiving.is_none() {if c.item_sequence!=call.received {return Err(crate::local_error(pb::ErrorCode::ProtocolError,"application item sequence"));}call.receiving=Some(Receiving{sequence:c.item_sequence,assembler:FragmentAssembler::new(f,1048576).map_err(|e|e.to_protocol_error())?});}
                    let r=call.receiving.as_mut().unwrap();if r.sequence!=c.item_sequence {return Err(crate::local_error(pb::ErrorCode::ProtocolError,"interleaved application item"));}
                    if !r.assembler.push(f).map_err(|e|e.to_protocol_error())? {return Ok(None);}
                    let bytes=call.receiving.take().unwrap().assembler.finish().map_err(|e|e.to_protocol_error())?;call.received+=1;
                    if call.outbound {
                        if let Some(request_id)=&call.config_request {
                            if c.item_sequence!=0 {return Err(crate::local_error(pb::ErrorCode::ProtocolError,"extra configuration reply"));}
                            let reply=crate::public_config::decode_reply(&bytes,request_id)?;
                            let config=reply.public_config.as_ref().unwrap();
                            println!("RPC_CONFIG {} request_id={} revision={} name={:?} application_version={:?} semantic_version={:?} config_sha256={}",Self::correlation(&key),hex::encode(request_id),reply.config_revision,reply.device_name,config.application_version,reply.config_semantic_version,hex::encode(Sha256::digest(config.encode_to_vec())));
                        } else {
                            let reply=example::EchoReply::decode(bytes.as_slice()).map_err(|_|crate::local_error(pb::ErrorCode::TypeMismatch,"invalid echo reply"))?;
                            let expected=call.expected.get(c.item_sequence as usize).ok_or_else(||crate::local_error(pb::ErrorCode::ProtocolError,"unexpected response item"))?;
                            if Sha256::digest(reply.text.as_bytes()).as_slice()!=expected {return Err(crate::local_error(pb::ErrorCode::TypeMismatch,"echo payload mismatch"));}
                            println!("RPC_REPLY item={} bytes={} sha256={}",c.item_sequence,bytes.len(),hex::encode(expected));
                        }
                    }
                    Ok(Some((bytes,call.outbound,call.output.clone(),call.handler.clone())))
                })();
                match result {
                    Ok(Some((bytes, outbound, output, callback))) => {
                        if !outbound {
                            let reply = callback
                                .as_ref()
                                .ok_or_else(|| {
                                    crate::local_error(
                                        pb::ErrorCode::MethodNotExposed,
                                        "handler binding missing",
                                    )
                                })
                                .and_then(|h| h(&bytes));
                            match reply {
                                Ok(reply) => {
                                    if output.try_send(Output::Item(reply)).is_err() {
                                        self.cancel_background(
                                            client,
                                            &key,
                                            crate::local_error(
                                                pb::ErrorCode::ResourceExhausted,
                                                "echo response queue full",
                                            ),
                                        )
                                        .await;
                                        return;
                                    }
                                }
                                Err(error) => {
                                    self.cancel_background(client, &key, error).await;
                                    return;
                                }
                            }
                        }
                        // Returning item credit is the explicit application consumption
                        // boundary, after decode/validation and release of the input item.
                        drop(bytes);
                        if let Err(e) = Self::execute(
                            client,
                            pb::sdk_command::Body::RpcWindow(pb::GrantRpcWindow {
                                peer_device_id: key.0.clone(),
                                window: Some(pb::RpcWindow {
                                    call_id: key.1.clone(),
                                    direction: c.direction,
                                    byte_credit: 0,
                                    item_credit: 1,
                                }),
                            }),
                        )
                        .await
                        {
                            self.cancel_background(client, &key, e).await;
                        } else if let Some(call) = self.calls.lock().unwrap().get(&key) {
                            call.wake.notify_waiters();
                        }
                    }
                    Ok(None) => {}
                    Err(e) => self.cancel_background(client, &key, e).await,
                }
            }
            Some(pb::rpc_event::Body::End(e)) => {
                let key = (peer, e.call_id.clone());
                if e.direction == 1 {
                    let output = self
                        .calls
                        .lock()
                        .unwrap()
                        .get(&key)
                        .map(|c| c.output.clone());
                    if let Some(output) = output {
                        if output.try_send(Output::End).is_err() {
                            self.cancel_background(
                                client,
                                &key,
                                crate::local_error(
                                    pb::ErrorCode::ResourceExhausted,
                                    "echo close queue full",
                                ),
                            )
                            .await;
                        }
                    }
                } else {
                    self.event_log(&key, "response_end", e.error.as_ref());
                    let result = {
                        let calls = self.calls.lock().unwrap();
                        calls.get(&key).map(|c| {
                            if c.receiving.is_some()
                                || e.item_count != c.received
                                || e.error.is_none()
                                    && c.received as usize
                                        != if c.config_request.is_some() {
                                            1
                                        } else {
                                            c.expected.len()
                                        }
                            {
                                Some(crate::local_error(
                                    pb::ErrorCode::ProtocolError,
                                    "application response cardinality",
                                ))
                            } else {
                                e.error.clone()
                            }
                        })
                    };
                    if let Some(error) = result {
                        self.finish(&key, Outcome::End(error, e.item_count));
                    }
                }
            }
            Some(pb::rpc_event::Body::Cancel(c)) => {
                let key = (peer, c.call_id);
                self.event_log(&key, "cancel", c.error.as_ref());
                self.finish(
                    &key,
                    Outcome::Cancel(c.error.unwrap_or_else(|| {
                        crate::local_error(pb::ErrorCode::Cancelled, "remote cancelled")
                    })),
                );
            }
            None => {}
        }
    }
    pub(super) async fn echo(
        &self,
        client: &Client,
        peer: Vec<u8>,
        text: String,
        bidi: bool,
        large: bool,
    ) -> Result<(), String> {
        let texts = if large {
            vec!["x".repeat(1048576 - 4); if bidi { 5 } else { 1 }]
        } else {
            vec![text; if bidi { 5 } else { 1 }]
        };
        let expected = texts
            .iter()
            .map(|s| Sha256::digest(s.as_bytes()).into())
            .collect();
        let request = pb::RpcRequest {
            call_id: id(),
            method_id: if bidi {
                "cyberbus.example.v1.Echo/Chat"
            } else {
                "cyberbus.example.v1.Echo/Unary"
            }
            .into(),
            request_type_url: REQUEST.into(),
            response_type_url: RESPONSE.into(),
            streaming: if bidi { 2 } else { 1 },
            semantic_version: "1.0.0".into(),
            timeout: Some(prost_types::Duration {
                seconds: 30,
                nanos: 0,
            }),
        };
        let key = (peer.clone(), request.call_id.clone());
        let (tx, mut result) = self.add(
            client.clone(),
            peer.clone(),
            request.clone(),
            true,
            expected,
        );
        if let Err(e) = Self::execute(
            client,
            pb::sdk_command::Body::RpcRequest(pb::InvokeRpc {
                peer_device_id: peer,
                request: Some(request),
            }),
        )
        .await
        {
            self.finish(&key, Outcome::Cancel(e.clone()));
            return Err(protocol_error(&e));
        }
        for text in texts {
            tx.send(Output::Item(example::EchoRequest { text }.encode_to_vec()))
                .await
                .map_err(|_| "RPC sender terminated")?;
        }
        tx.send(Output::End)
            .await
            .map_err(|_| "RPC sender terminated")?;
        self.wait(&mut result)
            .await
            .map(|count| println!("RPC_END items={count} error="))
    }
    pub(super) async fn public_config(&self, client: &Client, peer: Vec<u8>) -> Result<(), String> {
        let request_id = id();
        let request = pb::RpcRequest {
            call_id: id(),
            method_id: crate::public_config::METHOD.into(),
            request_type_url: crate::public_config::REQUEST.into(),
            response_type_url: crate::public_config::RESPONSE.into(),
            streaming: pb::RpcStreaming::Unary as i32,
            semantic_version: "1.0.0".into(),
            timeout: Some(prost_types::Duration {
                seconds: 30,
                nanos: 0,
            }),
        };
        let key = (peer.clone(), request.call_id.clone());
        let (tx, mut result) =
            self.add(client.clone(), peer.clone(), request.clone(), true, vec![]);
        self.calls
            .lock()
            .unwrap()
            .get_mut(&key)
            .unwrap()
            .config_request = Some(request_id.clone());
        if let Err(error) = Self::execute(
            client,
            pb::sdk_command::Body::RpcRequest(pb::InvokeRpc {
                peer_device_id: peer,
                request: Some(request),
            }),
        )
        .await
        {
            self.finish(&key, Outcome::Cancel(error.clone()));
            return Err(protocol_error(&error));
        }
        println!(
            "RPC_REQUEST_ACCEPTED mode=config {}",
            Self::correlation(&key)
        );
        tx.send(Output::Item(
            example::GetPublicConfigRequest { request_id }.encode_to_vec(),
        ))
        .await
        .map_err(|_| "configuration request sender terminated")?;
        tx.send(Output::End)
            .await
            .map_err(|_| "configuration request sender terminated")?;
        let count = self.wait(&mut result).await?;
        println!(
            "RPC_CONFIG_END {} items={count} error=",
            Self::correlation(&key)
        );
        Ok(())
    }
    async fn wait_outcome(
        result: &mut watch::Receiver<Option<Outcome>>,
    ) -> Result<Outcome, String> {
        loop {
            if let Some(outcome) = result.borrow_and_update().clone() {
                return Ok(outcome);
            }
            result
                .changed()
                .await
                .map_err(|_| "RPC terminal channel closed")?;
        }
    }
    async fn wait(&self, result: &mut watch::Receiver<Option<Outcome>>) -> Result<u64, String> {
        match Self::wait_outcome(result).await? {
            Outcome::End(None, count) => Ok(count),
            Outcome::End(Some(e), _) | Outcome::Cancel(e) => Err(protocol_error(&e)),
            Outcome::CancelRejected(e) => {
                Err(format!("SDK RpcCancel rejected: {}", protocol_error(&e)))
            }
        }
    }
    fn check_cancellation(outcome: Outcome, expected: pb::ErrorCode) -> Result<(), String> {
        let code = match outcome {
            Outcome::Cancel(e) | Outcome::End(Some(e), _) => e.code,
            Outcome::CancelRejected(e) => {
                return Err(format!("SDK RpcCancel rejected: {}", protocol_error(&e)))
            }
            Outcome::End(None, _) => return Err("cancellation incorrectly succeeded".into()),
        };
        if code != expected as i32 {
            return Err("unexpected cancellation error".into());
        }
        Ok(())
    }
    pub(super) async fn cancellation(
        &self,
        client: &Client,
        peer: Vec<u8>,
        deadline: bool,
    ) -> Result<(), String> {
        let request = pb::RpcRequest {
            call_id: id(),
            method_id: "cyberbus.example.v1.Echo/Chat".into(),
            request_type_url: REQUEST.into(),
            response_type_url: RESPONSE.into(),
            streaming: 2,
            semantic_version: "1.0.0".into(),
            timeout: Some(prost_types::Duration {
                seconds: if deadline { 1 } else { 30 },
                nanos: 0,
            }),
        };
        let key = (peer.clone(), request.call_id.clone());
        let (_tx, mut result) =
            self.add(client.clone(), peer.clone(), request.clone(), true, vec![]);
        if let Err(e) = Self::execute(
            client,
            pb::sdk_command::Body::RpcRequest(pb::InvokeRpc {
                peer_device_id: peer,
                request: Some(request),
            }),
        )
        .await
        {
            self.finish(&key, Outcome::Cancel(e.clone()));
            return Err(protocol_error(&e));
        }
        println!(
            "RPC_REQUEST_ACCEPTED mode={} {}",
            if deadline { "deadline" } else { "cancel" },
            Self::correlation(&key)
        );
        if !deadline {
            self.cancel(
                client,
                &key,
                crate::local_error(pb::ErrorCode::Cancelled, "explicit CLI cancellation"),
            )
            .await
            .map_err(|e| format!("SDK RpcCancel rejected: {}", protocol_error(&e)))?;
        }
        let expected = if deadline {
            pb::ErrorCode::DeadlineExceeded
        } else {
            pb::ErrorCode::Cancelled
        };
        Self::check_cancellation(Self::wait_outcome(&mut result).await?, expected)?;
        println!(
            "RPC_CANCELLED {:?} confirmation=local {}",
            expected,
            Self::correlation(&key)
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn closed_client() -> Client {
        let config = crate::ClientConfig::from_json(r#"{"issuer":"https://auth.example.com/oidc","client_id":"example-native-client","resource":"https://cyberbus.example/api","product_id":"cyberbus","native_clients":{"example-native-client":"cyberbus"},"redirect_uri":"http://127.0.0.1:18765/callback"}"#).unwrap();
        let client = Client::new(
            config,
            Box::new(cyberbus_auth::MemoryStore::default()),
            crate::StoreMode::CreateNew,
        )
        .await
        .unwrap();
        Adapter::execute(&client, pb::sdk_command::Body::SdkClose(pb::SdkClose {}))
            .await
            .unwrap();
        client
    }
    fn install(
        adapter: &Adapter,
        client: &Client,
        nanos: i32,
    ) -> (Key, mpsc::Sender<Output>, watch::Receiver<Option<Outcome>>) {
        let request = pb::RpcRequest {
            call_id: id(),
            timeout: Some(prost_types::Duration {
                seconds: if nanos == 0 { 30 } else { 0 },
                nanos,
            }),
            ..Default::default()
        };
        let key = (vec![7; 32], request.call_id.clone());
        let (tx, result) = adapter.add(client.clone(), key.0.clone(), request, true, vec![]);
        (key, tx, result)
    }
    fn reason(code: pb::ErrorCode) -> pb::ProtocolError {
        crate::local_error(code, "injected cancellation")
    }

    #[tokio::test]
    async fn explicit_cancel_propagates_real_sdk_rejection_even_matching_cancelled_code() {
        let client = closed_client().await;
        let adapter = Adapter::default();
        let (key, _tx, mut result) = install(&adapter, &client, 0);
        let e = adapter
            .cancel(&client, &key, reason(pb::ErrorCode::Cancelled))
            .await
            .unwrap_err();
        assert_eq!(e.code, pb::ErrorCode::Cancelled as i32);
        let outcome = Adapter::wait_outcome(&mut result).await.unwrap();
        assert!(matches!(outcome, Outcome::CancelRejected(_)));
        assert!(
            Adapter::check_cancellation(outcome, pb::ErrorCode::Cancelled)
                .unwrap_err()
                .contains("SDK RpcCancel rejected")
        );
        assert!(adapter.failed());
        assert!(!adapter.calls.lock().unwrap().contains_key(&key));
    }
    #[tokio::test]
    async fn deadline_writer_waits_for_correlated_sdk_expiry_on_both_endpoints() {
        // Any accidental RpcCancel against this real, closed SDK would reject
        // immediately and fail the test, just as the live expired call did.
        let client = closed_client().await;
        for outbound in [true, false] {
            let adapter = Adapter::default();
            let request = pb::RpcRequest {
                call_id: id(),
                timeout: Some(prost_types::Duration {
                    seconds: 0,
                    nanos: 1_000_000,
                }),
                ..Default::default()
            };
            let key = (vec![7; 32], request.call_id.clone());
            let (_tx, mut result) =
                adapter.add(client.clone(), key.0.clone(), request, outbound, vec![]);
            tokio::time::sleep(Duration::from_millis(10)).await;
            assert!(
                result.borrow().is_none(),
                "local timer must not publish a terminal or submit RpcCancel"
            );
            assert!(!adapter.failed());
            let body = if outbound {
                pb::rpc_event::Body::Cancel(pb::RpcCancel {
                    call_id: key.1.clone(),
                    error: Some(reason(pb::ErrorCode::DeadlineExceeded)),
                })
            } else {
                pb::rpc_event::Body::End(pb::RpcEnd {
                    call_id: key.1.clone(),
                    direction: 2,
                    item_count: 0,
                    error: Some(reason(pb::ErrorCode::DeadlineExceeded)),
                })
            };
            adapter
                .event(
                    &client,
                    pb::RpcEvent {
                        peer_device_id: key.0.clone(),
                        handler_id: vec![],
                        body: Some(body),
                    },
                )
                .await;
            let outcome = Adapter::wait_outcome(&mut result).await.unwrap();
            Adapter::check_cancellation(outcome, pb::ErrorCode::DeadlineExceeded).unwrap();
            // Let the background observer consume the same actual terminal.
            tokio::task::yield_now().await;
            assert!(!adapter.failed());
            assert!(!adapter.calls.lock().unwrap().contains_key(&key));
        }
    }
    #[tokio::test]
    async fn deadline_writer_fails_bounded_if_sdk_terminal_is_missing_or_for_another_peer() {
        let client = closed_client().await;
        let adapter = Adapter::default();
        let (key, _tx, mut result) = install(&adapter, &client, 1_000_000);
        adapter
            .event(
                &client,
                pb::RpcEvent {
                    peer_device_id: vec![8; 32],
                    handler_id: vec![],
                    body: Some(pb::rpc_event::Body::Cancel(pb::RpcCancel {
                        call_id: key.1.clone(),
                        error: Some(reason(pb::ErrorCode::DeadlineExceeded)),
                    })),
                },
            )
            .await;
        assert!(
            result.borrow().is_none(),
            "another peer's event cannot complete this call"
        );
        let outcome =
            tokio::time::timeout(Duration::from_secs(3), Adapter::wait_outcome(&mut result))
                .await
                .unwrap()
                .unwrap();
        assert!(
            matches!(&outcome, Outcome::End(Some(e), _) if e.code == pb::ErrorCode::Internal as i32)
        );
        assert!(Adapter::check_cancellation(outcome, pb::ErrorCode::DeadlineExceeded).is_err());
        assert!(adapter.failed());
        assert!(!adapter.calls.lock().unwrap().contains_key(&key));
    }
    #[tokio::test]
    async fn sdk_event_before_rejected_cancel_reply_never_publishes_success() {
        let client = closed_client().await;
        for code in [pb::ErrorCode::Cancelled, pb::ErrorCode::DeadlineExceeded] {
            let adapter = Adapter::default();
            let (key, _tx, mut result) = install(&adapter, &client, 0);
            assert!(adapter.begin_cancel(&key));
            // Deliver through the same event path used by the real SDK consumer.
            adapter
                .event(
                    &client,
                    pb::RpcEvent {
                        peer_device_id: key.0.clone(),
                        handler_id: vec![],
                        body: Some(pb::rpc_event::Body::Cancel(pb::RpcCancel {
                            call_id: key.1.clone(),
                            error: Some(reason(code)),
                        })),
                    },
                )
                .await;
            assert!(
                result.borrow().is_none(),
                "event must wait for RpcCancel result"
            );
            adapter.complete_cancel(&key, reason(code), &Err(reason(code)));
            assert!(Adapter::check_cancellation(
                Outcome::CancelRejected(reason(code)),
                pb::ErrorCode::Cancelled
            )
            .is_err());
            let outcome = Adapter::wait_outcome(&mut result).await.unwrap();
            assert!(Adapter::check_cancellation(outcome, code)
                .unwrap_err()
                .contains("SDK RpcCancel rejected"));
        }
    }
    #[tokio::test]
    async fn accepted_cancel_preserves_first_real_terminal_and_coalesces_duplicate_attempts() {
        let client = closed_client().await;
        for successful_response in [false, true] {
            let adapter = Adapter::default();
            let (key, _tx, mut result) = install(&adapter, &client, 0);
            assert!(adapter.begin_cancel(&key));
            assert!(!adapter.begin_cancel(&key));
            let terminal = if successful_response {
                Outcome::End(None, 0)
            } else {
                Outcome::Cancel(reason(pb::ErrorCode::Cancelled))
            };
            adapter.finish(&key, terminal);
            adapter.finish(
                &key,
                Outcome::Cancel(reason(pb::ErrorCode::DeadlineExceeded)),
            );
            adapter.complete_cancel(&key, reason(pb::ErrorCode::Cancelled), &Ok(()));
            let outcome = Adapter::wait_outcome(&mut result).await.unwrap();
            assert_eq!(
                Adapter::check_cancellation(outcome, pb::ErrorCode::Cancelled).is_ok(),
                !successful_response
            );
            assert!(!adapter.failed());
        }
    }
    #[tokio::test]
    async fn accepted_local_cancel_and_sdk_expiry_are_valid_but_distinct_from_rejection() {
        let client = closed_client().await;
        let adapter = Adapter::default();
        let (key, _tx, mut result) = install(&adapter, &client, 0);
        assert!(adapter.begin_cancel(&key));
        adapter.complete_cancel(&key, reason(pb::ErrorCode::Cancelled), &Ok(()));
        Adapter::check_cancellation(
            Adapter::wait_outcome(&mut result).await.unwrap(),
            pb::ErrorCode::Cancelled,
        )
        .unwrap();
        Adapter::check_cancellation(
            Outcome::End(Some(reason(pb::ErrorCode::DeadlineExceeded)), 0),
            pb::ErrorCode::DeadlineExceeded,
        )
        .unwrap();
        assert!(Adapter::check_cancellation(
            Outcome::Cancel(reason(pb::ErrorCode::Unavailable)),
            pb::ErrorCode::Cancelled
        )
        .is_err());
    }
    #[tokio::test]
    async fn terminal_log_direction_survives_local_finish_and_never_uses_handler_binding() {
        let client = closed_client().await;
        let adapter = Adapter::default();
        let (caller_key, _tx, _result) = install(&adapter, &client, 0);
        // A locally registered handler may be pinned for outbound calls too.
        adapter
            .calls
            .lock()
            .unwrap()
            .get_mut(&caller_key)
            .unwrap()
            .handler_id = vec![1; 16];
        assert_eq!(adapter.role(&caller_key), "caller");
        adapter.finish(
            &caller_key,
            Outcome::Cancel(reason(pb::ErrorCode::Cancelled)),
        );
        assert_eq!(adapter.role(&caller_key), "caller");
        let request = pb::RpcRequest {
            call_id: id(),
            ..Default::default()
        };
        let callee_key = (vec![8; 32], request.call_id.clone());
        let (_tx, _result) = adapter.add(client, callee_key.0.clone(), request, false, vec![]);
        adapter.finish(
            &callee_key,
            Outcome::Cancel(reason(pb::ErrorCode::DeadlineExceeded)),
        );
        assert_eq!(adapter.role(&callee_key), "callee");
        assert_eq!(adapter.role(&(vec![9; 32], id())), "unknown");
    }
    #[tokio::test]
    async fn rejected_initial_request_leaves_no_adapter_call_and_cannot_succeed() {
        let client = closed_client().await;
        let adapter = Adapter::default();
        for deadline in [false, true] {
            assert!(adapter
                .cancellation(&client, vec![7; 32], deadline)
                .await
                .is_err());
            assert!(adapter.calls.lock().unwrap().is_empty());
        }
    }
}
