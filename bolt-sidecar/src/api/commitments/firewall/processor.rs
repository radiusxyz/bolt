use ethereum_consensus::crypto::PublicKey;
use futures::{
    pin_mut,
    stream::{FuturesUnordered, SplitSink, SplitStream},
    FutureExt, SinkExt, StreamExt,
};
use serde::Serialize;
use serde_json::{json, Value};
use std::{collections::HashSet, time::Duration};
use std::{collections::VecDeque, future::Future, pin::Pin, task::Poll};
use tokio::{
    net::TcpStream,
    sync::{
        mpsc,
        oneshot::{self, error::RecvError},
        watch,
    },
    time::Interval,
};
use tokio_tungstenite::{
    tungstenite::{self, Message},
    MaybeTlsStream, WebSocketStream,
};
use tracing::{debug, error, info, instrument, trace, warn};
use uuid::Uuid;

use crate::{
    api::commitments::{
        server::CommitmentEvent,
        spec::{
            CommitmentError, MetadataResponse, GET_METADATA_METHOD, GET_VERSION_METHOD,
            REQUEST_INCLUSION_METHOD,
        },
    },
    common::BOLT_SIDECAR_VERSION,
    config::limits::LimitsOpts,
    primitives::{
        commitment::SignedCommitment,
        jsonrpc::{
            JsonRpcErrorResponse, JsonRpcRequestUuid, JsonRpcResponse, JsonRpcSuccessResponse,
        },
        misc::{Identified, IntoIdentified},
        CommitmentRequest, InclusionRequest,
    },
};

/// The interval at which to send ping messages from connected clients.
#[cfg(test)]
const PING_INTERVAL: Duration = Duration::from_secs(4);
#[cfg(not(test))]
const PING_INTERVAL: Duration = Duration::from_secs(30);

/// The reason for interrupting the [CommitmentRequestProcessor] future.
#[derive(Debug)]
pub enum InterruptReason {
    /// The processor was interrupted by the user.
    Shutdown,
    /// The websocket read stream was terminated.
    ReadStreamTerminated,
    /// The websocket connection was closed by the server
    ConnectionClosed,
    /// An error occurred in the write sink of the websocket connection.
    WriteSinkError(tungstenite::Error),
}

type PendingCommitmentResponse =
    Identified<oneshot::Receiver<Result<SignedCommitment, CommitmentError>>, Uuid>;

type CommitmentResponse = Result<Result<SignedCommitment, CommitmentError>, RecvError>;

impl Future for PendingCommitmentResponse {
    type Output = Identified<CommitmentResponse, Uuid>;

    fn poll(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let id = this.id();

        match this.inner_mut().poll_unpin(cx) {
            Poll::Ready(res) => Poll::Ready(res.into_identified(id)),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// The internal state of the [CommitmentRequestProcessor].
#[derive(Debug, Clone, Default)]
pub struct ProcessorState {
    /// The running limits of the sidecar.
    limits: LimitsOpts,
    /// The available validator public keys in the sidecar.
    available_validators: HashSet<PublicKey>,
}

impl ProcessorState {
    /// Creates a new instance of the [ProcessorState].
    pub fn new(limits: LimitsOpts, available_validators: HashSet<PublicKey>) -> Self {
        Self { limits, available_validators }
    }
}

/// The [CommitmentRequestProcessor] handles incoming commitment requests a the websocket
/// connection, and forwards them to the [CommitmentEvent] tx channel for processing.
#[allow(missing_debug_implementations)]
pub struct CommitmentRequestProcessor {
    /// The URL of the connected websocket server.
    url: String,
    /// The internal state of the processor.
    state: ProcessorState,
    /// The channel to send commitment events to be processed.
    api_events_tx: mpsc::Sender<CommitmentEvent>,
    /// The websocket writer sink.
    write_sink: SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, Message>,
    /// The websocket reader stream.
    read_stream: SplitStream<WebSocketStream<MaybeTlsStream<TcpStream>>>,
    /// The interval at which to send ping messages to the connected websocket server.
    ping_interval: Interval,
    /// The receiver for shutdown signals.
    shutdown_rx: watch::Receiver<()>,
    /// The collection of pending commitment requests responses, sent with [api_events_tx].
    /// SAFETY: the `poll` implementation of this struct promptly handles these responses and
    /// ensures this vector doesn't grow indefinitely.
    pending_commitment_responses: FuturesUnordered<PendingCommitmentResponse>,
    /// The collection of outgoing messages to be sent to the connected websocket server.
    outgoing_messages: VecDeque<Message>,
}

impl CommitmentRequestProcessor {
    /// Creates a new instance of the [CommitmentRequestProcessor].
    pub fn new(
        url: String,
        state: ProcessorState,
        tx: mpsc::Sender<CommitmentEvent>,
        stream: WebSocketStream<MaybeTlsStream<TcpStream>>,
        shutdown_rx: watch::Receiver<()>,
    ) -> Self {
        let (write_sink, read_stream) = stream.split();

        Self {
            url,
            state,
            api_events_tx: tx,
            write_sink,
            read_stream,
            ping_interval: tokio::time::interval(PING_INTERVAL),
            shutdown_rx,
            pending_commitment_responses: FuturesUnordered::new(),
            outgoing_messages: VecDeque::new(),
        }
    }
}

impl Future for CommitmentRequestProcessor {
    type Output = InterruptReason;

    #[instrument(name = "", skip_all, fields(url = %self.url))]
    fn poll(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        let this = self.get_mut();

        loop {
            let mut progress = false;
            // It is good practice to first prioritze local work done
            // Reference: https://github.com/libp2p/rust-libp2p/blob/3c1f856e868fac094fe0fb0fa860c19fdff8c9ca/docs/coding-guidelines.md#prioritize-local-work-over-new-work-from-a-remote

            // Local work tasks

            // 1. Handle commitment request responses after they've been processed.
            while let Poll::Ready(Some(response)) =
                this.pending_commitment_responses.poll_next_unpin(cx)
            {
                progress = true;
                this.handle_commitment_response(response);
            }

            // 2. If the write sink is ready, process outgoing messages.
            match this.write_sink.poll_ready_unpin(cx) {
                Poll::Ready(Ok(())) => {
                    while let Some(message) = this.outgoing_messages.pop_front() {
                        progress = true;

                        // Try to send the message to the sink, for later flushing.
                        if let Err(e) = this.write_sink.start_send_unpin(message) {
                            error!(?e, "failed to send message to websocket write sink");
                            continue;
                        }
                    }
                }
                Poll::Ready(Err(e)) => {
                    // We cannot proceed further. Better to close the connection and try again.
                    return Poll::Ready(InterruptReason::WriteSinkError(e));
                }
                Poll::Pending => { /* fallthrough */ }
            }

            // 3. Ensure the write sink is flushed so that message are sent to the caller server.
            //
            // NOTE: We're not considering "progress" flushing the sink, i.e. `Poll::Ready(())`.
            // That is because flushing an empty sink would lead to run this loop indefinitely
            if let Poll::Ready(Err(e)) = this.write_sink.poll_flush_unpin(cx) {
                error!(?e, "failed to flush websocket write sink");
                continue;
            }

            // 4. Handle shutdown signals before accepting any new work
            //
            // NOTE: (thedevbirb, 2025-01-15) this is a temporary workaround to ensure that the
            // shutdown signal wakes the task. https://github.com/chainbound/bolt/issues/673
            // will be a generalized solution to this problem.
            let mut shutdown = this.shutdown_rx.clone();
            let shutdown = shutdown.changed();
            pin_mut!(shutdown);
            match shutdown.poll_unpin(cx) {
                Poll::Ready(Ok(_)) => {
                    info!("received shutdown signal. closing websocket connection...");
                    return Poll::Ready(InterruptReason::Shutdown);
                }
                Poll::Ready(Err(_)) => {
                    error!("shutdown channel closed");
                }
                Poll::Pending => { /* fallthrough */ }
            }

            // Incoming work tasks

            // 5. Handle incoming websocket messages from the read stream.
            while let Poll::Ready(maybe_message) = this.read_stream.poll_next_unpin(cx) {
                progress = true;

                let Some(res_message) = maybe_message else {
                    warn!("websocket read stream terminated");
                    return Poll::Ready(InterruptReason::ReadStreamTerminated);
                };

                match res_message {
                    Ok(Message::Text(text)) => {
                        this.handle_text_message(text);
                    }
                    Ok(Message::Close(_)) => {
                        warn!("websocket connection closed by server");
                        return Poll::Ready(InterruptReason::ConnectionClosed);
                    }
                    Ok(Message::Binary(data)) => {
                        debug!(bytes_len = data.len(), "received unexpected binary message");
                    }
                    Ok(Message::Ping(_)) => {
                        trace!("received ping message");
                    }
                    Ok(Message::Pong(_)) => {
                        trace!("received pong message");
                    }
                    Ok(Message::Frame(_)) => {
                        debug!("received unexpected raw frame");
                    }
                    Err(e) => {
                        error!(?e, "error reading message from websocket connection");
                    }
                }
            }

            // 6. Handle ping messages
            match this.ping_interval.poll_tick(cx) {
                Poll::Ready(_) => {
                    progress = true;

                    trace!("sending ping message to websocket connection");
                    this.outgoing_messages.push_back(Message::Ping(vec![8, 0, 1, 7]));
                }
                Poll::Pending => { /* fallthrough */ }
            }

            if !progress {
                return Poll::Pending;
            }
        }
    }
}

impl CommitmentRequestProcessor {
    fn handle_commitment_response(&mut self, response: Identified<CommitmentResponse, Uuid>) {
        let id = response.id();

        let Ok(result_commitment) = response.into_inner() else {
            error!("failed to receive commitment response. dropped sender");
            return;
        };

        let response: JsonRpcResponse = match result_commitment {
            Ok(commitment) => JsonRpcSuccessResponse::new(json!(commitment))
                .with_id(Value::String(id.to_string()))
                .into(),
            Err(e) => {
                JsonRpcErrorResponse::new(e.into()).with_id(Value::String(id.to_string())).into()
            }
        };

        let message =
            Message::Text(serde_json::to_string(&response).expect("to stringify response"));

        // Add the message to the outgoing messages queue
        self.outgoing_messages.push_back(message);
    }

    fn handle_text_message(&mut self, text: String) {
        trace!(text, "received text message from websocket connection");
        let (tx, rx) = oneshot::channel();

        let request = match serde_json::from_str::<JsonRpcRequestUuid>(&text) {
            Ok(req) => req,
            Err(e) => {
                warn!(?e, "failed to parse JSON-RPC request");
                return;
            }
        };

        let id = request.id;

        match request.method.as_str() {
            GET_VERSION_METHOD => {
                let response =
                    JsonRpcSuccessResponse::new(Value::String(BOLT_SIDECAR_VERSION.clone()))
                        .with_uuid(id)
                        .into();
                self.send_response(response);
            }
            GET_METADATA_METHOD => {
                let public_key = request
                    .params
                    .first()
                    .and_then(|p| p.as_str())
                    .and_then(|p| hex::decode(p).ok())
                    .and_then(|p| PublicKey::try_from(p.as_slice()).ok());

                let response: JsonRpcResponse = if let Some(public_key) = public_key {
                    if self.state.available_validators.contains(&public_key) {
                        let metadata = MetadataResponse {
                            limits: self.state.limits,
                            version: BOLT_SIDECAR_VERSION.to_string(),
                        };
                        JsonRpcSuccessResponse::new(json!(metadata)).into()
                    } else {
                        JsonRpcErrorResponse::new(CommitmentError::ValidatorNotAvailable.into())
                            .into()
                    }
                } else {
                    JsonRpcErrorResponse::new(
                        CommitmentError::InvalidParams(
                            "missing or invalid validator public key".into(),
                        )
                        .into(),
                    )
                    .into()
                };

                self.send_response(response.with_uuid(id));
            }
            REQUEST_INCLUSION_METHOD => {
                let Some(param) = request.params.first().cloned() else {
                    let response: JsonRpcResponse = JsonRpcErrorResponse::new(
                        CommitmentError::InvalidParams("missing inclusion request".into()).into(),
                    )
                    .with_uuid(id)
                    .into();
                    self.send_response(response);
                    return;
                };

                let inclusion_request = match serde_json::from_value::<InclusionRequest>(param) {
                    Ok(req) => req,
                    Err(e) => {
                        let msg = format!("failed to parse inclusion request: {}", e);
                        error!(?e, "failed to parse inclusion request");
                        let response: JsonRpcResponse =
                            JsonRpcErrorResponse::new(CommitmentError::InvalidParams(msg).into())
                                .with_uuid(id)
                                .into();
                        self.send_response(response);
                        return;
                    }
                };

                let commitment_request = CommitmentRequest::Inclusion(inclusion_request);
                let commitment_event =
                    CommitmentEvent { request: commitment_request, response: tx };

                if let Err(e) = self.api_events_tx.try_send(commitment_event) {
                    error!(?e, "failed to send commitment event through channel");
                    let response: JsonRpcResponse =
                        JsonRpcErrorResponse::new(CommitmentError::Internal.into())
                            .with_uuid(id)
                            .into();
                    self.send_response(response);
                    return;
                }

                // Push the pending commitment response to the queue
                self.pending_commitment_responses.push(PendingCommitmentResponse::new(rx, id));
            }
            other => {
                warn!("unsupported method: {}", other);
            }
        };
    }

    fn send_response<T: Serialize>(&mut self, response: JsonRpcResponse<T>) {
        let message =
            Message::text(serde_json::to_string(&response).expect("to stringify response"));
        self.outgoing_messages.push_back(message);
    }
}
