use futures::{
    stream::{FuturesUnordered, SplitSink, SplitStream},
    FutureExt, SinkExt, StreamExt,
};
use std::{collections::VecDeque, future::Future, pin::Pin, task::Poll};
use tokio::{
    net::TcpStream,
    sync::{broadcast, broadcast::error::TryRecvError, mpsc, oneshot, oneshot::error::RecvError},
};
use tokio_tungstenite::{tungstenite::Message, MaybeTlsStream, WebSocketStream};
use tracing::{error, info, trace, warn};
use uuid::Uuid;

use crate::{
    api::commitments::server::{
        spec::{CommitmentError, RejectionError},
        CommitmentEvent,
    },
    primitives::{
        commitment::{InclusionRequestIdentified, SignedCommitment},
        misc::{Identified, IntoIdentified},
        CommitmentRequest,
    },
};

/// The reason for interrupting the [CommitmentRequestProcessor] future.
#[derive(Debug)]
pub enum InterruptReason {
    /// The processor was interrupted by the user.
    Shutdown,
    /// The websocket read stream was terminated.
    ReadStreamTerminated,
    /// The websocket connection was closed by the server
    ConnectionClosed,
}

type PendingCommitmentResponse =
    Identified<oneshot::Receiver<Result<SignedCommitment, CommitmentError>>, Uuid>;

impl Future for PendingCommitmentResponse {
    type Output = (Uuid, Result<Result<SignedCommitment, CommitmentError>, RecvError>);
    fn poll(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let id = this.id();

        match this.inner_mut().poll_unpin(cx) {
            Poll::Ready(res) => Poll::Ready((id, res)),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// The [CommitmentRequestProcessor] handles incoming commitment requests a the websocket
/// connection, and forwards them to the [CommitmentEvent] tx channel for processing.
#[allow(missing_debug_implementations)]
pub struct CommitmentRequestProcessor {
    /// The URL of the connected websocket server.
    url: String,
    /// The channel to send commitment events to be processed.
    api_events_tx: mpsc::Sender<CommitmentEvent>,
    /// The websocket writer sink.
    write_sink: SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, Message>,
    /// The websocket reader stream.
    read_stream: SplitStream<WebSocketStream<MaybeTlsStream<TcpStream>>>,
    /// The receiver for keep-alive ping messages.
    ping_rx: broadcast::Receiver<()>,
    /// The receiver for shutdown signals.
    shutdown_rx: broadcast::Receiver<()>,
    /// The collection of pending commitment requests responses, sent with [api_events_tx].
    /// NOTE: Is there a better way to avoid this monster type?
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
        tx: mpsc::Sender<CommitmentEvent>,
        write: SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, Message>,
        read: SplitStream<WebSocketStream<MaybeTlsStream<TcpStream>>>,
        ping_rx: broadcast::Receiver<()>,
        shutdown_rx: broadcast::Receiver<()>,
    ) -> Self {
        Self {
            url,
            api_events_tx: tx,
            write_sink: write,
            read_stream: read,
            ping_rx,
            shutdown_rx,
            pending_commitment_responses: FuturesUnordered::new(),
            outgoing_messages: VecDeque::new(),
        }
    }
}

impl Future for CommitmentRequestProcessor {
    type Output = InterruptReason;

    fn poll(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        let this = self.get_mut();
        let rpc_url = this.url.clone();

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
                let (id, response) = response;

                let Ok(result_commitment) = response else {
                    error!("failed to receive commitment response. dropped sender");
                    continue;
                };

                if let Ok(commitment) = result_commitment {
                    trace!(?rpc_url, ?commitment, "received commitment response");
                    let message = match &commitment {
                        SignedCommitment::Inclusion(ic) => {
                            ic.into_identified(id);
                            Message::text(
                                serde_json::to_string(&ic)
                                    .expect("to stringify inclusion commitment"),
                            )
                        }
                    };

                    // Add the message to the outgoing messages queue
                    this.outgoing_messages.push_back(message);
                }
            }

            // 2. Process outgoing messages
            while let Some(message) = this.outgoing_messages.pop_front() {
                // Check if the write sink is able to receive data.
                match this.write_sink.poll_ready_unpin(cx) {
                    Poll::Ready(Ok(())) => {
                        progress = true;

                        // Try to send the message to the sink, for later flushing.
                        if let Err(e) = this.write_sink.start_send_unpin(message) {
                            error!(?e, ?rpc_url, "failed to send message to websocket write sink");
                            continue;
                        }
                    }
                    Poll::Pending => {
                        // Put the message back and try again later
                        this.outgoing_messages.push_front(message);
                        break;
                    }
                    Poll::Ready(Err(e)) => {
                        error!(?e, "sink error while sending message to websocket");
                        continue;
                    }
                }
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
            match this.shutdown_rx.try_recv() {
                Ok(_) => {
                    info!("received shutdown signal. closing websocket connection...");
                    return Poll::Ready(InterruptReason::Shutdown);
                }
                Err(TryRecvError::Closed) => {
                    error!("shutdown channel closed");
                }
                _ => {}
            }

            // Incoming work tasks

            // 5. Handle incoming websocket messages from the read stream.
            while let Poll::Ready(maybe_message) = this.read_stream.poll_next_unpin(cx) {
                progress = true;

                let Some(res_message) = maybe_message else {
                    warn!(?rpc_url, "websocket read streaam terminated");
                    return Poll::Ready(InterruptReason::ReadStreamTerminated);
                };

                match res_message {
                    Ok(Message::Text(text)) => {
                        trace!(?rpc_url, text, "received text message from websocket connection");
                        // Create the channel to send and receive the commitment response
                        let (tx, rx) = oneshot::channel();

                        let request = serde_json::from_str::<InclusionRequestIdentified>(&text)
                            .map_err(|e| CommitmentError::Rejected(RejectionError::Json(e)));

                        let id = match request {
                            Ok(request) => {
                                let id = request.id();
                                let request = CommitmentRequest::Inclusion(request.into_inner());

                                let event = CommitmentEvent { request, response: tx };
                                if let Err(err) = this.api_events_tx.try_send(event) {
                                    error!(?err, "failed to forward commitment event to channel");
                                }

                                id
                            }
                            Err(err) => {
                                warn!(?err, ?rpc_url, "failed to parse commitment request");
                                if let Err(e) = tx.send(Err(err)) {
                                    error!(?e, "failed to send rejection through channel");
                                }
                                continue;
                            }
                        };

                        let pending_response = PendingCommitmentResponse::new(rx, id);

                        // add the pending response to this buffer for later processing
                        this.pending_commitment_responses.push(pending_response);
                    }
                    Ok(Message::Close(_)) => {
                        warn!(?rpc_url, "websocket connection closed by server");
                        return Poll::Ready(InterruptReason::ConnectionClosed);
                    }
                    Ok(_) => {} // ignore other message types
                    Err(e) => {
                        error!(?e, ?rpc_url, "error reading message from websocket connection");
                    }
                }
            }

            // 6. Handle ping messages
            match this.ping_rx.try_recv() {
                Ok(_) => {
                    progress = true;
                    this.outgoing_messages.push_back(Message::Ping(vec![8, 0, 1, 7]));
                }
                Err(TryRecvError::Closed) => {
                    error!("ping channel for keep-alive messages closed");
                }
                Err(TryRecvError::Lagged(lost)) => {
                    error!("ping channel for keep-alives lagged by {} messages", lost)
                }
                _ => {}
            }

            if !progress {
                return Poll::Pending;
            }
        }
    }
}
