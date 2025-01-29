use alloy::signers::local::PrivateKeySigner;
use ethereum_consensus::crypto::PublicKey;
use std::{
    collections::HashSet,
    fmt::{self, Debug, Formatter},
    sync::Arc,
};
use thiserror::Error;
use tokio::sync::{mpsc, watch};
use tokio_tungstenite::{
    connect_async_with_config,
    tungstenite::{self, client::IntoClientRequest, protocol::WebSocketConfig},
};
use tracing::{error, info};

use reqwest::Url;

use crate::{
    api::commitments::server::CommitmentEvent,
    common::{
        backoff::{retry_with_backoff_if, RetryConfig},
        secrets::EcdsaSecretKeyWrapper,
    },
    config::{chain::Chain, limits::LimitsOpts},
    primitives::misc::ShutdownSignal,
};

use super::{
    jwt::ProposerAuthClaims,
    processor::{CommitmentRequestProcessor, InterruptReason, ProcessorState},
};

/// The maximum messages size to receive via websocket connection, in bits, set to 32MiB.
///
/// It is enough to account for a commitment request with 6 blobs and the largest
/// memory-consuming transactions you can create. Reference: https://xn--2-umb.com/22/eth-max-mem/
const MAX_MESSAGE_SIZE: usize = 32 << 20;

/// Whether to use the Nagle algorithm for TCP connections.
///
/// Reference: https://en.wikipedia.org/wiki/Nagle%27s_algorithm
const USE_NAGLE: bool = false;

#[derive(Debug, Error)]
enum ConnectionHandlerError {
    #[error("error while opening websocket connection: {0}")]
    OnConnectionError(#[from] tokio_tungstenite::tungstenite::Error),
    #[error("error while processing commitments")]
    ProcessorInterrupted(InterruptReason),
}

/// A [CommitmentsReceiver] connects to multiple firewall-ed websocket RPC servers and
/// forwards [CommitmentEvent]s to a single receiver, return upon calling the
/// `[CommitmentsReceiver::run]` method.
pub struct CommitmentsReceiver {
    /// The operator's private key to sign authentication requests when opening websocket
    /// connections with RPCs.
    operator_private_key: EcdsaSecretKeyWrapper,
    /// The chain ID of the chain the sidecar is running. Used for authentication purposes.
    chain: Chain,
    /// The URLs of the websocket servers to connect to.
    urls: Vec<Url>,
    /// The shutdown signal.
    signal: ShutdownSignal,
    /// The sidecar running limits.
    limits: LimitsOpts,
    /// The available validator public keys on the sidecar.
    available_validators: HashSet<PublicKey>,
}

impl Debug for CommitmentsReceiver {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("CommitmentsReceiver")
            .field("operator_private_key", &"********")
            .field("chain", &self.chain)
            .field("urls", &self.urls)
            .finish()
    }
}

impl CommitmentsReceiver {
    /// Creates a new instance of the commitments receiver.
    pub fn new(
        operator_private_key: EcdsaSecretKeyWrapper,
        chain: Chain,
        limits: LimitsOpts,
        urls: Vec<Url>,
        available_validators: HashSet<PublicKey>,
    ) -> Self {
        Self {
            operator_private_key,
            chain,
            urls,
            limits,
            available_validators,
            signal: Box::pin(async {
                let _ = tokio::signal::ctrl_c().await;
            }),
        }
    }

    /// Sets the shutdown signal for the closing the open connections.
    pub fn with_shutdown(mut self, signal: ShutdownSignal) -> Self {
        self.signal = signal;
        self
    }

    /// Runs the [CommitmentsReceiver] and returns a receiver for incoming commitment
    /// events.
    pub fn run(self) -> mpsc::Receiver<CommitmentEvent> {
        // mspc channel where every websocket connection will send commitment events over its own
        // tx to a single receiver.
        let (api_events_tx, api_events_rx) = mpsc::channel(self.urls.len() * 2);
        let (shutdown_tx, shutdown_rx) = watch::channel(());

        ShutdownTicker::new(self.signal).spawn(shutdown_tx);

        let signer = PrivateKeySigner::from_signing_key(self.operator_private_key.0);
        let state = Arc::new(ProcessorState::new(self.limits, self.available_validators));
        let retry_config = RetryConfig { initial_delay_ms: 100, max_delay_secs: 2, factor: 2 };

        for url in &self.urls {
            // NOTE: We're cloning the variables here because we're moving the inputs into an async
            // task.
            let url = url.to_string();
            let api_events_tx = api_events_tx.clone();
            let shutdown_rx = shutdown_rx.clone();
            let signer = signer.clone();
            let state = state.clone();

            tokio::spawn(async move {
                retry_with_backoff_if(
                    None,
                    Some(retry_config),
                    // NOTE: this needs to be a closure because it must be re-called upon failure.
                    // As such we also need to clone the inputs again.
                    move || {
                        let url = url.clone();
                        let jwt = ProposerAuthClaims::new_from_signer(
                            url.clone(),
                            self.chain,
                            None,
                            signer.clone(),
                        )
                        .to_jwt()
                        .expect("failed to produce JWT");

                        let api_events_tx = api_events_tx.clone();
                        let shutdown_rx = shutdown_rx.clone();
                        let state = state.clone();

                        async move {
                            handle_connection(url, state, jwt, api_events_tx, shutdown_rx).await
                        }
                    },
                    handle_error,
                )
                .await
            });
        }

        api_events_rx
    }

    /// Returns the local addr the server is listening on (or configured with).
    pub fn urls(&self) -> &[Url] {
        self.urls.as_slice()
    }
}

/// Opens the websocket connection and starts the commitment request processor.
async fn handle_connection(
    url: String,
    state: Arc<ProcessorState>,
    jwt: String,
    api_events_tx: mpsc::Sender<CommitmentEvent>,
    shutdown_rx: watch::Receiver<()>,
) -> Result<(), ConnectionHandlerError> {
    let ws_config =
        WebSocketConfig { max_message_size: Some(MAX_MESSAGE_SIZE), ..Default::default() };

    let mut request = url.clone().into_client_request()?;
    request
        .headers_mut()
        .insert("Authorization", format!("Bearer {}", jwt).parse().expect("valid header"));

    match connect_async_with_config(request, Some(ws_config), USE_NAGLE).await {
        Ok((stream, response)) => {
            info!(?url, ?response, "opened websocket connection");

            // For each opened connection, create a new commitment processor
            // able to handle incoming message requests.
            let commitment_request_processor =
                CommitmentRequestProcessor::new(url, state, api_events_tx, stream, shutdown_rx);
            let interrupt_reason = commitment_request_processor.await;
            Err(ConnectionHandlerError::ProcessorInterrupted(interrupt_reason))
        }
        Err(e) => Err(ConnectionHandlerError::OnConnectionError(e)),
    }
}

/// Handles errors that occur while processing a websocket connection and returns a boolean
/// indicating whether the connection should be retried.
fn handle_error(err: &ConnectionHandlerError) -> bool {
    let mut is_shutdown = false;
    match err {
        ConnectionHandlerError::OnConnectionError(e) => match e {
            tungstenite::Error::Http(response) => {
                let body = response
                    .body()
                    .as_ref()
                    .map(|b| String::from_utf8_lossy(b))
                    .unwrap_or_default();
                let staus = response.status();
                error!(?staus, ?body, "http error while opening websocket connection. Retrying...");
            }
            e => {
                error!(?e, "error while opening websocket connection. Retrying...");
            }
        },
        ConnectionHandlerError::ProcessorInterrupted(InterruptReason::Shutdown) => {
            info!("Shutting down websocket connection");
            is_shutdown = true;
        }
        ConnectionHandlerError::ProcessorInterrupted(reason) => {
            error!(?reason, "commitment processor interrupted. Retrying...");
        }
    }
    !is_shutdown
}

/// A shutdown ticker that sends a shutdown signal to connected clients.
struct ShutdownTicker {
    signal: ShutdownSignal,
}

impl ShutdownTicker {
    /// Creates a new instance of the shutdown ticker.
    pub fn new(signal: ShutdownSignal) -> Self {
        Self { signal }
    }

    /// Spawn a task to shutdown message to the connected clients.
    pub fn spawn(self, tx: watch::Sender<()>) {
        tokio::spawn(async move {
            self.signal.await;

            if tx.send(()).is_err() {
                error!("failed to send shutdown signal: dropped receiver");
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use std::{net::SocketAddr, ops::ControlFlow, time::Duration};

    use axum::{
        body::Bytes,
        extract::{
            ws::{CloseFrame, Message, Utf8Bytes, WebSocket},
            ConnectInfo, WebSocketUpgrade,
        },
        response::IntoResponse,
        routing::get,
        Json, Router,
    };
    use axum_extra::{
        headers::{authorization::Bearer, Authorization, UserAgent},
        TypedHeader,
    };
    use futures::{FutureExt, SinkExt, StreamExt};
    use reqwest::StatusCode;
    use serde::Serialize;
    use tokio::sync::broadcast;
    use tracing::{debug, error, info, warn};
    use uuid::Uuid;

    use crate::{
        api::commitments::spec::{GET_VERSION_METHOD, REQUEST_INCLUSION_METHOD},
        common::secrets::EcdsaSecretKeyWrapper,
        config::chain::Chain,
        primitives::{
            commitment::SignedCommitment, jsonrpc::JsonRpcRequest, misc::IntoSigned,
            signature::AlloySignatureWrapper, InclusionRequest,
        },
    };

    use super::*;

    const FIREWALL_STREAM_PATH: &str = "/api/v1/firewall_stream";

    #[tokio::test]
    async fn test_firewall_rpc_stream_ws() {
        let _ = tracing_subscriber::fmt::try_init();

        // Shutdown servers after closing connections so we can test both types of shutdowns
        const CONNECTIONS_SHUTDOWN_IN_SECS: u64 = 5;
        const SERVERS_SHUTDOWN_IN_SECS: u64 = 7;

        let operator_private_key = EcdsaSecretKeyWrapper::random();

        // Create a Single-Producer-Multiple-Consumer (SPMC) channel via a broadcast that sends a
        // shutdown signal to all websocket servers.
        let (shutdown_servers_tx, shutdown_servers_rx) = broadcast::channel::<()>(1);

        let (shutdown_connections_tx, mut shutdown_connections_rx) = broadcast::channel::<()>(1);

        let port_1 = create_websocket_server(shutdown_servers_rx.resubscribe()).await;
        let port_2 = create_websocket_server(shutdown_servers_rx.resubscribe()).await;

        info!("Server 1 running on port: {}", port_1);
        info!("Server 2 running on port: {}", port_2);

        let stream = CommitmentsReceiver::new(
            operator_private_key,
            Chain::Holesky,
            LimitsOpts::default(),
            vec![
                format!("ws://127.0.0.1:{}{}", port_1, FIREWALL_STREAM_PATH).parse().unwrap(),
                // format!("ws://127.0.0.1:{}{}", port_2, FIREWALL_STREAM_PATH).parse().unwrap(),
            ],
            HashSet::new(),
        )
        .with_shutdown(async move { shutdown_connections_rx.recv().await.unwrap() }.boxed());

        let mut api_events_rx = stream.run();

        info!("Waiting for {CONNECTIONS_SHUTDOWN_IN_SECS} seconds before shutting down the connection...");
        info!("Waiting for {SERVERS_SHUTDOWN_IN_SECS} seconds before shutting down the servers...");

        let _ = tokio::time::timeout(Duration::from_secs(CONNECTIONS_SHUTDOWN_IN_SECS), async {
            loop {
                if let Some(event) = api_events_rx.recv().await {
                    info!("Received commitment event: {:?}", event);
                    let req = event.request.as_inclusion_request().unwrap().clone();
                    let dumb_signed_commitment = SignedCommitment::Inclusion(
                        req.into_signed(AlloySignatureWrapper::test_signature()),
                    );
                    event.response.send(Ok(dumb_signed_commitment)).unwrap();
                }
            }
        })
        .await;

        info!("Shutting down the connections...");
        shutdown_connections_tx.send(()).unwrap();

        tokio::time::sleep(Duration::from_secs(
            SERVERS_SHUTDOWN_IN_SECS - CONNECTIONS_SHUTDOWN_IN_SECS,
        ))
        .await;

        info!("Shutting down the servers...");
        shutdown_servers_tx.send(()).unwrap();
    }

    // Creates a websocket server
    async fn create_websocket_server(mut shutdown_rx: broadcast::Receiver<()>) -> u16 {
        let app = Router::new().route(FIREWALL_STREAM_PATH, get(ws_handler));
        // Bind to port 0 to let the OS pick a random port for us.
        // We will return it so that clients can connect with it.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        tokio::spawn(async {
            axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
                .with_graceful_shutdown(async move {
                    let _ = shutdown_rx.recv().await.is_ok();
                })
                .await
                .unwrap();
        });

        port
    }

    /// Example websocket handler.
    /// Reference: https://github.com/tokio-rs/axum/blob/da63c14467dd55b1615ddbc7fc4f08c11c3df022/examples/websockets/src/main.rs#L85
    ///
    /// The handler for the HTTP request (this gets called when the HTTP request lands at the start
    /// of websocket negotiation). After this completes, the actual switching from HTTP to
    /// websocket protocol will occur.
    /// This is the last point where we can extract TCP/IP metadata such as IP address of the client
    /// as well as things from HTTP headers such as user-agent of the browser etc.
    async fn ws_handler(
        ws: WebSocketUpgrade,
        ConnectInfo(addr): ConnectInfo<SocketAddr>,
        user_agent: Option<TypedHeader<UserAgent>>,
        TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
    ) -> impl IntoResponse {
        let user_agent = if let Some(TypedHeader(user_agent)) = user_agent {
            user_agent.to_string()
        } else {
            String::from("Unknown user agent")
        };

        // Extract the JWT from the Authorization header
        let jwt = auth.token();

        let decoded_claim = jsonwebtoken::decode::<ProposerAuthClaims>(
            jwt,
            &jsonwebtoken::DecodingKey::from_secret(&[]),
            &jsonwebtoken::Validation::default(),
        );

        match decoded_claim {
            Err(e) => {
                return (StatusCode::UNAUTHORIZED, Json(format!("Invalid JWT: {}", e)))
                    .into_response();
            }
            Ok(_claims) => {
                // NOTE: We're not checking ecrecovering the operator and checking whether it is
                // active on bolt
                info!("User `{user_agent}` at connected with a valid JWT");
            }
        }

        // finalize the upgrade process by returning upgrade callback.
        // we can customize the callback by sending additional info such as address.
        ws.on_upgrade(move |socket| handle_socket(socket, addr))
    }

    /// Example websocket upgrade callack.
    /// Reference: https://github.com/tokio-rs/axum/blob/da63c14467dd55b1615ddbc7fc4f08c11c3df022/examples/websockets/src/main.rs#L102
    ///
    /// Actual websocket statemachine (one will be spawned per connection)
    async fn handle_socket(mut socket: WebSocket, who: SocketAddr) {
        // send a ping just to kick things off and get a response
        if socket.send(Message::Ping(Bytes::from_static(&[1, 2, 3]))).await.is_ok() {
            info!("Pinged {who}...");
        }

        // By splitting socket we can send and receive at the same time. In this example we will
        // send unsolicited messages to client based on some sort of server's internal event
        // (i.e .timer).
        let (mut sender, mut receiver) = socket.split();

        // Spawn a task that will push several messages to the client (does not matter what client
        // does)
        let mut send_task = tokio::spawn(async move {
            let n_msg = 20;
            let inclusion_request = InclusionRequest::default();

            let inclusion_request_payload = JsonRpcRequest {
                jsonrpc: "2.0".to_string(),
                method: REQUEST_INCLUSION_METHOD.to_string(),
                id: Some(serde_json::Value::String(Uuid::now_v7().to_string())),
                params: vec![serde_json::to_value(inclusion_request).unwrap()],
            };

            let inclusion_request_msg = Message::Text(into_utf8_bytes(inclusion_request_payload));

            let get_version_msg = Message::Text(into_utf8_bytes(JsonRpcRequest {
                jsonrpc: "2.0".to_string(),
                method: GET_VERSION_METHOD.to_string(),
                id: Some(serde_json::Value::String(Uuid::now_v7().to_string())),
                params: vec![],
            }));

            let get_metadata_msg = Message::Text(into_utf8_bytes(JsonRpcRequest {
                jsonrpc: "2.0".to_string(),
                method: "bolt_metadata".to_string(),
                id: Some(serde_json::Value::String(Uuid::now_v7().to_string())),
                params: vec![],
            }));

            for i in 0..n_msg {
                // In case of any websocket error, we exit.
                let msg = if i % 5 == 0 {
                    Message::Text(Utf8Bytes::from_static(
                        "This is an invalid message and should be rejected",
                    ))
                } else if i % 6 == 0 {
                    get_version_msg.clone()
                } else if i % 7 == 0 {
                    get_metadata_msg.clone()
                } else {
                    inclusion_request_msg.clone()
                };

                if let Err(err) = sender.send(msg).await {
                    error!("Error sending message {i}: {err}");
                    return i;
                }

                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            }

            info!("Sending close to {who}...");
            if let Err(e) = sender
                .send(Message::Close(Some(CloseFrame {
                    code: axum::extract::ws::close_code::NORMAL,
                    reason: Utf8Bytes::from_static("Goodbye"),
                })))
                .await
            {
                warn!("Could not send Close due to {e}, probably it is ok?");
            }
            n_msg
        });

        // This second task will receive messages from client and print them on server console
        let mut recv_task = tokio::spawn(async move {
            let mut cnt = 0;
            while let Some(Ok(msg)) = receiver.next().await {
                cnt += 1;
                // print message and break if instructed to do so
                if process_message(msg, who).is_break() {
                    break;
                }
            }
            cnt
        });

        // If any one of the tasks exit, abort the other.
        tokio::select! {
            rv_a = (&mut send_task) => {
                match rv_a {
                    Ok(_) => {},
                    Err(a) => println!("Error sending messages {a:?}")
                }
                recv_task.abort();
            },
            rv_b = (&mut recv_task) => {
                match rv_b {
                    Ok(_) => {},
                    Err(b) => println!("Error receiving messages {b:?}")
                }
                send_task.abort();
            }
        }

        // returning from the handler closes the websocket connection
        info!("Websocket context {who} destroyed");
    }

    /// helper to print contents of messages to stdout. Has special treatment for Close.
    fn process_message(msg: Message, who: SocketAddr) -> ControlFlow<(), ()> {
        #[allow(clippy::match_same_arms)]
        match msg {
            Message::Text(t) => {
                debug!(">>> {who} sent str: {t:?}");
            }
            Message::Binary(d) => {
                debug!(">>> {} sent {} bytes: {:?}", who, d.len(), d);
            }
            Message::Close(c) => {
                if let Some(cf) = c {
                    println!(
                        ">>> {} sent close with code {} and reason `{}`",
                        who, cf.code, cf.reason
                    );
                } else {
                    println!(">>> {who} somehow sent close message without CloseFrame");
                }
                return ControlFlow::Break(());
            }

            Message::Pong(_) => {
                // println!(">>> {who} sent pong with {v:?}");
            }
            // You should never need to manually handle Message::Ping, as axum's websocket library
            // will do so for you automagically by replying with Pong and copying the v according to
            // spec. But if you need the contents of the pings you can see them here.
            Message::Ping(_) => {
                // println!(">>> {who} sent ping with {v:?}");
            }
        }
        ControlFlow::Continue(())
    }

    fn into_utf8_bytes<S: Serialize>(input: S) -> Utf8Bytes {
        let msg = serde_json::to_string(&input).unwrap();
        Utf8Bytes::from(msg)
    }
}
