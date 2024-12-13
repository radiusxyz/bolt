use futures::StreamExt;
use std::fmt::Debug;
use std::fmt::{self, Formatter};
use std::time::Duration;
use std::{future::Future, pin::Pin};
use thiserror::Error;
use tokio::sync::{broadcast, mpsc};
use tokio_tungstenite::connect_async_with_config;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tracing::{error, info};

use reqwest::Url;

use crate::api::commitments::delegation::processor::CommitmentRequestProcessor;
use crate::api::commitments::server::CommitmentEvent;
use crate::common::backoff::retry_with_backoff_if;
use crate::common::secrets::EcdsaSecretKeyWrapper;
use crate::config::chain::Chain;

use super::processor::InterruptReason;

/// The interval at which to send ping messages from connected clients.
#[cfg(test)]
const PING_INTERVAL: Duration = Duration::from_secs(3);
#[cfg(not(test))]
const PING_INTERVAL: Duration = Duration::from_secs(30);

/// The maximum number of retries to attempt when reconnecting to a websocket server.
const MAX_RETRIES: usize = 10;

type ShutdownSignal = Pin<Box<dyn Future<Output = ()> + Send>>;

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
    #[allow(dead_code)]
    operator_private_key: EcdsaSecretKeyWrapper,
    /// The chain ID of the chain the sidecar is running. Used for authentication purposes.
    chain: Chain,
    /// The URLs of the websocket servers to connect to.
    urls: Vec<Url>,
    /// The shutdown signal.
    signal: Option<ShutdownSignal>,
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
    pub fn new(operator_private_key: EcdsaSecretKeyWrapper, chain: Chain, urls: Vec<Url>) -> Self {
        Self {
            operator_private_key,
            chain,
            urls,
            signal: Some(Box::pin(async {
                let _ = tokio::signal::ctrl_c().await;
            })),
        }
    }

    /// Sets the shutdown signal for the closing the open connections.
    pub fn with_shutdown(mut self, signal: ShutdownSignal) -> Self {
        self.signal = Some(signal);
        self
    }

    /// Runs the [CommitmentsReceiver] and returns a receiver for incoming commitment
    /// events.
    pub async fn run(mut self) -> mpsc::Receiver<CommitmentEvent> {
        // mspc channel where every websocket connection will send commitment events over its own
        // tx to a single receiver.
        let (api_events_tx, api_events_rx) = mpsc::channel(self.urls.len() * 2);
        let (ping_tx, ping_rx) = broadcast::channel::<()>(1);
        let (shutdown_tx, shutdown_rx) = broadcast::channel::<()>(1);

        // a task to send pings to open connections to the servers at regular intervals
        tokio::spawn(async move {
            let ping_interval = tokio::time::interval(PING_INTERVAL);
            tokio::pin!(ping_interval);

            loop {
                ping_interval.tick().await;
                if let Err(err) = ping_tx.send(()) {
                    error!(?err, "internal error while sending ping task")
                }
            }
        });

        let signal = self.signal.take();
        if let Some(signal) = signal {
            tokio::spawn(async move {
                signal.await;
                if let Err(err) = shutdown_tx.send(()) {
                    error!(?err, "failed to send shutdown signal");
                }
            });
        }

        for url in &self.urls {
            // NOTE: We're cloning the variables here because we're moving the inputs into an async
            // task.
            let url = url.clone();
            let api_events_tx = api_events_tx.clone();
            let ping_rx = ping_rx.resubscribe();
            let shutdown_rx = shutdown_rx.resubscribe();

            tokio::spawn(async move {
                retry_with_backoff_if(
                    MAX_RETRIES,
                    // NOTE: this needs to be a closure because it must be re-called upon failure. 
                    // As such we also need to clone the inputs again.
                        move || {
                            let url = url.clone();
                            let api_events_tx = api_events_tx.clone();
                            let ping_rx = ping_rx.resubscribe();
                            let shutdown_rx = shutdown_rx.resubscribe();

                            async move {
                                handle_connection(url, api_events_tx, ping_rx, shutdown_rx).await
                            }
                        },
                    |err| {
                        // Retry unless shutdown signal is received.
                        !matches!(
                            err,
                            ConnectionHandlerError::ProcessorInterrupted(InterruptReason::Shutdown)
                        )
                    },
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

async fn handle_connection(
    url: Url,
    api_events_tx: mpsc::Sender<CommitmentEvent>,
    ping_rx: broadcast::Receiver<()>,
    shutdown_rx: broadcast::Receiver<()>,
) -> Result<(), ConnectionHandlerError> {
    let ws_config = WebSocketConfig { ..Default::default() };
    match connect_async_with_config(url.to_string(), Some(ws_config), false).await {
        Ok((stream, response)) => {
            info!(?url, ?response, "opened websocket connection");
            let (write_sink, read_stream) = stream.split();

            // For each opened connection, create a new commitment processor
            // able to handle incoming message requests.
            let commitment_request_processor = CommitmentRequestProcessor::new(
                url.clone(),
                api_events_tx.clone(),
                write_sink,
                read_stream,
                ping_rx.resubscribe(),
                shutdown_rx.resubscribe(),
            );
            // Run the commitment processor indefinitely, reconnecting on failure.
            let interrupt_reason = commitment_request_processor.await;
            Err(ConnectionHandlerError::ProcessorInterrupted(interrupt_reason))
        }
        Err(e) => {
            error!(?e, ?url, "failed to connect");
            Err(ConnectionHandlerError::OnConnectionError(e))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{borrow::Cow, net::SocketAddr, ops::ControlFlow, time::Duration};

    use alloy::primitives::PrimitiveSignature;
    use axum::{
        extract::{
            ws::{CloseFrame, Message, WebSocket},
            ConnectInfo, WebSocketUpgrade,
        },
        response::IntoResponse,
        routing::get,
        Router,
    };
    use axum_extra::{headers, TypedHeader};
    use futures::{FutureExt, SinkExt, StreamExt};
    use tokio::sync::broadcast;
    use tracing::{debug, error, info, warn};

    use crate::{
        api::commitments::delegation::receiver::CommitmentsReceiver,
        common::secrets::EcdsaSecretKeyWrapper,
        config::chain::Chain,
        primitives::commitment::{InclusionCommitment, SignedCommitment},
    };

    const FIREWALL_STREAM_PATH: &str = "/api/v1/firewall_stream";

    #[tokio::test]
    async fn test_firewall_rpc_stream_ws() {
        let _ = tracing_subscriber::fmt::try_init();

        // Shutdown servers after closing connections so we can test both types of shutdowns
        const CONNECTIONS_SHUTDOWN_IN_SECS: u64 = 5;
        const SERVERS_SHUTDOWN_IN_SECS: u64 = 7;

        let operator_private_key = EcdsaSecretKeyWrapper::random();

        // Create a Single-Producer-Multiple-Consumer (SPMC) channel via a broadcast that sends a shutdown
        // signal to all websocket servers.
        let (shutdown_servers_tx, shutdown_servers_rx) = broadcast::channel::<()>(1);

        let (shutdown_connections_tx, mut shutdown_connections_rx) = broadcast::channel::<()>(1);

        let port_1 = create_websocket_server(shutdown_servers_rx.resubscribe()).await;
        let port_2 = create_websocket_server(shutdown_servers_rx.resubscribe()).await;

        info!("Server 1 running on port: {}", port_1);
        info!("Server 2 running on port: {}", port_2);

        let stream = CommitmentsReceiver::new(
            operator_private_key,
            Chain::Holesky,
            vec![
                format!("ws://127.0.0.1:{}{}", port_1, FIREWALL_STREAM_PATH).parse().unwrap(),
                format!("ws://127.0.0.1:{}{}", port_2, FIREWALL_STREAM_PATH).parse().unwrap(),
            ],
        )
        .with_shutdown(async move { shutdown_connections_rx.recv().await.unwrap() }.boxed());

        let mut api_events_rx = stream.run().await;

        info!("Waiting for {CONNECTIONS_SHUTDOWN_IN_SECS} seconds before shutting down the connection...");
        info!("Waiting for {SERVERS_SHUTDOWN_IN_SECS} seconds before shutting down the servers...");

        let _ = tokio::time::timeout(Duration::from_secs(CONNECTIONS_SHUTDOWN_IN_SECS), async {
            loop {
                if let Some(event) = api_events_rx.recv().await {
                    info!("Received commitment event: {:?}", event);
                    let req = event.request.as_inclusion_request().unwrap().clone();
                    let dumb_signed_commitment =
                        SignedCommitment::Inclusion(InclusionCommitment::new_unchecked(
                            req,
                            PrimitiveSignature::test_signature(),
                        ));
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
        user_agent: Option<TypedHeader<headers::UserAgent>>,
        ConnectInfo(addr): ConnectInfo<SocketAddr>,
    ) -> impl IntoResponse {
        let user_agent = if let Some(TypedHeader(user_agent)) = user_agent {
            user_agent.to_string()
        } else {
            String::from("Unknown user agent")
        };
        info!("`{user_agent}` at {addr} connected.");
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
        if socket.send(Message::Ping(vec![1, 2, 3])).await.is_ok() {
            info!("Pinged {who}...");
        }

        // By splitting socket we can send and receive at the same time. In this example we will send
        // unsolicited messages to client based on some sort of server's internal event (i.e .timer).
        let (mut sender, mut receiver) = socket.split();

        // Spawn a task that will push several messages to the client (does not matter what client does)
        let mut send_task = tokio::spawn(async move {
            let n_msg = 20;
            for i in 0..n_msg {
                // In case of any websocket error, we exit.
                if let Err(err) =
                    sender.send(Message::Text(format!("Server message {i} ..."))).await
                {
                    error!("Error sending message {i}: {err}");
                    return i;
                }

                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            }

            info!("Sending close to {who}...");
            if let Err(e) = sender
                .send(Message::Close(Some(CloseFrame {
                    code: axum::extract::ws::close_code::NORMAL,
                    reason: Cow::from("Goodbye"),
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
}
