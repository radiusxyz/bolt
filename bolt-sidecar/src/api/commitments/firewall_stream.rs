use futures::stream::{FuturesUnordered, SplitSink, SplitStream};
use futures::{FutureExt, SinkExt, StreamExt};
use std::collections::VecDeque;
use std::task::Poll;
use std::time::Duration;
use std::{future::Future, pin::Pin};
use tokio::net::TcpStream;
use tokio::sync::broadcast::error::TryRecvError;
use tokio::sync::{broadcast, mpsc, oneshot};
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{connect_async_with_config, MaybeTlsStream, WebSocketStream};
use tracing::{error, info, warn};

use reqwest::Url;

use crate::common::secrets::EcdsaSecretKeyWrapper;
use crate::config::chain::Chain;
use crate::primitives::commitment::SignedCommitment;
use crate::primitives::{CommitmentRequest, InclusionRequest};

use super::server::CommitmentEvent;
use super::spec::CommitmentError;

/// The interval at which to send ping messages from connected clients.
const PING_INTERVAL: Duration = Duration::from_secs(30);

#[allow(dead_code)]
pub struct CommitmentsFirewallStream {
    /// The operator's private key to sign authentication requests when opening websocket
    /// connections with RPCs.
    operator_private_key: EcdsaSecretKeyWrapper,
    /// The chain ID of the chain the sidecar is running. Used for authentication purposes.
    chain: Chain,
    /// The URLs of the websocket servers to connect to.
    urls: Vec<Url>,
    /// The shutdown signal.
    signal: Option<Pin<Box<dyn Future<Output = ()> + Send>>>,
}

#[allow(dead_code)]
impl CommitmentsFirewallStream {
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

    pub async fn run(&self) -> mpsc::Receiver<CommitmentEvent> {
        // Create a Multiple-Producer-Single-Consumer (MPSC) channel to receive messages from the
        // websocket servers on a single stream.
        let (api_event_tx, api_events_rx) = mpsc::channel(self.urls.len() * 2);
        let (ping_tx, ping_rx) = broadcast::channel::<()>(1);

        // Create a task to send pings to the server at regular intervals
        let _ = tokio::spawn(async move {
            let ping_interval = tokio::time::interval(PING_INTERVAL);
            tokio::pin!(ping_interval);

            loop {
                ping_interval.tick().await;
                if let Err(err) = ping_tx.send(()) {
                    error!(?err, "internal error while sending ping task")
                }
            }
        });

        for url in &self.urls {
            let url = url.clone();
            let api_events_tx = api_event_tx.clone();
            let ping_rx = ping_rx.resubscribe();
            tokio::spawn(async move {
                handle_connection(url, api_events_tx, ping_rx).await;
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
) {
    let ws_config = WebSocketConfig {
        max_message_size: Some(1 << 10), // 64KB
        ..Default::default()
    };

    loop {
        match connect_async_with_config(url.to_string(), Some(ws_config), false).await {
            Ok((stream, _response)) => {
                info!(?url, "opened websocket connection");
                let (write, read) = stream.split();

                let message_processer = MessageProcesser::new(
                    url.clone(),
                    api_events_tx.clone(),
                    write,
                    read,
                    ping_rx.resubscribe(),
                );
                message_processer.await
            }
            Err(e) => {
                error!(?e, ?url, "failed to connect");
            }
        }

        // Reconnect on failure
        println!("Reconnecting to {}", url);
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

struct MessageProcesser {
    url: Url,
    tx: mpsc::Sender<CommitmentEvent>,
    write: SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, Message>,
    read: SplitStream<WebSocketStream<MaybeTlsStream<TcpStream>>>,
    ping_rx: broadcast::Receiver<()>,
    pending_commitment_responses: FuturesUnordered<
        Pin<
            Box<
                dyn Future<
                        Output = Result<
                            Result<SignedCommitment, CommitmentError>,
                            oneshot::error::RecvError,
                        >,
                    > + Send,
            >,
        >,
    >,
    outgoing_messages: VecDeque<Message>,
}

impl MessageProcesser {
    pub fn new(
        url: Url,
        tx: mpsc::Sender<CommitmentEvent>,
        write: SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, Message>,
        read: SplitStream<WebSocketStream<MaybeTlsStream<TcpStream>>>,
        ping_rx: broadcast::Receiver<()>,
    ) -> Self {
        Self {
            url,
            tx,
            write,
            read,
            ping_rx,
            pending_commitment_responses: FuturesUnordered::new(),
            outgoing_messages: VecDeque::new(),
        }
    }
}

impl Future for MessageProcesser {
    type Output = ();

    fn poll(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        let this = self.get_mut();
        let rpc_url = this.url.clone();

        loop {
            let mut progress = false;

            // 1. Handle incoming WebSocket messages
            match this.read.poll_next_unpin(cx) {
                Poll::Ready(Some(message)) => {
                    progress = true;

                    match message {
                        Ok(Message::Text(_text)) => {
                            let (tx, rx) = oneshot::channel();
                            let request = CommitmentRequest::Inclusion(InclusionRequest::default());
                            let event = CommitmentEvent { request, response: tx };
                            if let Err(err) = this.tx.try_send(event) {
                                error!(?err, "failed to forward commitment event to channel");
                            }

                            // Add the receiver's future to the FuturesUnordered
                            this.pending_commitment_responses.push(rx.boxed());
                        }
                        Ok(Message::Close(_)) => {
                            warn!(?rpc_url, "websocket connection closed by server");
                            return Poll::Ready(());
                        }
                        Err(e) => {
                            error!(?e, ?rpc_url, "error reading message from websocket connection");
                            return Poll::Ready(());
                        }
                        _ => {} // Ignore non-text messages
                    }
                }
                Poll::Ready(None) => {
                    warn!("websocket connection with {} closed by server", rpc_url);
                    return Poll::Ready(());
                }
                _ => {}
            }

            // 2. Handle commitment responses
            while let Poll::Ready(Some(response)) =
                this.pending_commitment_responses.poll_next_unpin(cx)
            {
                progress = true;
                match response {
                    Ok(commitment_result) => {
                        if let Ok(commitment) = commitment_result {
                            let message =
                                Message::text(serde_json::to_string(&commitment).unwrap());
                            this.outgoing_messages.push_back(message);
                        }
                    }
                    Err(e) => {
                        error!(?e, "failed to receive commitment response");
                    }
                }
            }

            // 3. Handle ping messages
            match this.ping_rx.try_recv() {
                Ok(_) => {
                    progress = true;
                    this.outgoing_messages.push_back(Message::Ping(vec![8, 0, 1, 7]));
                }
                Err(TryRecvError::Closed) => {
                    error!("ping channel for keep-alive messages closed");
                    return Poll::Ready(());
                }
                Err(TryRecvError::Lagged(lost)) => {
                    error!("ping channel for keep-alives lagged by {} messages", lost)
                }
                _ => {}
            }

            // 4. Process outgoing messages
            while let Some(message) = this.outgoing_messages.pop_front() {
                match this.write.poll_ready_unpin(cx) {
                    Poll::Ready(Ok(())) => {
                        progress = true;

                        if let Err(e) = this.write.start_send_unpin(message) {
                            error!(?e, ?rpc_url, "failed to send message to websocket connection");
                            // NOTE: Should we return here?
                            // return Poll::Ready(());
                        }
                    }
                    Poll::Pending => {
                        // Put the message back and try again later
                        this.outgoing_messages.push_front(message);
                        break;
                    }
                    Poll::Ready(Err(e)) => {
                        error!(?e, "sink error while sending message to websocket");
                        // NOTE: Should we return here?
                        // return Poll::Ready(());
                    }
                }
            }

            // 5. Ensure the write sink is flushed
            match this.write.poll_flush_unpin(cx) {
                Poll::Ready(Ok(())) => {
                    progress = true;
                }
                Poll::Ready(Err(e)) => {
                    error!(?e, "failed to flush websocket write sink");
                    // NOTE: Should we return here?
                    // return Poll::Ready(());
                }
                _ => {}
            }

            if !progress {
                return Poll::Pending;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{borrow::Cow, net::SocketAddr, ops::ControlFlow, time::Duration};

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
    use futures::{SinkExt, StreamExt};
    use tokio::sync::broadcast;

    use crate::{
        api::commitments::firewall_stream::CommitmentsFirewallStream,
        common::secrets::EcdsaSecretKeyWrapper, config::chain::Chain,
    };

    const FIREWALL_STREAM_PATH: &str = "/api/v1/firewall_stream";

    #[tokio::test]
    async fn test_firewall_rpc_stream_ws() {
        let operator_private_key = EcdsaSecretKeyWrapper::random();

        // Create a Single-Producer-Multiple-Consumer (SPMC) channel via a broadcast that sends a shutdown
        // signal to all websocket servers.
        let (shutdown_tx, shutdown_rx) = broadcast::channel::<()>(1);

        let port_1 = create_websocket_server(shutdown_tx.subscribe()).await;
        let port_2 = create_websocket_server(shutdown_rx).await;

        println!("Server 1 running on port: {}", port_1);
        println!("Server 2 running on port: {}", port_2);
        println!("Waiting for 5 seconds before shutting down the servers...");

        let stream = CommitmentsFirewallStream::new(
            operator_private_key,
            Chain::Holesky,
            vec![
                format!("ws://127.0.0.1:{}{}", port_1, FIREWALL_STREAM_PATH).parse().unwrap(),
                format!("ws://127.0.0.1:{}{}", port_2, FIREWALL_STREAM_PATH).parse().unwrap(),
            ],
        );

        let _ = tokio::time::timeout(Duration::from_secs(5), async {
            stream.run().await;
        })
        .await;

        // Shutdown the servers
        println!("Shutting down the servers...");
        shutdown_tx.send(()).unwrap();
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
        println!("`{user_agent}` at {addr} connected.");
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
            println!("Pinged {who}...");
        }

        // By splitting socket we can send and receive at the same time. In this example we will send
        // unsolicited messages to client based on some sort of server's internal event (i.e .timer).
        let (mut sender, mut receiver) = socket.split();

        // Spawn a task that will push several messages to the client (does not matter what client does)
        let mut send_task = tokio::spawn(async move {
            let n_msg = 20;
            for i in 0..n_msg {
                // In case of any websocket error, we exit.
                if sender.send(Message::Text(format!("Server message {i} ..."))).await.is_err() {
                    return i;
                }

                tokio::time::sleep(std::time::Duration::from_millis(300)).await;
            }

            println!("Sending close to {who}...");
            if let Err(e) = sender
                .send(Message::Close(Some(CloseFrame {
                    code: axum::extract::ws::close_code::NORMAL,
                    reason: Cow::from("Goodbye"),
                })))
                .await
            {
                println!("Could not send Close due to {e}, probably it is ok?");
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
                    Ok(a) => println!("{a} messages sent to {who}"),
                    Err(a) => println!("Error sending messages {a:?}")
                }
                recv_task.abort();
            },
            rv_b = (&mut recv_task) => {
                match rv_b {
                    Ok(b) => println!("Received {b} messages"),
                    Err(b) => println!("Error receiving messages {b:?}")
                }
                send_task.abort();
            }
        }

        // returning from the handler closes the websocket connection
        println!("Websocket context {who} destroyed");
    }

    /// helper to print contents of messages to stdout. Has special treatment for Close.
    fn process_message(msg: Message, who: SocketAddr) -> ControlFlow<(), ()> {
        match msg {
            Message::Text(t) => {
                println!(">>> {who} sent str: {t:?}");
            }
            Message::Binary(d) => {
                println!(">>> {} sent {} bytes: {:?}", who, d.len(), d);
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

            Message::Pong(v) => {
                println!(">>> {who} sent pong with {v:?}");
            }
            // You should never need to manually handle Message::Ping, as axum's websocket library
            // will do so for you automagically by replying with Pong and copying the v according to
            // spec. But if you need the contents of the pings you can see them here.
            Message::Ping(v) => {
                println!(">>> {who} sent ping with {v:?}");
            }
        }
        ControlFlow::Continue(())
    }
}
