use futures::stream::{SplitSink, SplitStream};
use futures::{SinkExt, StreamExt};
use std::time::Duration;
use std::{
    future::Future,
    net::{SocketAddr, ToSocketAddrs},
    pin::Pin,
};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::task;
// use tokio_stream::StreamExt;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::{connect_async, tungstenite::Message};
use tokio_tungstenite::{connect_async_with_config, MaybeTlsStream, WebSocketStream};

use reqwest::Url;

pub struct CommitmentsFirewallStream {
    urls: Vec<Url>,
    /// The shutdown signal.
    signal: Option<Pin<Box<dyn Future<Output = ()> + Send>>>,
}

impl CommitmentsFirewallStream {
    pub fn new(urls: Vec<Url>) -> Self {
        Self {
            urls,
            signal: Some(Box::pin(async {
                let _ = tokio::signal::ctrl_c().await;
            })),
        }
    }

    pub async fn run(&self) {
        // Create a Multiple-Producer-Single-Consumer (MPSC) channel to receive messages from the
        // websocket servers on a single stream.
        // TODO: Use a bounded channel
        let (tx, mut rx) = mpsc::unbounded_channel();

        for url in &self.urls {
            let url = url.clone();
            let tx = tx.clone();
            tokio::spawn(async move {
                handle_connection(url, tx).await;
            });
        }

        while let Some(msg) = rx.recv().await {
            println!("Received: {:?}", msg);
        }
    }

    /// Returns the local addr the server is listening on (or configured with).
    pub fn urls(&self) -> &[Url] {
        self.urls.as_slice()
    }
}

async fn handle_connection(url: Url, tx: mpsc::UnboundedSender<String>) {
    let ws_config = WebSocketConfig {
        max_message_size: Some(1 << 10), // 64KB
        ..Default::default()
    };

    loop {
        match connect_async_with_config(url.to_string(), Some(ws_config), false).await {
            Ok((stream, _response)) => {
                println!("Connected to: {}", url);
                let (mut write, read) = stream.split();

                // Create a task to send pings to the server at regular intervals
                let ping_task = tokio::spawn(async move {
                    let ping_interval = tokio::time::interval(Duration::from_secs(1));
                    tokio::pin!(ping_interval);

                    loop {
                        ping_interval.tick().await;
                        if write.send(Message::Ping(vec![8, 0, 1, 7])).await.is_err() {
                            println!("Ping failed. Disconnecting...");
                            break;
                        }
                    }
                });

                let tx_clone = tx.clone();
                let read_task = tokio::spawn(async move {
                    process_messages(read, tx_clone).await;
                });

                // PERF: is it more efficient to have a custom poll implementation?
                tokio::select! {
                    _ = ping_task => {
                        println!("Ping task ended. Disconnecting...");
                        break;
                    }
                    _ = read_task => {
                        println!("Read task ended. Disconnecting...");
                        break;
                    }
                }
            }
            Err(e) => {
                eprintln!("Failed to connect to {}: {:?}", url, e);
            }
        }

        // Reconnect on failure
        println!("Reconnecting to {}", url);
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

async fn process_messages(
    mut read: SplitStream<WebSocketStream<MaybeTlsStream<TcpStream>>>,
    tx: mpsc::UnboundedSender<String>,
) {
    while let Some(message) = read.next().await {
        match message {
            Ok(Message::Text(text)) => {
                println!("Received: {}", text);
                if tx.send(text).is_err() {
                    eprintln!("Failed to forward message to channel");
                }
            }
            Ok(Message::Close(_)) => {
                println!("WebSocket closed");
                break;
            }
            Err(e) => {
                eprintln!("WebSocket error: {:?}", e);
                break;
            }
            _ => {} // Ignore non-text messages
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

    use crate::api::commitments::firewall_stream::CommitmentsFirewallStream;

    const FIREWALL_STREAM_PATH: &str = "/api/v1/firewall_stream";

    #[tokio::test]
    async fn test_firewall_rpc_stream_ws() {
        // Create a Single-Producer-Multiple-Consumer (SPMC) channel via a broadcast that sends a shutdown
        // signal to all websocket servers.
        let (shutdown_tx, shutdown_rx) = broadcast::channel::<()>(1);

        let port_1 = create_websocket_server(shutdown_tx.subscribe()).await;
        let port_2 = create_websocket_server(shutdown_rx).await;

        println!("Server 1 running on port: {}", port_1);
        println!("Server 2 running on port: {}", port_2);
        println!("Waiting for 5 seconds before shutting down the servers...");

        let stream = CommitmentsFirewallStream::new(vec![
            format!("ws://127.0.0.1:{}{}", port_1, FIREWALL_STREAM_PATH).parse().unwrap(),
            format!("ws://127.0.0.1:{}{}", port_2, FIREWALL_STREAM_PATH).parse().unwrap(),
        ]);

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
