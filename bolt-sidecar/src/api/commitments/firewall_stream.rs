use futures::stream::{SplitSink, SplitStream};
use futures::StreamExt;
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

    pub fn with_shutdown<S>(self, urls: Vec<Url>, signal: S) -> Self
    where
        S: Future<Output = ()> + Send + 'static,
    {
        Self { urls, signal: Some(Box::pin(signal)) }
    }

    pub async fn run(&self) {
        // Channels to connect messages from all websocket connections.
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
        max_message_size: Some(64 << 10), // 64KB
        ..Default::default()
    };

    loop {
        match connect_async_with_config(url.to_string(), Some(ws_config), false).await {
            Ok((stream, _response)) => {
                println!("Connected to: {}", url);
                let (mut write, read) = stream.split();

                // Read and forward messages
                process_messages(read, tx.clone()).await;

                // Optionally, send pings or handle authentication
                // let ping_interval = tokio::time::interval(Duration::from_secs(30));
                // tokio::pin!(ping_interval);

                // loop {
                //     tokio::select! {
                //         _ = ping_interval.tick() => {
                //             if write.send(Message::Ping(Vec::new())).await.is_err() {
                //                 println!("Ping failed. Disconnecting...");
                //                 break;
                //             }
                //         }
                //     }
                // }
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
    use std::{net::SocketAddr, time::Duration};

    use axum::{
        extract::{ws::WebSocket, ConnectInfo, WebSocketUpgrade},
        response::IntoResponse,
        routing::get,
        Router,
    };
    use axum_extra::{headers, TypedHeader};
    use tokio::sync::broadcast;

    const FIREWALL_STREAM_PATH: &str = "/api/v1/firewall_stream";

    #[tokio::test]
    async fn test_firewall_rpc_stream_ws() {
        // Create a spmc channel via a broadcast that sends a shutdown signal to all websocket
        // servers.
        let (shutdown_tx, shutdown_rx) = broadcast::channel::<()>(1);

        let port_1 = create_websocket_server(shutdown_tx.subscribe()).await;
        let port_2 = create_websocket_server(shutdown_rx).await;

        println!("Server 1 running on port: {}", port_1);
        println!("Server 2 running on port: {}", port_2);

        println!("Waiting for 5 seconds before shutting down the servers...");
        tokio::time::sleep(Duration::from_secs(5)).await;

        // Shutdown the servers
        println!("Shutting down the servers...");
        shutdown_tx.send(()).unwrap();
    }

    async fn create_websocket_server(mut shutdown_rx: broadcast::Receiver<()>) -> u16 {
        let app = Router::new().route(FIREWALL_STREAM_PATH, get(ws_handler));
        // Bind to port 0 to let the OS pick a random port for us
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
            String::from("Unknown browser")
        };
        println!("`{user_agent}` at {addr} connected.");
        // finalize the upgrade process by returning upgrade callback.
        // we can customize the callback by sending additional info such as address.
        ws.on_upgrade(move |socket| handle_socket(socket, addr))
    }

    /// Actual websocket statemachine (one will be spawned per connection)
    async fn handle_socket(mut socket: WebSocket, who: SocketAddr) {
        println!("WebSocket connection from: {}", who);
    }
}
