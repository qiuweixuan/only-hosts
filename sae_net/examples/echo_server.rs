//!     cargo run --example echo_server
//!     cargo run --example echo_client 127.0.0.1:8082

#![warn(rust_2018_idioms)]

use tokio::net::TcpListener;

use sae_net::session::server_config::ServerConfig;
use sae_net::session::server_session::ServerSession;
use std::env;

#[tokio::main]
// async fn main() -> Result<(), Box<dyn std::error::Error>> {
async fn main() {
    let addr = env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:8082".to_string());

    let listener = TcpListener::bind(&addr)
        .await
        .expect("TcpListener bind error");
    println!("Listening on: {}", addr);

    
    loop {
        let (socket, _) = listener.accept().await.expect("TcpListener accept error");

        let config = ServerConfig::new();
        let mut session = ServerSession::new(socket, config);
        if let Err(err) = session.handshake().await {
            println!("handshake error: {:?}", err);
            return;
        } else {
            println!("handshake success");
        }

        let recv_msg = match session.recv_msg_payload().await {
            Ok(payload) => {
                let recv_msg = String::from_utf8(payload).expect("Payload to Message error");
                println!("recv payload: {:?}", recv_msg);
                recv_msg
            }
            Err(err) => {
                println!("recv payload error: {:?}", err);
                return;
            }
        };
        let payload = Vec::<u8>::from(recv_msg);
        if let Err(err) = session.send_msg_payload(&payload).await {
            println!("send payload error: {:?}", err);
            return;
        } else {
            println!(
                "send payload: {:?}",
                String::from_utf8(payload).expect("Payload to Message error")
            );
        }

        println!("Socket received FIN packet and closed connection");
    }
}
