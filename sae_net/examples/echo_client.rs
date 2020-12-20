//!     cargo run --example echo_server
//!     cargo run --example echo_client_session 127.0.0.1:8082

#![warn(rust_2018_idioms)]

use sae_net::session::client_config::ClientConfig;
use sae_net::session::client_session::ClientSession;
use std::env;
use std::net::SocketAddr;
use tokio::net::TcpStream;

#[tokio::main]
async fn main() {
    // Determine if we're going to run in TCP or UDP mode
    let args = env::args().skip(1).collect::<Vec<_>>();

    // Parse what address we're going to connect to
    let addr = args
        .first()
        .expect("this program requires at least one argument");
    let addr = addr.parse::<SocketAddr>().expect("SocketAddr parse error");

    let server_sock = TcpStream::connect(addr)
        .await
        .expect("TcpStream connect error");

    let config = ClientConfig::new();
    // let config = ClientConfig::new_ecc_config();

    let mut session = ClientSession::new(server_sock, config);
    let handshake_result = session.handshake().await;
    match handshake_result {
        Ok(_) => {
            println!("handshake success");
        }
        Err(err) => {
            println!("handshake error: {:?}", err);
            return;
        }
    };

    let payload = Vec::<u8>::from("Hello World");
    if let Err(err) = session.send_msg_payload(&payload).await {
        println!("send payload error: {:?}", err);
        return;
    } else {
        println!(
            "send payload: {:?}",
            String::from_utf8(payload).expect("Payload to Message error")
        );
    }
    match session.recv_msg_payload().await {
        Ok(payload) => {
            let recv_msg = String::from_utf8(payload).expect("Payload to Message error");
            println!("recv payload: {:?}", recv_msg);
        }
        Err(err) => {
            println!("recv payload error: {:?}", err);
            return;
        }
    };
}
