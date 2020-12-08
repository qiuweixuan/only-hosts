//!     cargo run --example echo_server
//!     cargo run --example echo_client_session 127.0.0.1:8082

#![warn(rust_2018_idioms)]

use std::env;
use std::error::Error;
use std::net::SocketAddr;
use tokio::net::TcpStream;
use tokio::try_join;

use sae_net::session::client_config::ClientConfig;
use sae_net::session::client_session::ClientSession;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Determine if we're going to run in TCP or UDP mode
    let args = env::args().skip(1).collect::<Vec<_>>();

    // Parse what address we're going to connect to
    let addr = args
        .first()
        .ok_or("this program requires at least one argument")?;
    let addr = addr.parse::<SocketAddr>()?;

    let server_sock = TcpStream::connect(addr).await?;
    // let mut client_session_duplex = SessionDuplex::new(server_sock);

    let client_join = tokio::spawn(async move {
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
        let send_msg_result = session.send_msg_payload(&payload).await;
        match send_msg_result {
            Ok(_) => {
                println!("send payload: {:?}", String::from_utf8(payload));
            }
            Err(err) => {
                println!("send payload error: {:?}", err);
                return;
            }
        };
    });

    if let Err(e) = try_join!(client_join) {
        println!("client_join failed, error={}", e);
    };

    Ok(())
}
