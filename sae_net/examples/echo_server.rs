//!     cargo run --example echo_server
//!     cargo run --example echo_client 127.0.0.1:8082

#![warn(rust_2018_idioms)]

use tokio::net::TcpListener;


use sae_net::session::{session_duplex::SessionDuplex};
use sae_net::msgs::type_enums::{ProtocolVersion};
use std::env;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Allow passing an address to listen on as the first argument of this
    // program, but otherwise we'll just set up our TCP listener on
    // 127.0.0.1:8082 for connections.
    let addr = env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:8082".to_string());

    // Next up we create a TCP listener which will listen for incoming
    // connections. This TCP listener is bound to the address we determined
    // above and must be associated with an event loop, so we pass in a handle
    // to our event loop. After the socket's created we inform that we're ready
    // to go and start accepting connections.
    let listener = TcpListener::bind(&addr).await?;
    println!("Listening on: {}", addr);

    loop {
        // Asynchronously wait for an inbound socket.
        let (socket, _) = listener.accept().await?;

        // And this is where much of the magic of this server happens. We
        // crucially want all clients to make progress concurrently, rather than
        // blocking one on completion of another. To achieve this we use the
        // `tokio::spawn` function to execute the work in the background.
        //
        // Essentially here we're executing a new task to run concurrently,
        // which will allow all of our clients to be processed concurrently.
        tokio::spawn(async move {
            let mut server_session_duplex = SessionDuplex::new(socket);

            let protocal_version = ProtocolVersion::SAEv1_0;

            while let Some(message) = server_session_duplex.read_one_message_detail_error(&protocal_version).await {
                println!("Receive message: {:?}", message);
                // echo 
                if let Err(_) = server_session_duplex.write_one_message(message).await{
                    return;
                }
            }
            println!("Socket received FIN packet and closed connection");
        });
    }
}