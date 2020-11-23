//!     cargo run --example print_each_packet_length
//!     cargo run --example connect_length 127.0.0.1:8082

#![warn(rust_2018_idioms)]

use tokio::net::TcpListener;
use tokio::stream::StreamExt;
use tokio_util::codec::{ LengthDelimitedCodec};
use tokio::prelude::*;

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
            // We're parsing each socket with the `LengthDelimitedCodec` included in `tokio::codec`.

            // let mut framed = LengthDelimitedCodec::new().framed(socket);

            let (read_half, mut write_half) = socket.into_split();

            let mut framed_read = LengthDelimitedCodec::builder()
                .length_field_offset(3) // length of type + version
                .length_field_length(2)  // length of payload_len
                .length_adjustment(5)   // length of header
                .num_skip(0)             //goto start location
                .new_read(read_half);

            // let mut framed = Framed::new(socket, LengthDelimitedCodec::new());

            // We loop while there are messages coming from the Stream `framed`.
            // The stream will return None once the client disconnects.
            while let Some(message) = framed_read.next().await {
                match message {
                    Ok(bytes) => {
                        println!("bytes: {:?}", bytes.len());
                        // println!("Sending ClientHello {:#?}", ch);

                        if let Err(e) = write_half.write_all(bytes.freeze().as_ref()).await {
                            println!("error on sending response; error = {:?}", e);
                            return;
                        }
                        else{
                            println!("success sending response");
                        }
                    }
                    Err(err) => println!("Socket closed with error: {:?}", err),
                }
            }
            println!("Socket received FIN packet and closed connection");
        });
    }
}
