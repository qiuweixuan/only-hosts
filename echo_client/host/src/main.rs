//! An example of hooking up stdin/stdout to either a TCP or UDP stream.
//!
//! This example will connect to a socket address specified in the argument list
//! and then forward all data read on stdin to the server, printing out all data
//! received on stdout. An optional `--udp` argument can be passed to specify
//! that the connection should be made over UDP instead of TCP, translating each
//! line entered on stdin to a UDP packet to be sent to the remote address.
//!
//! Note that this is not currently optimized for performance, especially
//! around buffer management. Rather it's intended to show an example of
//! working with a client.
//!
//! This example can be quite useful when interacting with the other examples in
//! this repository! Many of them recommend running this as a simple "hook up
//! stdin/stdout to a server" to get up and running.

//!     cargo run --example print_each_packet_length
//!     cargo run --example connect_length 127.0.0.1:8082

#![warn(rust_2018_idioms)]

use futures::StreamExt;
// use tokio::io;
use tokio::prelude::*;
// use tokio_util::codec::{FramedRead, LinesCodec,Encoder,LengthDelimitedCodec};
use tokio_util::codec::{LengthDelimitedCodec};

use std::env;
use std::error::Error;
use std::net::SocketAddr;
use tokio::net::TcpStream;
use tokio::try_join;

// use bytes::{BytesMut,Bytes};

use sae_net::msgs::message::{Message,MessagePayload};
use sae_net::msgs::handshake::{HandshakePayload, HandshakeMessagePayload, ClientHelloPayload,Random};
use sae_net::msgs::type_enums::{HandshakeType,CipherSuite,NamedGroup,ContentType,ProtocolVersion};
use sae_net::msgs::base::{PayloadU8};
use sae_net::msgs::codec::{Codec};

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
    let (read_half, mut write_half) = server_sock.into_split();

    // stdin -> write_half  task
    let read_join = tokio::spawn(async move {
        
        let client_random =  Random::from_slice(&b"\x02\x00\x00\x00\x01\x00"[..]);
        let client_cipher_suites = vec![ CipherSuite::FFCPWD_AES_128_GCM_SHA256, CipherSuite::FFCPWD_AES_256_GCM_SHA384];
        let clinet_name_groups = vec![NamedGroup::FFDHE3072,NamedGroup::FFDHE4096];
        let clinet_pwd_name = PayloadU8::new(Vec::<u8>::from("root"));

        let chp = HandshakeMessagePayload {
            typ: HandshakeType::ClientHello,
            payload: HandshakePayload::ClientHello(ClientHelloPayload {
                random: client_random,
                cipher_suites: client_cipher_suites,
                name_groups: clinet_name_groups,
                pwd_name: clinet_pwd_name,
            }),
        };
        let ch = Message {
            typ: ContentType::Handshake,
            version: ProtocolVersion::SAEv1_0,
            payload: MessagePayload::Handshake(chp),
        };

        println!("Sending ClientHello {:#?}", ch);

        let buf = ch.get_encoding();

        println!(" ClientHello buf: {:?}", buf.len());

        write_half.write_all(&buf).await.unwrap();
    });

    // read_half -> stdout  task
    let write_join = tokio::spawn(async move {

        let mut read_server = LengthDelimitedCodec::builder()
                .length_field_offset(3) // length of type + version
                .length_field_length(2)  // length of payload_len
                .length_adjustment(5) // length of header
                .num_skip(0)           //goto start location
                .new_read(read_half);

        if let Some(message) = read_server.next().await {
            match message {
                Ok(bytes) => {
                    let ch = Message::read_bytes(bytes.as_ref());
                    println!("Sending ClientHello {:#?}", ch);
                }
                Err(err) => println!("closed with error: {:?}", err),
            }
        };
    });
    

    if let Err(e) = try_join!(read_join, write_join) {
        println!("read_join or write_join failed, error={}", e);
    };

    Ok(())
}
