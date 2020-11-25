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

//!     cargo run --example echo_server
//!     cargo run --example echo_client 127.0.0.1:8082

#![warn(rust_2018_idioms)]

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
use sae_net::session::{session_duplex::SessionDuplex};


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
    let mut client_session_duplex = SessionDuplex::new(server_sock);

    let client_join = tokio::spawn(async move{
        
        let client_random =  Random::from_slice(&b"\x02\x00\x00\x00\x01\x00"[..]);
        let client_cipher_suites = vec![ CipherSuite::FFCPWD_AES_128_GCM_SHA256, CipherSuite::FFCPWD_AES_256_GCM_SHA384];
        let clinet_name_groups = vec![NamedGroup::FFDHE3072,NamedGroup::FFDHE4096];
        let clinet_pwd_name = PayloadU8::new(Vec::<u8>::from("root"));
        let protocal_version = ProtocolVersion::SAEv1_0;


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
            version: protocal_version.clone(),
            payload: MessagePayload::Handshake(chp),
        };

        println!("Sending ClientHello {:#?}", ch);

        // write ClientHello
        if let Err(_) = client_session_duplex.write_one_message(ch).await{
            return;
        }
        // read ServerHello
        let sh = match client_session_duplex.read_one_message_detail_error(&protocal_version).await{
            Some(message) => message,
            None => return,
        };
        
        println!("Receive ServerHello {:#?}", sh);

    });

    

    if let Err(e) = try_join!(client_join) {
        println!("client_join failed, error={}", e);
    };

    Ok(())
}
