//!     cargo run --example echo_server
//!     cargo run --example echo_client 127.0.0.1:8082

#![warn(rust_2018_idioms)]

use tokio::net::TcpListener;

use sae_core::SaeCaContext;
use sae_net::session::server_config::ServerConfig;
use sae_net::session::server_session::ServerSession;
use std::env;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Allow passing an address to listen on as the first argument of this
    // program, but otherwise we'll just set up our TCP listener on
    // 127.0.0.1:8082 for connections.
    // 获取服务端绑定地址
    let addr = env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:8082".to_string());

    // Next up we create a TCP listener which will listen for incoming
    // connections. This TCP listener is bound to the address we determined
    // above and must be associated with an event loop, so we pass in a handle
    // to our event loop. After the socket's created we inform that we're ready
    // to go and start accepting connections.

    // 获取服务端监听器
    let listener = TcpListener::bind(&addr).await?;
    println!("Listening on: {}", addr);

    // 获取请求的CA服务端上下文
    let mut ca_ctx = SaeCaContext::new_ctx();

    loop {
        // Asynchronously wait for an inbound socket.
        // 获取客户端连接
        let (socket, _) = listener.accept().await?;

        // 获取服务端配置
        let config = ServerConfig::new();

        // 创建服务端SAE—NET会话
        let mut session = ServerSession::new(socket, config);

        // 进行SAE握手过程
        {
            // 获取请求的CA服务端会话连接
            let mut ca_session =
                SaeCaContext::new_session(&mut ca_ctx).expect("new ca_session error!");
            
            if let Err(err) = session.handshake().await {
                println!("handshake error: {:?}", err);
                continue;
            } else {
                println!("handshake success");
            }
        }

        // And this is where much of the magic of this server happens. We
        // crucially want all clients to make progress concurrently, rather than
        // blocking one on completion of another. To achieve this we use the
        // `tokio::spawn` function to execute the work in the background.
        //
        // Essentially here we're executing a new task to run concurrently,
        // which will allow all of our clients to be processed concurrently.

        // 使用SAE会话进行数据传输，执行响应任务
        tokio::spawn(async move {
            loop {
                let recv_msg = match session.recv_msg_payload().await {
                    Ok(payload) => {
                        let recv_msg = String::from_utf8(payload).unwrap();
                        println!("recv payload: {:?}", recv_msg);
                        recv_msg
                    }
                    Err(_err) => {
                        // println!("recv payload error: {:?}", err);
                        println!("Socket received FIN packet and closed connection");
                        return;
                    }
                };
                let payload = Vec::<u8>::from(recv_msg);
                if let Err(err) = session.send_msg_payload(&payload).await {
                    println!("send payload error: {:?}", err);
                    return;
                } else {
                    println!("send payload: {:?}", String::from_utf8(payload).unwrap());
                }
            }
        });
    }
}
