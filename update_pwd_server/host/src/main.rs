//!     cargo run --example update_pwd_server
//!     cargo run --example echo_client 127.0.0.1:9090

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
    // 127.0.0.1:9090 for connections.
    // 获取服务端绑定地址
    let addr = env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:9090".to_string());

    // Next up we create a TCP listener which will listen for incoming
    // connections. This TCP listener is bound to the address we determined
    // above and must be associated with an event loop, so we pass in a handle
    // to our event loop. After the socket's created we inform that we're ready
    // to go and start accepting connections.

    // 获取服务端监听器
    let listener = TcpListener::bind(&addr).await?;
    println!("Listening on: {}", addr);

    loop {
        // Asynchronously wait for an inbound socket.
        // 获取客户端连接
        let (socket, _) = listener.accept().await?;

        // 获取服务端配置
        let config = ServerConfig::new();

        // 创建服务端SAE—NET会话
        let mut session = ServerSession::new(socket, config);

        // 创建可信应用上下文
        let mut core_ctx = SaeCaContext::new_ctx().expect("create core_ctx error!");
        let mut core_session =
            SaeCaContext::new_session(&mut core_ctx).expect("create core_session error!");

        // 进行SAE握手过程
        if let Err(err) = session.handshake_with_ta(&mut core_session).await {
            println!("handshake error: {:?}", err);
            continue;
        } else {
            println!("handshake success");
        }
        // And this is where much of the magic of this server happens. We
        // crucially want all clients to make progress concurrently, rather than
        // blocking one on completion of another. To achieve this we use the
        // `tokio::spawn` function to execute the work in the background.
        //
        // Essentially here we're executing a new task to run concurrently,
        // which will allow all of our clients to be processed concurrently.

        // 使用SAE会话进行数据传输，执行响应任务

        // 接收数据
        let recv_msg = match session.recv_msg_payload().await {
            Ok(payload) => {
                if payload.len() == 0 {
                    println!("Socket received FIN packet and closed connection");
                    return Ok(());
                }
                payload
            }
            Err(err) => {
                println!("recv payload error: {:?}", err);
                return Ok(());
            }
        };

        // 反序列化
        let cipher_req = serde_json::from_slice(&recv_msg)?;
        // 调用可信应用计算
        let cipher_res = core_session.termial_pwd_manage(&cipher_req)?;
        // 序列化
        let send_msg = serde_json::to_vec(&cipher_res)?;

        // 发送数据
        if let Err(err) = session.send_msg_payload(&send_msg).await {
            println!("send payload error: {:?}", err);
            return Ok(());
        } 
    }
}