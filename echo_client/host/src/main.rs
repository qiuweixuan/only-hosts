//!     cargo run --example echo_server
//!     cargo run --example echo_client_session 127.0.0.1:8082

#![warn(rust_2018_idioms)]

use std::env;
use std::error::Error;
use std::net::SocketAddr;
use tokio::net::TcpStream;
use tokio::try_join;

use sae_core::SaeCaContext;
use sae_net::session::client_config::ClientConfig;
use sae_net::session::client_session::ClientSession;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Determine if we're going to run in TCP or UDP mode
    // 获取命令行参数
    let args = env::args().skip(1).collect::<Vec<_>>();

    // Parse what address we're going to connect to
    // socket地址解析
    let addr = args
        .first()
        .ok_or("this program requires at least one argument")?;
    let addr = addr.parse::<SocketAddr>()?;

    // 获取请求的TCP服务端连接
    let server_sock = TcpStream::connect(addr).await?;

    // 获取客户端配置
    let config = ClientConfig::new();
    // let config = ClientConfig::new_ecc_config();
    // 创建客户端SAE—NET会话
    let mut session = ClientSession::new(server_sock, config);

    // 获取请求的CA服务端上下文
    let mut ctx = SaeCaContext::new_ctx();

    // 进行SAE握手过程
    {
        // 获取请求的CA服务端会话连接
        let mut ca_session = SaeCaContext::new_session(&mut ctx).expect("new ca_session error!");
        if let Err(err) = session.handshake().await {
            println!("handshake error: {:?}", err);
            return Ok(());
        } else {
            println!("handshake success");
        }
    }

    // 使用SAE会话进行数据传输，执行请求任务
    let client_join = tokio::spawn(async move {
        // 发送数据
        let payload = Vec::<u8>::from("Hello World");
        if let Err(err) = session.send_msg_payload(&payload).await {
            println!("send payload error: {:?}", err);
            return;
        } else {
            println!("send payload: {:?}", String::from_utf8(payload).unwrap());
        }
        // 获取数据
        match session.recv_msg_payload().await {
            Ok(payload) => {
                println!("recv payload: {:?}", String::from_utf8(payload));
            }
            Err(err) => {
                println!("recv payload error: {:?}", err);
                return;
            }
        };
    });

    // 等待任务执行完
    if let Err(e) = try_join!(client_join) {
        println!("client_task failed, error={}", e);
    };

    Ok(())
}
