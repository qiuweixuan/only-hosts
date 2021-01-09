//!     cargo run --example echo_server
//!     cargo run --example echo_client_session 127.0.0.1:8080

#![warn(rust_2018_idioms)]

use std::env;
use std::error::Error;
use std::net::SocketAddr;
use tokio::net::TcpStream;
use tokio::try_join;

use sae_net::session::client_config::ClientConfig;
use sae_net::session::client_session::ClientSession;

use structopt::StructOpt;
use log4rs;

#[derive(StructOpt, Debug)]
struct Cli {
    /// Pass an address we're going to connect to
    #[structopt(name = "addr", long = "--addr")]
    addr: String,

    /// Pass an account we're going to connect to
    #[structopt(name = "account", long = "--account")]
    account: Option<String>,

    /// Pass an password we're going to connect to
    #[structopt(name = "password", long = "--pwd")]
    password: Option<String>,

    /// Pass an log config file path
    #[structopt(name = "log", long = "--log", default_value = "./log/echo_client_log.yaml")]
    log: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // 获取命令行参数
    // Parse command line arguments
    let client_args = Cli::from_args();
    
    // 进行日志配置
    log4rs::init_file(client_args.log, Default::default())?;

    // Parse what address we're going to connect to
    // socket地址解析
    let addr = client_args.addr.clone();
    let addr = addr.parse::<SocketAddr>()?;

    // 获取请求的TCP服务端连接
    let server_sock = TcpStream::connect(addr).await?;

    // 获取客户端配置
    let mut config = ClientConfig::new();
    // let config = ClientConfig::new_ecc_config();
    // 设置配置
    if let Some(account) = client_args.account{
        config.set_account(&account.as_bytes());
    };
    if let Some(password) = client_args.password{
        config.set_password(&password.as_bytes());
    };

    // 创建客户端SAE—NET会话
    let mut session = ClientSession::new(server_sock, config);


    // 进行SAE握手过程
    /* if let Err(err) = session.handshake().await {
        println!("handshake error: {:?}", err);
        return Ok(());
    } else {
        println!("handshake success");
    } */
    if let Err(err) = session.handshake_with_ca().await {
        println!("handshake error: {:?}", err);
        return Ok(());
    } else {
        println!("handshake success");
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
