//!     cargo run --example echo_server
//!     cargo run --example update_pwd_client_session 127.0.0.1:9090

#![warn(rust_2018_idioms)]

use sae_core::SaeCaContext;
use sae_core;
use sae_net::session::client_config::ClientConfig;
use sae_net::session::client_session::ClientSession;
use std::error::Error;
use std::net::SocketAddr;
use tokio::net::TcpStream;

use serde_json;
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
    #[structopt(name = "log", long = "--log", default_value = "./log/upload_pwd_client_log.yaml")]
    log: String,

    #[structopt(subcommand)]
    command: Command,
}

#[derive(StructOpt, Debug)]
enum Command {
    /// Get the value of key.
    Get {
        /// Name of key to get
        key: String,
    },
    /// Set key to hold the string value.
    Set {
        /// Name of key to set
        key: String,

        /// Value to set.
        value: String,
    },
    /// Del the value of key.
    Del {
        /// Name of key to del
        key: String,
    },
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
   

    // Parse command line arguments
    let client_args = Cli::from_args();
    println!("args: {:?}",client_args);

    // 进行日志配置
    log4rs::init_file(client_args.log, Default::default())?;

    // 网络地址解析
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

    // 创建可信应用上下文
    let mut core_ctx = SaeCaContext::new_ctx().expect("create core_ctx error!");
    let mut core_session =
        SaeCaContext::new_session(&mut core_ctx).expect("create core_session error!");

    // 进行SAE握手过程
    if let Err(err) = session.handshake_with_ta(&mut core_session).await {
        println!("handshake error: {:?}", err);
        return Ok(());
    } else {
        println!("handshake success");
    }

    /* 使用SAE会话进行数据传输，执行请求任务 */

    // 子命令处理
    // 获取加密后的请求
    let cipher_req = match client_args.command {
        Command::Get { key } => core_session.get_remote_pwd_req(&key.as_bytes())?,
        Command::Set { key, value } => {
            core_session.set_remote_pwd_req(&key.as_bytes(), &value.as_bytes())?
        }
        Command::Del { key } => core_session.del_remote_pwd_req(&key.as_bytes())?,
    };

    let serialized_input = serde_json::to_vec(&cipher_req)?;
    // 发送数据
    if let Err(err) = session.send_msg_payload(&serialized_input).await {
        println!("send payload error: {:?}", err);
        return Ok(());
    }

    // 获取数据
    let serialized_output = match session.recv_msg_payload().await {
        Ok(payload) => payload,
        Err(err) => {
            println!("recv payload error: {:?}", err);
            return Ok(());
        }
    };

    // 获取解密后的响应
    let cipher_res = serde_json::from_slice(&serialized_output)?;
    let command_res = core_session.remote_pwd_res(&cipher_res)?;
    // println!("result: {:?}", &command_res);

    match command_res{
        sae_core::RemotePwdManageRes::Get{value,is_success} => 
        { println!("Get [value: {:?} ,is_success : {}] ", String::from_utf8(value),is_success); }
        _ => { println!("result: {:?}", &command_res); }
    };
   

    Ok(())
}
