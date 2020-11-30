use crate::session::{server_config::ServerConfig, session_duplex::SessionDuplex};
use tokio::net::TcpStream;

use crate::session::error::StateChangeError;
use crate::session::server_state::{self, ExpectClientHello, ServerHandshakeState};
// use std::sync::Arc;

pub struct ServerSession {
    pub duplex: SessionDuplex,
    pub config: ServerConfig,
}

impl ServerSession {
    pub fn new(sock: TcpStream, config: ServerConfig) -> ServerSession {
        ServerSession {
            duplex: SessionDuplex::new(sock),
            config,
        }
    }
    pub async fn handshake(&mut self) -> Result<(), StateChangeError> {
        // 启动握手
        if let Err(err) = self.inner_handshake().await {
            // 统一错误处理
            err.handle_error(&mut self.duplex,&self.config.protocal_version).await;
            return Err(err);
        }
        // 正常状态
        return Ok(());
    }

    async fn inner_handshake(&mut self) -> Result<(), StateChangeError> {
        // 初始化状态
        let mut state: server_state::NextServerHandshakeState = Box::new(ExpectClientHello::new());
        // 循环推进状态机，直至完成握手过程
        while state.is_handshake_finished() != true {
            // 接收数据包
            let message = self.duplex.read_one_message_or_err().await?;

            // 处理数据包
            if let Some(received_message) = message {
                println!("Receive message {:?}", received_message);
                state = state.handle(self, received_message).await?;
            } else {
                // 没有数据包
                return Err(StateChangeError::InvalidTransition);
            }
        }
        Ok(())
    }
}
