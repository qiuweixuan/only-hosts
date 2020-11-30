use crate::session::{client_config::ClientConfig, session_duplex::SessionDuplex};
use tokio::net::TcpStream;

use crate::session::client_state::{self, ClientHandshakeState, InitialClientHandshakeState};
use crate::session::error::StateChangeError;
// use std::sync::Arc;

pub struct ClientSession {
    pub duplex: SessionDuplex,
    pub config: ClientConfig,
}

impl ClientSession {
    pub fn new(sock: TcpStream, config: ClientConfig) -> ClientSession {
        ClientSession {
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

    async fn inner_handshake(&mut self) -> Result<(), StateChangeError>  {
        // 初始化状态
        let init_state = Box::new(InitialClientHandshakeState::new());
        let client_hello_message = init_state.initial_client_hello(self);
        let mut state : client_state::NextClientHandshakeState = init_state.handle(self, client_hello_message).await?;
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
