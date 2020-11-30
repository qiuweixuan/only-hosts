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
        // 开始握手
        let state_or_error = self.start_handshake().await;

        let mut state = match state_or_error {
            Ok(state) => state,
            Err(err) => {
                println!("StateChangeError {:?}", err);
                return Err(err);
            }
        };
        // while let Some(msg) = self.common.message_deframer.frames.pop_front() {
        //     match self.process_msg(msg) {
        //         Ok(_) => {}
        //         Err(err) => {
        //             self.error = Some(err.clone());
        //             return Err(err);
        //         }
        //     }
        // }

        while state.is_handshake_finished() != true {
            // 接收数据包
            let message = match self.duplex.read_one_message_or_err().await {
                Ok(message) => message,
                Err(err) => {
                    println!("StateChangeError {:?}", err);
                    return Err(err);
                }
            };

            // 处理数据包
            if let Some(received_message) = message {
                println!("Receive message {:?}", received_message);
                state = state.handle(self, received_message).await?;
            } else {
                // 没有数据包
                return Err(StateChangeError::InvalidTransition);
            }
        }
        return Ok(());
    }

    pub async fn start_handshake(&mut self) -> client_state::NextClientHandshakeStateOrError {
        let init_state = Box::new(InitialClientHandshakeState::new());
        let client_hello_message = init_state.initial_client_hello(self);
        init_state.handle(self, client_hello_message).await
    }
}
