use crate::session::{server_config::ServerConfig, session_duplex::SessionDuplex};
use tokio::net::TcpStream;

use crate::session::server_state::{self,ServerHandshakeState, ExpectClientHello};
use crate::session::{error::StateChangeError};
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
    pub async fn handshake(&mut self) ->  Result<(), StateChangeError> {

        let mut state : server_state::NextServerHandshakeState =  Box::new(ExpectClientHello::new());
        
        while state.is_handshake_finished() != true{
            // 接收数据包
            let message = match self.duplex.read_one_message_or_err().await{
                Ok(message) => message,
                Err(err) => {
                    println!("StateChangeError {:?}",err);
                    return Err(err);
                }
            };
            // 处理数据包
            if let Some(received_message) = message{
                println!("Receive message {:?}", received_message);
                state = state.handle(self, received_message).await?;
            }
            else
            {   
                // 没有数据包
                return Err(StateChangeError::InvalidTransition); 
            }
        }
               
        return Ok(());
    }
    

    pub async fn start_handshake(&mut self) -> server_state::NextServerHandshakeStateOrError {
        let init_state = Box::new(ExpectClientHello::new());
        Ok(init_state)
    }
}
