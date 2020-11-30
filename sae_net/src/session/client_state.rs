use crate::msgs::message::{Message,MessagePayload};
use crate::msgs::type_enums::{HandshakeType,ContentType};
use crate::msgs::handshake::{HandshakePayload, HandshakeMessagePayload, ClientHelloPayload,Random};
use crate::msgs::alert::{SaeAlert};
use crate::session::{error::StateChangeError,client_session::ClientSession};

use async_trait::async_trait;


pub type NextClientHandshakeState = Box<dyn ClientHandshakeState + Send + Sync>;
pub type NextClientHandshakeStateOrError = Result<NextClientHandshakeState, StateChangeError>;

#[async_trait]
pub trait ClientHandshakeState {
    /// Each handle() implementation consumes a whole SAE message, and returns
    /// either an error or the next state.
    async fn handle(self: Box<Self>, sess: &mut ClientSession, m: Message) -> NextClientHandshakeStateOrError;
    /// 判断握手过程是否结束
    fn is_handshake_finished(&self) -> bool;
}

// 初始化的客户端握手状态
pub struct InitialClientHandshakeState {
    pub client_random: Random,
}
impl InitialClientHandshakeState {
    pub fn new() -> InitialClientHandshakeState {
        let client_random =  Random::from_slice(&b"\x02\x00\x00\x00\x01\x00"[..]);
        InitialClientHandshakeState {
            client_random
        }
    }
    // fn initial_client_hello(self, sess: &mut ClientSession) -> Message {
    pub fn initial_client_hello(&self,sess: &mut ClientSession) -> Message {
        let client_random = self.client_random.clone();
        let client_cipher_suites = sess.config.cipher_suites.clone();
        let clinet_name_groups =  sess.config.name_groups.clone();
        let clinet_pwd_name = sess.config.pwd_name.clone();
        let clinet_protocal_version = sess.config.protocal_version.clone();
        
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
            version: clinet_protocal_version,
            payload: MessagePayload::Handshake(chp),
        };

        return ch;
    }
}

// 实现状态转换接口
#[async_trait]
impl ClientHandshakeState for InitialClientHandshakeState {
    async fn handle(mut self: Box<Self>, sess: &mut ClientSession, m: Message) -> NextClientHandshakeStateOrError {
        // 检查发送的消息
        StateChangeError::check_send_message(&m, &[ContentType::Handshake], &[HandshakeType::ClientHello])?;

        // 创建下一个状态
        let next_state = Box::new(ExpectServerHello {
            client_random: self.client_random,
        });

        println!("Send message {:?}", m);

        // 发送消息
        sess.duplex.write_one_message_or_err(m).await?;

        // 返回下一个状态
        return Ok(next_state);
    }

    fn is_handshake_finished(&self) -> bool{
        false
    }
}


// 等待ServerHello消息
pub struct ExpectServerHello {
    pub client_random: Random,
}

// 实现状态转换接口
#[async_trait]
impl ClientHandshakeState for ExpectServerHello {
    async fn handle(mut self: Box<Self>, sess: &mut ClientSession, m: Message) -> NextClientHandshakeStateOrError {
        // 检查收到的消息
        StateChangeError::check_receive_message(&m, &[ContentType::Handshake], &[HandshakeType::ServerHello])?;
        // 获取消息负载
        let server_hello = require_handshake_msg!(m, HandshakeType::ServerHello, HandshakePayload::ServerHello)?;
        
        // 状态处理未实现
        return Err(StateChangeError::InternelError("unimplement".to_string()));
    }

    fn is_handshake_finished(&self) -> bool{
        false
    }

}
