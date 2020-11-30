use crate::msgs::message::{Message,MessagePayload};
use crate::msgs::type_enums::{HandshakeType,ContentType,CipherSuite,NamedGroup};
use crate::msgs::handshake::{HandshakePayload, HandshakeMessagePayload,Random,ServerHelloPayload};
use crate::msgs::alert::{SaeAlert};


use crate::session::{error::StateChangeError,server_session::ServerSession,suites};

use async_trait::async_trait;


pub type NextServerHandshakeState = Box<dyn ServerHandshakeState + Send + Sync>;
pub type NextServerHandshakeStateOrError = Result<NextServerHandshakeState, StateChangeError>;

#[async_trait]
pub trait ServerHandshakeState {
    /// Each handle() implementation consumes a whole SAE message, and returns
    /// either an error or the next state.
    async fn handle(self: Box<Self>, sess: &mut ServerSession, m: Message) -> NextServerHandshakeStateOrError;
    /// 判断握手过程是否结束
    fn is_handshake_finished(&self) -> bool;
}

// 初始化的服务端握手状态
pub struct ExpectClientHello {
    pub server_random: Random,
}
impl ExpectClientHello {
    pub fn new() -> ExpectClientHello {
        let server_random =  Random::from_slice(&b"\x02\x00\x00\x00\x00\x00"[..]);
        ExpectClientHello {
            server_random
        }
    }
   
    pub fn initial_server_hello(&self, cipher_suite: &CipherSuite, name_group: &NamedGroup,sess: &mut ServerSession) -> Message {
        let server_random = self.server_random.clone();
        let server_cipher_suite = cipher_suite.clone();
        let server_name_group =  name_group.clone();
        let server_protocal_version = sess.config.protocal_version.clone();
        
        let shp = HandshakeMessagePayload {
            typ: HandshakeType::ServerHello,
            payload: HandshakePayload::ServerHello(ServerHelloPayload {
                random: server_random,
                cipher_suite: server_cipher_suite,
                name_group: server_name_group,
            }),
        };
        let sh = Message {
            typ: ContentType::Handshake,
            version: server_protocal_version,
            payload: MessagePayload::Handshake(shp),
        };

        return sh;
    }
}

// 实现状态转换接口
#[async_trait]
impl ServerHandshakeState for ExpectClientHello {
    async fn handle(mut self: Box<Self>, sess: &mut ServerSession, m: Message) -> NextServerHandshakeStateOrError {
        // 检查收到的消息
        // StateChangeError::check_receive_message(&m, &[ContentType::Handshake], &[HandshakeType::ClientHello])?;
        // 检查收到的消息，并获取负载
        let client_hello = require_handshake_msg!(m, HandshakeType::ClientHello, HandshakePayload::ClientHello)?;

        // 选择加密套件
        let maybe_ciphersuite = suites::choose_ciphersuite_preferring_server(&client_hello.cipher_suites, &sess.config.cipher_suites);

        // 没有合适的加密组件，返回握手失败告警
        if maybe_ciphersuite.is_none() {
            return Err(StateChangeError::AlertSend(
                SaeAlert::HandshakeFailure.value(),
            ))
        }
        let cipher_suite = maybe_ciphersuite.unwrap();

        // 选择命名群
        let maybe_namedgroup = suites::choose_namedgroup_preferring_server(&client_hello.name_groups, &sess.config.name_groups,&cipher_suite);
        // 没有合适的命名群，返回握手失败告警
        if maybe_namedgroup.is_none() {
            return Err(StateChangeError::AlertSend(
                SaeAlert::HandshakeFailure.value(),
            ))
        }
        let named_group = maybe_namedgroup.unwrap();

        // 构建ServerHello信息
        let sh = self.initial_server_hello(&cipher_suite,&named_group,sess);

        // 创建下一个状态
        // let next_state = Box::new(ExpectServerHello {
        //     server_random: self.server_random,
        // });
        
        println!("Send message {:?}", sh);


        // 发送消息
        sess.duplex.write_one_message_or_err(sh).await?;

        // 返回下一个状态
        // return Ok(next_state);
        // 状态处理未实现
        return Err(StateChangeError::InternelError("unimplement".to_string()));
    }

    fn is_handshake_finished(&self) -> bool{
        false
    }
}

/* 
// 等待ServerHello消息
pub struct ExpectServerHello {
    pub server_random: Random,
}

// 实现状态转换接口
#[async_trait]
impl ServerHandshakeState for ExpectServerHello {
    async fn handle(mut self: Box<Self>, sess: &mut ServerSession, m: Message) -> NextServerHandshakeStateOrError {
        // 状态处理未实现
        return Err(StateChangeError::InternelError("unimplement".to_string()));
    }

    fn is_handshake_finished(&self) -> bool{
        false
    }

}
 */