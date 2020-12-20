use crate::msgs::alert::SaeAlert;
use crate::msgs::base::{PayloadU16, PayloadU8};
use crate::msgs::handshake::{
    AuthCommitPayload, AuthConfirmPayload, ClientHelloPayload, HandshakeMessagePayload,
    HandshakePayload, Random, ServerHelloPayload,
};
use crate::msgs::message::{Message, MessagePayload};
use crate::msgs::type_enums::{ContentType, HandshakeType};
use crate::session::{client_session::ClientSession, error::StateChangeError};

use async_trait::async_trait;
// use sae_core::SaeCaContext;

pub type NextClientHandshakeState = Box<dyn ClientHandshakeState + Send + Sync>;
pub type NextClientHandshakeStateOrError = Result<NextClientHandshakeState, StateChangeError>;

#[async_trait]
pub trait ClientHandshakeState {
    /// Each handle() implementation consumes a whole SAE message, and returns
    /// either an error or the next state.
    async fn handle(
        self: Box<Self>,
        sess: &mut ClientSession,
        m: Message,
    ) -> NextClientHandshakeStateOrError;
    /// 判断握手过程是否结束
    fn is_handshake_finished(&self) -> bool;
}

// 初始化的客户端握手状态
pub struct InitialClientHandshakeState {
    pub client_random: Random,
}
impl InitialClientHandshakeState {
    pub fn new() -> InitialClientHandshakeState {
        let client_random = Random::from_slice(&b"\x02\x00\x00\x00\x01\x00"[..]);
        InitialClientHandshakeState { client_random }
    }
    // fn initial_client_hello(self, sess: &mut ClientSession) -> Message {
    pub fn initial_client_hello(&self, sess: &mut ClientSession) -> Message {
        let client_random = self.client_random.clone();
        let client_cipher_suites = sess.config.cipher_suites.clone();
        let clinet_name_groups = sess.config.name_groups.clone();
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
    async fn handle(
        mut self: Box<Self>,
        sess: &mut ClientSession,
        m: Message,
    ) -> NextClientHandshakeStateOrError {
        // 检查发送的消息
        StateChangeError::check_send_message(
            &m,
            &[ContentType::Handshake],
            &[HandshakeType::ClientHello],
        )?;

        // 创建下一个状态
        let next_state = Box::new(ExpectServerHello {
            client_random: self.client_random,
        });

        println!("Send ClientHello message : \n {:?}", m);

        // 发送消息
        sess.duplex.write_one_message_or_err(m).await?;

        // 返回下一个状态
        return Ok(next_state);
    }

    fn is_handshake_finished(&self) -> bool {
        false
    }
}

// 等待ServerHello消息
pub struct ExpectServerHello {
    pub client_random: Random,
}

impl ExpectServerHello {
    // 判断是否包含发送的加密套件、命名群
    fn is_success_choose(sess: &ClientSession, server_hello: &ServerHelloPayload) -> bool {
        // 如果不包含发送的加密套件
        if !sess
            .config
            .cipher_suites
            .contains(&server_hello.cipher_suite)
        {
            return false;
        }
        // 如果不包含发送的命名群
        if !sess.config.name_groups.contains(&server_hello.name_group) {
            return false;
        }
        // 如果加密套件和命名群不匹配
        if server_hello.cipher_suite.is_ffc() != server_hello.name_group.is_ffc() {
            return false;
        }
        return true;
    }

    // 生成认证提交信息
    fn initial_auth_commit(&self, sess: &mut ClientSession) -> Message {
        let server_protocal_version = sess.config.protocal_version.clone();
        let scalar_hex_str = "21680e1108ffc527f82b1f04ada3c75e66b0de0a4d30e9b0cad5d6679ea64aa824409cf36d43f3c0044ad116aac29eff3f8c4e3a52f160f6488573ba98f1c7c89399b64b1e60fe94e1fd875fc574b051498ee6b78504edb6a6b1b6e8cacf867cd7b5d7937da8d60032d589034bdcbd230c0f331cec623ba815e35f4750a3c0d80eaa6cf70fed92331f893be9e61569357a73cc4283825e5562e6d7f264acea0ce7ae01e4b3c11e0c45f4db43af78e1165292223cb6f22b52654f2f9af9406b748781054d983ab87ce51347d80e8941e1516f10fcf497e1a715c831211560ce00816b2207b5550c737fb73ca15a476d071d63f8be65ab71a40a4181405d44b7861706311d6aaddb432f859e940a1840e7a0e241d26b47eb5906f5403586067b4ed931c4240a6e77aadaacd794020e91d030047e98956fa088dc58b1fe1835634e7af748c4898b5056bddc5c7bf3c2fbc044ee43bae644fc9cc8f30d32f05f973abbb86231aaedc498be0eaea67edfed56280c5b8f4da127bf8b6af42679a75ab3";
        let element_hex_str = "9b37a6d51df18267f32ba132a9054a17ca6904faaae3996a4cfdad5bf9b5bd49af59d0c20e1c6cdf461f9aa4829bfbdd862156c24b44a45711ed3da8a128379ff6d17cc03ac99b320faeb3e9fa9038978ea4266d0a4d2ee55578fdaf008297a85337ea271bf4f396dfffbb9f36a08469a4a191a8ae2d5d31b24aa769757d1336e7945278cf697a8c4cfd82bc68fdb258df332f604f30bdc70f6330312818ffb2b43124fb1aa3afd29f8ea5e762d63cd95694b0187c0983e51828486f3c4926748ab0744614ad501e75d2da582c37c0226f2ad289a7beca268aa5af397bf94c4764489653930f8e9c6bf19d83ec1bb4d142abd96533518c855b931c62fac55626aae61f35452155e24de521e99962b7551a28728f185135f1a4980400819bc9e98cbfe8593e43ea4c3c90a55ae405ac1ba2e9e95dab40f9a94bbe2c72cc462a2af63d6426cd1ee0c8b04d3895d2c6ca787d99912f6701ae7705d49c27b6a8e9e649e0f16da8bd557b33b9a94d33b66772510ab4aed2130cd79732a6338d6f982f";
        let scalar_vec = scalar_hex_str.as_bytes().to_vec();
        let element_vec = element_hex_str.as_bytes().to_vec();

        let message_payload = HandshakeMessagePayload {
            typ: HandshakeType::ClientAuthCommit,
            payload: HandshakePayload::ClientAuthCommit(AuthCommitPayload {
                scalar: PayloadU16::new(scalar_vec),
                element: PayloadU16::new(element_vec),
            }),
        };
        let message = Message {
            typ: ContentType::Handshake,
            version: server_protocal_version,
            payload: MessagePayload::Handshake(message_payload),
        };

        return message;
    }
}

// 实现状态转换接口
#[async_trait]
impl ClientHandshakeState for ExpectServerHello {
    async fn handle(
        mut self: Box<Self>,
        sess: &mut ClientSession,
        m: Message,
    ) -> NextClientHandshakeStateOrError {
        // 检查收到的消息
        StateChangeError::check_receive_message(
            &m,
            &[ContentType::Handshake],
            &[HandshakeType::ServerHello],
        )?;
        // 获取消息负载
        let server_hello =
            require_handshake_msg!(m, HandshakeType::ServerHello, HandshakePayload::ServerHello)?;
        // 判断服务器发过来的参数
        if !Self::is_success_choose(&sess, &server_hello) {
            // 返回非法参数警告
            return Err(StateChangeError::AlertSend(SaeAlert::IllegalParameter));
        }
        // 将会话参数设置为与服务器协商好的参数
        sess.choose_ciphersuite = Some(server_hello.cipher_suite.clone());
        sess.choose_namedgroup = Some(server_hello.name_group.clone());

        // 构建ClientAuthCommit消息
        let auth_commit = self.initial_auth_commit(sess);

        println!("Send ClientAuthCommit message : \n {:?}", auth_commit);

        // 发送ClientAuthCommit消息
        sess.duplex.write_one_message_or_err(auth_commit).await?;

        // 创建下一个状态
        let next_state = Box::new(ExpectServerAuthCommit {});

        // 返回下一个状态
        return Ok(next_state);
    }

    fn is_handshake_finished(&self) -> bool {
        false
    }
}

// 等待ServerAuthCommit消息
pub struct ExpectServerAuthCommit;

impl ExpectServerAuthCommit {
    // 生成认证确认信息
    fn initial_auth_confirm(&self, sess: &mut ClientSession) -> Message {
        let server_protocal_version = sess.config.protocal_version.clone();
        let confirm_hex_str = "b305435edeba9de0cc6baa9223b6a0fc8fd4f389a8631f31204d7971e29e1c53";
        let confirm_vec = confirm_hex_str.as_bytes().to_vec();

        let message_payload = HandshakeMessagePayload {
            typ: HandshakeType::ClientAuthConfirm,
            payload: HandshakePayload::ClientAuthConfirm(AuthConfirmPayload {
                confirm: PayloadU8::new(confirm_vec),
            }),
        };
        let message = Message {
            typ: ContentType::Handshake,
            version: server_protocal_version,
            payload: MessagePayload::Handshake(message_payload),
        };

        return message;
    }
}

// 实现状态转换接口
#[async_trait]
impl ClientHandshakeState for ExpectServerAuthCommit {
    async fn handle(
        mut self: Box<Self>,
        sess: &mut ClientSession,
        m: Message,
    ) -> NextClientHandshakeStateOrError {
        // 检查收到的消息
        StateChangeError::check_receive_message(
            &m,
            &[ContentType::Handshake],
            &[HandshakeType::ServerAuthCommit],
        )?;
        // 获取消息负载
        let _server_auth_commit = require_handshake_msg!(
            m,
            HandshakeType::ServerAuthCommit,
            HandshakePayload::ServerAuthCommit
        )?;

        // 构建ClientAuthConfirm消息
        let auth_confirm = self.initial_auth_confirm(sess);

        println!("Send ClientAuthConfirm message : \n {:?}", auth_confirm);

        // 发送ClientAuthConfirm消息
        sess.duplex.write_one_message_or_err(auth_confirm).await?;

        // 创建下一个状态
        let next_state = Box::new(ExpectServerAuthConfirm {});

        // 返回下一个状态
        return Ok(next_state);
    }

    fn is_handshake_finished(&self) -> bool {
        false
    }
}

// 等待ServerAuthConfirm消息的状态
pub struct ExpectServerAuthConfirm;

// 实现状态转换接口
#[async_trait]
impl ClientHandshakeState for ExpectServerAuthConfirm {
    async fn handle(
        mut self: Box<Self>,
        _sess: &mut ClientSession,
        m: Message,
    ) -> NextClientHandshakeStateOrError {
        // 检查收到的消息
        StateChangeError::check_receive_message(
            &m,
            &[ContentType::Handshake],
            &[HandshakeType::ServerAuthConfirm],
        )?;
        // 获取消息负载
        let _server_auth_confirm = require_handshake_msg!(
            m,
            HandshakeType::ServerAuthConfirm,
            HandshakePayload::ServerAuthConfirm
        )?;

        // 创建下一个状态
        let next_state = Box::new(ClientHandshakeFinished {});

        // 返回下一个状态
        return Ok(next_state);
    }

    fn is_handshake_finished(&self) -> bool {
        false
    }
}

// 客户端握手成功状态
pub struct ClientHandshakeFinished;

// 实现状态转换接口
#[async_trait]
impl ClientHandshakeState for ClientHandshakeFinished {
    async fn handle(
        mut self: Box<Self>,
        _sess: &mut ClientSession,
        _m: Message,
    ) -> NextClientHandshakeStateOrError {
        // 状态处理未实现
        return Err(StateChangeError::InternelError("unimplement".to_string()));
    }

    fn is_handshake_finished(&self) -> bool {
        true
    }
}
