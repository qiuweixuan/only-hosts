use crate::msgs::alert::SaeAlert;
use crate::msgs::base::{PayloadU16, PayloadU8};
use crate::msgs::handshake::{
    AuthCommitPayload, AuthConfirmPayload, HandshakeMessagePayload, HandshakePayload, Random,
    ServerHelloPayload,
};
use crate::msgs::message::{Message, MessagePayload};
use crate::msgs::type_enums::{CipherSuite, ContentType, HandshakeType, NamedGroup};
use crate::session::{error::StateChangeError, server_session::ServerSession, suites};

use async_trait::async_trait;
// use hex;

pub type NextServerHandshakeState = Box<dyn ServerHandshakeState + Send + Sync>;
pub type NextServerHandshakeStateOrError = Result<NextServerHandshakeState, StateChangeError>;

#[async_trait]
pub trait ServerHandshakeState {
    /// Each handle() implementation consumes a whole SAE message, and returns
    /// either an error or the next state.
    async fn handle(
        self: Box<Self>,
        sess: &mut ServerSession,
        m: Message,
    ) -> NextServerHandshakeStateOrError;
    /// 判断握手过程是否结束
    fn is_handshake_finished(&self) -> bool;
}

// 初始化的服务端握手状态
pub struct ExpectClientHello {
    pub server_random: Random,
}
impl ExpectClientHello {
    pub fn new() -> ExpectClientHello {
        let server_random = Random::from_slice(&b"\x02\x00\x00\x00\x00\x00"[..]);
        ExpectClientHello { server_random }
    }

    pub fn initial_server_hello(
        &self,
        cipher_suite: &CipherSuite,
        name_group: &NamedGroup,
        sess: &mut ServerSession,
    ) -> Message {
        let server_random = self.server_random.clone();
        let server_cipher_suite = cipher_suite.clone();
        let server_name_group = name_group.clone();
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

    pub fn initial_auth_commit(&self, sess: &mut ServerSession) -> Message {
        let server_protocal_version = sess.config.protocal_version.clone();
        let scalar_hex_str = "6632ac3abc83ee96ce9cfc1ee809c9bd4ea9dec5e6d891937191428bb63d42fc72528a98e5cbef6ee05ff216aa4d8452fff11700415c6a54050653badd0329eae741db73433b9b00c6f5df568341290714ed5304ed8f7d3691a96a30e51dce469c1c0f8b19edc731e15c2fa96757483c44a737ebdb5da5dd9a57a648f31642ae29b42b6b9190ea30bdc4943d03160b9e0fac0b01f232593304366a5ece91f2fa969765860eaf2789550affa76f79235f6450968dfab9fa5a7c902b3fdd17e5823fedeaf82ad346b587e882aa8834dfe87b21ac033236424fb21d933f183103029f9e6b0e1c073cde411c7468f810db9fd7256b1338e1e8213fe20b9ad196004a4b1c20526dc7d0ddaf6a4d7f9864c711429ba3de788986b1cad48926aed4f3ff9bc02c192d095d435b273743f9db668d88a17a64b7f2c8bb6ced05f7e133d5b8829c3f088dce8ebd684565cac6147e03946495caa87a1a42ef03f9ddfc4aacc8562d4ed1898c9452027dd38f1052e328456b9d14ef4ed84ebd3fd559069c5129";
        let element_hex_str = "cc341d1af02bb87daa52861d2398b300226644ce4c93a09213ddf0dff67292714c49a5bfc0d5e39c516f45da9938d2f5c399ccc07959b5683493baaa62633d32abafb5bb15f6d79d4aef0f41424597d486242951becd63ce35708abd1538c8bc5319ed5fc99d586f4ace923a33a3c03a6eddeb13565b68e649310580b76687911d6d24ef3d8ffcfcc0bef2d2efc4f00360b873f7598ea4735941d740453acf75a62a61a5f091650baf9d1303319e343d6b5d692362b5fc19ec92035439d08441f9c5b9f0f116899a96d32e03574de3929aea7360bf9ef3640bb3aeea6304332b665bc27fb414fa555bef37fc5566a4a6f742a7f0f8ccb44e56ee6dee7831ac28f73a58ef04fcdb0cd513d14e0b94fc667e24d87ddccd8bb0ad16b89512ac3ee9d9e5904d2837e374b7831418518ea4ba1852342ac60f1737a4fcbdc6971e9753f55b3932e383f5f1dc13d2b25d5172fe129ecfc891445a8e0faeca17c5374028526c7276612aad315a77398cf223fb6492db71f1e89de4d0e2e16856beb366c9";
        let scalar_vec = hex::decode(scalar_hex_str).unwrap();
        let element_vec = hex::decode(element_hex_str).unwrap();

        let message_payload = HandshakeMessagePayload {
            typ: HandshakeType::ServerAuthCommit,
            payload: HandshakePayload::ServerAuthCommit(AuthCommitPayload {
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
impl ServerHandshakeState for ExpectClientHello {
    async fn handle(
        mut self: Box<Self>,
        sess: &mut ServerSession,
        m: Message,
    ) -> NextServerHandshakeStateOrError {
        // 检查收到的消息
        StateChangeError::check_receive_message(
            &m,
            &[ContentType::Handshake],
            &[HandshakeType::ClientHello],
        )?;
        // 获取消息负载
        let client_hello =
            require_handshake_msg!(m, HandshakeType::ClientHello, HandshakePayload::ClientHello)?;

        // 打印收到的pwd_name
        let pwd_name = client_hello.pwd_name.clone().into_inner();
        println!("Received pwd_name: {:?}", String::from_utf8(pwd_name));

        // 选择加密套件
        let maybe_ciphersuite = suites::choose_ciphersuite_preferring_server(
            &client_hello.cipher_suites,
            &sess.config.cipher_suites,
        );

        // 没有合适的加密组件，返回握手失败告警
        if maybe_ciphersuite.is_none() {
            return Err(StateChangeError::AlertSend(SaeAlert::HandshakeFailure));
        }
        let cipher_suite = maybe_ciphersuite.unwrap();

        // 选择命名群
        let maybe_namedgroup = suites::choose_namedgroup_preferring_server(
            &client_hello.name_groups,
            &sess.config.name_groups,
            &cipher_suite,
        );
        // 没有合适的命名群，返回握手失败告警
        if maybe_namedgroup.is_none() {
            return Err(StateChangeError::AlertSend(SaeAlert::HandshakeFailure));
        }
        let named_group = maybe_namedgroup.unwrap();

        // 将会话参数设置为从客户端可选组合挑选好的参数
        sess.choose_ciphersuite = Some(cipher_suite.clone());
        sess.choose_namedgroup = Some(named_group.clone());

        // 构建ServerHello信息
        let sh = self.initial_server_hello(&cipher_suite, &named_group, sess);
        println!("Send ServerHello message : \n {:?}", sh);

        // 发送ServerHello消息
        sess.duplex.write_one_message_or_err(sh).await?;

        // 构建ServerAuthCommit消息
        let auth_commit = self.initial_auth_commit(sess);

        println!("Send ServerAuthCommit message :\n {:?}", auth_commit);

        // 发送ServerAuthCommit消息
        sess.duplex.write_one_message_or_err(auth_commit).await?;

        // 创建下一个状态
        let next_state = Box::new(ExpectClientAuthCommit {});

        // 返回下一个状态
        return Ok(next_state);
    }

    fn is_handshake_finished(&self) -> bool {
        false
    }
}

// 等待ClientAuthCommit消息的状态
pub struct ExpectClientAuthCommit;

impl ExpectClientAuthCommit {
    // 生成认证确认信息
    fn initial_auth_confirm(&self, sess: &mut ServerSession) -> Message {
        let server_protocal_version = sess.config.protocal_version.clone();
        let confirm_hex_str = "62ef3902425759037499616b5e5412ce76c6e624e419f18782298f41ec9fc37d";
        let confirm_vec = hex::decode(confirm_hex_str).unwrap();

        let message_payload = HandshakeMessagePayload {
            typ: HandshakeType::ServerAuthConfirm,
            payload: HandshakePayload::ServerAuthConfirm(AuthConfirmPayload {
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
impl ServerHandshakeState for ExpectClientAuthCommit {
    async fn handle(
        mut self: Box<Self>,
        sess: &mut ServerSession,
        m: Message,
    ) -> NextServerHandshakeStateOrError {
        // 检查收到的消息
        StateChangeError::check_receive_message(
            &m,
            &[ContentType::Handshake],
            &[HandshakeType::ClientAuthCommit],
        )?;
        // 获取消息负载
        let server_auth_commit = require_handshake_msg!(
            m,
            HandshakeType::ClientAuthCommit,
            HandshakePayload::ClientAuthCommit
        )?;

        // 构建ServerAuthConfirm消息
        let auth_confirm = self.initial_auth_confirm(sess);

        println!("Send ServerAuthConfirm message : \n {:?}", auth_confirm);

        // 发送ServerAuthConfirm消息
        sess.duplex.write_one_message_or_err(auth_confirm).await?;

        // 创建下一个状态
        let next_state = Box::new(ExpectClientAuthConfirm {});

        // 返回下一个状态
        return Ok(next_state);
    }

    fn is_handshake_finished(&self) -> bool {
        false
    }
}

// 等待ClientAuthConfirm消息的状态
pub struct ExpectClientAuthConfirm;

// 实现状态转换接口
#[async_trait]
impl ServerHandshakeState for ExpectClientAuthConfirm {
    async fn handle(
        mut self: Box<Self>,
        _sess: &mut ServerSession,
        m: Message,
    ) -> NextServerHandshakeStateOrError {
        // 检查收到的消息
        StateChangeError::check_receive_message(
            &m,
            &[ContentType::Handshake],
            &[HandshakeType::ClientAuthConfirm],
        )?;
        // 获取消息负载
        let client_auth_confirm = require_handshake_msg!(
            m,
            HandshakeType::ClientAuthConfirm,
            HandshakePayload::ClientAuthConfirm
        )?;

        // 创建下一个状态
        let next_state = Box::new(ServerHandshakeFinished {});

        // 返回下一个状态
        return Ok(next_state);
    }

    fn is_handshake_finished(&self) -> bool {
        false
    }
}

// 服务端握手成功状态
pub struct ServerHandshakeFinished;

// 实现状态转换接口
#[async_trait]
impl ServerHandshakeState for ServerHandshakeFinished {
    async fn handle(
        mut self: Box<Self>,
        _sess: &mut ServerSession,
        _m: Message,
    ) -> NextServerHandshakeStateOrError {
        // 状态处理未实现
        return Err(StateChangeError::InternelError("unimplement".to_string()));
    }

    fn is_handshake_finished(&self) -> bool {
        true
    }
}
