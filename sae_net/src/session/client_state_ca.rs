use crate::msgs::alert::SaeAlert;
use crate::msgs::base::{PayloadU16, PayloadU8};
use crate::msgs::handshake::{
    AuthCommitPayload, AuthConfirmPayload, ClientHelloPayload, HandshakeMessagePayload,
    HandshakePayload, Random, ServerHelloPayload,
};
use crate::msgs::message::{Message, MessagePayload};
use crate::msgs::type_enums::{ContentType, HandshakeType};
use crate::session::{client_session::ClientSession, error::StateChangeError};

use sae_core::SaeCaContext;
use std::io::Write;

// pub type NextClientHandshakeState = Box<dyn ClientHandshakeState>;
// pub type NextClientHandshakeStateOrError = Result<NextClientHandshakeState, StateChangeError>;

// 初始化的客户端握手状态
pub struct InitialClientHandshakeState {}

impl InitialClientHandshakeState {
    pub fn new() -> InitialClientHandshakeState {
        InitialClientHandshakeState {}
    }

    pub fn initial_client_hello<'a>(
        &self,
        sess: &mut ClientSession,
        ca_session: &mut SaeCaContext<'a>,
    ) -> Result<Message, StateChangeError> {
        // 根据配置进行设置
        let client_cipher_suites = sess.config.cipher_suites.clone();
        let clinet_name_groups = sess.config.name_groups.clone();
        let clinet_pwd_name = sess.config.pwd_name.clone();
        let clinet_protocal_version = sess.config.protocal_version.clone();
        // 获取随机数
        /* GeneRandom */
        let mut client_random_buf = match ca_session.gene_random(Random::LEN) {
            Ok(rand_res) => rand_res.rand,
            Err(err) => return Err(StateChangeError::InternelError(err.message().to_string())),
        };
        // 设置随机数
        let client_random = Random::from_slice(&client_random_buf);
        sess.randoms
            .client
            .as_mut()
            .write_all(&mut client_random_buf)
            .map_err(StateChangeError::convert_error_fn(
                "set sess.randoms.client error!",
            ))?;
        // 加载密码(初始化SAE-CORE端密码)
        /* LoadDevUserPassword */
        ca_session
            .load_dev_user_password(&clinet_pwd_name.clone().into_inner())
            .map_err(|err| StateChangeError::InternelError(err.message().to_string()))?;

        // 设置消息负载
        let chp = HandshakeMessagePayload {
            typ: HandshakeType::ClientHello,
            payload: HandshakePayload::ClientHello(ClientHelloPayload {
                random: client_random,
                cipher_suites: client_cipher_suites,
                name_groups: clinet_name_groups,
                pwd_name: clinet_pwd_name,
            }),
        };
        // 设置消息
        let ch = Message {
            typ: ContentType::Handshake,
            version: clinet_protocal_version,
            payload: MessagePayload::Handshake(chp),
        };

        return Ok(ch);
    }
}

// 实现状态转换接口
impl InitialClientHandshakeState {
    pub async fn handle<'a>(
        self: Box<Self>,
        sess: &mut ClientSession,
        _ca_session: &mut SaeCaContext<'a>,
        m: Message,
    ) -> Result<Box<ExpectServerHello>, StateChangeError> {
        // 检查发送的消息
        StateChangeError::check_send_message(
            &m,
            &[ContentType::Handshake],
            &[HandshakeType::ClientHello],
        )?;

        // 创建下一个状态
        let next_state = Box::new(ExpectServerHello {});

        println!("Send ClientHello message : \n {:?}", m);

        // 发送消息
        sess.duplex.write_one_message_or_err(m).await?;

        // 返回下一个状态
        return Ok(next_state);
    }

    pub fn is_handshake_finished(&self) -> bool {
        false
    }
}

// 等待ServerHello消息
pub struct ExpectServerHello {}

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
    fn initial_auth_commit<'a>(
        &self,
        sess: &mut ClientSession,
        ca_session: &mut SaeCaContext<'a>,
    ) -> Result<Message, StateChangeError> {
        let client_random: &[u8] = &sess.randoms.client[..];
        let server_random: &[u8] = &sess.randoms.server[..];
        /* ComputeCommitElement */
        let commit_element = ca_session
            .compute_commit_element(client_random, server_random)
            .map_err(|err| StateChangeError::InternelError(err.message().to_string()))?;
        let scalar_vec = commit_element.scalar;
        let element_vec = commit_element.element;

        let server_protocal_version = sess.config.protocal_version.clone();

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

        return Ok(message);
    }

    // 处理ServerHello消息，根据负载设置会话状态
    fn handle_server_hello<'a>(
        &self,
        sess: &mut ClientSession,
        ca_session: &mut SaeCaContext<'a>,
        server_hello: &ServerHelloPayload,
    ) -> Result<(), StateChangeError> {
        // 将会话参数设置为与服务器协商好的参数
        sess.choose_ciphersuite = Some(server_hello.cipher_suite.clone());
        sess.choose_namedgroup = Some(server_hello.name_group.clone());
        // 设置会话随机数
        sess.randoms
            .server
            .as_mut()
            .write_all(&mut server_hello.random.clone_inner())
            .map_err(StateChangeError::convert_error_fn(
                "set sess.randoms.server error!",
            ))?;

        /* InitNamedGroupReq */
        let group_code: u16 = server_hello.name_group.clone().get_u16();
        ca_session
            .init_named_group(group_code)
            .map_err(|err| StateChangeError::InternelError(err.message().to_string()))?;

        return Ok(());
    }
}

// 实现状态转换接口
impl ExpectServerHello {
    pub async fn handle<'a>(
        self: Box<Self>,
        sess: &mut ClientSession,
        ca_session: &mut SaeCaContext<'a>,
        m: Message,
    ) -> Result<Box<ExpectServerAuthCommit>, StateChangeError> {
        /* 根据接收到的消息进行本一阶段的处理 */

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
        self.handle_server_hello(sess, ca_session, &server_hello)?;

        /* 构建发送的消息和下一阶段状态 */

        // 构建ClientAuthCommit消息
        let auth_commit = self.initial_auth_commit(sess, ca_session)?;

        println!("Send ClientAuthCommit message : \n {:?}", auth_commit);

        // 发送ClientAuthCommit消息
        sess.duplex.write_one_message_or_err(auth_commit).await?;

        // 创建下一个状态
        let next_state = Box::new(ExpectServerAuthCommit {});

        // 返回下一个状态
        return Ok(next_state);
    }

    pub fn is_handshake_finished(&self) -> bool {
        false
    }
}

// 等待ServerAuthCommit消息
pub struct ExpectServerAuthCommit;

impl ExpectServerAuthCommit {
    // 生成认证确认信息
    fn initial_auth_confirm<'a>(
        &self,
        sess: &mut ClientSession,
        ca_session: &mut SaeCaContext<'a>,
        server_auth_commit: &AuthCommitPayload,
    ) -> Result<Message, StateChangeError> {
        let server_scalar = server_auth_commit.scalar.clone().into_inner();
        let server_element = server_auth_commit.element.clone().into_inner();

        /* ComputeConfirmElement */
        let client_confirm = ca_session
            .compute_confirm_element(&server_scalar, &server_element)
            .map_err(|err| StateChangeError::InternelError(err.message().to_string()))?;
        let confirm_vec = client_confirm.token;


        let server_protocal_version = sess.config.protocal_version.clone();

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

        return Ok(message);
    }
}

// 实现状态转换接口

impl ExpectServerAuthCommit {
    pub async fn handle<'a>(
        self: Box<Self>,
        sess: &mut ClientSession,
        ca_session: &mut SaeCaContext<'a>,
        m: Message,
    ) -> Result<Box<ExpectServerAuthConfirm>, StateChangeError> {
        // 检查收到的消息
        StateChangeError::check_receive_message(
            &m,
            &[ContentType::Handshake],
            &[HandshakeType::ServerAuthCommit],
        )?;
        // 获取消息负载
        let server_auth_commit = require_handshake_msg!(
            m,
            HandshakeType::ServerAuthCommit,
            HandshakePayload::ServerAuthCommit
        )?;

        // 构建ClientAuthConfirm消息
        let auth_confirm = self.initial_auth_confirm(sess, ca_session, &server_auth_commit)?;

        println!("Send ClientAuthConfirm message : \n {:?}", auth_confirm);

        // 发送ClientAuthConfirm消息
        sess.duplex.write_one_message_or_err(auth_confirm).await?;

        // 创建下一个状态
        let next_state = Box::new(ExpectServerAuthConfirm {});

        // 返回下一个状态
        return Ok(next_state);
    }

    pub fn is_handshake_finished(&self) -> bool {
        false
    }
}

// 等待ServerAuthConfirm消息的状态
pub struct ExpectServerAuthConfirm;

// 实现状态转换接口
impl ExpectServerAuthConfirm {
    pub async fn handle<'a>(
        self: Box<Self>,
        sess: &mut ClientSession,
        ca_session: &mut SaeCaContext<'a>,
        m: Message,
    ) -> Result<Box<ClientHandshakeFinished>, StateChangeError> {
        // 检查收到的消息
        StateChangeError::check_receive_message(
            &m,
            &[ContentType::Handshake],
            &[HandshakeType::ServerAuthConfirm],
        )?;
        // 获取消息负载
        let server_auth_confirm = require_handshake_msg!(
            m,
            HandshakeType::ServerAuthConfirm,
            HandshakePayload::ServerAuthConfirm
        )?;

        /* ConfirmExchange */
        let server_confirm = server_auth_confirm.confirm.clone().into_inner();
        let client_pmk = ca_session
            .confirm_exchange(&server_confirm)
            .map_err(|err| StateChangeError::InternelError(err.message().to_string()))?;
        if !client_pmk.is_confirm {
            return Err(StateChangeError::InternelError("Reject Server Confirm".to_string()));
        }
        else{
            sess.handshake_secret = Some(client_pmk.pmk);
        }

        // 创建下一个状态
        let next_state = Box::new(ClientHandshakeFinished {});

        // 返回下一个状态
        return Ok(next_state);
    }

    pub fn is_handshake_finished(&self) -> bool {
        false
    }
}

// 客户端握手成功状态
pub struct ClientHandshakeFinished;

// 实现状态转换接口

impl ClientHandshakeFinished {
    pub async fn handle(
        self: Box<Self>,
        _sess: &mut ClientSession,
        _m: Message,
    ) -> Result<Box<ClientHandshakeFinished>, StateChangeError> {
        // 状态处理未实现
        return Err(StateChangeError::InternelError("unimplement".to_string()));
    }

    pub fn is_handshake_finished(&self) -> bool {
        true
    }
}
