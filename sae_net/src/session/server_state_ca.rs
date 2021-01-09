use crate::msgs::alert::SaeAlert;
use crate::msgs::base::{PayloadU16, PayloadU8};
use crate::msgs::handshake::{
    AuthCommitPayload, AuthConfirmPayload, ClientHelloPayload, HandshakeMessagePayload,
    HandshakePayload, Random, ServerHelloPayload,
};
use crate::msgs::message::{Message, MessagePayload};
use crate::msgs::type_enums::{ContentType, HandshakeType};
use crate::session::{error::StateChangeError, server_session::ServerSession, suites};

// use pub async_trait::pub async_trait;
use sae_core::SaeCaContext;
use std::io::Write;

// pub type NextServerHandshakeState = Box<dyn ServerHandshakeState + Send + Sync>;
// pub type NextServerHandshakeStateOrError = Result<NextServerHandshakeState, StateChangeError>;

// 初始化的服务端握手状态
pub struct ExpectClientHello {}

impl ExpectClientHello {
    // 构造ServerHello消息
    pub fn initial_server_hello<'a>(
        &self,
        sess: &mut ServerSession,
        ca_session: &mut SaeCaContext<'a>,
    ) -> Result<Message, StateChangeError> {
        // 根据配置进行设置
        let server_cipher_suite = sess
            .choose_ciphersuite
            .ok_or(StateChangeError::InternelError(
                "get sess.choose_ciphersuite error!".to_string(),
            ))?
            .clone();
        let server_name_group = sess
            .choose_namedgroup
            .ok_or(StateChangeError::InternelError(
                "get sess.choose_name_group error!".to_string(),
            ))?
            .clone();
        let server_protocal_version = sess.config.protocal_version.clone();

        // 获取随机数
        /* GeneRandom */
        let mut server_random_buf = match ca_session.gene_random(Random::LEN) {
            Ok(rand_res) => rand_res.rand,
            Err(err) => return Err(StateChangeError::InternelError(err.message().to_string())),
        };
        // 设置随机数
        let server_random = Random::from_slice(&server_random_buf);
        sess.randoms
            .server
            .as_mut()
            .write_all(&mut server_random_buf)
            .map_err(StateChangeError::convert_error_fn(
                "set sess.randoms.server error!",
            ))?;
        // 设置消息负载
        let shp = HandshakeMessagePayload {
            typ: HandshakeType::ServerHello,
            payload: HandshakePayload::ServerHello(ServerHelloPayload {
                random: server_random,
                cipher_suite: server_cipher_suite,
                name_group: server_name_group,
            }),
        };
        // 设置消息
        let sh = Message {
            typ: ContentType::Handshake,
            version: server_protocal_version,
            payload: MessagePayload::Handshake(shp),
        };

        return Ok(sh);
    }

    // 构造ServerAuthCommit消息
    pub fn initial_auth_commit<'a>(
        &self,
        sess: &mut ServerSession,
        ca_session: &mut SaeCaContext<'a>,
    ) -> Result<Message, StateChangeError> {
        // 获取会话随机数
        let client_random: &[u8] = &sess.randoms.client[..];
        let server_random: &[u8] = &sess.randoms.server[..];

        /* ComputeCommitElement */
        let commit_element = ca_session
            .compute_commit_element(client_random, server_random)
            .map_err(|err| StateChangeError::InternelError(err.message().to_string()))?;
        let scalar_vec = commit_element.scalar;
        let element_vec = commit_element.element;

        // 设置会话协议
        let server_protocal_version = sess.config.protocal_version.clone();

        // 设置消息负载
        let message_payload = HandshakeMessagePayload {
            typ: HandshakeType::ServerAuthCommit,
            payload: HandshakePayload::ServerAuthCommit(AuthCommitPayload {
                scalar: PayloadU16::new(scalar_vec),
                element: PayloadU16::new(element_vec),
            }),
        };
        // 设置消息
        let message = Message {
            typ: ContentType::Handshake,
            version: server_protocal_version,
            payload: MessagePayload::Handshake(message_payload),
        };

        return Ok(message);
    }

    // 处理ClientHello消息，根据负载设置会话状态
    fn handle_client_hello<'a>(
        &self,
        sess: &mut ServerSession,
        ca_session: &mut SaeCaContext<'a>,
        client_hello: &ClientHelloPayload,
    ) -> Result<(), StateChangeError> {
        // 打印收到的pwd_name
        let clinet_pwd_name = client_hello.pwd_name.clone().into_inner();
        log::debug!(
            "Received pwd_name: {:?}",
            String::from_utf8(clinet_pwd_name.clone())
        );
        // 加载密码(初始化SAE-CORE端密码)
        /* LoadDevUserPassword */
        ca_session
            .load_dev_user_password(&clinet_pwd_name)
            .map_err(|err| StateChangeError::InternelError(err.message().to_string()))?;
        // 选择加密套件
        let maybe_ciphersuite = suites::choose_ciphersuite_preferring_server(
            &client_hello.cipher_suites,
            &sess.config.cipher_suites,
        );

        // 没有合适的加密组件，返回握手失败告警
        let cipher_suite =
            maybe_ciphersuite.ok_or(StateChangeError::AlertSend(SaeAlert::HandshakeFailure))?;

        // 选择命名群
        let maybe_namedgroup = suites::choose_namedgroup_preferring_server(
            &client_hello.name_groups,
            &sess.config.name_groups,
            &cipher_suite,
        );
        // 没有合适的命名群，返回握手失败告警
        let named_group =
            maybe_namedgroup.ok_or(StateChangeError::AlertSend(SaeAlert::HandshakeFailure))?;

        /* InitNamedGroupReq */
        let group_code: u16 = named_group.clone().get_u16();
        ca_session
            .init_named_group(group_code)
            .map_err(|err| StateChangeError::InternelError(err.message().to_string()))?;

        // 将会话参数设置为从客户端可选组合挑选好的参数
        sess.choose_ciphersuite = Some(cipher_suite.clone());
        sess.choose_namedgroup = Some(named_group.clone());
        // 设置会话随机数
        sess.randoms
            .client
            .as_mut()
            .write_all(&mut client_hello.random.clone_inner())
            .map_err(StateChangeError::convert_error_fn(
                "set sess.randoms.server error!",
            ))?;

        return Ok(());
    }
}

// 实现状态转换接口
impl ExpectClientHello {
    pub async fn handle<'a>(
        self: Box<Self>,
        sess: &mut ServerSession,
        ca_session: &mut SaeCaContext<'a>,
        m: Message,
    ) -> Result<Box<ExpectClientAuthCommit>, StateChangeError> {
        // 检查收到的消息
        StateChangeError::check_receive_message(
            &m,
            &[ContentType::Handshake],
            &[HandshakeType::ClientHello],
        )?;
        // 获取消息负载
        let client_hello =
            require_handshake_msg!(m, HandshakeType::ClientHello, HandshakePayload::ClientHello)?;

        // 处理收到的消息负载
        self.handle_client_hello(sess, ca_session, &client_hello)?;

        // 构建ServerHello信息
        let sh = self.initial_server_hello(sess, ca_session)?;
        log::debug!("Send ServerHello message : \n {:?}", sh);

        // 发送ServerHello消息
        sess.duplex.write_one_message_or_err(sh).await?;

        // 构建ServerAuthCommit消息
        let auth_commit = self.initial_auth_commit(sess, ca_session)?;

        log::debug!("Send ServerAuthCommit message :\n {:?}", auth_commit);

        // 发送ServerAuthCommit消息
        sess.duplex.write_one_message_or_err(auth_commit).await?;

        // 创建下一个状态
        let next_state = Box::new(ExpectClientAuthCommit {});

        // 返回下一个状态
        return Ok(next_state);
    }

    pub fn is_handshake_finished(&self) -> bool {
        false
    }
}

// 等待ClientAuthCommit消息的状态
pub struct ExpectClientAuthCommit;

impl ExpectClientAuthCommit {
    // 生成认证确认信息
    fn initial_auth_confirm<'a>(
        &self,
        sess: &mut ServerSession,
        ca_session: &mut SaeCaContext<'a>,
        client_auth_commit: &AuthCommitPayload,
    ) -> Result<Message, StateChangeError> {
        let client_scalar = client_auth_commit.scalar.clone().into_inner();
        let client_element = client_auth_commit.element.clone().into_inner();

        /* ComputeConfirmElement */
        let server_confirm = ca_session
            .compute_confirm_element(&client_scalar, &client_element)
            .map_err(|err| StateChangeError::InternelError(err.message().to_string()))?;
        let confirm_vec = server_confirm.token;

        let server_protocal_version = sess.config.protocal_version.clone();

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

        return Ok(message);
    }
}

// 实现状态转换接口

impl ExpectClientAuthCommit {
    pub async fn handle<'a>(
        self: Box<Self>,
        sess: &mut ServerSession,
        ca_session: &mut SaeCaContext<'a>,
        m: Message,
    ) -> Result<Box<ExpectClientAuthConfirm>, StateChangeError> {
        // 检查收到的消息
        StateChangeError::check_receive_message(
            &m,
            &[ContentType::Handshake],
            &[HandshakeType::ClientAuthCommit],
        )?;
        // 获取消息负载
        let client_auth_commit = require_handshake_msg!(
            m,
            HandshakeType::ClientAuthCommit,
            HandshakePayload::ClientAuthCommit
        )?;

        // 构建ServerAuthConfirm消息
        let auth_confirm = self.initial_auth_confirm(sess, ca_session, &client_auth_commit)?;

        log::debug!("Send ServerAuthConfirm message : \n {:?}", auth_confirm);

        // 发送ServerAuthConfirm消息
        sess.duplex.write_one_message_or_err(auth_confirm).await?;

        // 创建下一个状态
        let next_state = Box::new(ExpectClientAuthConfirm {});

        // 返回下一个状态
        return Ok(next_state);
    }

    pub fn is_handshake_finished(&self) -> bool {
        false
    }
}

// 等待ClientAuthConfirm消息的状态
pub struct ExpectClientAuthConfirm;

// 实现状态转换接口
impl ExpectClientAuthConfirm {
    pub async fn handle<'a>(
        self: Box<Self>,
        sess: &mut ServerSession,
        ca_session: &mut SaeCaContext<'a>,
        m: Message,
    ) -> Result<Box<ServerHandshakeFinished>, StateChangeError> {
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

        /* ConfirmExchange */
        let client_confirm = client_auth_confirm.confirm.clone().into_inner();
        let server_pmk = ca_session
            .confirm_exchange(&client_confirm)
            .map_err(|err| StateChangeError::InternelError(err.message().to_string()))?;
        if !server_pmk.is_confirm {
            return Err(StateChangeError::InternelError(
                "Reject Client Confirm".to_string(),
            ));
        } else {
            sess.handshake_secret = Some(server_pmk.pmk);
        }

        // 创建下一个状态
        let next_state = Box::new(ServerHandshakeFinished {});

        // 返回下一个状态
        return Ok(next_state);
    }

    pub fn is_handshake_finished(&self) -> bool {
        false
    }
}

// 服务端握手成功状态
pub struct ServerHandshakeFinished;

// 实现状态转换接口
impl ServerHandshakeFinished {
    pub async fn handle(
        self: Box<Self>,
        _sess: &mut ServerSession,
        _m: Message,
    ) -> Result<Box<ServerHandshakeFinished>, StateChangeError> {
        // 状态处理未实现
        return Err(StateChangeError::InternelError("unimplement".to_string()));
    }

    pub fn is_handshake_finished(&self) -> bool {
        true
    }
}
