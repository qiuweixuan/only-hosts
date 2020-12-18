use ring::{aead, hkdf};
use tokio::net::TcpStream;

use crate::msgs::handshake::Random;
use crate::msgs::message::{Message, MessagePayload};
use crate::msgs::type_enums::ContentType;
use crate::msgs::type_enums::{CipherSuite, NamedGroup};
use crate::session::client_state::{self, ClientHandshakeState, InitialClientHandshakeState};
use crate::session::common::{SessionCommon, SessionRandoms};
use crate::session::error::StateChangeError;
use crate::session::{client_config::ClientConfig, session_duplex::SessionDuplex};

use sae_core::SaeCaContext;

pub struct ClientSession {
    pub duplex: SessionDuplex,
    pub config: ClientConfig,
    pub choose_ciphersuite: Option<CipherSuite>,
    pub choose_namedgroup: Option<NamedGroup>,
    pub common: SessionCommon,
}

impl ClientSession {
    pub fn new(sock: TcpStream, config: ClientConfig) -> ClientSession {
        ClientSession {
            duplex: SessionDuplex::new(sock),
            config,
            choose_ciphersuite: None,
            choose_namedgroup: None,
            common: SessionCommon::new(),
        }
    }
    pub async fn handshake(&mut self) -> Result<(), StateChangeError> {
        

        let mut ca_ctx = SaeCaContext::new_ctx()
            .map_err(StateChangeError::convert_error_fn("create ca_ctx error!"))?;
        let mut ca_session = SaeCaContext::new_session(&mut ca_ctx)
            .map_err(StateChangeError::convert_error_fn("create ca_session error!"))?;
        

        // 启动握手
        if let Err(err) = self.inner_handshake(&mut ca_session).await {
            // 统一错误处理
            err.handle_error(&mut self.duplex, &self.config.protocal_version)
                .await;
            return Err(err);
        }

        // 正常状态
        return Ok(());
    }

    async fn inner_handshake<'a>(&mut self,ca_session: &mut SaeCaContext<'a>) -> Result<(), StateChangeError> {
        ca_session.test();
        // 初始化状态
        let init_state = Box::new(InitialClientHandshakeState::new());
        let client_hello_message = init_state.initial_client_hello(self);
        let mut state: client_state::NextClientHandshakeState =
            init_state.handle(self, client_hello_message).await?;
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

        let client_random = Random::from_slice(&b"\x02\x00\x00\x00\x01\x00"[..]).clone_inner();
        let server_random = Random::from_slice(&b"\x02\x00\x00\x00\x00\x00"[..]).clone_inner();
        let hkdf_algo = &hkdf::HKDF_SHA256;
        let aead_algo = &aead::AES_256_GCM;
        let handshake_secret_hex_str =
            "59bcf341b58ae026f07f3d704eabda760636a83a75a3ff2fa130b263c0848e17";
        let handshake_secret = hex::decode(handshake_secret_hex_str).unwrap();
        let client_randoms = SessionRandoms {
            we_are_client: true,
            client: client_random.clone(),
            server: server_random.clone(),
        };

        self.common
            .init_sae10_enc_dec(&handshake_secret, &client_randoms, hkdf_algo, aead_algo);
        Ok(())
    }

    pub async fn recv_msg_payload(&mut self) -> Result<Vec<u8>, StateChangeError> {
        // 接收信息
        let result = self.common.recv_msg(&mut self.duplex).await;
        let message = match result {
            Err(err) => {
                // 统一错误处理
                err.handle_error(&mut self.duplex, &self.config.protocal_version)
                    .await;
                return Err(err);
            }
            Ok(message) => message,
        };
        let payload = if let Some(mut received_message) = message {
            received_message.take_opaque_payload().unwrap().0
        } else {
            Vec::<u8>::new()
        };

        return Ok(payload);
    }

    pub async fn send_msg_payload(&mut self, payload: &[u8]) -> Result<(), StateChangeError> {
        let msg = Message {
            typ: ContentType::ApplicationData,
            version: self.config.protocal_version.clone(),
            payload: MessagePayload::new_opaque(payload.to_vec()),
        };
        // 发送信息
        self.common.send_msg(&mut self.duplex, msg).await?;
        return Ok(());
    }
}


