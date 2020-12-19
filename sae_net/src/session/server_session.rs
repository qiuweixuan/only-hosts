use tokio::net::TcpStream;
use ring::{aead, hkdf};

use crate::session::{server_config::ServerConfig, session_duplex::SessionDuplex,suites};
use crate::session::error::StateChangeError;
use crate::session::server_state::{self, ExpectClientHello};
use crate::session::common::{SessionRandoms,SessionCommon};
use crate::msgs::handshake::Random;
use crate::msgs::type_enums::{CipherSuite,NamedGroup};
use crate::msgs::message::{Message, MessagePayload};
use crate::msgs::type_enums::ContentType;

use sae_core::SaeCaContext;
use crate::session::server_state_ca;


pub struct ServerSession {
    pub duplex: SessionDuplex,
    pub config: ServerConfig,
    pub choose_ciphersuite: Option<CipherSuite>,
    pub choose_namedgroup: Option<NamedGroup>,
    pub handshake_secret: Option<Vec<u8>>,
    pub randoms: SessionRandoms,
    pub common: SessionCommon,
}

impl ServerSession {
    pub fn new(sock: TcpStream, config: ServerConfig) -> ServerSession {
        ServerSession {
            duplex: SessionDuplex::new(sock),
            config,
            choose_ciphersuite: None,
            choose_namedgroup: None,
            handshake_secret: None,
            randoms: SessionRandoms::for_server(),
            common: SessionCommon::new(),
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

    async fn inner_handshake(&mut self) -> Result<(), StateChangeError> {
        // 初始化状态
        let mut state: server_state::NextServerHandshakeState = Box::new(ExpectClientHello::new());
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
        let server_randoms = SessionRandoms {
            we_are_client: false,
            client: client_random.clone(),
            server: server_random.clone(),
        };
    
        self.common.init_sae10_enc_dec(&handshake_secret,&server_randoms, hkdf_algo, aead_algo);


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


    pub async fn handshake_with_ca(&mut self) -> Result<(), StateChangeError> {
        // 创建CA上下文
        let mut ca_ctx = SaeCaContext::new_ctx()
            .map_err(StateChangeError::convert_error_fn("create ca_ctx error!"))?;
        let mut ca_session = SaeCaContext::new_session(&mut ca_ctx)
            .map_err(StateChangeError::convert_error_fn("create ca_session error!"))?;
        

        // 启动握手
        if let Err(err) = self.inner_handshake_with_ca(&mut ca_session).await {
            // 统一错误处理
            err.handle_error(&mut self.duplex, &self.config.protocal_version)
                .await;
            return Err(err);
        }

        // 正常状态
        return Ok(());
    }

    async fn recv_message(&mut self) -> Result<Message, StateChangeError>{
        // 接收数据包
        let message = self.duplex.read_one_message_or_err().await?;

        // 处理数据包
        if let Some(received_message) = message {
            println!("Receive message: \n {:?}", received_message);
           return Ok(received_message);
        } else {
            // 没有数据包
            return Err(StateChangeError::InvalidTransition);
        }
    }


    async fn inner_handshake_with_ca<'a>(&mut self,ca_session: &mut SaeCaContext<'a>) -> Result<(), StateChangeError> {
        
        /* 初始化状态 ExpectClientHello */
        let state = Box::new(server_state_ca::ExpectClientHello{});
        /* 循环推进状态机，直至完成握手过程 */ 

        let message = ServerSession::recv_message(self).await?;
        // ExpectClientHello -> ExpectClientAuthCommit 
        let state = state.handle(self,ca_session,message).await?;

        let message = ServerSession::recv_message(self).await?;
        // ExpectClientAuthCommit  -> ExpectClientAuthConfirm
        let state = state.handle(self,ca_session,message).await?;

        let message = ServerSession::recv_message(self).await?;
        // ExpectClientAuthConfirm -> ServerHandshakeFinished
        state.handle(self,ca_session,message).await?;

        
        let cipher_suite = self
            .choose_ciphersuite
            .ok_or(StateChangeError::InternelError(
                "get sess.choose_ciphersuite error!".to_string(),
            ))?
            .clone();

        let support_suite = suites::get_support_suite(&cipher_suite)
            .ok_or(StateChangeError::InternelError(
                "get support_suite error!".to_string(),
            ))?
            .clone();

        let handshake_secret = self.handshake_secret.clone().ok_or(StateChangeError::InternelError(
            "get sess.handshake_secret error!".to_string(),
        ))?;

        let hkdf_algo = support_suite.hkdf_algorithm;
        let aead_algo = support_suite.aead_algorithm;
        let client_randoms = &self.randoms;
        // let handshake_secret_hex_str =
        //     "59bcf341b58ae026f07f3d704eabda760636a83a75a3ff2fa130b263c0848e17";
        // let handshake_secret = hex::decode(handshake_secret_hex_str).unwrap();

        self.common
            .init_sae10_enc_dec(&handshake_secret, client_randoms, hkdf_algo, aead_algo);
        Ok(())
    }
}
