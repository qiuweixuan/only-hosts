use crate::crypt::cipher;

use crate::crypt::key_schedule::{self, KeySchedule, SecretKind};
use crate::msgs::alert::SaeAlert;
use crate::msgs::fragmenter::{MessageFragmenter, MAX_FRAGMENT_LEN};
use crate::msgs::handshake::Random;
use crate::msgs::message::Message;
use crate::msgs::type_enums::ContentType;
use crate::session::error::StateChangeError;
use crate::session::{record_layer, session_duplex};
use ring::{aead, hkdf};
use std::collections::VecDeque;
use std::io::Write;

#[derive(Clone, Debug)]
pub struct SessionRandoms {
    pub we_are_client: bool,
    pub client: [u8; Random::LEN],
    pub server: [u8; Random::LEN],
}

impl SessionRandoms {
    pub fn for_server() -> SessionRandoms {
        let ret = SessionRandoms {
            we_are_client: false,
            client: [0u8; Random::LEN],
            server: [0u8; Random::LEN],
        };

        ret
    }

    pub fn for_client() -> SessionRandoms {
        let ret = SessionRandoms {
            we_are_client: true,
            client: [0u8; Random::LEN],
            server: [0u8; Random::LEN],
        };
        ret
    }

    pub fn join_client_server_randoms(&self) -> [u8; 2 * Random::LEN] {
        let mut randoms = [0u8; 2 * Random::LEN];
        randoms.as_mut().write_all(&self.client).unwrap();
        randoms[Random::LEN..]
            .as_mut()
            .write_all(&self.server)
            .unwrap();
        randoms
    }

    pub fn join_server_client_randoms(&self) -> [u8; 2 * Random::LEN] {
        let mut randoms = [0u8; 2 * Random::LEN];
        randoms.as_mut().write_all(&self.server).unwrap();
        randoms[Random::LEN..]
            .as_mut()
            .write_all(&self.client)
            .unwrap();
        randoms
    }
}

pub struct SessionSecrets {
    pub randoms: SessionRandoms,
    ks: KeySchedule,
}

impl SessionSecrets {
    pub fn new(
        randoms: &SessionRandoms,
        algorithm: &hkdf::Algorithm,
        pms: &[u8],
    ) -> SessionSecrets {
        let mut ks = KeySchedule::new_with_empty_secret(algorithm.clone());
        ks.input_secret(&pms);
        let ret = SessionSecrets {
            randoms: randoms.clone(),
            ks,
        };
        ret
    }

    pub fn client_application_traffic_secret(&self) -> hkdf::Prk {
        let randoms = self.randoms.join_client_server_randoms();
        let secret = self.ks.derive(
            self.ks.algorithm(),
            SecretKind::ClientApplicationTrafficSecret,
            &randoms,
        );
        secret
    }
    pub fn server_application_traffic_secret(&self) -> hkdf::Prk {
        let randoms = self.randoms.join_client_server_randoms();
        let secret = self.ks.derive(
            self.ks.algorithm(),
            SecretKind::ServerApplicationTrafficSecret,
            &randoms,
        );
        secret
    }

    pub fn derive_traffic_key(
        secret: &hkdf::Prk,
        aead_algorithm: &'static aead::Algorithm,
    ) -> aead::UnboundKey {
        key_schedule::hkdf_expand(secret, aead_algorithm, b"key", &[])
    }

    pub(crate) fn derive_traffic_iv(secret: &hkdf::Prk) -> cipher::Iv {
        key_schedule::hkdf_expand(secret, cipher::IvLen, b"iv", &[])
    }

    pub(crate) fn new_key_iv(
        &self,
        aead_algorithm: &'static aead::Algorithm,
    ) -> (aead::UnboundKey, cipher::Iv, aead::UnboundKey, cipher::Iv) {
        let client_secret = self.client_application_traffic_secret();
        let server_secret = self.server_application_traffic_secret();
        let client_write_key = Self::derive_traffic_key(&client_secret, aead_algorithm);
        let client_write_iv = Self::derive_traffic_iv(&client_secret);
        let server_write_key = Self::derive_traffic_key(&server_secret, aead_algorithm);
        let server_write_iv = Self::derive_traffic_iv(&server_secret);
        let (write_key, write_iv, read_key, read_iv) = if self.randoms.we_are_client {
            (
                client_write_key,
                client_write_iv,
                server_write_key,
                server_write_iv,
            )
        } else {
            (
                server_write_key,
                server_write_iv,
                client_write_key,
                client_write_iv,
            )
        };
        return (write_key, write_iv, read_key, read_iv);
    }
}

pub struct SessionCommon {
    record_layer: record_layer::RecordLayer,
    message_fragmenter: MessageFragmenter,
    tcp_session_eof: bool,
}

impl SessionCommon {
    pub fn new() -> SessionCommon {
        SessionCommon {
            record_layer: record_layer::RecordLayer::new(),
            message_fragmenter: MessageFragmenter::new(MAX_FRAGMENT_LEN),
            tcp_session_eof: false,
        }
    }

    pub fn is_close_session(&self) -> bool {
        return self.tcp_session_eof == true;
    }

    pub fn close_session(&mut self) {
        self.tcp_session_eof = true;
    }

    pub fn init_sae10_enc_dec(
        &mut self,
        handshake_secret: &[u8],
        randoms: &SessionRandoms,
        hkdf_algo: &hkdf::Algorithm,
        aead_algo: &'static aead::Algorithm,
    ) {
        let master_secret = SessionSecrets::new(&randoms, &hkdf_algo, &handshake_secret);

        let (read_decrypter, write_encrypter) =
            cipher::new_sae10_cipher_pair(&aead_algo, &master_secret);

        self.record_layer.set_message_decrypter(read_decrypter);
        self.record_layer.set_message_encrypter(write_encrypter);
    }

    pub async fn recv_msg(
        &mut self,
        duplex: &mut session_duplex::SessionDuplex,
    ) -> Result<Option<Message>, StateChangeError> {
        let mut ret_msg = None;

        // 判断会话是否关闭
        if self.is_close_session() {
            return Err(StateChangeError::InternelError(
                "Tcp Session EOF".to_string(),
            ));
        }

        // 接收数据包
        let msg = duplex.read_one_message_or_err().await?;

        // 处理数据包
        if let Some(mut recv_msg) = msg {
            if self.record_layer.is_decrypting() {
                // 记录层解密达到上限
                if self.record_layer.wants_close_before_decrypt() {
                    self.close_session();
                    return Err(StateChangeError::AlertSend(SaeAlert::CloseNotify));
                }
                log::debug!("[recv_msg] : {:?}", recv_msg);
                // 进行解密
                let dm = self.record_layer.decrypt_incoming(recv_msg)?;
                recv_msg = dm;
            }

            // 检查收到消息类型
            StateChangeError::check_receive_message(
                &recv_msg,
                &[ContentType::ApplicationData],
                &[],
            )?;
            // 获取消息
            ret_msg = Some(recv_msg);
        } else {
            // 没有数据包则会话已关闭
            self.close_session();
        }

        return Ok(ret_msg);
    }

    pub async fn send_msg(
        &mut self,
        duplex: &mut session_duplex::SessionDuplex,
        message: Message,
    ) -> Result<(), StateChangeError> {
        // 判断会话是否关闭
        if self.is_close_session() {
            return Err(StateChangeError::InternelError(
                "Tcp Session EOF".to_string(),
            ));
        }

        // 进行分包操作
        let mut plain_messages = VecDeque::new();
        self.message_fragmenter
            .fragment(message, &mut plain_messages);
        // 发送信息
        for mut send_msg in plain_messages {
            if self.record_layer.is_encrypting() {
                // 记录层加密达到上限
                if self.record_layer.wants_close_before_encrypt() {
                    self.close_session();
                    return Err(StateChangeError::AlertSend(SaeAlert::CloseNotify));
                }

                // 进行解密
                let em = self.record_layer.encrypt_outgoing(send_msg.to_borrowed())?;
                send_msg = em;
            }
            log::debug!("[send_msg] : {:?}", send_msg);
            duplex.write_one_message_or_err(send_msg).await?;
        }

        return Ok(());
    }
}

#[cfg(test)]
mod test {
    use super::{SessionRandoms, SessionSecrets};
    use crate::crypt::cipher;
    use crate::msgs::codec::Codec;
    use crate::msgs::handshake::Random;
    use crate::msgs::message::{Message, MessagePayload};
    use crate::msgs::type_enums::{ContentType, ProtocolVersion};
    use ring::{aead, hkdf};
    #[test]
    fn test_session_secrets() {
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
        let server_randoms = SessionRandoms {
            we_are_client: false,
            client: client_random.clone(),
            server: server_random.clone(),
        };

        let client_master_secret =
            SessionSecrets::new(&client_randoms, &hkdf_algo, &handshake_secret);
        let server_master_secret =
            SessionSecrets::new(&server_randoms, &hkdf_algo, &handshake_secret);

        let (client_read, client_write) =
            cipher::new_sae10_cipher_pair(&aead_algo, &client_master_secret);
        let (server_read, server_write) =
            cipher::new_sae10_cipher_pair(&aead_algo, &server_master_secret);

        let payload_data: Vec<u8> = vec![1, 2, 3];
        let plain_msg = Message {
            typ: ContentType::ApplicationData,
            version: ProtocolVersion::SAEv1_0,
            payload: MessagePayload::new_opaque(payload_data),
        };
        let seq: u64 = 1;
        let enc_msg = client_write.encrypt(plain_msg.to_borrowed(), seq).unwrap();
        let dec_msg = server_read.decrypt(enc_msg, seq).unwrap();
        assert_eq!(plain_msg.get_encoding(), dec_msg.get_encoding());

        let seq: u64 = 2;
        let enc_msg = server_write.encrypt(plain_msg.to_borrowed(), seq).unwrap();
        let dec_msg = client_read.decrypt(enc_msg, seq).unwrap();
        assert_eq!(plain_msg.get_encoding(), dec_msg.get_encoding());
    }
}
