use crate::msgs::alert::SaeAlert;
use crate::msgs::codec::{self, Codec};
use crate::msgs::fragmenter;
use crate::msgs::message::{BorrowMessage, Message, MessagePayload};
use crate::msgs::type_enums::{ContentType, ProtocolVersion};
use crate::session::common::SessionSecrets;
use crate::session::error::StateChangeError;
use ring::{aead, hkdf};

#[derive(Debug)]
pub(crate) struct Iv([u8; ring::aead::NONCE_LEN]);

/* impl Iv {
    pub fn new(value: [u8; ring::aead::NONCE_LEN]) -> Self {
        Self(value)
    }

    pub fn copy(value: &[u8]) -> Self {
        debug_assert_eq!(value.len(), ring::aead::NONCE_LEN);
        let mut iv = Iv::new(Default::default());
        iv.0.copy_from_slice(value);
        iv
    }

    pub fn value(&self) -> &[u8; 12] {
        &self.0
    }
} */

pub(crate) struct IvLen;

impl hkdf::KeyType for IvLen {
    fn len(&self) -> usize {
        aead::NONCE_LEN
    }
}

impl From<hkdf::Okm<'_, IvLen>> for Iv {
    fn from(okm: hkdf::Okm<IvLen>) -> Self {
        let mut r = Iv(Default::default());
        okm.fill(&mut r.0[..]).unwrap();
        r
    }
}

/// Objects with this trait can decrypt TLS messages.
pub trait MessageDecrypter: Send + Sync {
    fn decrypt(&self, m: Message, seq: u64) -> Result<Message, StateChangeError>;
}

/// Objects with this trait can encrypt TLS messages.
pub trait MessageEncrypter: Send + Sync {
    fn encrypt(&self, m: BorrowMessage, seq: u64) -> Result<Message, StateChangeError>;
}

impl dyn MessageEncrypter {
    pub fn invalid() -> Box<dyn MessageEncrypter> {
        Box::new(InvalidMessageEncrypter {})
    }
}

impl dyn MessageDecrypter {
    pub fn invalid() -> Box<dyn MessageDecrypter> {
        Box::new(InvalidMessageDecrypter {})
    }
}

pub type MessageCipherPair = (Box<dyn MessageDecrypter>, Box<dyn MessageEncrypter>);

/// A `MessageEncrypter` which doesn't work.
pub struct InvalidMessageEncrypter {}

impl MessageEncrypter for InvalidMessageEncrypter {
    fn encrypt(&self, _m: BorrowMessage, _seq: u64) -> Result<Message, StateChangeError> {
        Err(StateChangeError::InternelError(
            "encrypt not yet available".to_string(),
        ))
    }
}

/// A `MessageDecrypter` which doesn't work.
pub struct InvalidMessageDecrypter {}

impl MessageDecrypter for InvalidMessageDecrypter {
    fn decrypt(&self, _m: Message, _seq: u64) -> Result<Message, StateChangeError> {
        Err(StateChangeError::InternelError(
            "decrypt not yet available".to_string(),
        ))
    }
}

struct SAE10MessageEncrypter {
    enc_key: aead::LessSafeKey,
    iv: Iv,
}

struct SAE10MessageDecrypter {
    dec_key: aead::LessSafeKey,
    iv: Iv,
}

fn unpad_sae10(v: &mut Vec<u8>) -> ContentType {
    loop {
        match v.pop() {
            Some(0) => {}

            Some(content_type) => return ContentType::read_bytes(&[content_type]).unwrap(),

            None => return ContentType::Unknown(0),
        }
    }
}

fn make_sae10_nonce(iv: &Iv, seq: u64) -> ring::aead::Nonce {
    let mut nonce = [0u8; ring::aead::NONCE_LEN];
    codec::put_u64(seq, &mut nonce[4..]);

    nonce.iter_mut().zip(iv.0.iter()).for_each(|(nonce, iv)| {
        *nonce ^= *iv;
    });

    aead::Nonce::assume_unique_for_key(nonce)
}

fn make_sae10_aad(len: usize) -> ring::aead::Aad<[u8; 1 + 2 + 2]> {
    ring::aead::Aad::from([
        0x17, // ContentType::ApplicationData
        0x10, // ProtocolVersion (major)
        0x00, // ProtocolVersion (minor)
        (len >> 8) as u8,
        len as u8,
    ])
}

impl MessageEncrypter for SAE10MessageEncrypter {
    fn encrypt(&self, msg: BorrowMessage, seq: u64) -> Result<Message, StateChangeError> {
        let total_len = msg.payload.len() + 1 + self.enc_key.algorithm().tag_len();
        let mut buf = Vec::with_capacity(total_len);
        buf.extend_from_slice(&msg.payload);
        msg.typ.encode(&mut buf);

        let nonce = make_sae10_nonce(&self.iv, seq);
        let aad = make_sae10_aad(total_len);

        self.enc_key
            .seal_in_place_append_tag(nonce, aad, &mut buf)
            .map_err(|_| StateChangeError::InternelError("encrypt failed".to_string()))?;

        Ok(Message {
            typ: ContentType::ApplicationData,
            version: ProtocolVersion::SAEv1_0,
            payload: MessagePayload::new_opaque(buf),
        })
    }
}

impl MessageDecrypter for SAE10MessageDecrypter {
    fn decrypt(&self, mut msg: Message, seq: u64) -> Result<Message, StateChangeError> {
        let decrypt_error = StateChangeError::AlertSend(SaeAlert::BadRecordMac);

        let payload = msg.take_opaque_payload().ok_or(decrypt_error.clone())?;
        let mut buf = payload.0;

        if buf.len() < self.dec_key.algorithm().tag_len() {
            return Err(decrypt_error.clone());
        }

        let nonce = make_sae10_nonce(&self.iv, seq);
        let aad = make_sae10_aad(buf.len());
        let plain_len = self
            .dec_key
            .open_in_place(nonce, aad, &mut buf)
            .map_err(|_| decrypt_error.clone())?
            .len();

        buf.truncate(plain_len);

        let content_type = unpad_sae10(&mut buf);
        if content_type == ContentType::Unknown(0) {
            let _msg = "peer sent bad TLSInnerPlaintext".to_string();
            return Err(decrypt_error.clone());
        }

        if buf.len() > fragmenter::MAX_FRAGMENT_LEN {
            return Err(decrypt_error.clone());
        }

        Ok(Message {
            typ: content_type,
            version: ProtocolVersion::SAEv1_0,
            payload: MessagePayload::new_opaque(buf),
        })
    }
}

impl SAE10MessageEncrypter {
    fn new(key: aead::UnboundKey, enc_iv: Iv) -> SAE10MessageEncrypter {
        SAE10MessageEncrypter {
            enc_key: aead::LessSafeKey::new(key),
            iv: enc_iv,
        }
    }
}

impl SAE10MessageDecrypter {
    fn new(key: aead::UnboundKey, dec_iv: Iv) -> SAE10MessageDecrypter {
        SAE10MessageDecrypter {
            dec_key: aead::LessSafeKey::new(key),
            iv: dec_iv,
        }
    }
}

pub fn new_sae10_cipher_pair(
    aead_algo: &'static aead::Algorithm,
    secrets: &SessionSecrets,
) -> MessageCipherPair {
    let (write_key, write_iv, read_key, read_iv) = secrets.new_key_iv(aead_algo);
    (
        Box::new(SAE10MessageDecrypter::new(read_key, read_iv)),
        Box::new(SAE10MessageEncrypter::new(write_key, write_iv)),
    )
}
