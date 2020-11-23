use crate::msgs::base::Payload;
use crate::msgs::codec::{Codec, Reader};
use crate::msgs::handshake::HandshakeMessagePayload;
use crate::msgs::type_enums::{ContentType, HandshakeType, ProtocolVersion};
// use std::mem;

// SAE消息体负载
#[derive(Debug)]
pub enum MessagePayload {
    // Alert(AlertMessagePayload),
    Handshake(HandshakeMessagePayload),
    // ChangeCipherSpec(ChangeCipherSpecPayload),
    Opaque(Payload),
}

impl MessagePayload {
    pub fn encode(&self, bytes: &mut Vec<u8>) {
        match *self {
            // MessagePayload::Alert(ref x) => x.encode(bytes),
            MessagePayload::Handshake(ref x) => x.encode(bytes),
            // MessagePayload::ChangeCipherSpec(ref x) => x.encode(bytes),
            MessagePayload::Opaque(ref x) => x.encode(bytes),
        }
    }

    pub fn length(&self) -> usize {
        match *self {
            // MessagePayload::Alert(ref x) => x.length(),
            MessagePayload::Handshake(ref x) => x.length(),
            // MessagePayload::ChangeCipherSpec(ref x) => x.length(),
            MessagePayload::Opaque(ref x) => x.0.len(),
        }
    }

    pub fn new_opaque(data: Vec<u8>) -> MessagePayload {
        MessagePayload::Opaque(Payload::new(data))
    }
}

// SAE消息体帧(SAE frame)
#[derive(Debug)]
pub struct Message {
    pub typ: ContentType,
    pub version: ProtocolVersion,
    pub payload: MessagePayload,
}

// SAE消息体帧错误类型
pub enum MessageError {
    TooShortForHeader,
    TooShortForLength,
    IllegalLength,
    IllegalContentType,
    IllegalProtocolVersion,
}

// 头部、负载、总长度限制
// 这是Ciphertext的最大长度。这是2^14的有效负载字节，一个头，以及一个2KB的密文开销。
impl Message {
    /// This is the maximum on-the-wire size of a TLSCiphertext.
    /// That's 2^14 payload bytes, a header, and a 2KB allowance
    /// for ciphertext overheads.
    pub const MAX_PAYLOAD: u16 = 16384 + 2048;

    /// Content type, version and size.
    pub const HEADER_SIZE: u16 = 1 + 2 + 2;

    /// Maximum on-wire message size.
    pub const MAX_WIRE_SIZE: usize = (Message::MAX_PAYLOAD + Message::HEADER_SIZE) as usize;
}

// 消息体编解码
impl Codec for Message {
    fn read(r: &mut Reader) -> Option<Message> {
        Message::read_with_detailed_error(r).ok()
    }

    fn encode(&self, bytes: &mut Vec<u8>) {
        self.typ.encode(bytes);
        self.version.encode(bytes);
        (self.payload.length() as u16).encode(bytes);
        self.payload.encode(bytes);
    }
}

impl Message {
    /// Like Message::read(), but allows the important distinction between:
    /// this message might be valid if we read more data; and this message will
    /// never be valid.
    pub fn read_with_detailed_error(r: &mut Reader) -> Result<Message, MessageError> {
        // 解析头部，首先判断头部长度是否满足条件
        let typ = ContentType::read(r).ok_or(MessageError::TooShortForHeader)?;
        let version = ProtocolVersion::read(r).ok_or(MessageError::TooShortForHeader)?;
        let len = u16::read(r).ok_or(MessageError::TooShortForHeader)?;

        // 依次判断类型，协议版本，长度

        // Don't accept any new content-types.
        if let ContentType::Unknown(_) = typ {
            return Err(MessageError::IllegalContentType);
        }

        // Reject oversize messages
        if len >= Message::MAX_PAYLOAD {
            return Err(MessageError::IllegalLength);
        }

        // Don't accept any new versions
        if let ProtocolVersion::Unknown(_) = version {
            return Err(MessageError::IllegalProtocolVersion);
        }

        // 读取缓冲区数据
        let mut sub = r.sub(len as usize).ok_or(MessageError::TooShortForLength)?;
        // 根据不同类型进行存储
        let payload = match typ {
            ContentType::Handshake => {
                let data = HandshakeMessagePayload::read(&mut sub).unwrap();
                MessagePayload::Handshake(data)
            }
            _ => {
                let data = Payload::read(&mut sub).unwrap();
                MessagePayload::Opaque(data)
            }
        };
        Ok(Message {
            typ,
            version,
            payload,
        })
    }

    pub fn is_content_type(&self, typ: ContentType) -> bool {
        self.typ == typ
    }

    pub fn is_handshake_type(&self, hstyp: HandshakeType) -> bool {
        // Bit of a layering violation, but OK.
        if let MessagePayload::Handshake(ref hsp) = self.payload {
            hsp.typ == hstyp
        } else {
            false
        }
    }

    /*  pub fn take_payload(self) -> Vec<u8> {
        // self.into_opaque().take_opaque_payload().unwrap().0
        let mut buf = Vec::new();
        self.payload.encode(&mut buf);
        buf
    }

    pub fn take_opaque_payload(&mut self) -> Option<Payload> {
        if let MessagePayload::Opaque(ref mut op) = self.payload {
            Some(mem::replace(op, Payload::empty()))
        } else {
            None
        }
    }

    pub fn into_opaque(self) -> Message {
        if let MessagePayload::Opaque(_) = self.payload {
            return self;
        }

        let mut buf = Vec::new();
        self.payload.encode(&mut buf);

        Message {
            typ: self.typ,
            version: self.version,
            payload: MessagePayload::new_opaque(buf),
        }
    } */
}
