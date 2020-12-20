use crate::msgs::base::{PayloadU16, PayloadU8};
use crate::msgs::codec::{self, Codec, Reader};
use crate::msgs::type_enums::{CipherSuite, HandshakeType, NamedGroup};

use std::io::Write;

// 动态数组宏声明
// macro_rules! declare_u8_vec(
//     ($name:ident, $itemtype:ty) => {
//       pub type $name = Vec<$itemtype>;
//       impl Codec for $name {
//         fn encode(&self, bytes: &mut Vec<u8>) {
//           codec::encode_vec_u8(bytes, self);
//         }
//         fn read(r: &mut Reader) -> Option<$name> {
//           codec::read_vec_u8::<$itemtype>(r)
//         }
//       }
//     }
//   );

macro_rules! declare_u16_vec(
    ($name:ident, $itemtype:ty) => {
      pub type $name = Vec<$itemtype>;
      impl Codec for $name {
        fn encode(&self, bytes: &mut Vec<u8>) {
          codec::encode_vec_u16(bytes, self);
        }
        fn read(r: &mut Reader) -> Option<$name> {
          codec::read_vec_u16::<$itemtype>(r)
        }
      }
    }
  );

// 握手协议随机数
const RANDOM_LEN: usize = 6;
#[derive(Debug, PartialEq, Clone)]
pub struct Random([u8; RANDOM_LEN]);

impl Codec for Random {
    fn encode(&self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(&self.0);
    }

    fn read(r: &mut Reader) -> Option<Random> {
        let bytes = r.take(RANDOM_LEN)?;
        let mut opaque = [0; RANDOM_LEN];
        opaque.clone_from_slice(bytes);
        Some(Random(opaque))
    }
}

impl Random {
    pub fn from_slice(bytes: &[u8]) -> Random {
        let mut rd = Reader::init(bytes);
        Random::read(&mut rd).unwrap()
    }

    pub fn write_slice(&self, mut bytes: &mut [u8]) {
        let buf = self.get_encoding();
        bytes.write_all(&buf).unwrap();
    }

    pub fn clone_inner(&self) -> [u8; RANDOM_LEN] {
        self.0.clone()
    }

    pub const LEN: usize = RANDOM_LEN;
}

// CipherSuites类型声明: 数组总长度前缀为u16,之后存多个加密组件编码
declare_u16_vec!(CipherSuites, CipherSuite);

// NamedGroups类型声明
declare_u16_vec!(NamedGroups, NamedGroup);

// ClientHello负载
#[derive(Debug)]
pub struct ClientHelloPayload {
    pub random: Random,
    pub cipher_suites: CipherSuites,
    pub name_groups: NamedGroups,
    pub pwd_name: PayloadU8,
}

impl Codec for ClientHelloPayload {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.random.encode(bytes);
        self.cipher_suites.encode(bytes);
        self.name_groups.encode(bytes);
        self.pwd_name.encode(bytes);
    }

    fn read(r: &mut Reader) -> Option<ClientHelloPayload> {
        let ret = ClientHelloPayload {
            random: Random::read(r)?,
            cipher_suites: CipherSuites::read(r)?,
            name_groups: NamedGroups::read(r)?,
            pwd_name: PayloadU8::read(r)?,
        };
        Some(ret)
    }
}

// ServerHello负载
#[derive(Debug)]
pub struct ServerHelloPayload {
    pub random: Random,
    pub cipher_suite: CipherSuite,
    pub name_group: NamedGroup,
}

impl Codec for ServerHelloPayload {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.random.encode(bytes);
        self.cipher_suite.encode(bytes);
        self.name_group.encode(bytes);
    }

    fn read(r: &mut Reader) -> Option<ServerHelloPayload> {
        let ret = ServerHelloPayload {
            random: Random::read(r)?,
            cipher_suite: CipherSuite::read(r)?,
            name_group: NamedGroup::read(r)?,
        };
        Some(ret)
    }
}

// AuthCommitPayload负载
#[derive(Debug)]
pub struct AuthCommitPayload {
    pub scalar: PayloadU16,
    pub element: PayloadU16,
}

impl Codec for AuthCommitPayload {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.scalar.encode(bytes);
        self.element.encode(bytes);
    }

    fn read(r: &mut Reader) -> Option<AuthCommitPayload> {
        let ret = AuthCommitPayload {
            scalar: PayloadU16::read(r)?,
            element: PayloadU16::read(r)?,
        };
        Some(ret)
    }
}

// AuthConfirmPayload负载
#[derive(Debug)]
pub struct AuthConfirmPayload {
    pub confirm: PayloadU8,
}

impl Codec for AuthConfirmPayload {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.confirm.encode(bytes);
    }

    fn read(r: &mut Reader) -> Option<AuthConfirmPayload> {
        let ret = AuthConfirmPayload {
            confirm: PayloadU8::read(r)?,
        };
        Some(ret)
    }
}

// 握手协议负载（不带类型和长度）
#[derive(Debug)]
pub enum HandshakePayload {
    ClientHello(ClientHelloPayload),
    ServerHello(ServerHelloPayload),
    ClientAuthCommit(AuthCommitPayload),
    ServerAuthCommit(AuthCommitPayload),
    ClientAuthConfirm(AuthConfirmPayload),
    ServerAuthConfirm(AuthConfirmPayload),
}

impl HandshakePayload {
    fn encode(&self, bytes: &mut Vec<u8>) {
        match *self {
            HandshakePayload::ClientHello(ref x) => x.encode(bytes),
            HandshakePayload::ServerHello(ref x) => x.encode(bytes),
            HandshakePayload::ClientAuthCommit(ref x) => x.encode(bytes),
            HandshakePayload::ServerAuthCommit(ref x) => x.encode(bytes),
            HandshakePayload::ClientAuthConfirm(ref x) => x.encode(bytes),
            HandshakePayload::ServerAuthConfirm(ref x) => x.encode(bytes),
        }
    }
}

// 握手协议消息体（负载类型，负载长度以及负载本身）
#[derive(Debug)]
pub struct HandshakeMessagePayload {
    // type
    pub typ: HandshakeType,
    // length, and encoded payload
    pub payload: HandshakePayload,
}

impl Codec for HandshakeMessagePayload {
    fn encode(&self, bytes: &mut Vec<u8>) {
        // encode payload to learn length
        let mut sub: Vec<u8> = Vec::new();
        self.payload.encode(&mut sub);

        // output type, length, and encoded payload
        self.typ.encode(bytes);
        codec::u24(sub.len() as u32).encode(bytes);
        bytes.append(&mut sub);
    }

    fn read(r: &mut Reader) -> Option<HandshakeMessagePayload> {
        // 依次获取type,len和剩余payload
        let typ = HandshakeType::read(r)?;
        let len = codec::u24::read(r)?.0 as usize;
        let mut sub = r.sub(len)?;
        let payload = match typ {
            HandshakeType::ClientHello => {
                HandshakePayload::ClientHello(ClientHelloPayload::read(&mut sub)?)
            }
            HandshakeType::ServerHello => {
                HandshakePayload::ServerHello(ServerHelloPayload::read(&mut sub)?)
            }
            HandshakeType::ClientAuthCommit => {
                HandshakePayload::ClientAuthCommit(AuthCommitPayload::read(&mut sub)?)
            }
            HandshakeType::ServerAuthCommit => {
                HandshakePayload::ServerAuthCommit(AuthCommitPayload::read(&mut sub)?)
            }
            HandshakeType::ClientAuthConfirm => {
                HandshakePayload::ClientAuthConfirm(AuthConfirmPayload::read(&mut sub)?)
            }
            HandshakeType::ServerAuthConfirm => {
                HandshakePayload::ServerAuthConfirm(AuthConfirmPayload::read(&mut sub)?)
            }
            _ => return None,
        };

        // 返回解析的结果
        if sub.any_left() {
            None
        } else {
            Some(HandshakeMessagePayload { typ, payload })
        }
    }
}

impl HandshakeMessagePayload {
    pub fn length(&self) -> usize {
        let mut buf = Vec::new();
        self.encode(&mut buf);
        buf.len()
    }
}
