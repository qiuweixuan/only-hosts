use crate::msgs::base::PayloadU8;
use crate::msgs::handshake::{CipherSuites, NamedGroups};
use crate::msgs::type_enums::{CipherSuite, NamedGroup, ProtocolVersion};

#[derive(Clone)]
pub struct ClientConfig {
    pub cipher_suites: CipherSuites,
    pub name_groups: NamedGroups,
    pub pwd_name: PayloadU8,
    pub protocal_version: ProtocolVersion,
}

impl ClientConfig {
    pub fn new() -> ClientConfig {
        let cipher_suites = vec![
            CipherSuite::FFCPWD_AES_128_GCM_SHA256,
            CipherSuite::FFCPWD_AES_256_GCM_SHA384,
        ];
        let name_groups = vec![NamedGroup::FFDHE3072];
        let pwd_name = PayloadU8::new(Vec::<u8>::from("root"));
        let protocal_version = ProtocolVersion::SAEv1_0;

        ClientConfig {
            cipher_suites,
            name_groups,
            pwd_name,
            protocal_version,
        }
    }

    pub fn new_ecc_config() -> ClientConfig {
        let cipher_suites = vec![
            CipherSuite::ECCPWD_AES_128_GCM_SHA256,
            CipherSuite::ECCPWD_AES_256_GCM_SHA384,
        ];
        let name_groups = vec![NamedGroup::Sepc384r1, NamedGroup::Secp521r1];
        let pwd_name = PayloadU8::new(Vec::<u8>::from("root"));
        let protocal_version = ProtocolVersion::SAEv1_0;

        ClientConfig {
            cipher_suites,
            name_groups,
            pwd_name,
            protocal_version,
        }
    }
}
