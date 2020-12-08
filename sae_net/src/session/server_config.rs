use crate::msgs::handshake::{CipherSuites,NamedGroups};
use crate::msgs::type_enums::{CipherSuite,NamedGroup,ProtocolVersion};

#[derive(Clone)]
pub struct ServerConfig {
    pub cipher_suites: CipherSuites,
    pub name_groups: NamedGroups,
    pub protocal_version: ProtocolVersion,
}

impl ServerConfig{
    pub fn new() -> ServerConfig{
        let cipher_suites = vec![ CipherSuite::FFCPWD_AES_128_GCM_SHA256, CipherSuite::FFCPWD_AES_256_GCM_SHA384];
        let name_groups = vec![NamedGroup::FFDHE3072,NamedGroup::FFDHE4096];
        let protocal_version = ProtocolVersion::SAEv1_0;

        ServerConfig {
            cipher_suites,
            name_groups,
            protocal_version
        }
    }
}

