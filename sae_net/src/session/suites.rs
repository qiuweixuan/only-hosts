use crate::msgs::type_enums::{CipherSuite, NamedGroup};
use ring::{aead, hkdf};

pub fn choose_ciphersuite_preferring_server(
    client_suites: &[CipherSuite],
    server_suites: &[CipherSuite],
) -> Option<CipherSuite> {
    if let Some(selected) = server_suites.iter().find(|x| client_suites.contains(&x)) {
        return Some(selected.clone());
    }

    None
}

// .filter(|format| ecpoints_ext.contains(format))

pub fn choose_namedgroup_preferring_server(
    client_namedgroups: &[NamedGroup],
    server_namedgroups: &[NamedGroup],
    choose_ciphersuite: &CipherSuite,
) -> Option<NamedGroup> {
    let is_ffc = choose_ciphersuite.is_ffc();

    if let Some(selected) = server_namedgroups
        .iter()
        .filter(|x| x.is_ffc() == is_ffc)
        .find(|x| client_namedgroups.contains(&x))
    {
        return Some(selected.clone());
    }

    None
}

#[derive(Copy, Clone)]
pub struct SupportedCipherSuite {
    pub suite: CipherSuite,
    pub aead_algorithm: &'static ring::aead::Algorithm,
    pub hkdf_algorithm: &'static ring::hkdf::Algorithm,
}

static SUPPORT_SUITES: &[SupportedCipherSuite] = &[
    FFCPWD_AES_128_GCM_SHA256_SUITE,
    FFCPWD_AES_256_GCM_SHA384_SUITE,
];

pub static FFCPWD_AES_128_GCM_SHA256_SUITE: SupportedCipherSuite = SupportedCipherSuite {
    suite: CipherSuite::FFCPWD_AES_128_GCM_SHA256,
    aead_algorithm: &aead::AES_128_GCM,
    hkdf_algorithm: &hkdf::HKDF_SHA256,
};
pub static FFCPWD_AES_256_GCM_SHA384_SUITE: SupportedCipherSuite = SupportedCipherSuite {
    suite: CipherSuite::FFCPWD_AES_256_GCM_SHA384,
    aead_algorithm: &aead::AES_256_GCM,
    hkdf_algorithm: &hkdf::HKDF_SHA384,
};

pub fn get_support_suite(
    choose_ciphersuite: &CipherSuite,
) -> Option<&'static SupportedCipherSuite> {
    SUPPORT_SUITES
        .iter()
        .find(|x| x.suite == *choose_ciphersuite)
}
