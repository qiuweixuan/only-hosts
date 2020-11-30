use crate::msgs::type_enums::{CipherSuite,NamedGroup};

pub fn choose_ciphersuite_preferring_server(
    client_suites: &[CipherSuite],
    server_suites: &[CipherSuite],
) -> Option<CipherSuite> {
    if let Some(selected) = server_suites
        .iter()
        .find(|x| client_suites.contains(&x))
    {
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

