use crate::msgs::base::PayloadU8;
use ring;
use ring::{
    digest,
    hkdf::{self, KeyType as _},
};

/// The kinds of secret we can extract from `KeySchedule`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SecretKind {
    ClientApplicationTrafficSecret,
    ServerApplicationTrafficSecret,
    DerivedSecret,
}

impl SecretKind {
    fn to_bytes(self) -> &'static [u8] {
        match self {
            SecretKind::ClientApplicationTrafficSecret => b"c ap traffic",
            SecretKind::ServerApplicationTrafficSecret => b"s ap traffic",
            SecretKind::DerivedSecret => b"derived",
        }
    }
}

pub struct KeySchedule {
    current: hkdf::Prk,
    algorithm: ring::hkdf::Algorithm,
}

impl KeySchedule {
    pub fn new(algorithm: hkdf::Algorithm, secret: &[u8]) -> KeySchedule {
        let zeroes = [0u8; digest::MAX_OUTPUT_LEN];
        let zeroes = &zeroes[..algorithm.len()];
        let salt = hkdf::Salt::new(algorithm, &zeroes);
        KeySchedule {
            current: salt.extract(secret),
            algorithm,
        }
    }

    #[inline]
    pub fn algorithm(&self) -> hkdf::Algorithm {
        self.algorithm
    }

    pub fn new_with_empty_secret(algorithm: hkdf::Algorithm) -> KeySchedule {
        let zeroes = [0u8; digest::MAX_OUTPUT_LEN];
        Self::new(algorithm, &zeroes[..algorithm.len()])
    }

    /// Input the given secret.
    pub fn input_secret(&mut self, secret: &[u8]) {
        let salt: hkdf::Salt = self.derive_for_empty_hash(SecretKind::DerivedSecret);
        self.current = salt.extract(secret);
    }

    /// Derive a secret of given `kind`, using current handshake hash `hs_hash`.
    pub fn derive<T, L>(&self, key_type: L, kind: SecretKind, hs_hash: &[u8]) -> T
    where
        T: for<'a> From<hkdf::Okm<'a, L>>,
        L: hkdf::KeyType,
    {
        hkdf_expand(&self.current, key_type, kind.to_bytes(), hs_hash)
    }

    /// Derive a secret of given `kind` using the hash of the empty string
    /// for the handshake hash.  Useful only for
    /// `SecretKind::ResumptionPSKBinderKey` and
    /// `SecretKind::DerivedSecret`.
    fn derive_for_empty_hash<T>(&self, kind: SecretKind) -> T
    where
        T: for<'a> From<hkdf::Okm<'a, hkdf::Algorithm>>,
    {
        let digest_alg = self.algorithm.hmac_algorithm().digest_algorithm();
        let empty_hash = digest::digest(digest_alg, &[]);
        self.derive(self.algorithm, kind, empty_hash.as_ref())
    }
}

pub(crate) fn hkdf_expand<T, L>(secret: &hkdf::Prk, key_type: L, label: &[u8], context: &[u8]) -> T
where
    T: for<'a> From<hkdf::Okm<'a, L>>,
    L: hkdf::KeyType,
{
    hkdf_expand_info(secret, key_type, label, context, |okm| okm.into())
}

fn hkdf_expand_info<F, T, L>(
    secret: &hkdf::Prk,
    key_type: L,
    label: &[u8],
    context: &[u8],
    f: F,
) -> T
where
    F: for<'b> FnOnce(hkdf::Okm<'b, L>) -> T,
    L: hkdf::KeyType,
{
    let output_len = u16::to_be_bytes(key_type.len() as u16);
    let label_len = u8::to_be_bytes(label.len() as u8);
    let context_len = u8::to_be_bytes(context.len() as u8);

    let info = &[
        &output_len[..],
        &label_len[..],
        label,
        &context_len[..],
        context,
    ];
    let okm = secret.expand(info, key_type).unwrap();

    f(okm)
}

pub(crate) struct PayloadU8Len(pub(crate) usize);
impl hkdf::KeyType for PayloadU8Len {
    fn len(&self) -> usize {
        self.0
    }
}

impl From<hkdf::Okm<'_, PayloadU8Len>> for PayloadU8 {
    fn from(okm: hkdf::Okm<PayloadU8Len>) -> Self {
        let mut r = vec![0u8; okm.len().0];
        okm.fill(&mut r[..]).unwrap();
        PayloadU8::new(r)
    }
}
