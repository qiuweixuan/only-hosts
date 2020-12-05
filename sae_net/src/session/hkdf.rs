use ring::{aead, hkdf::{self, KeyType as _}, hmac, digest};


pub(crate) fn hkdf_expand<T, L>(secret: &hkdf::Prk, key_type: L, label: &[u8], context: &[u8]) -> T
    where
        T: for <'a> From<hkdf::Okm<'a, L>>,
        L: hkdf::KeyType,
{
    hkdf_expand_info(secret, key_type, label, context, |okm| okm.into())
}

fn hkdf_expand_info<F, T, L>(secret: &hkdf::Prk, key_type: L, label: &[u8], context: &[u8], f: F)
        -> T
    where
        F: for<'b> FnOnce(hkdf::Okm<'b, L>) -> T,
        L: hkdf::KeyType
{
   

    let output_len = u16::to_be_bytes(key_type.len() as u16);
    let label_len = u8::to_be_bytes( label.len() as u8);
    let context_len = u8::to_be_bytes(context.len() as u8);

    let info = &[&output_len[..], &label_len[..], label, &context_len[..], context];
    let okm = secret.expand(info, key_type).unwrap();

    f(okm)
}