use tokio_util::codec::*;

use bytes::{BufMut, Bytes, BytesMut};

#[test]
fn encode_overflow() {
    // Test reproducing tokio-rs/tokio#681.
    let mut codec = length_delimited::Builder::new().new_codec();
    let mut buf = BytesMut::with_capacity(1024);

    // Put some data into the buffer without resizing it to hold more.
    let some_as = std::iter::repeat(b'a').take(1024).collect::<Vec<_>>();
    buf.put_slice(&some_as[..]);

    // Trying to encode the length header should resize the buffer if it won't fit.
    codec.encode(Bytes::from("hello"), &mut buf).unwrap();
}

#[test]
fn bytes_hex() {
    // let data = b"ab\x01\x0b";
    // let v = data.to_vec();
    // let b = Bytes::from(&data[..]);
    // let b = Bytes::from(v);
    // assert_eq!(b.len(), 4);
    // println!("{:?}", b);
    // println!("{:x}", b);
    // println!("{:#02X}", b);

    let mut data = Vec::<u8>::new();
    data.put_slice(b"ab\x01\x0b");
    let b = Bytes::from(data);
    assert_eq!(b.len(), 4);
    assert_eq!(&b[..], b"ab\x01\x0b");
    assert_eq!(format!("{:x}", b), "6162010b");
    assert_eq!(format!("{:#02X}",b), "6162010B");
}
