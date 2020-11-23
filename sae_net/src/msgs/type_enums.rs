use crate::msgs::codec::{Reader, Codec};

// 协议名
enum_builder! {
    @U16
    EnumName: ProtocolVersion;
    EnumVal{ 
        SAEv1_0 => 0x0100
    }
}

// 整体加密套件
enum_builder! {
    @U16
    EnumName: CipherSuite;
    EnumVal{
        FFCPWD_AES_128_GCM_SHA256 => 0x0100,
        FFCPWD_AES_256_GCM_SHA384 => 0x0101,
        ECCPWD_AES_128_GCM_SHA256 => 0x0200,
        ECCPWD_AES_256_GCM_SHA384 => 0x0201
    }
}


// 哈希算法
enum_builder! {
    @U8
    EnumName: HashAlgorithm;
    EnumVal{
        MD5 => 0x01,
        SHA1 => 0x02,
        SHA224 => 0x03,
        SHA256 => 0x04,
        SHA384 => 0x05,
        SHA512 => 0x06
    }
}


// 块加密算法
enum_builder! {
    @U8
    EnumName: BulkAlgorithm;
    EnumVal{
        AES_128_GCM => 0x01,
        AES_256_GCM => 0x02
    }
}

// 密钥交换算法
enum_builder! {
    @U8
    EnumName: KeyExchangeAlgorithm;
    EnumVal{
        SAE_FFC => 0x01,
        SAE_ECC => 0x02
    }
}

// 命名群（ECP OR MODP)
enum_builder! {
    @U16
    EnumName: NamedGroup;
    EnumVal{
        Sepc384r1 => 0x0001,
        Secp521r1 => 0x0002,
        FFDHE3072 => 0x0101,
        FFDHE4096 => 0x0102,
        FFDHE6144 => 0x0103,
        FFDHE8192 => 0x0104
    }
}

// 子协议类型
enum_builder! {
    @U8
    EnumName: ContentType;
    EnumVal{
        ChangePassword => 0x14,
        Alert => 0x15,
        Handshake => 0x16,
        ApplicationData => 0x17
    }
}

// 握手子协议类型
enum_builder! {
    /// The `HandshakeType` TLS protocol enum.  Values in this enum are taken
    /// from the various RFCs covering TLS, and are listed by IANA.
    /// The `Unknown` item is used when processing unrecognised ordinals.
    @U8
    EnumName: HandshakeType;
    EnumVal{
        ClientHello => 0x01,
        ServerHello => 0x02,
        ClientAuthCommit => 0x03,
        ServerAuthCommit => 0x04,
        ClientAuthConfirm => 0x05,
        ServerAuthConfirm => 0x06
    }
}
