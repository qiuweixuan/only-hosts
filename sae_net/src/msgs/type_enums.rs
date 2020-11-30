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

impl CipherSuite{
    pub fn is_ecc(&self) -> bool{
        match* self{
            CipherSuite::ECCPWD_AES_128_GCM_SHA256 |  CipherSuite::ECCPWD_AES_256_GCM_SHA384 => true,
            _ => false
        }
    }
    pub fn is_ffc(&self) -> bool{
        !self.is_ecc()
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

impl NamedGroup{
    pub fn is_ecc(&self) -> bool{
        match* self{
            NamedGroup::Sepc384r1 |  NamedGroup::Secp521r1 => true,
            _ => false
        }
    }
    pub fn is_ffc(&self) -> bool{
        !self.is_ecc()
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


enum_builder! {
    /// The `AlertLevel` TLS protocol enum.  Values in this enum are taken
    /// from the various RFCs covering TLS, and are listed by IANA.
    /// The `Unknown` item is used when processing unrecognised ordinals.
    @U8
    EnumName: AlertLevel;
    EnumVal{
        Warning => 0x01,
        Fatal => 0x02
    }
}

enum_builder! {
    /// The `AlertDescription` TLS protocol enum.  Values in this enum are taken
    /// from the various RFCs covering TLS, and are listed by IANA.
    /// The `Unknown` item is used when processing unrecognised ordinals.
    @U8
    EnumName: AlertDescription;
    EnumVal{
        CloseNotify => 0x00,
        UnexpectedMessage => 0x0a,
        BadRecordMac => 0x14,
        DecryptionFailed => 0x15,
        RecordOverflow => 0x16,
        DecompressionFailure => 0x1e,
        HandshakeFailure => 0x28,
        NoCertificate => 0x29,
        BadCertificate => 0x2a,
        UnsupportedCertificate => 0x2b,
        CertificateRevoked => 0x2c,
        CertificateExpired => 0x2d,
        CertificateUnknown => 0x2e,
        IllegalParameter => 0x2f,
        UnknownCA => 0x30,
        AccessDenied => 0x31,
        DecodeError => 0x32,
        DecryptError => 0x33,
        ExportRestriction => 0x3c,
        ProtocolVersion => 0x46,
        InsufficientSecurity => 0x47,
        InternalError => 0x50,
        InappropriateFallback => 0x56,
        UserCanceled => 0x5a,
        NoRenegotiation => 0x64,
        MissingExtension => 0x6d,
        UnsupportedExtension => 0x6e,
        CertificateUnobtainable => 0x6f,
        UnrecognisedName => 0x70,
        BadCertificateStatusResponse => 0x71,
        BadCertificateHashValue => 0x72,
        UnknownPSKIdentity => 0x73,
        CertificateRequired => 0x74,
        NoApplicationProtocol => 0x78
    }
}
