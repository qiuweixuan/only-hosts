use crate::msgs::type_enums::{AlertLevel, AlertDescription};
use crate::msgs::codec::{Codec, Reader};



#[derive(Debug,PartialEq,Clone)]
pub struct AlertMessagePayload {
    pub level: AlertLevel,
    pub description: AlertDescription,
}

impl Codec for AlertMessagePayload {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.level.encode(bytes);
        self.description.encode(bytes);
    }

    fn read(r: &mut Reader) -> Option<AlertMessagePayload> {
        let level = AlertLevel::read(r)?;
        let description = AlertDescription::read(r)?;

        Some(AlertMessagePayload {
            level,
            description,
        })
    }
}

impl AlertMessagePayload {
    pub fn length(&self) -> usize {
        1 + 1
    }
}



#[derive(Debug,PartialEq,Clone)]
pub enum SaeAlert {
    CloseNotify,
    UnexpectedMessage,
    HandshakeFailure,
    IllegalParameter,
    DecodeError,
    DecryptError,
    BadRecordMac,
}

impl SaeAlert {
    pub fn value(&self) -> AlertMessagePayload{
        match *self{
            SaeAlert::CloseNotify => AlertMessagePayload {
                level: AlertLevel::Warning,
                description: AlertDescription::CloseNotify
            },
            SaeAlert::UnexpectedMessage => AlertMessagePayload {
                level: AlertLevel::Fatal,
                description: AlertDescription::UnexpectedMessage
            },
            SaeAlert::HandshakeFailure => AlertMessagePayload {
                level: AlertLevel::Fatal,
                description: AlertDescription::HandshakeFailure
            },
            SaeAlert::IllegalParameter => AlertMessagePayload {
                level: AlertLevel::Fatal,
                description: AlertDescription::IllegalParameter
            },
            SaeAlert::DecodeError => AlertMessagePayload {
                level: AlertLevel::Fatal,
                description: AlertDescription::DecodeError
            },
            SaeAlert::DecryptError => AlertMessagePayload {
                level: AlertLevel::Fatal,
                description: AlertDescription::DecryptError
            },
            SaeAlert::BadRecordMac => AlertMessagePayload {
                level: AlertLevel::Fatal,
                description: AlertDescription::BadRecordMac
            },
        }
    }
}



