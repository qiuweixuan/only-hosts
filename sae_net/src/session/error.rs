use crate::msgs::alert::{AlertMessagePayload, SaeAlert};
use crate::msgs::message::{Message, MessagePayload};
use crate::msgs::type_enums::{ContentType, HandshakeType};

#[derive(Debug, PartialEq, Clone)]
pub enum StateChangeError {
    AlertSend(AlertMessagePayload),
    AlertReceive(AlertMessagePayload),
    InternelError(String),
    InvalidTransition,
}
impl StateChangeError {
    pub fn check_send_message(
        m: &Message,
        content_types: &[ContentType],
        handshake_types: &[HandshakeType],
    ) -> Result<(), StateChangeError> {
        if !content_types.contains(&m.typ) {
            println!(
                "Send a {:?} message while expecting {:?}",
                m.typ, content_types
            );
            return Err(StateChangeError::InvalidTransition);
        }
        if let MessagePayload::Handshake(ref hsp) = m.payload {
            if !handshake_types.is_empty() && !handshake_types.contains(&hsp.typ) {
                println!(
                    "Send a {:?} handshake message while expecting {:?}",
                    hsp.typ, handshake_types
                );
                return Err(StateChangeError::InvalidTransition);
            }
        }
        Ok(())
    }
    pub fn check_receive_message(
        m: &Message,
        content_types: &[ContentType],
        handshake_types: &[HandshakeType],
    ) -> Result<(), StateChangeError> {
        if !content_types.contains(&m.typ) {
            println!(
                "Received a {:?} message while expecting {:?}",
                m.typ, content_types
            );
            return Err(StateChangeError::AlertSend(
                SaeAlert::UnexpectedMessage.value(),
            ));
        }
        if let MessagePayload::Handshake(ref hsp) = m.payload {
            if !handshake_types.is_empty() && !handshake_types.contains(&hsp.typ) {
                println!(
                    "Received a {:?} handshake message while expecting {:?}",
                    hsp.typ, handshake_types
                );
                return Err(StateChangeError::AlertSend(
                    SaeAlert::UnexpectedMessage.value(),
                ));
            }
        }
        Ok(())
    }
}


