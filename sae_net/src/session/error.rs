use crate::msgs::alert::{AlertMessagePayload, SaeAlert};
use crate::msgs::message::{Message, MessagePayload};
use crate::msgs::type_enums::{ContentType, HandshakeType,ProtocolVersion};


use crate::session::session_duplex::SessionDuplex;

#[derive(Debug, PartialEq, Clone)]
pub enum StateChangeError {
    AlertSend(SaeAlert),
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
            // return Err(StateChangeError::InvalidTransition);
            return Err(StateChangeError::InternelError(
                "check_send_message error".to_string(),
            ));
        }
        if let MessagePayload::Handshake(ref hsp) = m.payload {
            if !handshake_types.is_empty() && !handshake_types.contains(&hsp.typ) {
                println!(
                    "Send a {:?} handshake message while expecting {:?}",
                    hsp.typ, handshake_types
                );
                // return Err(StateChangeError::InvalidTransition);
                return Err(StateChangeError::InternelError(
                    "check_send_message error".to_string(),
                ));
            }
        }
        Ok(())
    }
    pub fn check_receive_message(
        m: &Message,
        content_types: &[ContentType],
        handshake_types: &[HandshakeType],
    ) -> Result<(), StateChangeError> {
        if m.typ == ContentType::Alert {
            if let MessagePayload::Alert(ref hsp) = m.payload {
                return Err(StateChangeError::AlertReceive(hsp.clone()));
            }
        }

        // 检查数据包类型
        if !content_types.contains(&m.typ) {
            println!(
                "Received a {:?} message while expecting {:?}",
                m.typ, content_types
            );
            return Err(StateChangeError::AlertSend(
                SaeAlert::UnexpectedMessage,
            ));
        }
        if let MessagePayload::Handshake(ref hsp) = m.payload {
            if !handshake_types.is_empty() && !handshake_types.contains(&hsp.typ) {
                println!(
                    "Received a {:?} handshake message while expecting {:?}",
                    hsp.typ, handshake_types
                );
                return Err(StateChangeError::AlertSend(
                    SaeAlert::UnexpectedMessage,
                ));
            }
        }
        Ok(())
    }
    // 错误处理
    pub async fn handle_error(&self, session_duplex : &mut SessionDuplex, protocal_version: &ProtocolVersion) {
        // 打印错误
        println!("StateChangeError {:?}", self);

        // 尝试发送错误处理
        if let Self::AlertSend(alert) = self{
            let alert_message = Message::build_alert(protocal_version, alert.clone());
            session_duplex.write_one_message_or_err(alert_message).await.ok();
        }
       
    }

    pub fn convert_error_fn<T>(error_str: &str) ->  impl FnOnce(T) ->  Self{
        let error_str = error_str.to_string();
        let error_closer = move |_| { StateChangeError::InternelError(error_str) };
        return error_closer;
    }
}
