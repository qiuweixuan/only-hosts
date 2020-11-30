macro_rules! require_handshake_msg(
    ( $m:expr, $handshake_type:path, $payload_type:path ) => (
      
      match $m.payload {
          MessagePayload::Handshake(ref hsp) => match hsp.payload {
              $payload_type(ref hm) => Ok(hm),
              _ => Err(StateChangeError::AlertSend(
                SaeAlert::UnexpectedMessage,
            ))
          }
          _ => Err(StateChangeError::AlertSend(
            SaeAlert::UnexpectedMessage,
        ))
      }
    )
);