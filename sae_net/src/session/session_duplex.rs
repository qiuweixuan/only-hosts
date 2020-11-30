use crate::msgs::alert::{SaeAlert};
use crate::msgs::codec::{Codec, Reader};
use crate::msgs::message::Message;
use crate::msgs::type_enums::ProtocolVersion;
use crate::session::error::StateChangeError;

use futures::StreamExt;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio::prelude::*;
use tokio_util::codec::{FramedRead, LengthDelimitedCodec};

/// 会话层双工通信器
/// 提供SAE Message读写功能
/// 使用tokio::net::TcpStream进行构建

/// write_half: 写消息帧 ->双工写端
/// codec_read_half: 双端读端 -> 解码出消息帧
pub struct SessionDuplex {
    pub write_half: OwnedWriteHalf,
    pub codec_read_half: FramedRead<OwnedReadHalf, LengthDelimitedCodec>,
}

impl SessionDuplex {
    pub fn new(sock: TcpStream) -> SessionDuplex {
        let (read_half, write_half) = sock.into_split();

        let codec_read_half: FramedRead<OwnedReadHalf, LengthDelimitedCodec> =
            LengthDelimitedCodec::builder()
                .max_frame_length(Message::MAX_WIRE_SIZE) // max length
                .length_field_offset((Message::TYPE_SIZE + Message::VERSION_SIZE) as usize) // length of type + version
                .length_field_length((Message::LEN_SIZE) as usize) // length of payload_len
                .length_adjustment((Message::HEADER_SIZE) as isize) // length of header
                .num_skip(0) //goto start location
                .new_read(read_half);

        SessionDuplex {
            write_half,
            codec_read_half,
        }
    }

    pub async fn read_one_message_detail_error(
        &mut self,
        protocal_version: &ProtocolVersion,
    ) -> Option<Message> {
        if let Some(message) = self.codec_read_half.next().await {
            match message {
                Ok(bytes) => {
                    let mut rd = Reader::init(bytes.as_ref());
                    match Message::read_with_detailed_error(&mut rd) {
                        // 正常读取消息（返回消息）
                        Ok(message) => return Some(message),
                        // 解析消息错误
                        Err(err) => println!(
                            "[read_one_message_detail_error] decode one message with error: {:?}",
                            err
                        ),
                    }
                }
                // 读取消息错误
                Err(err) => println!(
                    "[read_one_message_detail_error] read one message with error: {:?}",
                    err
                ),
            };
            // 发送DecodeError警告
            let alert_message = Message::build_alert(protocal_version, SaeAlert::DecodeError);
            self.write_one_message(alert_message).await.ok();
        }
        return None;
    }

    pub async fn write_one_message(&mut self, message: Message) -> Result<(), std::io::Error> {
        let buf = message.get_encoding();
        match self.write_half.write_all(&buf).await {
            Err(err) => {
                println!("[write_one_message]  error {:?}", err);
                Err(err)
            }
            Ok(()) => Ok(()),
        }
    }

    // Ok正常读取信息，Err发生编码错误
    pub async fn read_one_message_or_err(&mut self) -> Result<Option<Message>, StateChangeError> {
        if let Some(message) = self.codec_read_half.next().await {
            match message {
                Ok(bytes) => {
                    let mut rd = Reader::init(bytes.as_ref());
                    match Message::read_with_detailed_error(&mut rd) {
                        // 正常读取消息（返回消息）
                        Ok(message) => return Ok(Some(message)),
                        // 解析消息错误
                        Err(err) => println!(
                            "[read_one_message_detail_error] decode one message with error: {:?}",
                            err
                        ),
                    }
                }
                // 读取消息错误
                Err(err) => println!(
                    "[read_one_message_detail_error] read one message with error: {:?}",
                    err
                ),
            };
            // 返回DecodeError警告
            return Err(StateChangeError::AlertSend(SaeAlert::DecodeError));
        }
        return Ok(None);
    }

    pub async fn write_one_message_or_err(&mut self, message: Message) -> Result<(), StateChangeError> {
        let buf = message.get_encoding();
        match self.write_half.write_all(&buf).await {
            Err(err) => {
                println!("[write_one_message]  error {:?}", err);
                Err(StateChangeError::InternelError(err.to_string()))
            }
            Ok(()) => Ok(()),
        }
    }


}
