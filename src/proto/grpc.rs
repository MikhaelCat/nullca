#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrpcMessage {
    pub is_compressed: bool,
    pub length: u32,
    pub payload: Vec<u8>,
}

pub struct GrpcParser;

impl GrpcParser {
    pub fn parse_messages(mut data: &[u8]) -> Vec<GrpcMessage> {
        let mut messages = Vec::new();

        while data.len() >= 5 {
            let is_compressed = data[0] != 0;
            let length = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);

            let total_len = 5 + length as usize;
            if data.len() < total_len {
                break; // Incomplete message
            }

            let payload = data[5..total_len].to_vec();
            messages.push(GrpcMessage {
                is_compressed,
                length,
                payload,
            });

            data = &data[total_len..];
        }

        messages
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_grpc_message() {
        let raw = [
            0x00,                   // uncompressed
            0x00, 0x00, 0x00, 0x04, // length = 4
            0x08, 0x96, 0x01, 0x00, // protobuf payload
        ];

        let msgs = GrpcParser::parse_messages(&raw);
        assert_eq!(msgs.len(), 1);
        assert!(!msgs[0].is_compressed);
        assert_eq!(msgs[0].length, 4);
        assert_eq!(msgs[0].payload, vec![0x08, 0x96, 0x01, 0x00]);
    }
}
