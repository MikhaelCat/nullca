use std::collections::VecDeque;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Http2FrameType {
    Data,
    Headers,
    Priority,
    RstStream,
    Settings,
    PushPromise,
    Ping,
    GoAway,
    WindowUpdate,
    Continuation,
    Unknown(u8),
}

impl From<u8> for Http2FrameType {
    fn from(val: u8) -> Self {
        match val {
            0x0 => Http2FrameType::Data,
            0x1 => Http2FrameType::Headers,
            0x2 => Http2FrameType::Priority,
            0x3 => Http2FrameType::RstStream,
            0x4 => Http2FrameType::Settings,
            0x5 => Http2FrameType::PushPromise,
            0x6 => Http2FrameType::Ping,
            0x7 => Http2FrameType::GoAway,
            0x8 => Http2FrameType::WindowUpdate,
            0x9 => Http2FrameType::Continuation,
            other => Http2FrameType::Unknown(other),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Http2Frame {
    pub length: u32,
    pub frame_type: Http2FrameType,
    pub flags: u8,
    pub stream_id: u32,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderField {
    pub name: String,
    pub value: String,
}

/// RFC 7541 HPACK Context with Static & Dynamic tables
pub struct HpackDecoder {
    dynamic_table: VecDeque<HeaderField>,
    max_table_size: usize,
}

impl Default for HpackDecoder {
    fn default() -> Self {
        Self::new(4096)
    }
}

impl HpackDecoder {
    pub fn new(max_table_size: usize) -> Self {
        Self {
            dynamic_table: VecDeque::new(),
            max_table_size,
        }
    }

    /// RFC 7541 Appendix A - Static Table
    fn get_static_entry(index: usize) -> Option<(&'static str, &'static str)> {
        match index {
            1 => Some((":authority", "")),
            2 => Some((":method", "GET")),
            3 => Some((":method", "POST")),
            4 => Some((":path", "/")),
            5 => Some((":path", "/index.html")),
            6 => Some((":scheme", "http")),
            7 => Some((":scheme", "https")),
            8 => Some((":status", "200")),
            9 => Some((":status", "204")),
            10 => Some((":status", "206")),
            11 => Some((":status", "304")),
            12 => Some((":status", "400")),
            13 => Some((":status", "404")),
            14 => Some((":status", "500")),
            15 => Some(("accept-charset", "")),
            16 => Some(("accept-encoding", "gzip, deflate")),
            17 => Some(("accept-language", "")),
            18 => Some(("accept-ranges", "")),
            19 => Some(("accept", "")),
            20 => Some(("access-control-allow-origin", "")),
            21 => Some(("age", "")),
            22 => Some(("allow", "")),
            23 => Some(("authorization", "")),
            24 => Some(("cache-control", "")),
            25 => Some(("content-disposition", "")),
            26 => Some(("content-encoding", "")),
            27 => Some(("content-language", "")),
            28 => Some(("content-length", "")),
            29 => Some(("content-location", "")),
            30 => Some(("content-range", "")),
            31 => Some(("content-type", "")),
            32 => Some(("cookie", "")),
            33 => Some(("date", "")),
            34 => Some(("etag", "")),
            35 => Some(("expect", "")),
            36 => Some(("expires", "")),
            37 => Some(("from", "")),
            38 => Some(("host", "")),
            39 => Some(("if-match", "")),
            40 => Some(("if-modified-since", "")),
            41 => Some(("if-none-match", "")),
            42 => Some(("if-range", "")),
            43 => Some(("if-unmodified-since", "")),
            44 => Some(("last-modified", "")),
            45 => Some(("link", "")),
            46 => Some(("location", "")),
            47 => Some(("max-forwards", "")),
            48 => Some(("proxy-authenticate", "")),
            49 => Some(("proxy-authorization", "")),
            50 => Some(("range", "")),
            51 => Some(("referer", "")),
            52 => Some(("refresh", "")),
            53 => Some(("retry-after", "")),
            54 => Some(("server", "")),
            55 => Some(("set-cookie", "")),
            56 => Some(("strict-transport-security", "")),
            57 => Some(("transfer-encoding", "")),
            58 => Some(("user-agent", "")),
            59 => Some(("vary", "")),
            60 => Some(("via", "")),
            61 => Some(("www-authenticate", "")),
            _ => None,
        }
    }

    pub fn decode(&mut self, mut input: &[u8]) -> Result<Vec<HeaderField>, &'static str> {
        let mut headers = Vec::new();

        while !input.is_empty() {
            let byte = input[0];

            if byte & 0x80 != 0 {
                // 1. Indexed Header Field Representation (1xxxxxxx)
                let (index, consumed) = Self::decode_integer(input, 7)?;
                input = &input[consumed..];
                let (name, value) = self.lookup_entry(index)?;
                headers.push(HeaderField { name, value });
            } else if byte & 0x40 != 0 {
                // 2. Literal Header Field with Incremental Indexing (01xxxxxx)
                let (index, consumed) = Self::decode_integer(input, 6)?;
                input = &input[consumed..];

                let name = if index == 0 {
                    let (s, _consumed_str) = Self::decode_string(&mut input)?;
                    s
                } else {
                    self.lookup_name(index)?
                };

                let (value, _) = Self::decode_string(&mut input)?;
                let field = HeaderField {
                    name: name.clone(),
                    value: value.clone(),
                };

                self.add_dynamic_entry(field.clone());
                headers.push(field);
            } else if byte & 0x20 != 0 {
                // 3. Dynamic Table Size Update (001xxxxx)
                let (new_size, consumed) = Self::decode_integer(input, 5)?;
                input = &input[consumed..];
                self.max_table_size = new_size;
            } else {
                // 4. Literal Header Field without Indexing / Never Indexed (0000xxxx or 0001xxxx)
                let (index, consumed) = Self::decode_integer(input, 4)?;
                input = &input[consumed..];

                let name = if index == 0 {
                    let (s, _) = Self::decode_string(&mut input)?;
                    s
                } else {
                    self.lookup_name(index)?
                };

                let (value, _) = Self::decode_string(&mut input)?;
                headers.push(HeaderField { name, value });
            }
        }

        Ok(headers)
    }

    fn lookup_entry(&self, index: usize) -> Result<(String, String), &'static str> {
        if index == 0 {
            return Err("Index 0 is invalid in HPACK");
        }
        if index <= 61 {
            if let Some((n, v)) = Self::get_static_entry(index) {
                return Ok((n.to_string(), v.to_string()));
            }
        }

        let dynamic_idx = index - 62;
        if dynamic_idx < self.dynamic_table.len() {
            let entry = &self.dynamic_table[dynamic_idx];
            return Ok((entry.name.clone(), entry.value.clone()));
        }

        Err("HPACK Index out of range")
    }

    fn lookup_name(&self, index: usize) -> Result<String, &'static str> {
        let (name, _) = self.lookup_entry(index)?;
        Ok(name)
    }

    fn add_dynamic_entry(&mut self, field: HeaderField) {
        let entry_size = field.name.len() + field.value.len() + 32;
        while self.current_table_size() + entry_size > self.max_table_size
            && !self.dynamic_table.is_empty()
        {
            self.dynamic_table.pop_back();
        }
        self.dynamic_table.push_front(field);
    }

    fn current_table_size(&self) -> usize {
        self.dynamic_table
            .iter()
            .map(|f| f.name.len() + f.value.len() + 32)
            .sum()
    }

    fn decode_integer(input: &[u8], prefix_bits: u8) -> Result<(usize, usize), &'static str> {
        if input.is_empty() {
            return Err("Unexpected EOF while decoding integer");
        }

        let mask = (1 << prefix_bits) - 1;
        let mut value = (input[0] & mask) as usize;

        if value < mask as usize {
            return Ok((value, 1));
        }

        let mut shift = 0;
        let mut consumed = 1;

        while consumed < input.len() {
            let b = input[consumed];
            consumed += 1;
            value += ((b & 0x7f) as usize) << shift;
            if b & 0x80 == 0 {
                return Ok((value, consumed));
            }
            shift += 7;
            if shift > 28 {
                return Err("Integer overflow in HPACK");
            }
        }

        Err("Unexpected EOF in multi-byte integer")
    }

    fn decode_string(input: &mut &[u8]) -> Result<(String, usize), &'static str> {
        if input.is_empty() {
            return Err("Unexpected EOF in string header");
        }

        let is_huffman = (input[0] & 0x80) != 0;
        let (len, consumed) = Self::decode_integer(input, 7)?;
        *input = &input[consumed..];

        if input.len() < len {
            return Err("String length exceeds remaining buffer");
        }

        let str_bytes = &input[..len];
        *input = &input[len..];

        if is_huffman {
            let decoded_bytes = crate::proto::huffman::decode_huffman(str_bytes)
                .map_err(|_| "Huffman decoding failed")?;
            let s = String::from_utf8(decoded_bytes)
                .map_err(|_| "Invalid UTF-8 in Huffman decoded string")?;
            Ok((s, consumed + len))
        } else {
            let s = String::from_utf8_lossy(str_bytes).to_string();
            Ok((s, consumed + len))
        }
    }
}

pub struct Http2Parser;

impl Http2Parser {
    pub fn parse_frames(mut data: &[u8]) -> Vec<Http2Frame> {
        // Skip client connection preface if present
        if data.starts_with(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n") {
            data = &data[24..];
        }

        let mut frames = Vec::new();

        while data.len() >= 9 {
            let length = ((data[0] as u32) << 16) | ((data[1] as u32) << 8) | (data[2] as u32);
            let frame_type = Http2FrameType::from(data[3]);
            let flags = data[4];
            let stream_id = u32::from_be_bytes([data[5] & 0x7f, data[6], data[7], data[8]]);

            let total_len = 9 + length as usize;
            if data.len() < total_len {
                break; // Incomplete frame
            }

            let payload = data[9..total_len].to_vec();
            frames.push(Http2Frame {
                length,
                frame_type,
                flags,
                stream_id,
                payload,
            });

            data = &data[total_len..];
        }

        frames
    }

    /// Coalesces sequential HEADERS / PUSH_PROMISE and CONTINUATION frames
    /// into single defragmented HEADERS frames with the END_HEADERS (0x04) flag set.
    pub fn defragment_continuation_frames(frames: &[Http2Frame]) -> Vec<Http2Frame> {
        let mut defrag = Vec::new();
        let mut in_progress_header: Option<Http2Frame> = None;

        for frame in frames {
            match frame.frame_type {
                Http2FrameType::Headers | Http2FrameType::PushPromise => {
                    let end_headers = (frame.flags & 0x04) != 0;
                    if end_headers {
                        if let Some(prev) = in_progress_header.take() {
                            defrag.push(prev);
                        }
                        defrag.push(frame.clone());
                    } else {
                        if let Some(prev) = in_progress_header.take() {
                            defrag.push(prev);
                        }
                        in_progress_header = Some(frame.clone());
                    }
                }
                Http2FrameType::Continuation => {
                    if let Some(ref mut cur) = in_progress_header {
                        if cur.stream_id == frame.stream_id {
                            cur.payload.extend_from_slice(&frame.payload);
                            cur.length = cur.payload.len() as u32;
                            if (frame.flags & 0x04) != 0 {
                                cur.flags |= 0x04; // Set END_HEADERS
                                defrag.push(cur.clone());
                                in_progress_header = None;
                            }
                            continue;
                        }
                    }
                    // Standalone continuation or stream mismatch
                    defrag.push(frame.clone());
                }
                _ => {
                    if let Some(prev) = in_progress_header.take() {
                        defrag.push(prev);
                    }
                    defrag.push(frame.clone());
                }
            }
        }

        if let Some(leftover) = in_progress_header {
            defrag.push(leftover);
        }

        defrag
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hpack_static_lookup() {
        let mut decoder = HpackDecoder::default();
        // Index 2 is :method: GET (0x82)
        let raw = [0x82];
        let headers = decoder.decode(&raw).expect("HPACK decode failed");
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].name, ":method");
        assert_eq!(headers[0].value, "GET");
    }

    #[test]
    fn test_http2_frame_parsing() {
        // Frame: length=5, type=0 (DATA), flags=1 (END_STREAM), stream_id=1, payload="hello"
        let raw = [
            0x00, 0x00, 0x05, // Length: 5
            0x00, // Type: DATA
            0x01, // Flags: END_STREAM
            0x00, 0x00, 0x00, 0x01, // Stream ID: 1
            b'h', b'e', b'l', b'l', b'o',
        ];

        let frames = Http2Parser::parse_frames(&raw);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].frame_type, Http2FrameType::Data);
        assert_eq!(frames[0].stream_id, 1);
        assert_eq!(frames[0].payload, b"hello");
    }

    #[test]
    fn test_defragment_continuation_frames() {
        let f1 = Http2Frame {
            length: 1,
            frame_type: Http2FrameType::Headers,
            flags: 0x00, // No END_HEADERS
            stream_id: 3,
            payload: vec![0x82], // :method: GET
        };
        let f2 = Http2Frame {
            length: 1,
            frame_type: Http2FrameType::Continuation,
            flags: 0x04, // END_HEADERS
            stream_id: 3,
            payload: vec![0x84], // :path: /
        };
        let f3 = Http2Frame {
            length: 4,
            frame_type: Http2FrameType::Data,
            flags: 0x01,
            stream_id: 3,
            payload: b"ping".to_vec(),
        };

        let raw = vec![f1, f2, f3];
        let defrag = Http2Parser::defragment_continuation_frames(&raw);

        assert_eq!(defrag.len(), 2);
        assert_eq!(defrag[0].frame_type, Http2FrameType::Headers);
        assert_eq!(defrag[0].flags & 0x04, 0x04);
        assert_eq!(defrag[0].payload, vec![0x82, 0x84]);
        assert_eq!(defrag[1].frame_type, Http2FrameType::Data);
    }
}
