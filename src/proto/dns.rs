//! DNS-over-HTTPS (DoH) & Wire Format DNS Message Dissector (RFC 1035, RFC 8484).
//!
//! Parses binary DNS queries and responses exchanged over TLS (DoT) or HTTP/2 & HTTP/3 (DoH),
//! resolving compressed domain labels, record types (A, AAAA, CNAME, TXT, MX), and RCODEs.

use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsRecordType {
    A,
    Ns,
    Cname,
    Soa,
    Ptr,
    Mx,
    Txt,
    Aaaa,
    Srv,
    Any,
    Unknown(u16),
}

impl From<u16> for DnsRecordType {
    fn from(val: u16) -> Self {
        match val {
            1 => DnsRecordType::A,
            2 => DnsRecordType::Ns,
            5 => DnsRecordType::Cname,
            6 => DnsRecordType::Soa,
            12 => DnsRecordType::Ptr,
            15 => DnsRecordType::Mx,
            16 => DnsRecordType::Txt,
            28 => DnsRecordType::Aaaa,
            33 => DnsRecordType::Srv,
            255 => DnsRecordType::Any,
            other => DnsRecordType::Unknown(other),
        }
    }
}

impl std::fmt::Display for DnsRecordType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DnsRecordType::A => write!(f, "A"),
            DnsRecordType::Ns => write!(f, "NS"),
            DnsRecordType::Cname => write!(f, "CNAME"),
            DnsRecordType::Soa => write!(f, "SOA"),
            DnsRecordType::Ptr => write!(f, "PTR"),
            DnsRecordType::Mx => write!(f, "MX"),
            DnsRecordType::Txt => write!(f, "TXT"),
            DnsRecordType::Aaaa => write!(f, "AAAA"),
            DnsRecordType::Srv => write!(f, "SRV"),
            DnsRecordType::Any => write!(f, "ANY"),
            DnsRecordType::Unknown(id) => write!(f, "TYPE{}", id),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuestion {
    pub qname: String,
    pub qtype: DnsRecordType,
    pub qclass: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsResourceRecord {
    pub name: String,
    pub rtype: DnsRecordType,
    pub class: u16,
    pub ttl: u32,
    pub rdata: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsMessage {
    pub id: u16,
    pub is_response: bool,
    pub opcode: u8,
    pub authoritative: bool,
    pub truncated: bool,
    pub recursion_desired: bool,
    pub recursion_available: bool,
    pub rcode: u8,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsResourceRecord>,
    pub authorities: Vec<DnsResourceRecord>,
    pub additionals: Vec<DnsResourceRecord>,
}

impl DnsMessage {
    pub fn rcode_str(&self) -> &'static str {
        match self.rcode {
            0 => "NoError",
            1 => "FormErr",
            2 => "ServFail",
            3 => "NXDomain",
            4 => "NotImp",
            5 => "Refused",
            _ => "UnknownRcode",
        }
    }
}

pub struct DnsParser;

impl DnsParser {
    /// Heuristic detector to determine if bytes match RFC 1035 DNS wire framing.
    pub fn is_probable_dns(data: &[u8]) -> bool {
        if data.len() < 12 {
            return false;
        }
        let qdcount = u16::from_be_bytes([data[4], data[5]]);
        let ancount = u16::from_be_bytes([data[6], data[7]]);
        let nscount = u16::from_be_bytes([data[8], data[9]]);
        let arcount = u16::from_be_bytes([data[10], data[11]]);

        // DNS messages typically have 1-5 questions and reasonable record counts
        if (1..=10).contains(&qdcount) && ancount < 100 && nscount < 50 && arcount < 50 {
            // First question starts at offset 12 with label len > 0 and < 64
            let first_label_len = data[12];
            if first_label_len > 0
                && first_label_len < 64
                && (12 + first_label_len as usize) < data.len()
            {
                return true;
            }
        }
        false
    }

    /// Parses an RFC 1035 / RFC 8484 wire-format DNS query or response.
    pub fn parse(data: &[u8]) -> Option<DnsMessage> {
        if data.len() < 12 {
            return None;
        }

        let id = u16::from_be_bytes([data[0], data[1]]);
        let flags = u16::from_be_bytes([data[2], data[3]]);

        let is_response = (flags & 0x8000) != 0;
        let opcode = ((flags >> 11) & 0x0F) as u8;
        let authoritative = (flags & 0x0400) != 0;
        let truncated = (flags & 0x0200) != 0;
        let recursion_desired = (flags & 0x0100) != 0;
        let recursion_available = (flags & 0x0080) != 0;
        let rcode = (flags & 0x000F) as u8;

        let qdcount = u16::from_be_bytes([data[4], data[5]]) as usize;
        let ancount = u16::from_be_bytes([data[6], data[7]]) as usize;
        let nscount = u16::from_be_bytes([data[8], data[9]]) as usize;
        let arcount = u16::from_be_bytes([data[10], data[11]]) as usize;

        let mut offset = 12;

        // 1. Parse Questions
        let mut questions = Vec::with_capacity(qdcount);
        for _ in 0..qdcount {
            let (qname, consumed) = Self::read_domain_name(data, offset)?;
            offset += consumed;

            if offset + 4 > data.len() {
                return None;
            }
            let qtype = DnsRecordType::from(u16::from_be_bytes([data[offset], data[offset + 1]]));
            let qclass = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
            offset += 4;

            questions.push(DnsQuestion {
                qname,
                qtype,
                qclass,
            });
        }

        // 2. Parse Answers
        let mut answers = Vec::with_capacity(ancount);
        for _ in 0..ancount {
            let (rr, consumed) = Self::read_resource_record(data, offset)?;
            offset += consumed;
            answers.push(rr);
        }

        // 3. Parse Authority Records
        let mut authorities = Vec::with_capacity(nscount);
        for _ in 0..nscount {
            let (rr, consumed) = Self::read_resource_record(data, offset)?;
            offset += consumed;
            authorities.push(rr);
        }

        // 4. Parse Additional Records
        let mut additionals = Vec::with_capacity(arcount);
        for _ in 0..arcount {
            let (rr, consumed) = Self::read_resource_record(data, offset)?;
            offset += consumed;
            additionals.push(rr);
        }

        Some(DnsMessage {
            id,
            is_response,
            opcode,
            authoritative,
            truncated,
            recursion_desired,
            recursion_available,
            rcode,
            questions,
            answers,
            authorities,
            additionals,
        })
    }

    fn read_resource_record(data: &[u8], mut offset: usize) -> Option<(DnsResourceRecord, usize)> {
        let initial_offset = offset;
        let (name, consumed) = Self::read_domain_name(data, offset)?;
        offset += consumed;

        if offset.checked_add(10).is_none_or(|end| end > data.len()) {
            return None;
        }

        let rtype = DnsRecordType::from(u16::from_be_bytes([data[offset], data[offset + 1]]));
        let class = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
        let ttl = u32::from_be_bytes([
            data[offset + 4],
            data[offset + 5],
            data[offset + 6],
            data[offset + 7],
        ]);
        let rdlength = u16::from_be_bytes([data[offset + 8], data[offset + 9]]) as usize;
        offset += 10;

        if offset
            .checked_add(rdlength)
            .is_none_or(|end| end > data.len())
        {
            return None;
        }

        let rdata_slice = &data[offset..offset + rdlength];
        let rdata = match rtype {
            DnsRecordType::A if rdlength == 4 => {
                let ip = Ipv4Addr::new(
                    rdata_slice[0],
                    rdata_slice[1],
                    rdata_slice[2],
                    rdata_slice[3],
                );
                ip.to_string()
            }
            DnsRecordType::Aaaa if rdlength == 16 => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(rdata_slice);
                let ip = Ipv6Addr::from(octets);
                ip.to_string()
            }
            DnsRecordType::Cname | DnsRecordType::Ns | DnsRecordType::Ptr => {
                let (target_name, _) = Self::read_domain_name(data, offset)
                    .unwrap_or_else(|| ("<malformed>".into(), 0));
                target_name
            }
            DnsRecordType::Mx if rdlength >= 2 => {
                let preference = u16::from_be_bytes([rdata_slice[0], rdata_slice[1]]);
                let (exchange, _) = Self::read_domain_name(data, offset + 2)
                    .unwrap_or_else(|| ("<malformed>".into(), 0));
                format!("{} {}", preference, exchange)
            }
            DnsRecordType::Txt => {
                // RFC 1035 §3.3.14: one or more <character-string> entries
                let mut cur = 0;
                let mut parts = Vec::new();
                while cur < rdata_slice.len() {
                    let seg_len = rdata_slice[cur] as usize;
                    cur += 1;
                    let seg_end = (cur + seg_len).min(rdata_slice.len());
                    parts.push(String::from_utf8_lossy(&rdata_slice[cur..seg_end]));
                    cur = seg_end;
                }
                parts.join("")
            }
            _ => {
                // Hex string fallback
                rdata_slice
                    .iter()
                    .map(|b| format!("{:02x}", b))
                    .collect::<Vec<_>>()
                    .join("")
            }
        };

        let total_consumed = (offset + rdlength) - initial_offset;
        Some((
            DnsResourceRecord {
                name,
                rtype,
                class,
                ttl,
                rdata,
            },
            total_consumed,
        ))
    }

    /// Reads a DNS domain name from bytes at `offset`, following RFC 1035 compression pointers.
    /// Returns `Some((domain_name, bytes_consumed_from_original_offset))`.
    pub fn read_domain_name(data: &[u8], mut offset: usize) -> Option<(String, usize)> {
        let mut labels = Vec::new();
        let mut bytes_consumed = 0;
        let mut has_jumped = false;
        let mut jumps = 0;

        loop {
            if offset >= data.len() {
                return None;
            }

            let len_byte = data[offset];

            // 1. Compression pointer (first 2 bits are 11: 0xC0..)
            if len_byte & 0xC0 == 0xC0 {
                if offset + 1 >= data.len() {
                    return None;
                }
                let pointer_offset =
                    (((len_byte & 0x3F) as usize) << 8) | (data[offset + 1] as usize);
                if !has_jumped {
                    bytes_consumed += 2;
                    has_jumped = true;
                }
                offset = pointer_offset;
                jumps += 1;
                if jumps > 10 {
                    return None; // Guard against pointer loops
                }
                continue;
            }

            // 2. Terminating null byte (end of domain)
            if len_byte == 0 {
                if !has_jumped {
                    bytes_consumed += 1;
                }
                break;
            }

            // 3. Standard label
            let label_len = len_byte as usize;
            if !has_jumped {
                bytes_consumed += 1 + label_len;
            }
            offset += 1;

            if offset + label_len > data.len() {
                return None;
            }

            let label_str = String::from_utf8_lossy(&data[offset..offset + label_len]);
            labels.push(label_str.to_string());
            offset += label_len;
        }

        let full_name = if labels.is_empty() {
            ".".to_string()
        } else {
            labels.join(".")
        };

        Some((full_name, bytes_consumed))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_dns_query_wire() {
        // Standard DNS Query for "example.com" A (Type 1), ID = 0x1234
        let raw_query = vec![
            0x12, 0x34, // ID: 0x1234
            0x01, 0x00, // Flags: Standard Query, RD=1
            0x00, 0x01, // QDCOUNT: 1
            0x00, 0x00, // ANCOUNT: 0
            0x00, 0x00, // NSCOUNT: 0
            0x00, 0x00, // ARCOUNT: 0
            // QNAME: 7 "example" 3 "com" 0
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00,
            0x01, // QTYPE: A (1)
            0x00, 0x01, // QCLASS: IN (1)
        ];

        let msg = DnsParser::parse(&raw_query).expect("Must parse DNS query");
        assert_eq!(msg.id, 0x1234);
        assert!(!msg.is_response);
        assert_eq!(msg.questions.len(), 1);
        assert_eq!(msg.questions[0].qname, "example.com");
        assert_eq!(msg.questions[0].qtype, DnsRecordType::A);
        assert_eq!(msg.questions[0].qclass, 1);
        assert!(msg.answers.is_empty());
    }

    #[test]
    fn test_parse_dns_response_with_compression_pointer() {
        // DNS Response for "api.local": CNAME "target.internal", A "93.184.216.34"
        let raw_response = vec![
            0x56, 0x78, // ID: 0x5678
            0x81, 0x80, // Flags: QR=1 (Response), RD=1, RA=1, NoError (0)
            0x00, 0x01, // QDCOUNT: 1
            0x00, 0x01, // ANCOUNT: 1
            0x00, 0x00, // NSCOUNT: 0
            0x00, 0x00, // ARCOUNT: 0
            // Question: "api.local"
            0x03, b'a', b'p', b'i', 0x05, b'l', b'o', b'c', b'a', b'l', 0x00, 0x00,
            0x01, // QTYPE: A
            0x00, 0x01, // QCLASS: IN
            // Answer: Compression pointer to 0x000C ("api.local")
            0xC0, 0x0C, 0x00, 0x01, // TYPE: A (1)
            0x00, 0x01, // CLASS: IN (1)
            0x00, 0x00, 0x01, 0x2C, // TTL: 300s
            0x00, 0x04, // RDLENGTH: 4
            93, 184, 216, 34, // RDATA: 93.184.216.34
        ];

        let msg = DnsParser::parse(&raw_response).expect("Must parse DNS response");
        assert_eq!(msg.id, 0x5678);
        assert!(msg.is_response);
        assert_eq!(msg.rcode_str(), "NoError");
        assert_eq!(msg.answers.len(), 1);
        assert_eq!(msg.answers[0].name, "api.local");
        assert_eq!(msg.answers[0].rtype, DnsRecordType::A);
        assert_eq!(msg.answers[0].ttl, 300);
        assert_eq!(msg.answers[0].rdata, "93.184.216.34");
    }

    #[test]
    fn test_parse_dns_multi_segment_txt_and_mx() {
        // Response with TXT (2 chunks: "v=spf1 " and "include:_spf.google.com")
        // and MX (preference 10, exchange "mail.google.com")
        let mut raw = vec![
            0x99, 0x99, // ID
            0x81, 0x80, // Response
            0x00, 0x00, // QDCOUNT: 0
            0x00, 0x02, // ANCOUNT: 2
            0x00, 0x00, // NSCOUNT: 0
            0x00, 0x00, // ARCOUNT: 0
        ];

        // Answer 1: TXT record for "example.com"
        raw.extend_from_slice(&[
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00,
        ]);
        raw.extend_from_slice(&[0x00, 0x10]); // TYPE: TXT (16)
        raw.extend_from_slice(&[0x00, 0x01]); // CLASS: IN (1)
        raw.extend_from_slice(&[0x00, 0x00, 0x0e, 0x10]); // TTL: 3600
        let txt1 = b"v=spf1 ";
        let txt2 = b"include:_spf.google.com ~all";
        let rdlength = (1 + txt1.len() + 1 + txt2.len()) as u16;
        raw.extend_from_slice(&rdlength.to_be_bytes());
        raw.push(txt1.len() as u8);
        raw.extend_from_slice(txt1);
        raw.push(txt2.len() as u8);
        raw.extend_from_slice(txt2);

        // Answer 2: MX record for "example.com" (preference 10, mail.google.com)
        raw.extend_from_slice(&[0xC0, 0x0C]); // Name pointer
        raw.extend_from_slice(&[0x00, 0x0F]); // TYPE: MX (15)
        raw.extend_from_slice(&[0x00, 0x01]); // CLASS: IN (1)
        raw.extend_from_slice(&[0x00, 0x00, 0x0e, 0x10]); // TTL: 3600
        let mut mx_rdata = Vec::new();
        mx_rdata.extend_from_slice(&10u16.to_be_bytes());
        mx_rdata.extend_from_slice(&[
            0x04, b'm', b'a', b'i', b'l', 0x06, b'g', b'o', b'o', b'g', b'l', b'e', 0x03, b'c',
            b'o', b'm', 0x00,
        ]);
        raw.extend_from_slice(&(mx_rdata.len() as u16).to_be_bytes());
        raw.extend_from_slice(&mx_rdata);

        let msg = DnsParser::parse(&raw).expect("Must parse DNS response");
        assert_eq!(msg.answers.len(), 2);
        assert_eq!(msg.answers[0].rtype, DnsRecordType::Txt);
        assert_eq!(msg.answers[0].rdata, "v=spf1 include:_spf.google.com ~all");
        assert_eq!(msg.answers[1].rtype, DnsRecordType::Mx);
        assert_eq!(msg.answers[1].rdata, "10 mail.google.com");
    }
}
