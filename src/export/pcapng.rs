use crate::engine::event::{Direction, TlsEvent};
use std::fs::File;
use std::io::{self, Write};
use std::path::Path;

pub struct PcapNgWriter {
    file: File,
}

impl PcapNgWriter {
    pub fn create<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        let mut file = File::create(path)?;

        // 1. Write Section Header Block (SHB)
        // Block Type: 0x0A0D0D0A (4 bytes)
        // Block Length: 28 (4 bytes)
        // Byte-Order Magic: 0x1A2B3C4D (4 bytes)
        // Major: 1, Minor: 0 (4 bytes)
        // Section Length: -1 (8 bytes)
        // Block Length repeated: 28 (4 bytes)
        let mut shb = Vec::new();
        shb.extend_from_slice(&0x0A0D0D0Au32.to_le_bytes()); // Type
        shb.extend_from_slice(&28u32.to_le_bytes()); // Block Total Length
        shb.extend_from_slice(&0x1A2B3C4Du32.to_le_bytes()); // Byte-Order Magic
        shb.extend_from_slice(&1u16.to_le_bytes()); // Major
        shb.extend_from_slice(&0u16.to_le_bytes()); // Minor
        shb.extend_from_slice(&(-1i64).to_le_bytes()); // Section Length
        shb.extend_from_slice(&28u32.to_le_bytes()); // Block Total Length
        file.write_all(&shb)?;

        // 2. Write Interface Description Block (IDB)
        // Block Type: 0x00000001
        // Block Length: 20
        // LinkType: 1 (Ethernet)
        // Reserved: 0
        // SnapLen: 65535
        let mut idb = Vec::new();
        idb.extend_from_slice(&0x00000001u32.to_le_bytes());
        idb.extend_from_slice(&20u32.to_le_bytes());
        idb.extend_from_slice(&1u16.to_le_bytes()); // LINKTYPE_ETHERNET
        idb.extend_from_slice(&0u16.to_le_bytes()); // Reserved
        idb.extend_from_slice(&65535u32.to_le_bytes()); // SnapLen
        idb.extend_from_slice(&20u32.to_le_bytes());
        file.write_all(&idb)?;

        Ok(Self { file })
    }

    pub fn write_to_file<P: AsRef<Path>>(events: &[TlsEvent], path: P) -> io::Result<()> {
        let mut writer = Self::create(path)?;
        for event in events {
            writer.write_event(event)?;
        }
        Ok(())
    }

    pub fn write_event(&mut self, event: &TlsEvent) -> io::Result<()> {
        if event.data.is_empty() {
            return Ok(());
        }

        // Build synthetic Ethernet + IPv4 + TCP packet wrapping plaintext payload
        let packet = Self::build_synthetic_tcp_packet(event);
        let cap_len = packet.len() as u32;

        // Enhanced Packet Block (EPB)
        // Type: 0x00000006
        // Interface ID: 0 (4 bytes)
        // Timestamp High: 4 bytes, Low: 4 bytes (microseconds or resolution)
        // Captured Len: 4 bytes, Original Len: 4 bytes
        // Packet Data (aligned to 4 bytes)
        // Block Length: repeated

        let pad_len = (4 - (cap_len % 4)) % 4;
        let total_block_len = 32 + cap_len + pad_len;

        let ts_us = event.timestamp_ns / 1000;
        let ts_high = (ts_us >> 32) as u32;
        let ts_low = (ts_us & 0xFFFFFFFF) as u32;

        let mut epb = Vec::with_capacity(total_block_len as usize);
        epb.extend_from_slice(&0x00000006u32.to_le_bytes()); // Block Type EPB
        epb.extend_from_slice(&total_block_len.to_le_bytes());
        epb.extend_from_slice(&0u32.to_le_bytes()); // Interface ID
        epb.extend_from_slice(&ts_high.to_le_bytes());
        epb.extend_from_slice(&ts_low.to_le_bytes());
        epb.extend_from_slice(&cap_len.to_le_bytes());
        epb.extend_from_slice(&cap_len.to_le_bytes());
        epb.extend_from_slice(&packet);

        epb.resize(epb.len() + pad_len as usize, 0);

        epb.extend_from_slice(&total_block_len.to_le_bytes());

        self.file.write_all(&epb)?;
        self.file.flush()?;

        Ok(())
    }

    fn build_synthetic_tcp_packet(event: &TlsEvent) -> Vec<u8> {
        let payload = &event.data;
        let ip_len = (20 + 20 + payload.len()) as u16;

        let mut packet = Vec::with_capacity(14 + ip_len as usize);

        // 1. Ethernet Header (14 bytes)
        packet.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]); // Dst MAC
        packet.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x02]); // Src MAC
        packet.extend_from_slice(&[0x08, 0x00]); // EtherType IPv4

        // 2. IPv4 Header (20 bytes)
        let (src_ip, dst_ip) = {
            let parse_ip = |s: &Option<String>| -> Option<[u8; 4]> {
                s.as_ref()?
                    .parse::<std::net::Ipv4Addr>()
                    .ok()
                    .map(|ip| ip.octets())
            };
            let default_egress = ([127, 0, 0, 1], [127, 0, 0, 2]);
            let default_ingress = ([127, 0, 0, 2], [127, 0, 0, 1]);
            let (def_src, def_dst) = match event.direction {
                Direction::Egress => default_egress,
                Direction::Ingress => default_ingress,
            };
            let src = parse_ip(&event.src_addr).unwrap_or(def_src);
            let dst = parse_ip(&event.dst_addr).unwrap_or(def_dst);
            (src, dst)
        };

        packet.push(0x45); // Version 4, IHL 5
        packet.push(0x00); // DSCP / ECN
        packet.extend_from_slice(&ip_len.to_be_bytes()); // Total Length
        packet.extend_from_slice(&0x1234u16.to_be_bytes()); // Identification
        packet.extend_from_slice(&0x4000u16.to_be_bytes()); // Flags: Don't Fragment
        packet.push(64); // TTL
        packet.push(6); // Protocol: TCP
        packet.extend_from_slice(&[0x00, 0x00]); // Header Checksum (0 for local)
        packet.extend_from_slice(&src_ip);
        packet.extend_from_slice(&dst_ip);

        // 3. TCP Header (20 bytes)
        let (src_port, dst_port) = match (event.src_port, event.dst_port) {
            (Some(sp), Some(dp)) => (sp, dp),
            _ => {
                let ephemeral_port =
                    (10000 + (event.pid % 40000) + (event.fd as u32 % 1000)) as u16;
                match event.direction {
                    Direction::Egress => (ephemeral_port, 443),
                    Direction::Ingress => (443, ephemeral_port),
                }
            }
        };

        packet.extend_from_slice(&src_port.to_be_bytes());
        packet.extend_from_slice(&dst_port.to_be_bytes());
        packet.extend_from_slice(&1000u32.to_be_bytes()); // Sequence Number
        packet.extend_from_slice(&1000u32.to_be_bytes()); // Acknowledgment Number
        packet.push(0x50); // Data offset (5 words = 20 bytes)
        packet.push(0x18); // Flags: PSH + ACK
        packet.extend_from_slice(&65535u16.to_be_bytes()); // Window Size
        packet.extend_from_slice(&[0x00, 0x00]); // Checksum
        packet.extend_from_slice(&[0x00, 0x00]); // Urgent Pointer

        // 4. Decrypted Plaintext Payload
        packet.extend_from_slice(payload);

        packet
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_pcapng_writer_generation() {
        let tmp = NamedTempFile::new().expect("Failed to create temp file");
        let path = tmp.path();

        {
            let mut writer = PcapNgWriter::create(path).expect("Failed to create PCAP-NG");
            let event = TlsEvent::new(
                1700000000000000000,
                4242,
                4242,
                3,
                Direction::Egress,
                "test".into(),
                b"GET / HTTP/1.1\r\nHost: test.local\r\n\r\n".to_vec(),
                Some(120),
            )
            .with_socket_info(
                Some("192.168.1.50".into()),
                Some("10.0.0.1".into()),
                Some(54321),
                Some(443),
            );
            writer.write_event(&event).expect("Failed to write event");
        }

        let bytes = std::fs::read(path).expect("Failed to read back pcapng");
        assert!(
            bytes.len() > 48,
            "File should contain SHB, IDB and EPB blocks"
        );
        assert_eq!(
            &bytes[0..4],
            &[0x0A, 0x0D, 0x0D, 0x0A],
            "Magic SHB mismatch"
        );
        // Verify real IP octets exist in packet
        assert!(bytes.windows(4).any(|w| w == [192, 168, 1, 50]));
        assert!(bytes.windows(4).any(|w| w == [10, 0, 0, 1]));
    }
}
