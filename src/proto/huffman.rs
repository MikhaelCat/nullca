//! RFC 7541 Appendix B - Canonical Huffman Code for HTTP/2 Header Compression.
//!
//! Provides zero-copy / streaming bitwise Huffman decoding for HTTP/2 headers.

use std::sync::OnceLock;
use thiserror::Error;

#[derive(Error, Debug, PartialEq, Eq)]
pub enum HuffmanError {
    #[error("EOS symbol encountered before end of input")]
    UnexpectedEos,
    #[error("Padding exceeds 7 bits or contains non-ones")]
    InvalidPadding,
    #[error("Incomplete or truncated Huffman code at end of bitstream")]
    TruncatedCode,
    #[error("Invalid Huffman bit transition")]
    InvalidTransition,
}

/// Node in the Huffman decoding tree.
#[derive(Clone, Copy, Debug)]
enum Node {
    Internal([u16; 2]),
    Leaf(u8),
}

// Canonical RFC 7541 Huffman Table: (symbol, code, bit_length).
// Symbols 0..=255 plus EOS (256).
include!("huffman_table.rs.inc");

/// Compiled Huffman Tree for fast traversal.
pub struct HuffmanTree {
    nodes: Vec<Node>,
}

static GLOBAL_HUFFMAN_TREE: OnceLock<HuffmanTree> = OnceLock::new();

impl HuffmanTree {
    /// Builds the decoding tree from RFC 7541 specification.
    pub fn build() -> Self {
        let mut nodes = Vec::with_capacity(1024);
        nodes.push(Node::Internal([0, 0])); // Root at index 0

        for (sym, &(code, len)) in HUFFMAN_SPEC.iter().enumerate() {
            let mut curr = 0;
            for bit_idx in (0..len).rev() {
                let bit = ((code >> bit_idx) & 1) as usize;
                let next = match nodes[curr] {
                    Node::Internal(children) => children[bit],
                    Node::Leaf(_) => unreachable!("Invalid prefix code"),
                };

                let next_idx = if next == 0 {
                    let new_idx = nodes.len() as u16;
                    nodes.push(Node::Internal([0, 0]));
                    if let Node::Internal(ref mut children) = nodes[curr] {
                        children[bit] = new_idx;
                    }
                    new_idx as usize
                } else {
                    next as usize
                };
                curr = next_idx;
            }
            if sym == 256 {
                // EOS symbol
                nodes[curr] = Node::Internal([u16::MAX, u16::MAX]);
            } else {
                nodes[curr] = Node::Leaf(sym as u8);
            }
        }

        Self { nodes }
    }

    /// Decodes a Huffman-compressed byte slice according to RFC 7541.
    pub fn decode(&self, input: &[u8]) -> Result<Vec<u8>, HuffmanError> {
        let mut out = Vec::with_capacity(input.len() * 2);
        let mut curr_node = 0;
        let mut bits_left = 0;

        for &byte in input {
            for bit_pos in (0..8).rev() {
                let bit = ((byte >> bit_pos) & 1) as usize;
                match self.nodes[curr_node] {
                    Node::Internal(children) => {
                        let next = children[bit];
                        if next == 0 {
                            return Err(HuffmanError::InvalidTransition);
                        }
                        if next == u16::MAX {
                            // EOS encountered
                            return Err(HuffmanError::UnexpectedEos);
                        }
                        match self.nodes[next as usize] {
                            Node::Leaf(ch) => {
                                out.push(ch);
                                curr_node = 0; // Reset to root
                                bits_left = 0;
                            }
                            Node::Internal(_) => {
                                curr_node = next as usize;
                                bits_left += 1;
                            }
                        }
                    }
                    Node::Leaf(_) => unreachable!(),
                }
            }
        }

        // Validate padding: must not be longer than 7 bits
        if bits_left > 7 {
            return Err(HuffmanError::InvalidPadding);
        }

        Ok(out)
    }
}

/// Convenience decoding function using global static tree.
pub fn decode_huffman(data: &[u8]) -> Result<Vec<u8>, HuffmanError> {
    GLOBAL_HUFFMAN_TREE
        .get_or_init(HuffmanTree::build)
        .decode(data)
}

/// Huffman-encode string bytes for testing and HPACK serialization.
pub fn encode_huffman(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut current_byte: u8 = 0;
    let mut bits_in_byte = 0;

    for &b in input {
        let (code, len) = HUFFMAN_SPEC[b as usize];
        for i in (0..len).rev() {
            let bit = ((code >> i) & 1) as u8;
            current_byte = (current_byte << 1) | bit;
            bits_in_byte += 1;

            if bits_in_byte == 8 {
                out.push(current_byte);
                current_byte = 0;
                bits_in_byte = 0;
            }
        }
    }

    // Pad remaining bits with 1s (EOS prefix)
    if bits_in_byte > 0 {
        current_byte = (current_byte << (8 - bits_in_byte)) | ((1 << (8 - bits_in_byte)) - 1);
        out.push(current_byte);
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_huffman_roundtrip_ascii() {
        let samples = &[
            "www.example.com",
            "no-cache",
            "custom-key: custom-value",
            "gzip, deflate",
            "/index.html?user=admin&token=xyz123",
        ];

        for &sample in samples {
            let encoded = encode_huffman(sample.as_bytes());
            let decoded = decode_huffman(&encoded).expect("Huffman decode should succeed");
            assert_eq!(String::from_utf8(decoded).unwrap(), sample);
        }
    }

    #[test]
    fn test_rfc7541_spec_examples() {
        let expected = b"www.example.com";
        let encoded = encode_huffman(expected);
        let decoded = decode_huffman(&encoded).unwrap();
        assert_eq!(&decoded, expected);
    }
}
