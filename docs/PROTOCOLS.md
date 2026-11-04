# NullCA Supported Protocols & Dissectors

NullCA includes built-in, zero-dependency dissectors for modern web and application protocols.

---

## 1. HTTP/1.1 Dissector (`src/proto/http1.rs`)
- **Full Request & Response Parsing**: Method, URI, HTTP version, Status code, reason phrase.
- **Transfer Encodings**:
  - `Content-Length`: Accumulates exact payload bytes.
  - `Transfer-Encoding: chunked`: Decodes variable-size hex chunk headers, concatenates chunk data, and strips trailing CRLF sequences.
- **Stateful Pipelining**: Reassembles fragmented packets across multiple socket reads.

---

## 2. HTTP/2 & HPACK Engine (`src/proto/http2.rs`, `src/proto/huffman.rs`)
- **RFC 7540 Frame Dissection**:
  - `DATA` (0x0)
  - `HEADERS` (0x1) with priority flags and stream dependency
  - `SETTINGS` (0x4) with parameter table updates
  - `PING` (0x6) and `GOAWAY` (0x7)
  - `CONTINUATION` (0x9) for reassembling oversized header blocks across frames
- **RFC 7541 HPACK Decompression**:
  - Full 61-entry static header table.
  - Dynamic table state machine with FIFO evictions and maximum size tracking.
  - Incremental indexing (`01xxxxxx`), literal headers without indexing (`0000xxxx`), never-indexed headers (`0001xxxx`).
  - Canonical RFC 7541 Huffman code tree decoder with EOS padding validation.
- **Virtual Stream Multiplexing**: Reassembles concurrent multiplexed requests and responses on the same TCP socket.

---

## 3. HTTP/3 & QUIC Frame Engine (`src/proto/http3.rs`, `src/proto/qpack.rs`)
- **RFC 9114 HTTP/3 Frame Parsing**:
  - `DATA` (0x00): Plaintext application payload extraction.
  - `HEADERS` (0x01): QPACK-encoded request and response header fields.
  - `CANCEL_PUSH` (0x03), `SETTINGS` (0x04), `PUSH_PROMISE` (0x05), `GOAWAY` (0x07), `MAX_PUSH_ID` (0x0D).
- **RFC 9000 QUIC Variable-Length Integer Codec**:
  - Decodes 62-bit variable integers with 2-bit prefix masks (`00` for 1 byte, `01` for 2 bytes, `10` for 4 bytes, `11` for 8 bytes).
  - Handles frame length and stream identifier varints without memory allocations.
- **RFC 9204 QPACK Decompressor (`src/proto/qpack.rs`)**:
  - Full 99-entry static lookup table for common HTTP/3 headers (`:method`, `:path`, `:status`, `strict-transport-security`, etc.).
  - Indexed (`1xxxxxxx`), literal with static name reference, and literal with literal name decoders.
  - Canonical RFC 7541/9204 Huffman code tree decompression.

---

## 4. gRPC & Protocol Buffers Dissector (`src/proto/grpc.rs`, `src/proto/protobuf.rs`)
- **gRPC Framing**: Strips 5-byte gRPC frame headers (`Compressed-Flag` + 4-byte `Message-Length`).
- **Protobuf Wire Types**:
  - `0`: Varint (`int32`, `int64`, `uint32`, `bool`, `enum`)
  - `1`: 64-bit Fixed (`fixed64`, `sfixed64`, `double`)
  - `2`: Length-delimited (`string`, `bytes`, embedded messages, packed repeated fields)
  - `5`: 32-bit Fixed (`fixed32`, `sfixed32`, `float`)
- **Heuristic Schema Reconstruction**: Infers field numbers, data types, and nested sub-messages directly without pre-loaded `.proto` definitions.

---

## 4. WebSocket Dissector (`src/proto/websocket.rs`)
- **RFC 6455 Frame Parser**:
  - `FIN` bit and RSV flags.
  - Opcodes: Continuation (0x0), Text (0x1), Binary (0x2), Close (0x8), Ping (0x9), Pong (0xA).
  - Masking: De-masks 4-byte XOR client keys (`payload[i] ^ mask[i % 4]`).
  - Variable Payload Length: 7-bit, 16-bit (`0x7E`), and 64-bit (`0x7F`) extended lengths.
- **RFC 7692 Permessage-Deflate Decompression**:
  - Transparently identifies frames with `RSV1 = 1`.
  - Appends the standard RFC 7692 synchronization trailer (`0x00, 0x00, 0xFF, 0xFF`) and decompresses raw DEFLATE streams on the fly into plaintext inspectable messages and JSON.
- **Message Assembly**: Reassembles multi-frame fragmented messages into clean UTF-8 text, binary buffers, or structured JSON.

---

## 5. X.509 ASN.1 Certificate & PKI Dissector (`src/proto/x509.rs`)
- **Supported Formats**: PEM (`-----BEGIN CERTIFICATE-----`), DER binary, Multi-certificate bundles, System CA directories, CSR (PKCS#10), and CRL (X.509 Revocation Lists).
- **Public Key & Signature Algorithms**:
  - **RSA**: 1024 to 8192 bits, PKCS#1 v1.5, RSASSA-PSS (`sha256WithRSAEncryption`, `sha384WithRSAEncryption`, `sha512WithRSAEncryption`).
  - **NIST Curves**: P-256 (`secp256r1`), P-384 (`secp384r1`), P-521 (`secp521r1`).
  - **Blockchain & European Curves**: Koblitz `secp256k1`, Brainpool (`brainpoolP256r1`, `brainpoolP512r1`).
  - **Edwards Curves**: Ed25519 and Ed448 Goldilocks.
  - **National Standards**: Russian **ГОСТ Р 34.10-2001** and **ГОСТ Р 34.10-2012** (256/512 bit) with Streebog hashes, Chinese **SM2** with **SM3** hash.
  - **NIST Post-Quantum Cryptography (PQC)**: **ML-DSA (Dilithium-2, 3, 5)**, **Falcon-512/1024**, and **ML-KEM (Kyber)**.
- **ASN.1 String Encodings**: UTF8String, PrintableString, IA5String, **BMPString** (UTF-16BE), **UniversalString** (UTF-32BE), and **TeletexString** (T.61).
- **Cryptographic Fingerprints**: Exact FIPS 180-4 SHA-256 and SHA-1 implementations.
- **Remote TLS Fetcher**: Live network inspection (`nullca inspect-cert target:port`) retrieving peer certificate chains without trusting local root stores.

---

## 6. Database & Non-HTTP Dissectors (`src/proto/database.rs`)
- **PostgreSQL**: Startup messages, Query (`Q`), Parse (`P`), Bind (`B`), Execute (`E`), CommandComplete (`C`), ErrorResponse (`E`).
- **Redis (RESP3 & RESP2)**: Simple strings (`+`), Errors (`-`), Integers (`:`), Bulk strings (`$`), Arrays (`*`), Maps (`%`).
- **SMTP**: Command inspection (`HELO`, `EHLO`, `MAIL FROM`, `RCPT TO`, `DATA`, `QUIT`).

---

## 7. Stream Decompression Engine (`src/proto/compression.rs`)
- **Brotli (`br`)**: RFC 7932 Brotli decompression engine enabling transparent inspection of modern web API responses.
- **Gzip (`gzip`)**: RFC 1952 decompression with CRC32 and ISIZE validation.
- **Deflate (`deflate`)**: RFC 1950 (Zlib wrapper) and RFC 1951 (raw Deflate) fallback.
- **Auto-detection**: Content-Encoding header inspection and magic byte sniffing (`1F 8B` for Gzip, `78 9C` for Zlib).

---

## 8. TCP 4-Tuple Socket Resolution (`src/engine/discover.rs`)
- **Kernel Inode Resolution**: Traces socket file descriptors via `/proc/<pid>/fd/<fd>` symlinks (`socket:[inode]`).
- **Table Lookup**: Efficiently looks up matching endpoints in `/proc/<pid>/net/tcp` and `/proc/<pid>/net/tcp6`.
- **Direction-Aware Mapping**: Maps source and destination IPs and ports according to Egress (local -> remote) or Ingress (remote -> local) flow direction.
- **PCAP-NG Integration**: Emits Wireshark captures with exact real 4-tuple IP addresses instead of dummy loopback endpoints.

---

## 9. Memory-Bounded Stream Reassembler & LRU (`src/proto/reassembler.rs`)
- **Active Connection Table**: Bounds maximum concurrent stream reassembly to prevent memory exhaustion attacks.
- **Stale Pruning (`prune_stale`)**: Evicts inactive connection buffers exceeding configurable TTLs.
- **LRU Fallback**: Evicts oldest connection when reaching table capacity.
- **RFC 7230 §3.3.3 Delimitation Rules**:
  - `Content-Length` accumulation.
  - `Transfer-Encoding: chunked` termination detection (`0\r\n\r\n`).
  - `Connection: close` EOF-delimited responses: waits for socket connection close / `flush_connection()` without premature truncation.
  - HTTP 1xx, 204 (No Content), and 304 (Not Modified) zero-body immediate completion.
- **Zero-Residual Memory**: Automatically cleans up and frees connection map entries when fragmented messages are fully reassembled and drained.

---

## 10. DNS & DNS-over-HTTPS (DoH) Wire Dissector (`src/proto/dns.rs`)
- **RFC 1035 & RFC 8484 Wire Format**: Dissects native port 53 UDP/TCP DNS packets as well as HTTP/2 and HTTP/3 `application/dns-message` DoH queries and responses.
- **QNAME Decompression Jump Table**:
  - Decodes standard label sequences (e.g. `\x03www\x06google\x03com\x00`).
  - Resolves recursive compression pointers (`0xC000` bitmask) with depth loop protection.
- **Supported Resource Record (RR) Types**:
  - `A` (IPv4 address resolution)
  - `AAAA` (IPv6 128-bit address resolution)
  - `CNAME` (Canonical name alias pointer)
  - `TXT` (SPF, DKIM, verification strings)
  - `MX` (Mail exchange preference & hostname)
  - `NS`, `PTR`, `SRV`, `SOA`
- **DNS Flags & RCODE**: Query/Response (QR), Opcode, Authoritative Answer (AA), Truncation (TC), Recursion Desired (RD), Recursion Available (RA), Response Code (NoError, FormErr, ServFail, NXDomain).

---

## 11. Server-Sent Events (SSE) & AI Streaming Token Dissector (`src/proto/sse.rs`)
- **RFC 8895 Stream Parser**:
  - Parses streaming HTTP responses with `Content-Type: text/event-stream`.
  - Dissects field prefixes: `event:`, `data:`, `id:`, and `retry:`.
- **AI / LLM Streaming Token Reconstruction**:
  - Automatically identifies OpenAI ChatGPT, Anthropic Claude, and Ollama streaming chunks (`data: {"choices":[{"delta":{"content":"..."}}]}`).
  - Extracts and joins streaming text tokens on the fly into complete responses.
  - Displays real-time streaming output in the interactive cockpit dashboard.
