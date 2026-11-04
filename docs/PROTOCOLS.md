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

## 3. gRPC & Protocol Buffers Dissector (`src/proto/grpc.rs`, `src/proto/protobuf.rs`)
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
