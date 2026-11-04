# Passive Security Auditor & OpenAPI Synthesis

This document details NullCA's automated security posture auditing engine and its OpenAPI 3.0 specification generator.

---

## 1. Passive Security & Hygiene Auditor (`src/engine/audit.rs`)

NullCA includes a streaming security posture analyzer designed to inspect captured HTTP exchanges for defense-in-depth gaps, insecure configurations, and credential leakage without transmitting active scanner probes.

### Evaluated Security Controls:

| Category | Finding | Severity | Description |
|---|---|:---:|---|
| **HSTS** | Missing `Strict-Transport-Security` | **Medium** | Connection does not enforce HTTPS, leaving users vulnerable to SSL stripping. |
| **HSTS** | `max-age=0` (Disabled) | **High** | HSTS is explicitly turned off. |
| **CORS** | `Access-Control-Allow-Origin: *` with Credentials | **Critical** | Browser allows any origin to read authenticated responses. |
| **CORS** | Wildcard Origin on sensitive API | **Low** | Any origin can query this endpoint. |
| **MIME Sniffing** | Missing `X-Content-Type-Options: nosniff` | **Low** | Browser may execute uploaded text files as script/HTML. |
| **CSP** | Missing `Content-Security-Policy` on HTML | **Medium** | Absence of XSS mitigation controls. |
| **CSP** | Weak CSP (`unsafe-inline` / `unsafe-eval`) | **Low** | CSP script protections can be bypassed. |
| **Clickjacking** | Missing `X-Frame-Options` or `frame-ancestors` | **Medium** | Site can be framed inside external iframes. |
| **Cookies** | Cookie missing `Secure` attribute | **High / Medium** | Cookie will be transmitted over plaintext HTTP. |
| **Cookies** | Session cookie missing `HttpOnly` | **High** | Cookie readable by malicious JavaScript (`document.cookie`). |
| **Cookies** | Cookie missing `SameSite` attribute | **Low** | Increased susceptibility to Cross-Site Request Forgery (CSRF). |
| **Server Disclosure** | Detailed server banner disclosure | **Info** | Exposes exact software version (e.g. `Apache/2.4.49 (Unix)`). |
| **Stack Disclosure** | `X-Powered-By` header | **Low** | Discloses backend framework (e.g. `Express`, `PHP/8.1`). |
| **Secret Leak** | Leaked AWS / Stripe / GitHub token in payload | **Critical / High** | High-entropy credential detected in payload bodies. |

### Running the Auditor
```bash
nullca audit --har traffic.har
```

Output:
```
══════════════════════════════════════════════════════════════════════════
            ⚡ NullCA Passive Security & Hygiene Audit Report             
══════════════════════════════════════════════════════════════════════════
Total Exchanges Audited: 14 | 1 Critical | 2 High | 3 Medium | 2 Low | 1 Info
──────────────────────────────────────────────────────────────────────────
1. [CRITICAL] Critical CORS Misconfiguration (Wildcard with Credentials) - POST https://api.example.com/oauth/token
   Access-Control-Allow-Origin is '*' while Access-Control-Allow-Credentials is true.
   Remediation: Never allow credentials with a wildcard origin. Validate allowed origins against an explicit allow-list.

2. [HIGH] Session Cookie Missing 'HttpOnly' Attribute - POST https://api.example.com/oauth/token
   Session identifier cookie can be read by JavaScript via document.cookie, increasing XSS impact.
   Remediation: Append '; HttpOnly' to all authentication and session cookies.
```

---

## 2. Automated OpenAPI 3.0.3 Specification Generator (`src/export/openapi.rs`)

Reverse-engineering undocumented microservice APIs or updating outdated documentation is automated in NullCA via real-time traffic analysis.

### Path Parameter Clustering
NullCA uses regex pattern matchers to detect dynamic path parameters:
- **Numeric IDs**: `/api/v1/users/1024` -> `/api/v1/users/{user_id}`
- **UUIDs**: `/items/550e8400-e29b-41d4-a716-446655440000` -> `/items/{item_id}`
- **Hex Hashes**: `/commits/a1b2c3d4e5f6...` -> `/commits/{hash_1}`

### Recursive JSON Schema Inference
JSON bodies in requests and responses are analyzed to recursively synthesize full OpenAPI 3.0 schemas:
- Primitives (`string`, `integer`, `number`, `boolean`, `nullable`).
- Arrays with inferred item schemas (`array` of objects or primitives).
- Objects with nested properties and required field lists.
- Automatic string format hints (`uuid`, `date-time`).

### Generating Specifications:
```bash
nullca export-openapi --har traffic.har --output swagger.json --title "Order Service"
```

The resulting `swagger.json` can be loaded directly into Swagger UI, Redoc, Postman, or Burp Suite.

---

## 3. Deep JWT Cryptographic Security Scanner (`src/engine/jwt_audit.rs`)

NullCA incorporates an in-depth cryptographic JWT auditor and offline secret cracking engine:

### Vulnerability Checks:
1. **Algorithm 'none' Signature Bypass (CVE-2015-9235)**:
   - Detects tokens specifying `alg: "none"`, allowing attackers to forge arbitrary claims without holding signing keys.
2. **Offline HMAC-SHA256 Dictionary Cracker**:
   - Zero-dependency RFC 2104 HMAC-SHA256 implementation utilizing NullCA's cryptographic SHA-256 engine.
   - Automatically cracks weak shared secrets against common dictionary lists (e.g. `secret`, `password`, `admin`, `123456`, `jwt`).
3. **Token Expiration (`exp`) Absence & Temporal Validity**:
   - Flags tokens lacking the mandatory `exp` claim (valid indefinitely).
   - Flags expired tokens accepted or emitted by backend APIs.

### TUI Cockpit & Auditor Integration:
- Scanned tokens from `Authorization: Bearer <jwt>`, cookie headers, and JSON request/response bodies are audited automatically.
- Tab 3 (`Secrets & Flags`) in the interactive cockpit highlights cracked keys and signature bypasses in bright warning banners.

---

## 4. Postman Collection v2.1.0 Exporter (`src/export/postman.rs`)

Converts captured network sessions into native Postman Collections:
- Generates valid Postman schema (`https://schema.getpostman.com/json/collection/v2.1.0/collection.json`).
- Decomposes URLs into structured `protocol`, `host` slices, `path` slices, and `query` key-value pairs.
- Preserves raw request bodies with automatic JSON language detection.
- Generates collections from HAR files via CLI (`nullca export-postman --har capture.har --output collection.json`) or directly from decoded traffic.

---

## 5. PCAP-NG Decryption Secrets Block (DSB) (`src/export/pcapng.rs`)

- Implements PCAP-NG Block Type `0x0000000A` (Decryption Secrets Block) with Secrets Type `0x544c534b` (`TLSK`).
- Embeds TLS master secrets and keylog lines directly into exported `.pcapng` files.
- **Wireshark Zero-Configuration Decryption**: Allows analysts to open `.pcapng` files in Wireshark without manually setting `(Pre)-Master-Secret log filename` in preferences.
