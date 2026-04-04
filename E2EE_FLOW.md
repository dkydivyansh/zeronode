# ZeroNode E2EE Architecture: Chunked Encryption Flow

Handling enormous files (10 GB+) securely and reliably over the web requires abandoning traditional single-pass encryption streams. ZeroNode strictly enforces **Chunked Encryption** (Method 2) for its frontend-to-backend pipeline.

---

## Why Chunked Encryption is Mandatory

### 1. Immediate Error Detection (Fast Failure)
AES-GCM relies on an "Authentication Tag" to guarantee data hasn't been tampered with. In a single 10 GB stream, this tag is evaluated exactly *once* at the very end of the file. If a single bit flips during transmission at the 500 MB point, you must download the entire 10 GB before the algorithm detects the corruption and drops the file. 
**The Solution:** In Chunked Encryption, every 1 MB block has its own authentication tag. If chunk #500 corrupts, decryption fails instantly at 500 MB without wasting 9.5 GB of bandwidth. The client can request a retry of just that specific 1 MB block.

### 2. Pausing, Resuming, and Retries
If an upload drops at 9.9 GB, resuming a single AES-GCM cipher stream is a cryptographic nightmare risking nonce-reuse vulnerabilities. 
**The Solution:** Chunked Encryption makes every 1 MB block a self-contained encrypted puzzle piece. If the connection fails, the frontend simply asks the server *"How many chunks do you have?"* and resumes seamlessly from chunk #9,901.

### 3. Parallel Processing (Speed)
Single-stream encryption is linear — you must encrypt the file byte-by-byte using a single CPU thread.
**The Solution:** Independent chunks allow the frontend Web Workers to utilize **all available CPU cores**. Thread A encrypts chunk 1, Thread B encrypts chunk 2, massively accelerating the local processing speed. These encrypted chunks can be pushed over the network via concurrent XHR requests.

### 4. Random Access (Video Streaming)
If a user is streaming an encrypted 10 GB movie and skips to the 1-hour mark, a single AES-GCM stream forces the browser to decrypt the first hour entirely before fetching the middle.
**The Solution:** The frontend mathematically calculates exactly which 1-MB chunks correspond to the 1-hour timestamp, requests *only* those specific byte ranges from the server using HTTP `Range` headers, decrypts them instantly, and resumes playback in milliseconds.

---

## Client-Server Contract

### 1. Cryptographic Standard
- **Algorithm:** AES-256-GCM
- **Chunk Size:** 1 MB (1,048,576 bytes) *Standardized to balance network packet limits and crypto overhead.*
- **Key Derivation (Frontend):** Root AES Keys are derived on the frontend using PBKDF2 or Argon2 from a vault master password. The server *never* sees this plaintext root key.
- **Nonce/IV Strategy:** Every chunk requires a unique Initialization Vector (IV). For sequential chunks, the chunk index (0, 1, 2...) can be deterministically appended to a master file-IV to ensure cryptographically secure uniqueness per chunk.

### 2. Data Structure of a Chunk
Every 1 MB of plaintext becomes an encrypted payload comprising:
`[12-byte IV] + [Encrypted Ciphertext] + [16-byte Auth Tag]`

### 3. Upload Flow (What the Server Expects) — ✅ IMPLEMENTED

The frontend breaks the file into 1 MB encrypted chunks and uploads them via a 3-phase REST API.

**Phase 1 — Init:**
```
POST /app/api/file/init
Content-Type: application/json

{ "file_name": "secret_movie.mp4", "aes_key": "<vault-encrypted AES key>" }

→ Response 201: { "uuid": "8f4b23a1-9c8d-4f1b-a3d4-72e91b2c4d5f" }
```
This creates the DB metadata record and touches an empty `<uuid>.bin` on disk.

**Phase 2 — Parallel Chunk Upload:**
```
POST /app/api/file/<uuid>/chunk
X-Chunk-Offset: 0                    ← byte position in the final file
Content-Type: application/octet-stream
Body: <raw encrypted chunk bytes>

→ Response 200: { "status": "ok", "offset": 0, "size": 1048576 }
```
The server uses `seek(offset)` to write each chunk at the exact byte position. Because each chunk is independent, the frontend **can fire all chunk requests in parallel** from Web Workers.

Example parallel upload for a 3 MB file:
```
Worker A → POST /chunk  X-Chunk-Offset: 0         (bytes 0–1MB)
Worker B → POST /chunk  X-Chunk-Offset: 1048576   (bytes 1MB–2MB)
Worker C → POST /chunk  X-Chunk-Offset: 2097152   (bytes 2MB–3MB)
```

**Phase 3 — Finalize:**
```
POST /app/api/file/<uuid>/finalize

→ Response 200: { "uuid": "...", "file_name": "...", "size": 3145728, "last_modified": "..." }
```
Validates the `.bin` file has content and commits the final timestamp.

### 4. Download Flow — ✅ IMPLEMENTED

```
GET /app/api/file/<uuid>

→ Response 200: Binary stream (application/octet-stream)
   Content-Disposition: attachment; filename="secret_movie.mp4"
```

1. **Metadata Fetch:** Client first requests `GET /app/api/file/<uuid>/meta` to retrieve the encrypted `aes_key` and `file_name`.
2. **Byte Ranging:** Client fires the GET request. Flask's `send_file()` uses WSGI `FileWrapper` / OS-level `sendfile()` syscall to stream the binary directly from disk to the network socket — **zero RAM footprint** even for 100 GB files.
3. **Partial Content / Resume:** Standard HTTP `Range` headers are supported. If the connection drops at 5 GB, the client resumes with `Range: bytes=5368709120-`.
4. **Decryption Loop:** The frontend receives chunks, splits them back into 1 MB blocks, verifies each authentication tag via `crypto.subtle.decrypt()`, and pipes deciphered output to the user.
