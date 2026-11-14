# ZeroNode E2EE Architecture: Chunked Encryption & Key Wrapping Specification

## 1. Architectural Overview & Cryptographic Guarantee

ZeroNode operates on a **cryptographically blind server model**. All cryptographic primitives are executed exclusively in the client's browser using the native **WebCrypto API** (`crypto.subtle`). 

- The server stores only raw AES-GCM ciphertext payloads (`.bin` files) and wrapped Data Encryption Keys (DEKs).
- The server never possesses, receives, or computes plaintext user passwords, private keys, or unencrypted file bytes.
- ZeroNode strictly enforces **5 MB Chunked Encryption** for all file storage operations to achieve high performance, stream resume resilience, immediate integrity detection, and parallel processing.

```
+---------------------------------------------------------------------------------------+
|                                  BROWSER CLIENT                                       |
|                                                                                       |
|  Master Password --------> [ PBKDF2-SHA256 ] -----------------> Master Vault Key     |
|  Recovery Phrase --------> [ PBKDF2-SHA256 ] -----------------> Recovery Master Key   |
|                                                                                       |
|  [ P-256 ECDH Keypair ]                                                               |
|        |                                                                              |
|        +-- Private Key --+--> [ AES-256-GCM Wrap with Master Vault Key ]   --> Server |
|        |                 +--> [ AES-256-GCM Wrap with Recovery Master Key ] -> Server |
|        +-- Public Key (SPKI) ------------------------------------------------> Server |
|        |                                                                              |
|        +-- (Self-ECDH Derivation: PrivKey x PubKey) ----------> VaultMasterKey (AES)  |
|                                                                       |               |
|  Plaintext File ---> Split 5 MB Chunks ---> [ AES-256-GCM ] <---------+               |
|                              |              (FileKey DEK)                             |
|                              v                                                        |
|                     Ciphertext Chunks                                                 |
|                              |                                                        |
+------------------------------|--------------------------------------------------------+
                               |  Parallel XHR (X-Chunk-Offset)
                               v
+---------------------------------------------------------------------------------------+
|                                    ZERONODE SERVER                                    |
|                                                                                       |
|  POST /app/api/file/<uuid>/chunk  ---> OS seek(offset) ---> data/<user_id>/<uuid>.bin |
|  POST /app/api/file/init          ---> Store wrapped DEK -> data/<user_id>/<user>.db  |
+---------------------------------------------------------------------------------------+
```

---

## 2. Core Cryptographic Standards

| Layer | Primitive | Parameters | Storage / Location |
|-------|-----------|------------|--------------------|
| **Master Key Derivation** | PBKDF2-SHA256 | 250,000 iterations, 16-byte cryptographically secure random salt | Ephemeral in browser memory during unlock |
| **Recovery Key Derivation** | PBKDF2-SHA256 | 250,000 iterations, 16-byte cryptographically secure random recovery salt | Derived on-demand from 12-word BIP-39 mnemonic |
| **Identity / Vault Keypair** | ECDH P-256 | NIST P-256 (`secp256r1`) curve | Private key stored wrapped on server; sessionized in IndexedDB |
| **Key Wrapping** | AES-256-GCM | 256-bit key, 12-byte random IV, 16-byte authentication tag | Uploaded to `/app/api/key/save` |
| **Vault Master Key** | Self-ECDH | `crypto.subtle.deriveKey({ name: "ECDH", public }, priv, { name: "AES-GCM", length: 256 })` | Ephemeral; derives symmetric master key to unwrap file DEKs |
| **File Encryption Key (DEK)** | AES-256-GCM | 256-bit randomly generated per file | Stored wrapped as `aes_key` in `<user_id>.db` `files` table |
| **Chunk Encryption** | AES-256-GCM | 5 MB chunks (5,242,880 bytes), deterministic 12-byte IV per chunk | Streamed to disk as raw `.bin` payloads |

---

## 3. Key Wrapping & Vault Recovery Hierarchy

### 3.1 Vault Setup (Phase 1)
1. **ECDH Keypair Generation**: The browser generates an extractable `P-256 ECDH Keypair`.
2. **Password Master Key**: The user selects an 8+ character master password. The browser creates a 16-byte random salt and derives `Master_Vault_Key` using `PBKDF2-SHA256` (250,000 rounds).
3. **Password Key Wrap**: The ECDH private key is exported to `pkcs8`, encrypted with `Master_Vault_Key` using AES-256-GCM with a random 12-byte IV.
   $$\text{packed} = [\text{IV}_{12}] \parallel [\text{Ciphertext}] \parallel [\text{AuthTag}_{16}]$$
   The packed bytes are Base64-encoded as `encrypted_private_key`.
4. **Seed Phrase Recovery Wrap**: The browser generates a 12-word BIP-39 recovery mnemonic using `crypto.getRandomValues(new Uint16Array(12))` against a 2048-word dictionary (`wordlist.js`). A separate 16-byte `recovery_salt` is generated, and a `Recovery_Master_Key` is derived via PBKDF2. The private key is wrapped and Base64-encoded as `recovery_encrypted_private_key`.
5. **Server Persistence**: The client uploads the public key (`spki`), both wrapped private keys, and both salts to `/app/api/key/save`:
   ```json
   {
     "public_key": "<SPKI_Base64>",
     "encrypted_private_key": "<Wrapped_PrivKey_Base64>",
     "salt": "<Salt_Base64>",
     "recovery_encrypted_private_key": "<Recovery_Wrapped_PrivKey_Base64>",
     "recovery_salt": "<Recovery_Salt_Base64>"
   }
   ```
6. **Session Storage & IndexedDB Isolation**:
   - The decrypted private key is imported into WebCrypto with `extractable = false` to prevent memory/DOM scraping.
   - It is sessionized into an isolated IndexedDB database (`ZNodeSession`, store: `keys`, key: `vault_priv`).
   - The public key is mirrored in `sessionStorage.setItem("vault_pub", ...)`.
   - `sessionStorage.setItem("vault_unlocked", "true")`.

### 3.2 Session Unlock (Phase 2)
When the user accesses the dashboard:
1. The client queries `GET /app/api/key/status`.
2. If unlocked (`vault_unlocked == "true"` in `sessionStorage` and `vault_priv` exists in `ZNodeSession`), the unlock modal is dismissed.
3. If locked, the modal requests the password, fetches wrapped keys via `GET /app/api/key/load`, derives `Master_Vault_Key` with the stored salt, unwraps the ECDH private key, and sessionizes it into IndexedDB.

### 3.3 Recovery & Credential Reset (Phase 3)
If the user forgets their password:
1. The client fetches the recovery bundle via `GET /app/api/key/recovery`.
2. The user enters their 12-word recovery phrase.
3. The browser derives `Recovery_Master_Key`, unwraps the private key, and prompts for a new master password.
4. The browser re-wraps the private key with the new password and generates a fresh 12-word recovery phrase.
5. The new bundles are committed via `POST /app/api/key/reset`.

---

## 4. Chunked File Encryption Lifecycle

Handling multi-gigabyte files (up to 10 GB quota per user) in the browser requires strict chunking to avoid memory exhaustion and enable parallel uploads.

### 4.1 Chunk Specifications
- **Chunk Size:** Standardized to **5 MB (5,242,880 bytes)** (`OPFS_CHUNK_SIZE`).
- **Deterministic IV Derivation:**
  Every chunk derives a deterministic 12-byte IV using the chunk's 32-bit zero-based sequence index `idx`:
  ```javascript
  const iv = new Uint8Array(12);
  new DataView(iv.buffer).setUint32(8, chunkIdx, false); // Big-Endian index in bytes 8..11
  ```
  > [!IMPORTANT]
  > Because every file is assigned a completely random, unique 256-bit DEK (`fileKey`), using a counter-derived IV per chunk is cryptographically sound and guarantees zero nonce reuse across identical files or distinct chunks.

- **Chunk Payload Structure:**
  The output of WebCrypto `crypto.subtle.encrypt({ name: "AES-GCM", iv }, fileKey, plaintextChunk)` is:
  $$\text{Payload} = [\text{AES-GCM Ciphertext}] \parallel [\text{16-byte Authentication Tag}]$$
  For a full 5 MB chunk, the encrypted size sent over the wire is `5,242,880 + 16 = 5,242,896` bytes (`CHUNK_WITH_TAG`).
  The 12-byte IV is **not** prepended to the chunk on disk or over the wire, saving bandwidth and keeping block indexing strictly linear.

---

## 5. Three-Phase Upload Protocol

```
Browser Client                                                    ZeroNode Server
      |                                                                 |
      | 1. POST /app/api/file/init { file_name, aes_key, folder_id }    |
      |---------------------------------------------------------------->|
      |                                                                 | Create DB row (size = -1)
      |                                                                 | Touch 0-byte <uuid>.bin
      | <-- 201 Created { "uuid": "8f4b23a1-..." } ---------------------|
      |                                                                 |
      | 2. Parallel Pool (up to 4 concurrent XHRs):                     |
      |    POST /app/api/file/<uuid>/chunk                              |
      |    Header: X-Chunk-Offset: 0                                    |
      |    Body: <Binary Encrypted Chunk 0 (5MB + 16B)>                 |
      |---------------------------------------------------------------->| seek(0) & write
      |                                                                 |
      |    POST /app/api/file/<uuid>/chunk                              |
      |    Header: X-Chunk-Offset: 5242896                              |
      |    Body: <Binary Encrypted Chunk 1 (5MB + 16B)>                 |
      |---------------------------------------------------------------->| seek(5242896) & write
      |                                                                 |
      | <-- 200 OK { "status": "ok", "offset": 0, "size": 5242896 } ----|
      |                                                                 |
      | 3. POST /app/api/file/<uuid>/finalize                           |
      |---------------------------------------------------------------->| Validate size on disk
      |                                                                 | Commit size & timestamp
      | <-- 200 OK { "uuid": "...", "size": 10485792, "file_name": .. } | Invalidate stats cache
```

### Phase 1: Upload Initialization
- **Endpoint:** `POST /app/api/file/init`
- **Request Body:**
  ```json
  {
    "file_name": "quarterly_report.pdf",
    "aes_key": "<Base64_Wrapped_DEK>",
    "folder_id": "optional-folder-uuid"
  }
  ```
- **Backend Operation:**
  1. Triggers `_cleanup_stale_uploads()`: Any upload stuck with `file_size = -1` older than 5 minutes is cleaned up.
  2. Generates a new file UUID (`file_uuid`).
  3. Touches an empty `<file_uuid>.bin` on disk.
  4. Inserts a row in the user's `files` table with `file_size = -1` (staged/incomplete).
- **Response:** `201 Created` with `{ "uuid": "<file_uuid>" }`.

### Phase 2: Parallel Chunk Streaming
- **Endpoint:** `POST /app/api/file/<uuid>/chunk`
- **Headers:**
  - `X-Chunk-Offset: <integer_byte_offset>` (e.g., `0`, `5242896`, `10485792`)
  - `Content-Type: application/octet-stream`
- **Body:** Raw binary bytes of the encrypted chunk.
- **Client Concurrency:** Client maintains a worker pool (`MAX_CONCURRENT = 4`) uploading chunks in parallel.
- **Backend Operation:**
  1. Verifies ownership of `<uuid>` against the authenticated session user.
  2. Opens `<uuid>.bin` in `r+b` mode.
  3. Executes `f.seek(offset)` and writes the raw chunk bytes directly to disk.
- **Response:** `200 OK` with `{ "status": "ok", "offset": <int>, "size": <bytes> }`.

### Phase 3: Finalization
- **Endpoint:** `POST /app/api/file/<uuid>/finalize`
- **Backend Operation:**
  1. Inspects the physical file size on disk via `os.path.getsize(file_path)`.
  2. Rejects files with 0 bytes (unless the file is an empty Markdown note `.md`).
  3. Updates `files` table: sets `file_size = actual_size` and updates `last_modified`.
  4. Invalidates the user's storage metrics cache (`invalidate_stats_cache()`).
- **Response:** `200 OK` with final file metadata:
  ```json
  {
    "uuid": "8f4b23a1-9c8d-4f1b-a3d4-72e91b2c4d5f",
    "file_name": "quarterly_report.pdf",
    "size": 10485792,
    "last_modified": "2026-11-14T09:20:00.000000+00:00"
  }
  ```

---

## 6. Download & Decryption Engines

ZeroNode dynamically routes file downloads through two distinct client-side decryption engines based on file size and document type.

```
Incoming Download Request
           |
           v
   Is file > 100 MB or binary download?
          /                          \
       YES                            NO
        |                              |
        v                              v
[ Engine B: OPFS Parallel ]    [ Engine A: RAM / IndexedDB ]
- Uses HTTP Range headers      - Fetches full binary stream
- 4 concurrent workers         - Slices CHUNK_WITH_TAG blocks
- Direct write to OPFS file    - Decrypts in RAM
- Zero browser RAM bloat       - Caches in ZeroNodeVaultCache
- Saves directly to disk       - Instant preview in lightbox
```

### 6.1 Metadata Pre-flight
Prior to fetching binary content, the client always queries:
```
GET /app/api/file/<uuid>/meta
```
The response supplies:
```json
{
  "uuid": "...",
  "file_name": "movie.mp4",
  "aes_key": "<Base64_Wrapped_DEK>",
  "file_size": 524289600,
  "folder_id": null,
  "last_modified": "..."
}
```
The client calls `DriveCrypto.unwrapFileKey(metadata.aes_key, masterKey)` using the session `VaultMasterKey` to obtain the CryptoKey DEK in browser memory.

### 6.2 Engine A: RAM & IndexedDB Cache Engine (Files $\le$ 100 MB)
1. **Network Fetch:** Client executes `GET /app/api/file/<uuid>`. The server streams binary chunks with `as_attachment=False` and strict security headers (`X-Content-Type-Options: nosniff`, `Cross-Origin-Resource-Policy: same-origin`).
2. **Chunk Slicing:** The browser slices the downloaded buffer into blocks of `CHUNK_WITH_TAG` (5,242,896 bytes).
3. **Decryption Loop:** For each block `i`:
   ```javascript
   const iv = new Uint8Array(12);
   new DataView(iv.buffer).setUint32(8, i, false);
   const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, fileKey, chunk);
   ```
4. **Caching:** The encrypted blob is stored in IndexedDB (`ZeroNodeVaultCache`, store: `encrypted_blobs`) to enable offline viewing and instant subsequent loads. If decrypted size $\le$ 10 MB, the decrypted `Blob` is kept in `decryptedSessionCache` (RAM map).

### 6.3 Engine B: OPFS Parallel Streaming Engine (Files $>$ 100 MB)
To prevent browser tab crashes from RAM allocation limits during multi-gigabyte downloads:
1. **OPFS File Allocation:** Creates an isolated temporary handle in the browser's Origin Private File System via `navigator.storage.getDirectory()`.
2. **Chunk Index Calculation:**
   $$\text{numChunks} = \left\lceil \frac{\text{fileSize}}{\text{CHUNK\_WITH\_TAG}} \right\rceil$$
3. **Worker Pool Execution (`OPFS_WORKER_LIMIT = 4`):**
   - Workers pop chunk indices from a shared queue.
   - Each worker computes byte offsets:
     $$\text{start} = \text{chunkIdx} \times \text{CHUNK\_WITH\_TAG}$$
     $$\text{end} = \min\left((\text{chunkIdx} + 1) \times \text{CHUNK\_WITH\_TAG} - 1, \; \text{fileSize} - 1\right)$$
   - Dispatches HTTP Range request:
     ```
     GET /app/api/file/<uuid>
     Range: bytes=${start}-${end}
     ```
   - Server streams only that byte slice using native OS `sendfile` syscalls.
   - Worker reconstructs `iv` from `chunkIdx` and decrypts the slice.
4. **Asynchronous Write Lock:**
   A mutual exclusion lock serializes writes to the OPFS `FileSystemWritableFileStream` to prevent Chromium `InvalidStateError`:
   ```javascript
   await writable.write({
     type: "write",
     position: chunkIdx * OPFS_CHUNK_SIZE,
     data: decryptedData
   });
   ```
5. **Disk Export:** Once all chunks finish, the file is exported directly from OPFS to the user's downloads folder.

---

## 7. Cryptographic Attack Surface & Mitigation Matrix

| Threat Vector | Attack Scenario | ZeroNode Defense Mechanism |
|---------------|-----------------|----------------------------|
| **Server Compromise / Malicious Host** | Attacker obtains full access to filesystem and master SQLite database. | Server holds only opaque `.bin` chunks and wrapped DEKs. Without the client's master password, data recovery is computationally infeasible ($2^{256}$ AES security margin). |
| **Nonce / IV Reuse** | Attacker replays chunk uploads or predicts initialization vectors to forge plaintext. | Every file receives an independent 256-bit random DEK. Within each file, chunk IVs increment strictly by chunk index; IV collisions between files are impossible due to disjoint keys. |
| **Ciphertext Tampering / Bit-flipping** | Attacker flips bits in transit or in the `.bin` storage. | AES-GCM evaluates a 16-byte polynomial authentication tag per 5 MB block. Any single-bit corruption immediately throws an `OperationError` during WebCrypto decryption, halting execution. |
| **Memory Extraction (XSS / Extension)** | Malicious browser extension attempts to read private keys from DOM or JavaScript variables. | The ECDH private key is imported with `extractable = false` and held in IndexedDB. DEKs are ephemeral and scoped only to active transfer tasks. |
| **Stale Upload Abandonment (Disk DoS)** | Client initiates millions of uploads without completing them to exhaust host storage. | `_cleanup_stale_uploads()` scans and deletes incomplete files (`file_size = -1`) older than 5 minutes on every upload initiation and listing call. |
| **Unauthorized Cross-Origin Read** | Malicious third-party origin attempts to fetch `.bin` payloads via embedded tags. | Server enforces `Cross-Origin-Resource-Policy: same-origin`, `Cross-Origin-Opener-Policy: same-origin`, and `X-Content-Type-Options: nosniff` on all streaming routes. |
