# ZeroNode

> **Zero-knowledge, end-to-end encrypted personal vault.**  
> Built for people who take data privacy seriously-powered by Flask, SQLite, and the browser's native WebCrypto API.

---

## What is ZeroNode?

**ZeroNode** is a privacy-first vault application engineered on a simple principle: **the server should never know your business.** 

Most cloud storage providers can see your files, index your contents, or reset your password whenever they want. ZeroNode does things differently. Your browser handles 100% of the cryptographic heavy lifting. Before any file or metadata ever leaves your machine, it gets scrambled with AES-256-GCM. 

To the server, everything you upload is just an opaque blob of random binary chunks (`.bin`) paired with encrypted keys it can’t open. Even if someone physically walks off with the host server or inspects the master database, your data remains mathematically impossible to read without your master credentials.

---

## Highlights

- 🛡️ **True Zero-Knowledge Architecture**  
  Plaintext passwords, private keys, and unencrypted files never touch the network or the server disk.
- ⚡ **5 MB Chunked Streaming Engine**  
  Got massive 10 GB+ files? No problem. ZeroNode slices files into 5 MB encrypted chunks, uploads them in parallel Web Worker pools, and uses the browser's native **Origin Private File System (OPFS)** to decrypt and assemble large streams without exhausting your RAM.
- 🔑 **Dual-Wrap Key Hierarchy**  
  Your P-256 elliptic curve private key is encrypted twice: once with your master password (via PBKDF2-SHA256 with 250,000 iterations) and once with a randomized **12-word BIP-39 recovery phrase**. If you ever forget your password, you can restore your vault using your seed phrase.
- 📁 **Encrypted Drive & File Explorer**  
  Full folder tree management, nested directories, move operations with recursion protection, instant filename search, and cascade deletion.
- 📝 **In-Vault Markdown Notes & Document Viewer**  
  Create and edit encrypted Markdown notes with live previewing, and view encrypted PDFs and media files directly in your browser without ever decrypting them to unencrypted temporary files on disk.
- 🌐 **100% Air-Gapped & Zero CDNs**  
  Fonts (Inter, Space Grotesk, Noto Serif), Tailwind CSS runtime, and vendor libraries are completely self-hosted inside the repository. Zero external telemetry, zero tracking scripts, zero CDN dependencies.
- 🛂 **SSO & Whitelist Access Control**  
  OAuth 2.0 authentication combined with strict database-backed email whitelisting, session lifetime enforcement, administrative rank controls, and nuclear liquidation protocols.

---

## Quick Start

### Option A: Running with Docker (Recommended)

The easiest way to get ZeroNode up and running is via Docker Compose:

1. **Clone the repository:**
   ```bash
   git clone https://github.com/your-username/zeronode.git
   cd zeronode
   ```

2. **Set up your environment:**
   ```bash
   cp .env.example .env
   ```
   Open `.env` and fill in your SSO credentials and root admin email:
   ```env
   SECRET_KEY=generate-a-strong-random-secret
   SSO_CLIENT_ID=your-sso-client-id
   SSO_CLIENT_SECRET=your-sso-client-secret
   SSO_REDIRECT_URI=http://localhost:8862/auth/callback
   ADMIN_EMAIL=your-email@example.com
   ```

3. **Fire it up:**
   ```bash
   docker-compose up -d --build
   ```
   Head over to `http://localhost:8862` in your browser. You're ready to roll!

---

### Option B: Local Python Setup

If you prefer running directly on your host machine:

1. **Prerequisites:**
   - Python 3.11 or higher
   - Virtual environment manager (`venv`)

2. **Create and activate a virtual environment:**
   ```bash
   # On macOS/Linux:
   python3 -m venv venv
   source venv/bin/activate

   # On Windows:
   python -m venv venv
   .\venv\Scripts\activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure environment:**
   ```bash
   cp .env.example .env
   # Edit .env with your favorite text editor
   ```

5. **Start the server:**
   ```bash
   python run.py
   ```
   The development server will boot on `http://127.0.0.1:8862`.

---

## Dashboard Modules

| Module | Route | What it does |
|---|---|---|
| **Home** | `/app/home` | Your command center. Displays authenticated identity details, live vault storage quota meters, session countdown, and quick links. |
| **Drive** | `/app/drive` | Full-fledged encrypted file explorer. Supports drag-and-drop chunked uploads, folder creation, search, markdown editing, and media/PDF previews. |
| **Admin** | `/app/admin` | Privileged operations console (restricted to users in the `admins` ledger). View host disk health, inspect user storage footprints, manage whitelisted emails, promote admins, or trigger node wipes. |

---

## Security & Defense-in-Depth

ZeroNode doesn't just encrypt your files—it hardens the entire web environment around them:

- **Strict Content Security Policy (CSP):** Blocks inline script tampering and external unauthorized endpoints.
- **Cross-Origin Opener Policy (COOP) & Cross-Origin Resource Policy (CORP):** Set to `same-origin` to isolate windows and prevent cross-origin memory snooping.
- **Non-Extractable Keys:** Client session keys are loaded into WebCrypto as non-extractable keys (`extractable = false`), protecting them against rogue DOM scripts.
- **Anti-DoS Stale Cleanups:** Incomplete uploads (`file_size = -1`) older than 5 minutes are automatically purged from disk to prevent storage exhaustion attacks.
- **Nuclear Liquidation Protocols:**
  - **Self-Wipe:** Users can authoritatively purge their personal identity, encrypted blobs, and database records at any time.
  - **Server Liquidation:** Admins can trigger a nuclear wipe protocol with Windows/Linux file-lock override routines that permanently removes `.env`, database volumes, and shuts down the process.

For technical deep-dives into the architecture and cryptographic specifications, refer to [PROJECT.md](PROJECT.md) and [E2EE_FLOW.md](E2EE_FLOW.md).

---

## Contributing

Got ideas to make ZeroNode even more airtight, faster, or easier to run? Pull requests are welcome!

1. Fork the repo.
2. Create your feature branch (`git checkout -b feature/cool-feature`).
3. Commit your changes (`git commit -m 'Add some cool feature'`).
4. Push to the branch (`git push origin feature/cool-feature`).
5. Open a Pull Request.

---

## License

Built with ❤️ for privacy and security. Distributed under the MIT License. See `LICENSE` for more information.

---

## Keywords

`zero-knowledge` · `end-to-end-encryption` · `e2ee` · `privacy` · `encrypted-storage` · `vault` · `webcrypto-api` · `aes-256-gcm` · `ecdh-p256` · `pbkdf2` · `bip39` · `opfs` · `origin-private-file-system` · `self-hosted` · `air-gapped` · `secure-cloud` · `flask` · `sqlite-wal` · `zero-trust`
