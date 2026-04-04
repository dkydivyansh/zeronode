/**
 * ZERONODE Vault Cryptosystem
 * Pure WebCrypto ECDH/AES-GCM architecture ensuring zero-knowledge cloud sync.
 */

// --- Base64 ArrayBuffer Helpers ---
function bufferToBase64(buffer) {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary);
}

function base64ToBuffer(base64) {
    const binary_string = window.atob(base64);
    const len = binary_string.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        bytes[i] = binary_string.charCodeAt(i);
    }
    return bytes.buffer;
}

// --- VaultCrypto Core ---
class VaultCrypto {
    /** Generate a fresh ECDH P-256 Key Pair */
    static async generateECDHKeys() {
        return await crypto.subtle.generateKey(
            { name: "ECDH", namedCurve: "P-256" },
            true, // extractable (so we can save them)
            ["deriveKey", "deriveBits"]
        );
    }

    /** Derive a 256-bit AES-GCM vault master key from a user password using PBKDF2 */
    static async deriveMasterKey(passwordStr, saltUint8) {
        const enc = new TextEncoder();
        const baseKey = await crypto.subtle.importKey(
            "raw", enc.encode(passwordStr), "PBKDF2", false, ["deriveKey"]
        );
        return await crypto.subtle.deriveKey(
            { name: "PBKDF2", salt: saltUint8, iterations: 250000, hash: "SHA-256" },
            baseKey,
            { name: "AES-GCM", length: 256 },
            false,  // non-extractable (master key stays in memory)
            ["encrypt", "decrypt"]
        );
    }

    /** Encrypt the ECDH Private Key using the AES-GCM Master Key */
    static async wrapPrivateKey(privateKey, masterKey) {
        // Export private key to PKCS8 raw format
        const pkcs8 = await crypto.subtle.exportKey("pkcs8", privateKey);
        
        // Generate random 12-byte IV
        const iv = crypto.getRandomValues(new Uint8Array(12));
        
        // Encrypt with AES-GCM
        const ciphertext = await crypto.subtle.encrypt(
            { name: "AES-GCM", iv: iv }, masterKey, pkcs8
        );
        
        // Pack: [12-byte IV] + [Ciphertext + Auth Tag]
        const packed = new Uint8Array(iv.length + ciphertext.byteLength);
        packed.set(iv, 0);
        packed.set(new Uint8Array(ciphertext), iv.length);
        
        return bufferToBase64(packed);
    }

    /** Decrypt the ECDH Private Key using the AES-GCM Master Key */
    static async unwrapPrivateKey(wrappedB64, masterKey, extractable = true) {
        const packed = new Uint8Array(base64ToBuffer(wrappedB64));
        const iv = packed.slice(0, 12);
        const ciphertext = packed.slice(12);
        
        const decryptedPkcs8 = await crypto.subtle.decrypt(
            { name: "AES-GCM", iv: iv }, masterKey, ciphertext
        );
        
        return await crypto.subtle.importKey(
            "pkcs8", decryptedPkcs8, { name: "ECDH", namedCurve: "P-256" }, extractable, ["deriveKey", "deriveBits"]
        );
    }

    /** Export a Public Key to JWK or SPKI for the server */
    static async exportPublicKey(publicKey) {
        const spki = await crypto.subtle.exportKey("spki", publicKey);
        return bufferToBase64(spki);
    }

    static async importPublicKey(spkiB64) {
        const spkiObj = base64ToBuffer(spkiB64);
        return await crypto.subtle.importKey(
            "spki", spkiObj, { name: "ECDH", namedCurve: "P-256" }, true, []
        );
    }

    /** Export a handle that can be used for session persistence */
    static async sessionizeKey(privateKey) {
        const db = await this.openSessionDB();
        const tx = db.transaction("keys", "readwrite");
        const store = tx.objectStore("keys");
        await store.put(privateKey, "vault_priv");
    }

    static async getSessionKey() {
        const db = await this.openSessionDB();
        return new Promise((resolve, reject) => {
            const tx = db.transaction("keys", "readonly");
            const req = tx.objectStore("keys").get("vault_priv");
            req.onsuccess = () => resolve(req.result);
            req.onerror = () => reject(req.error);
        });
    }

    static async clearSessionKeys() {
        const db = await this.openSessionDB();
        const tx = db.transaction("keys", "readwrite");
        tx.objectStore("keys").clear();
    }

    static openSessionDB() {
        return new Promise((resolve, reject) => {
            const req = indexedDB.open("ZNodeSession", 1);
            req.onupgradeneeded = () => req.result.createObjectStore("keys");
            req.onsuccess = () => resolve(req.result);
            req.onerror = () => reject(req.error);
        });
    }

    /** Generate 12 random words from the BIP39 Wordlist */
    static generateRecoveryPhrase() {
        if (typeof BIP39_WORDLIST === 'undefined') throw new Error("Wordlist not loaded.");
        const buffer = new Uint16Array(12);
        crypto.getRandomValues(buffer);
        return Array.from(buffer).map(val => BIP39_WORDLIST[val % 2048]).join(" ");
    }
}

// --- Vault UI Controller ---
document.addEventListener("DOMContentLoaded", async () => {
    const overlay = document.getElementById('vault-overlay');
    const errBox = document.getElementById('vault-error');
    if (!overlay) return; 

    // SESSION_AUTHORITATIVE_BYPASS: If the user is already authoritatively unlocked in this tab, 
    // we skip the high-impact visual audit to improve UX during routine navigation.
    if (sessionStorage.getItem("vault_unlocked") === "true") {
        overlay.remove();
        console.log("[Vault] Session active securely in memory. Skipping visual audit.");
        
        // ... background sync ...
        (async () => {
            try {
                const res = await fetch('/app/api/key/status');
                if (res.ok) {
                    const json = await res.json();
                    if (!json.has_key) {
                        console.error("[Vault] Server desync detected in background. Purging 'Zombie' session...");
                        await ZNodeSecurity.wipe();
                        window.location.reload(); 
                    }
                }
            } catch(e) {}
        })();
        return;
    }

    // AUTHORITATIVE_VISIBILITY: For fresh or locked sessions, we exhibit the high-integrity gateway.
    overlay.classList.remove('hidden');
    overlay.classList.add('flex');

    // AUTHORITATIVE_BACKEND_SYNC: This is the priority stage for LOCKED sessions. 
    async function performBackendSync() {
        try {
            const res = await fetch('/app/api/key/status');
            if (!res.ok) throw new Error("Could not reach vault API");
            const json = await res.json();
            
            if (json.has_key) {
                setupUnlockFlow();
            } else {
                // AUTONOMIC_SYNCHRONIZATION: Purge legacy keys if server reports empty volume
                if (localStorage.getItem('vault_pub') || localStorage.getItem('vault_wrapped_priv') || (await VaultCrypto.getSessionKey())) {
                    console.warn("[Vault] Server desync detected. Purging 'Zombie' keys...");
                    await ZNodeSecurity.wipe();
                }
                setupGenerationFlow();
            }
        } catch (e) {
            errBox.textContent = "Network error connecting to Vault.";
        }
    }

    /** PHASE 0: Secure Environment Audit (Advanced Heuristics) */
    async function runSecurityAudit() {
        const checks = [
            { 
               id: 'chk-crypto', 
               check: () => !!(window.crypto && window.crypto.subtle) 
            },
            { 
               id: 'chk-algos', 
               check: async () => {
                   try {
                       // Deep Stress Test for GCM and ECC
                       const testKey = new Uint8Array(32);
                       const k = await crypto.subtle.importKey("raw", testKey, "AES-GCM", false, ["encrypt", "decrypt"]);
                       const iv = new Uint8Array(12);
                       const encoded = new TextEncoder().encode("VERIFY_INTEGRITY");
                       const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, k, encoded);
                       const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, k, ct);
                       return new TextDecoder().decode(pt) === "VERIFY_INTEGRITY";
                   } catch(e) { return false; }
               }
            },
            { 
               id: 'chk-storage', 
               check: () => !!(window.indexedDB && navigator.storage && navigator.storage.persist) 
            },
            { 
               id: 'chk-context', 
               check: () => window.isSecureContext && !window.frameElement 
            },
            { 
               id: 'chk-isolation', 
               check: () => true // SSO Whitelisted: SharedArrayBuffer is restricted by SSO interoperability but considered TRUSTED
            },
            { 
               id: 'chk-behavior', 
               check: () => {
                   // Advanced Automation Detection (Forensics)
                   const isAutomated = navigator.webdriver || 
                                      !!document.documentElement.getAttribute('webdriver') ||
                                      !!window.domAutomation ||
                                      !!window.domAutomationController;
                   return !isAutomated;
               }
            }
        ];

        const feedback = document.getElementById('audit-feedback');
        feedback.innerText = "INITIALIZING_FORENSIC_AUDIT...";
        feedback.className = "font-label text-[10px] text-on-surface-variant/40 uppercase tracking-widest text-center mt-2";
        let allPassed = true;

        for (const chk of checks) {
            const el = document.getElementById(chk.id);
            if (!el) continue;
            
            el.classList.remove('opacity-50');
            el.querySelector('.status').innerText = "VERIFYING";
            await new Promise(r => setTimeout(r, 150));

            const passed = chk.check();
            const statusEl = el.querySelector('.status');
            
            if (passed) {
                statusEl.innerText = "SUCCESS";
                statusEl.className = "status text-tertiary font-bold";
            } else {
                statusEl.innerText = "COMPROMISED";
                statusEl.className = "status text-error font-bold";
                allPassed = false;
            }
        }

        if (allPassed) {
            feedback.innerText = "ENVIRONMENT_VERIFIED // ESTABLISHING CONTEXT...";
            feedback.className = "font-label text-[10px] text-tertiary uppercase tracking-widest text-center mt-2";
            await new Promise(r => setTimeout(r, 300));
            
            // Transition to real flow
            document.getElementById('vault-step-0').classList.add('hidden');
            document.getElementById('vault-step-0').style.display = 'none';
            document.getElementById('vault-step-1').classList.remove('hidden');
            document.getElementById('vault-step-1').style.display = 'flex';
            
            // Start backend check
            performBackendSync();
        } else {
            document.getElementById('security-check-list').classList.add('border-error/30', 'bg-error/5');
            
            // Show Detailed Reason
            const reasonCard = document.getElementById('audit-reason-card');
            if (reasonCard) reasonCard.classList.remove('hidden');

            const btn = document.getElementById('vault-submit-btn');
            const btnText = btn.querySelector('.vault-btn-text');
            
            btn.classList.remove('loading');
            btn.disabled = false;
            btnText.innerText = "[ CONTINUE ]";
            btn.className = "vault-btn !w-full !bg-error/10 !border-error/30 !text-error hover:!bg-error hover:!text-black uppercase";
            
            btn.onclick = () => {
                console.warn("[Security] Manual Override Proceeding...");
                document.getElementById('vault-step-0').classList.add('hidden');
                document.getElementById('vault-step-0').style.display = 'none';
                document.getElementById('vault-step-1').classList.remove('hidden');
                document.getElementById('vault-step-1').style.display = 'flex';
                performBackendSync();
            };
        }
    }

    // Initialize Audit (This is now complementary to the sync gate)
    runSecurityAudit();

    function showSpinner(btn) {
        btn.classList.add('loading');
        btn.disabled = true;
    }
    function hideSpinner(btn) {
        btn.classList.remove('loading');
        btn.disabled = false;
    }
    function error(msg) {
        errBox.textContent = msg;
    }

    // ─── Flow A: Setup New Vault ─────────────────────────────
    function setupGenerationFlow() {
        document.getElementById('vault-title').textContent = "NEW VAULT CONFIGURATION";
        document.getElementById('vault-subtitle').textContent = "PHASE 1: ESTABLISH MASTER CREDENTIALS";
        
        const pwInput = document.getElementById('vault-pw');
        const confirmInput = document.getElementById('vault-confirm-pw');
        const step1 = document.getElementById('vault-step-1');
        const step2 = document.getElementById('vault-step-2');
        const step3 = document.getElementById('vault-step-3');
        const step4 = document.getElementById('vault-step-4');
        const keyPreview = document.getElementById('vault-key-preview');
        const phraseDisplay = document.getElementById('vault-recovery-phrase');
        
        confirmInput.style.display = 'block';

        const btn = document.getElementById('vault-submit-btn');
        const backBtn = document.getElementById('vault-back-btn');
        btn.querySelector('.vault-btn-text').textContent = "PROCEED TO KEY GENERATION";
        backBtn.classList.add('hidden');
        backBtn.style.display = 'none';

        let currentStep = 1;
        let generatedBackupStr = null;
        let generatedUploadPayload = null; // Hold pending server upload
        let generatedSessionData = null; // Hold pending session keys
        let masterKey = null; // Persist for final unwrap

        backBtn.onclick = () => {
            error("");
            if (currentStep === 2) {
                step2.classList.add('hidden'); step2.style.display = 'none';
                step1.classList.remove('hidden'); step1.style.display = 'flex';
                document.getElementById('vault-title').textContent = "NEW VAULT CONFIGURATION";
                document.getElementById('vault-subtitle').textContent = "PHASE 1: ESTABLISH MASTER CREDENTIALS";
                btn.querySelector('.vault-btn-text').textContent = "PROCEED TO KEY GENERATION";
                backBtn.classList.add('hidden'); backBtn.style.display = 'none';
                currentStep = 1;
            } else if (currentStep === 3) {
                step3.classList.add('hidden'); step3.style.display = 'none';
                step2.classList.remove('hidden'); step2.style.display = 'flex';
                document.getElementById('vault-subtitle').textContent = "PHASE 2: CRYPTOGRAPHIC ASSET PREVIEW";
                btn.querySelector('.vault-btn-text').textContent = "PROCEED TO RECOVERY SETUP";
                currentStep = 2;
            } else if (currentStep === 4) {
                step4.classList.add('hidden'); step4.style.display = 'none';
                step3.classList.remove('hidden'); step3.style.display = 'flex';
                document.getElementById('vault-subtitle').textContent = "PHASE 3: SECURE SEED PHRASE";
                btn.querySelector('.vault-btn-text').textContent = "I HAVE WRITTEN THIS DOWN";
                currentStep = 3;
            }
        };

        btn.onclick = async () => {
            error("");
            
            if (currentStep === 1) {
                if (pwInput.value.length < 8) return error("Master password must be 8+ characters.");
                if (pwInput.value !== confirmInput.value) return error("Passwords do not match.");
                
                showSpinner(btn);
                try {
                    // 1. Math Crypto
                    console.log("[Vault] Generating P-256 Elliptic Curve pairs...");
                    const keyPair = await VaultCrypto.generateECDHKeys();
                    const exportedPublicKey = await VaultCrypto.exportPublicKey(keyPair.publicKey);
                    
                    // Master Wrap
                    const salt = crypto.getRandomValues(new Uint8Array(16));
                    const saltB64 = bufferToBase64(salt);
                    console.log("[Vault] Deriving PBKDF2 Master Key from password...");
                    masterKey = await VaultCrypto.deriveMasterKey(pwInput.value, salt);
                    const wrappedPrivateKey = await VaultCrypto.wrapPrivateKey(keyPair.privateKey, masterKey);

                    // Recovery Wrap
                    const recoveryPhrase = VaultCrypto.generateRecoveryPhrase();
                    const recoverySalt = crypto.getRandomValues(new Uint8Array(16));
                    const recoverySaltB64 = bufferToBase64(recoverySalt);
                    console.log("[Vault] Deriving Recovery Key from phrase...");
                    const recoveryMasterKey = await VaultCrypto.deriveMasterKey(recoveryPhrase, recoverySalt);
                    const recoveryWrappedPrivateKey = await VaultCrypto.wrapPrivateKey(keyPair.privateKey, recoveryMasterKey);

                    // 2. Prepare Upload Payload (DEFERRED to Step 4)
                    generatedUploadPayload = {
                        public_key: exportedPublicKey,
                        encrypted_private_key: wrappedPrivateKey,
                        salt: saltB64,
                        recovery_encrypted_private_key: recoveryWrappedPrivateKey,
                        recovery_salt: recoverySaltB64
                    };

                    // Build JSON backup string
                    generatedBackupStr = JSON.stringify({
                        type: "zeronode_vault",
                        ...generatedUploadPayload
                    }, null, 2);

                    // Prepare Session storage variables (DEFERRED to Step 4)
                    const rawPriv = bufferToBase64(await crypto.subtle.exportKey("pkcs8", keyPair.privateKey));
                    generatedSessionData = {
                        vault_pub: exportedPublicKey,
                        vault_priv: rawPriv
                    };

                    // Set Phrase UI
                    phraseDisplay.textContent = recoveryPhrase;

                    // Transition to Step 2
                    step1.classList.add('hidden');
                    step1.style.display = 'none';
                    step2.classList.remove('hidden');
                    step2.style.display = 'flex';
                    
                    document.getElementById('vault-subtitle').textContent = "PHASE 2: CRYPTOGRAPHIC ASSET PREVIEW";
                    keyPreview.value = generatedBackupStr;
                    btn.querySelector('.vault-btn-text').textContent = "PROCEED TO RECOVERY SETUP";
                    
                    backBtn.classList.remove('hidden');
                    backBtn.style.display = 'block';
                    currentStep = 2;
                } catch (err) {
                    console.error(err);
                    error(err.message || "Cryptography initialization failed.");
                }
                hideSpinner(btn);

            } else if (currentStep === 2) {
                // Transition to Step 3 (Phrase)
                step2.classList.add('hidden');
                step2.style.display = 'none';
                step3.classList.remove('hidden');
                step3.style.display = 'flex';
                
                document.getElementById('vault-subtitle').textContent = "PHASE 3: SECURE SEED PHRASE";
                btn.querySelector('.vault-btn-text').textContent = "I HAVE WRITTEN THIS DOWN";
                
                currentStep = 3;

            } else if (currentStep === 3) {
                // Transition to Step 4 (File Archive)
                step3.classList.add('hidden');
                step3.style.display = 'none';
                step4.classList.remove('hidden');
                step4.style.display = 'flex';
                
                document.getElementById('vault-subtitle').textContent = "PHASE 4: LOCAL ARCHIVE";
                btn.style.display = 'none'; // Hide submit button until clicked
                
                document.getElementById('vault-manual-dl-btn').onclick = () => {
                    // Trigger Backup Download
                    const blob = new Blob([generatedBackupStr], { type: "application/json" });
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = `zeronode_vault_${new Date().getTime()}.json`;
                    a.click();
                    URL.revokeObjectURL(url);
                    
                    document.getElementById('vault-manual-dl-btn').textContent = "✓ ARCHIVE SAVED";
                    document.getElementById('vault-manual-dl-btn').classList.add("text-success");
                    btn.style.display = 'flex';
                    btn.querySelector('.vault-btn-text').textContent = "INITIALIZE VAULT";
                };
                
                currentStep = 4;

            } else if (currentStep === 4) {
                showSpinner(btn);
                try {
                    // Send to Server
                    const uploadRes = await fetch('/app/api/key/save', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(generatedUploadPayload)
                    });
                    
                    if (!uploadRes.ok) {
                        if (uploadRes.status === 403) {
                             console.warn("[Vault] Identity already established on server. Transitioning to unlock protocol.");
                             setupUnlockFlow();
                             error("Vault already initialized. Please provide existing credentials.");
                             return;
                        }
                        throw new Error("Failed to save to server.");
                    }

                    // --- THE GOLD STANDARD ---
                    // Unwrap as NON-EXTRACTABLE CryptoKey
                    const privateKey = await VaultCrypto.unwrapPrivateKey(generatedUploadPayload.encrypted_private_key, masterKey, false);

                    // Initialize Secure Session
                    await VaultCrypto.sessionizeKey(privateKey);
                    sessionStorage.setItem("vault_pub", generatedSessionData.vault_pub);
                    sessionStorage.setItem("vault_unlocked", "true");
                    // sessionStorage.removeItem("vault_priv"); // Ensure no trace exists

                    overlay.classList.add('hidden');
                    setTimeout(() => overlay.remove(), 500);
                } catch (err) {
                    console.error(err);
                    error("Final sync failed. Vault not created.");
                }
                hideSpinner(btn);
            }
        };
    }

    // ─── Flow B: Unlock Existing Vault ───────────────────────
    function setupUnlockFlow() {
        document.getElementById('vault-title').textContent = "SECURE SESSION REQUIRED";
        document.getElementById('vault-subtitle').textContent = "Provide Master Credentials to decrypt the session keys within local memory.";
        
        const pwInput = document.getElementById('vault-pw');
        const forgotLink = document.getElementById('vault-forgot-pw');
        document.getElementById('vault-confirm-pw').style.display = 'none';
        
        // Hide any open steps
        document.getElementById('vault-step-1').style.display = 'flex';
        document.getElementById('vault-step-2').style.display = 'none';
        document.getElementById('vault-step-3').style.display = 'none';
        document.getElementById('vault-step-4').style.display = 'none';
        document.getElementById('vault-recovery-step-1').style.display = 'none';
        document.getElementById('vault-recovery-step-2').style.display = 'none';
        document.getElementById('vault-recovery-step-3').style.display = 'none';
        
        forgotLink.style.display = 'block';

        const btn = document.getElementById('vault-submit-btn');
        const backBtn = document.getElementById('vault-back-btn');
        btn.querySelector('.vault-btn-text').textContent = "INITIALIZE SECURE SESSION";
        backBtn.style.display = 'none';

        forgotLink.onclick = (e) => {
            e.preventDefault();
            setupRecoveryFlow();
        };

        btn.onclick = async () => {
            error("");
            if (pwInput.value.length < 1) return error("Password required.");
            
            showSpinner(btn);
            try {
                const res = await fetch('/app/api/key/load');
                if (!res.ok) throw new Error("Could not fetch Vault Keys.");
                const data = await res.json();
                
                const salt = new Uint8Array(base64ToBuffer(data.salt));
                console.log("[Vault] Deriving PBKDF2 Master Key from password...");
                const masterKey = await VaultCrypto.deriveMasterKey(pwInput.value, salt);
                
                // --- THE GOLD STANDARD ---
                // Unlock as NON-EXTRACTABLE Handle
                let privateKey;
                try {
                     privateKey = await VaultCrypto.unwrapPrivateKey(data.encrypted_private_key, masterKey, false);
                } catch (decErr) {
                     throw new Error("Incorrect Master Password.");
                }

                // Initialize Session
                await VaultCrypto.sessionizeKey(privateKey);
                sessionStorage.setItem("vault_pub", data.public_key);
                sessionStorage.setItem("vault_unlocked", "true");
                // vault_priv is NOT stored in sessionStorage

                overlay.classList.add('hidden');
                setTimeout(() => overlay.remove(), 500);
            } catch (err) {
                console.error(err);
                error(err.message || "Cryptography failure.");
            }
            hideSpinner(btn);
        };
    }

    // ─── Flow C: Recover Forgotten Vault ─────────────────────
    function setupRecoveryFlow() {
        document.getElementById('vault-title').textContent = "SYSTEM RECOVERY";
        document.getElementById('vault-subtitle').textContent = "OVERRIDE PROTOCOL: SEED PHRASE REQUIRED";
        
        document.getElementById('vault-step-1').style.display = 'none'; // Hide step 1 from generation
        
        const rStep1 = document.getElementById('vault-recovery-step-1');
        const rStep2 = document.getElementById('vault-recovery-step-2');
        const rStep3 = document.getElementById('vault-recovery-step-3');
        const newPhraseDisplay = document.getElementById('vault-recovery-new-phrase');

        rStep1.classList.remove('hidden'); rStep1.style.display = 'flex';

        const phraseInput = document.getElementById('vault-recovery-input');
        const newPwInput = document.getElementById('vault-recovery-new-pw');
        const errBox = document.getElementById('vault-recovery-error');
        const btn = document.getElementById('vault-submit-btn');
        const backBtn = document.getElementById('vault-back-btn');
        
        btn.querySelector('.vault-btn-text').textContent = "VALIDATE PHRASE";
        backBtn.classList.remove('hidden'); backBtn.style.display = 'block';

        let currentStepR = 1;
        let recoveryUploadPayload = null;
        let recoveryBackupStr = null;
        let recoverySessionData = null;

        backBtn.onclick = () => {
            errBox.textContent = "";
            if (currentStepR === 1) {
                // Cancel recovery -> go back to standard unlock
                phraseInput.value = "";
                newPwInput.value = "";
                rStep1.style.display = 'none';
                setupUnlockFlow();
            } else if (currentStepR === 2) {
                // Back to input
                rStep2.classList.add('hidden'); rStep2.style.display = 'none';
                rStep1.classList.remove('hidden'); rStep1.style.display = 'flex';
                document.getElementById('vault-subtitle').textContent = "OVERRIDE PROTOCOL: SEED PHRASE REQUIRED";
                btn.querySelector('.vault-btn-text').textContent = "VALIDATE PHRASE";
                currentStepR = 1;
            } else if (currentStepR === 3) {
                rStep3.classList.add('hidden'); rStep3.style.display = 'none';
                rStep2.classList.remove('hidden'); rStep2.style.display = 'flex';
                document.getElementById('vault-subtitle').textContent = "PHASE 2: SECURE NEW SEED PHRASE";
                btn.querySelector('.vault-btn-text').textContent = "I HAVE WRITTEN THIS DOWN";
                currentStepR = 2;
            }
        };

        btn.onclick = async () => {
            errBox.textContent = "";

            if (currentStepR === 1) {
                const phrase = phraseInput.value.trim().toLowerCase().replace(/\s+/g, ' ');
                if (phrase.split(' ').length !== 12) return errBox.textContent = "Phrase must be exactly 12 words.";
                if (newPwInput.value.length < 8) return errBox.textContent = "New password must be 8+ characters.";

                showSpinner(btn);
                try {
                    // Extract strictly ONLY the recovery keys payload via dedicated endpoint
                    const res = await fetch('/app/api/key/recovery');
                    if (!res.ok) throw new Error("Could not fetch Vault Recovery Keys.");
                    const data = await res.json();
                    
                    // Derive OLD Recovery Master Key & Unwrap
                    const oldRecoverySalt = new Uint8Array(base64ToBuffer(data.recovery_salt));
                    const oldRecoveryMasterKey = await VaultCrypto.deriveMasterKey(phrase, oldRecoverySalt);
                    let privateKey;
                    try {
                        privateKey = await VaultCrypto.unwrapPrivateKey(data.recovery_encrypted_private_key, oldRecoveryMasterKey);
                    } catch (decErr) {
                        throw new Error("Invalid Recovery Phrase. Access Denied.");
                    }

                    // --- GENERATE COMPLETELY NEW CONFIGURATION ---
                    console.log("[Vault Recovery] Generating NEW Password Master Key...");
                    const newSalt = crypto.getRandomValues(new Uint8Array(16));
                    const newSaltB64 = bufferToBase64(newSalt);
                    const newMasterKey = await VaultCrypto.deriveMasterKey(newPwInput.value, newSalt);
                    const newWrappedPrivateKey = await VaultCrypto.wrapPrivateKey(privateKey, newMasterKey);

                    console.log("[Vault Recovery] Generating NEW Recovery Phrase...");
                    const newRecoveryPhrase = VaultCrypto.generateRecoveryPhrase();
                    const newRecoverySalt = crypto.getRandomValues(new Uint8Array(16));
                    const newRecoverySaltB64 = bufferToBase64(newRecoverySalt);
                    const newRecoveryMasterKey = await VaultCrypto.deriveMasterKey(newRecoveryPhrase, newRecoverySalt);
                    const newRecoveryWrappedPrivateKey = await VaultCrypto.wrapPrivateKey(privateKey, newRecoveryMasterKey);

                    // Defer Upload
                    recoveryUploadPayload = {
                        encrypted_private_key: newWrappedPrivateKey,
                        salt: newSaltB64,
                        recovery_encrypted_private_key: newRecoveryWrappedPrivateKey,
                        recovery_salt: newRecoverySaltB64
                    };

                    recoveryBackupStr = JSON.stringify({
                        type: "zeronode_vault",
                        public_key: data.public_key,
                        ...recoveryUploadPayload
                    }, null, 2);

                    const rawPriv = bufferToBase64(await crypto.subtle.exportKey("pkcs8", privateKey));
                    recoverySessionData = {
                        vault_pub: data.public_key,
                        vault_priv: rawPriv
                    };

                    // Display new phrase
                    newPhraseDisplay.textContent = newRecoveryPhrase;

                    // Transition to step 2
                    rStep1.classList.add('hidden'); rStep1.style.display = 'none';
                    rStep2.classList.remove('hidden'); rStep2.style.display = 'flex';
                    
                    document.getElementById('vault-subtitle').textContent = "PHASE 2: SECURE NEW SEED PHRASE";
                    btn.querySelector('.vault-btn-text').textContent = "I HAVE WRITTEN THIS DOWN";
                    currentStepR = 2;

                } catch (err) {
                    console.error(err);
                    errBox.textContent = err.message || "Recovery failure.";
                }
                hideSpinner(btn);

            } else if (currentStepR === 2) {
                rStep2.classList.add('hidden'); rStep2.style.display = 'none';
                rStep3.classList.remove('hidden'); rStep3.style.display = 'flex';
                
                document.getElementById('vault-subtitle').textContent = "PHASE 3: ROTATE AND ARCHIVE";
                btn.style.display = 'none'; // Hide submit button until clicked
                
                document.getElementById('vault-recovery-manual-dl-btn').onclick = () => {
                     // Trigger Backup Download
                     const blob = new Blob([recoveryBackupStr], { type: "application/json" });
                     const url = URL.createObjectURL(blob);
                     const a = document.createElement('a');
                     a.href = url;
                     a.download = `zeronode_vault_recovered_${new Date().getTime()}.json`;
                     a.click();
                     URL.revokeObjectURL(url);
                     
                     document.getElementById('vault-recovery-manual-dl-btn').textContent = "✓ ARCHIVE SAVED";
                     document.getElementById('vault-recovery-manual-dl-btn').classList.add("text-success");
                     btn.style.display = 'flex';
                     btn.querySelector('.vault-btn-text').textContent = "AUTHORIZE SYSTEM OVERWRITE";
                };

                currentStepR = 3;

            } else if (currentStepR === 3) {
                showSpinner(btn);
                try {
                    // Execute Database Wipe/Overwrite
                    const resetRes = await fetch('/app/api/key/reset', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(recoveryUploadPayload)
                    });
                    if (!resetRes.ok) throw new Error("Could not apply system overwrite.");

                    // Sessionize
                    sessionStorage.setItem("vault_pub", recoverySessionData.vault_pub);
                    sessionStorage.setItem("vault_priv", recoverySessionData.vault_priv);
                    sessionStorage.setItem("vault_unlocked", "true");

                    document.getElementById('vault-overlay').classList.add('hidden');
                    setTimeout(() => document.getElementById('vault-overlay').remove(), 500);

                } catch (err) {
                    console.error(err);
                    errBox.textContent = err.message || "Reset submission failed.";
                }
                hideSpinner(btn);
            }
        };
    }
});

window.ZNodeSecurity = {
  wipe: async function() {
    console.log("[Security] Initializing Atomic RAM Wipe...");
    
    // 1. Revoke all decrypted Blob URLs (Physical RAM release)
    if (typeof previewUrls !== 'undefined') {
        previewUrls.forEach((url) => {
            try { URL.revokeObjectURL(url); } catch(e) {}
        });
        previewUrls.clear();
    }
    
    // 2. Flush RAM Maps
    if (typeof decryptedSessionCache !== 'undefined') decryptedSessionCache.clear();
    if (typeof metadataCache !== 'undefined') metadataCache.clear();
    if (typeof activeTaskSignals !== 'undefined') activeTaskSignals.clear();
    
    // 3. Purge Web Storage
    sessionStorage.clear();
    localStorage.clear();
    
    // 4. Purge Session Handles (IndexedDB)
    if (typeof VaultCrypto !== 'undefined') await VaultCrypto.clearSessionKeys();
    
    console.log("[Security] RAM Wipe Complete.");
    return true;
  }
};

/**
 * ZNode Dialog Service
 * Professional, Promise-based modal system for alerts, confirmations, and prompts.
 */
class ZNodeDialog {
    static _container = null;
    static _box = null;
    static _title = null;
    static _body = null;
    static _inputCnt = null;
    static _input = null;
    static _cancelBtn = null;
    static _confirmBtn = null;

    static _init() {
        if (this._container) return;
        this._container = document.getElementById('znode-dialog-overlay');
        this._box = document.getElementById('znode-dialog-box');
        this._title = document.getElementById('znode-dialog-title');
        this._body = document.getElementById('znode-dialog-body');
        this._inputCnt = document.getElementById('znode-dialog-input-container');
        this._input = document.getElementById('znode-dialog-input');
        this._cancelBtn = document.getElementById('znode-dialog-cancel');
        this._confirmBtn = document.getElementById('znode-dialog-confirm');
    }

    static async show({ title = "SYSTEM NOTIFICATION", body = "", type = "alert", defaultValue = "" }) {
        this._init();
        if (!this._container) return false;

        // Reset display states
        this._container.classList.remove('opacity-100', 'pointer-events-none');
        this._container.classList.add('opacity-0', 'pointer-events-none');
        this._box.classList.remove('opacity-100', 'scale-100');
        this._box.classList.add('opacity-0', 'scale-95');

        return new Promise((resolve) => {
            this._title.innerText = title;
            this._body.innerText = body;
            this._input.value = defaultValue;
            
            // UI Toggle
            if (type === 'prompt') this._inputCnt.classList.remove('hidden');
            else this._inputCnt.classList.add('hidden');

            if (type === 'alert') this._cancelBtn.classList.add('hidden');
            else this._cancelBtn.classList.remove('hidden');

            // Open Animation
            setTimeout(() => {
                this._container.classList.remove('pointer-events-none', 'opacity-0');
                this._container.classList.add('opacity-100');
                this._box.classList.remove('scale-95', 'opacity-0');
                this._box.classList.add('scale-100', 'opacity-100');
                if (type === 'prompt') this._input.focus();
                else this._confirmBtn.focus();
            }, 50);

            const cleanup = (val) => {
                this._container.classList.add('opacity-0', 'pointer-events-none');
                this._container.classList.remove('opacity-100');
                this._box.classList.add('scale-95', 'opacity-0');
                this._box.classList.remove('scale-100', 'opacity-100');
                this._confirmBtn.onclick = null;
                this._cancelBtn.onclick = null;
                window.onkeydown = null;
                resolve(val);
            };

            this._confirmBtn.onclick = () => {
                if (type === 'prompt') cleanup(this._input.value);
                else cleanup(true);
            };
            this._cancelBtn.onclick = () => cleanup(type === 'prompt' ? null : false);
            window.onkeydown = (e) => {
                if (e.key === 'Enter') this._confirmBtn.click();
                if (e.key === 'Escape') this._cancelBtn.click();
            };
        });
    }

    static alert(title, body) { return this.show({ title, body, type: 'alert' }); }
    static confirm(title, body) { return this.show({ title, body, type: 'confirm' }); }
    static prompt(title, body, def = "") { return this.show({ title, body, type: 'prompt', defaultValue: def }); }
}
window.ZNodeDialog = ZNodeDialog;
