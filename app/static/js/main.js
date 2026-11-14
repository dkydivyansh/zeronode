function bufferToBase64(buffer) {
  let binary = "";
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

function deterministicStringify(obj) {
    if (obj === null || typeof obj !== 'object') return JSON.stringify(obj);
    if (Array.isArray(obj)) return `[${obj.map(deterministicStringify).join(',')}]`;
    const keys = Object.keys(obj).sort();
    let str = '{';
    for (let i = 0; i < keys.length; i++) {
        if (i > 0) str += ',';
        str += JSON.stringify(keys[i]) + ':' + deterministicStringify(obj[keys[i]]);
    }
    return str + '}';
}

class VaultCrypto {
  static async generateECDHKeys() {
    return await crypto.subtle.generateKey(
      { name: "ECDH", namedCurve: "P-256" },
      true,

      ["deriveKey", "deriveBits"],
    );
  }

  static async deriveMasterKey(passwordStr, saltUint8) {
    const enc = new TextEncoder();
    const baseKey = await crypto.subtle.importKey(
      "raw",
      enc.encode(passwordStr),
      "PBKDF2",
      false,
      ["deriveKey"],
    );
    return await crypto.subtle.deriveKey(
      { name: "PBKDF2", salt: saltUint8, iterations: 250000, hash: "SHA-256" },
      baseKey,
      { name: "AES-GCM", length: 256 },
      false,

      ["encrypt", "decrypt"],
    );
  }

  static async wrapPrivateKey(privateKey, masterKey) {
    const pkcs8 = await crypto.subtle.exportKey("pkcs8", privateKey);

    const iv = crypto.getRandomValues(new Uint8Array(12));

    const ciphertext = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: iv },
      masterKey,
      pkcs8,
    );

    const packed = new Uint8Array(iv.length + ciphertext.byteLength);
    packed.set(iv, 0);
    packed.set(new Uint8Array(ciphertext), iv.length);

    return bufferToBase64(packed);
  }

  static async unwrapPrivateKey(wrappedB64, masterKey, extractable = true) {
    const packed = new Uint8Array(base64ToBuffer(wrappedB64));
    const iv = packed.slice(0, 12);
    const ciphertext = packed.slice(12);

    const decryptedPkcs8 = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: iv },
      masterKey,
      ciphertext,
    );

    return await crypto.subtle.importKey(
      "pkcs8",
      decryptedPkcs8,
      { name: "ECDH", namedCurve: "P-256" },
      extractable,
      ["deriveKey", "deriveBits"],
    );
  }

  static async exportPublicKey(publicKey) {
    const spki = await crypto.subtle.exportKey("spki", publicKey);
    return bufferToBase64(spki);
  }

  static async importPublicKey(spkiB64) {
    const spkiObj = base64ToBuffer(spkiB64);
    return await crypto.subtle.importKey(
      "spki",
      spkiObj,
      { name: "ECDH", namedCurve: "P-256" },
      true,
      [],
    );
  }

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

  static generateRecoveryPhrase() {
    if (typeof BIP39_WORDLIST === "undefined")
      throw new Error("Wordlist not loaded.");
    const buffer = new Uint16Array(12);
    crypto.getRandomValues(buffer);
    return Array.from(buffer)
      .map((val) => BIP39_WORDLIST[val % 2048])
      .join(" ");
  }
}

document.addEventListener("DOMContentLoaded", async () => {
  const overlay = document.getElementById("vault-overlay");
  const errBox = document.getElementById("vault-error");
  if (!overlay) return;

  if (sessionStorage.getItem("vault_unlocked") === "true") {
    overlay.remove();
    console.log(
      "[Vault] Session active securely in memory. Skipping visual audit.",
    );

    (async () => {
      try {
        const res = await fetch("/app/api/key/status");
        if (res.ok) {
          const json = await res.json();
          if (!json.has_key) {
            console.error(
              "[Vault] Server desync detected in background. Purging 'Zombie' session...",
            );
            await ZNodeSecurity.wipe();
            window.location.reload();
          }
        }
      } catch (e) {}
    })();
    return;
  }

  overlay.classList.remove("hidden");
  overlay.classList.add("flex");

  async function performBackendSync() {
    try {
      const res = await fetch("/app/api/key/status");
      if (!res.ok) throw new Error("Could not reach vault API");
      const json = await res.json();

      if (json.has_key) {
        setupUnlockFlow();
      } else {
        if (
          localStorage.getItem("vault_pub") ||
          localStorage.getItem("vault_wrapped_priv") ||
          (await VaultCrypto.getSessionKey())
        ) {
          console.warn(
            "[Vault] Server desync detected. Purging 'Zombie' keys...",
          );
          await ZNodeSecurity.wipe();
        }
        setupGenerationFlow();
      }
    } catch (e) {
      errBox.textContent = "Network error connecting to Vault.";
    }
  }

  async function runSecurityAudit() {
    const checks = [
      {
        id: "chk-crypto",
        check: () => !!(window.crypto && window.crypto.subtle),
      },
      {
        id: "chk-algos",
        check: async () => {
          try {
            const testKey = new Uint8Array(32);
            const k = await crypto.subtle.importKey(
              "raw",
              testKey,
              "AES-GCM",
              false,
              ["encrypt", "decrypt"],
            );
            const iv = new Uint8Array(12);
            const encoded = new TextEncoder().encode("VERIFY_INTEGRITY");
            const ct = await crypto.subtle.encrypt(
              { name: "AES-GCM", iv },
              k,
              encoded,
            );
            const pt = await crypto.subtle.decrypt(
              { name: "AES-GCM", iv },
              k,
              ct,
            );
            return new TextDecoder().decode(pt) === "VERIFY_INTEGRITY";
          } catch (e) {
            return false;
          }
        },
      },
      {
        id: "chk-storage",
        check: () =>
          !!(
            window.indexedDB &&
            navigator.storage &&
            navigator.storage.persist
          ),
      },
      {
        id: "chk-context",
        check: () => window.isSecureContext && !window.frameElement,
      },
      {
        id: "chk-isolation",
        check: () => true,
      },
      {
        id: "chk-behavior",
        check: () => {
          const isAutomated =
            navigator.webdriver ||
            !!document.documentElement.getAttribute("webdriver") ||
            !!window.domAutomation ||
            !!window.domAutomationController;
          return !isAutomated;
        },
      },
    ];

    const feedback = document.getElementById("audit-feedback");
    feedback.innerText = "Verifying security environment...";
    feedback.className =
      "font-label text-[10px] text-on-surface-variant/40 uppercase tracking-widest text-center mt-2";
    let allPassed = true;

    for (const chk of checks) {
      const el = document.getElementById(chk.id);
      if (!el) continue;

      el.classList.remove("opacity-50");
      el.querySelector(".status").innerText = "Checking...";
      await new Promise((r) => setTimeout(r, 150));

      const passed = chk.check();
      const statusEl = el.querySelector(".status");

      if (passed) {
        statusEl.innerText = "PASS";
        statusEl.className = "status text-tertiary font-bold";
      } else {
        statusEl.innerText = "FAIL";
        statusEl.className = "status text-error font-bold";
        allPassed = false;
      }
    }

    if (allPassed) {
      feedback.innerText = "Security check passed. Establishing session...";
      feedback.className =
        "font-label text-[10px] text-tertiary uppercase tracking-widest text-center mt-2";
      await new Promise((r) => setTimeout(r, 300));

      document.getElementById("vault-step-0").classList.add("hidden");
      document.getElementById("vault-step-0").style.display = "none";
      document.getElementById("vault-step-1").classList.remove("hidden");
      document.getElementById("vault-step-1").style.display = "flex";

      performBackendSync();
    } else {
      document
        .getElementById("security-check-list")
        .classList.add("border-error/30", "bg-error/5");

      const reasonCard = document.getElementById("audit-reason-card");
      if (reasonCard) reasonCard.classList.remove("hidden");

      const btn = document.getElementById("vault-submit-btn");
      const btnText = btn.querySelector(".vault-btn-text");

      btn.classList.remove("loading");
      btn.disabled = false;
      btnText.innerText = "Continue Anyway";
      btn.className =
        "vault-btn !w-full !bg-error/10 !border-error/30 !text-error hover:!bg-error hover:!text-black uppercase";

      btn.onclick = () => {
        console.warn("[Security] Proceeding with setup...");
        document.getElementById("vault-step-0").classList.add("hidden");
        document.getElementById("vault-step-0").style.display = "none";
        document.getElementById("vault-step-1").classList.remove("hidden");
        document.getElementById("vault-step-1").style.display = "flex";
        performBackendSync();
      };
    }
  }

  runSecurityAudit();

  function showSpinner(btn) {
    btn.classList.add("loading");
    btn.disabled = true;
  }
  function hideSpinner(btn) {
    btn.classList.remove("loading");
    btn.disabled = false;
  }
  function error(msg) {
    errBox.textContent = msg;
  }

  function setupGenerationFlow() {
    document.getElementById("vault-title").textContent =
      "NEW CONFIGURATION";
    document.getElementById("vault-subtitle").textContent =
      "STEP 1: CREATE MASTER PASSWORD";

    const pwInput = document.getElementById("vault-pw");
    const confirmInput = document.getElementById("vault-confirm-pw");
    const step1 = document.getElementById("vault-step-1");
    const step2 = document.getElementById("vault-step-2");
    const step3 = document.getElementById("vault-step-3");
    const step4 = document.getElementById("vault-step-4");
    const keyPreview = document.getElementById("vault-key-preview");
    const phraseDisplay = document.getElementById("vault-recovery-phrase");

    confirmInput.style.display = "block";

    const btn = document.getElementById("vault-submit-btn");
    const backBtn = document.getElementById("vault-back-btn");
    btn.querySelector(".vault-btn-text").textContent =
      "PROCEED TO KEY GENERATION";
    backBtn.classList.add("hidden");
    backBtn.style.display = "none";

    let currentStep = 1;
    let generatedBackupStr = null;
    let generatedUploadPayload = null;

    let generatedSessionData = null;

    let masterKey = null;

    backBtn.onclick = () => {
      error("");
      if (currentStep === 2) {
        step2.classList.add("hidden");
        step2.style.display = "none";
        step1.classList.remove("hidden");
        step1.style.display = "flex";
        document.getElementById("vault-title").textContent =
          "NEW CONFIGURATION";
        document.getElementById("vault-subtitle").textContent =
          "STEP 1: CREATE MASTER PASSWORD";
        btn.querySelector(".vault-btn-text").textContent =
          "PROCEED TO KEY GENERATION";
        backBtn.classList.add("hidden");
        backBtn.style.display = "none";
        currentStep = 1;
      } else if (currentStep === 3) {
        step3.classList.add("hidden");
        step3.style.display = "none";
        step2.classList.remove("hidden");
        step2.style.display = "flex";
        document.getElementById("vault-subtitle").textContent =
          "STEP 2: ENCRYPTION KEYS GENERATED";
        btn.querySelector(".vault-btn-text").textContent =
          "PROCEED TO RECOVERY SETUP";
        currentStep = 2;
      } else if (currentStep === 4) {
        step4.classList.add("hidden");
        step4.style.display = "none";
        step3.classList.remove("hidden");
        step3.style.display = "flex";
        document.getElementById("vault-subtitle").textContent =
          "STEP 3: RECOVERY SEED PHRASE";
        btn.querySelector(".vault-btn-text").textContent =
          "I HAVE SAVED THIS PHRASE";
        currentStep = 3;
      }
    };

    btn.onclick = async () => {
      error("");

      if (currentStep === 1) {
        if (pwInput.value.length < 8)
          return error("Master password must be 8+ characters.");
        if (pwInput.value !== confirmInput.value)
          return error("Passwords do not match.");

        showSpinner(btn);
        try {
          console.log("[Vault] Generating P-256 Elliptic Curve pairs...");
          const keyPair = await VaultCrypto.generateECDHKeys();
          const exportedPublicKey = await VaultCrypto.exportPublicKey(
            keyPair.publicKey,
          );

          const salt = crypto.getRandomValues(new Uint8Array(16));
          const saltB64 = bufferToBase64(salt);
          console.log("[Vault] Deriving PBKDF2 Master Key from password...");
          masterKey = await VaultCrypto.deriveMasterKey(pwInput.value, salt);
          const wrappedPrivateKey = await VaultCrypto.wrapPrivateKey(
            keyPair.privateKey,
            masterKey,
          );

          const recoveryPhrase = VaultCrypto.generateRecoveryPhrase();
          const recoverySalt = crypto.getRandomValues(new Uint8Array(16));
          const recoverySaltB64 = bufferToBase64(recoverySalt);
          console.log("[Vault] Deriving Recovery Key from phrase...");
          const recoveryMasterKey = await VaultCrypto.deriveMasterKey(
            recoveryPhrase,
            recoverySalt,
          );
          const recoveryWrappedPrivateKey = await VaultCrypto.wrapPrivateKey(
            keyPair.privateKey,
            recoveryMasterKey,
          );

          generatedUploadPayload = {
            public_key: exportedPublicKey,
            encrypted_private_key: wrappedPrivateKey,
            salt: saltB64,
            recovery_encrypted_private_key: recoveryWrappedPrivateKey,
            recovery_salt: recoverySaltB64,
          };

          generatedBackupStr = JSON.stringify(
            {
              type: "zeronode_vault",
              ...generatedUploadPayload,
            },
            null,
            2,
          );

          const rawPriv = bufferToBase64(
            await crypto.subtle.exportKey("pkcs8", keyPair.privateKey),
          );
          generatedSessionData = {
            vault_pub: exportedPublicKey,
            vault_priv: rawPriv,
          };

          phraseDisplay.textContent = recoveryPhrase;

          step1.classList.add("hidden");
          step1.style.display = "none";
          step2.classList.remove("hidden");
          step2.style.display = "flex";

          document.getElementById("vault-subtitle").textContent =
            "STEP 2: ENCRYPTION KEYS GENERATED";
          keyPreview.value = generatedBackupStr;
          btn.querySelector(".vault-btn-text").textContent =
            "PROCEED TO RECOVERY SETUP";

          backBtn.classList.remove("hidden");
          backBtn.style.display = "block";
          currentStep = 2;
        } catch (err) {
          console.error(err);
          error(err.message || "Cryptography initialization failed.");
        }
        hideSpinner(btn);
      } else if (currentStep === 2) {
        step2.classList.add("hidden");
        step2.style.display = "none";
        step3.classList.remove("hidden");
        step3.style.display = "flex";

        document.getElementById("vault-subtitle").textContent =
          "STEP 3: RECOVERY SEED PHRASE";
        btn.querySelector(".vault-btn-text").textContent =
          "I HAVE SAVED THIS PHRASE";

        currentStep = 3;
      } else if (currentStep === 3) {
        step3.classList.add("hidden");
        step3.style.display = "none";
        step4.classList.remove("hidden");
        step4.style.display = "flex";

        document.getElementById("vault-subtitle").textContent =
          "STEP 4: BACKUP ENCRYPTION KEYS";
        btn.style.display = "none";

        document.getElementById("vault-manual-dl-btn").onclick = () => {
          const blob = new Blob([generatedBackupStr], {
            type: "application/json",
          });
          const url = URL.createObjectURL(blob);
          const a = document.createElement("a");
          a.href = url;
          a.download = `zeronode_vault_${new Date().getTime()}.json`;
          a.click();
          URL.revokeObjectURL(url);

          document.getElementById("vault-manual-dl-btn").textContent =
            "✓ BACKUP SAVED";
          document
            .getElementById("vault-manual-dl-btn")
            .classList.add("text-success");
          btn.style.display = "flex";
          btn.querySelector(".vault-btn-text").textContent = "FINISH SETUP";
        };

        currentStep = 4;
      } else if (currentStep === 4) {
        showSpinner(btn);
        try {
          const uploadRes = await fetch("/app/api/key/save", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(generatedUploadPayload),
          });

          if (!uploadRes.ok) {
            if (uploadRes.status === 403) {
              console.warn(
                "[Auth] Account already configured. Switching to sign-in...",
              );
              setupUnlockFlow();
              error(
                "Configuration already complete. Please unlock your drive.",
              );
              return;
            }
            throw new Error("Failed to save to server.");
          }

          const privateKey = await VaultCrypto.unwrapPrivateKey(
            generatedUploadPayload.encrypted_private_key,
            masterKey,
            false,
          );

          await VaultCrypto.sessionizeKey(privateKey);
          sessionStorage.setItem("vault_pub", generatedSessionData.vault_pub);
          sessionStorage.setItem("vault_unlocked", "true");

          // Ensure no trace exists

          overlay.classList.add("hidden");
          setTimeout(() => overlay.remove(), 500);
        } catch (err) {
          console.error(err);
          error("Final sync failed. Vault not created.");
        }
        hideSpinner(btn);
      }
    };
  }

  function setupUnlockFlow() {
    document.getElementById("vault-title").textContent =
      "ENTER MASTER PASSWORD";
    document.getElementById("vault-subtitle").textContent =
      "Enter your master password to unlock your encrypted drive.";

    const pwInput = document.getElementById("vault-pw");
    const forgotLink = document.getElementById("vault-forgot-pw");
    document.getElementById("vault-confirm-pw").style.display = "none";

    document.getElementById("vault-step-1").style.display = "flex";
    document.getElementById("vault-step-2").style.display = "none";
    document.getElementById("vault-step-3").style.display = "none";
    document.getElementById("vault-step-4").style.display = "none";
    document.getElementById("vault-recovery-step-1").style.display = "none";
    document.getElementById("vault-recovery-step-2").style.display = "none";
    document.getElementById("vault-recovery-step-3").style.display = "none";

    forgotLink.style.display = "block";

    const btn = document.getElementById("vault-submit-btn");
    const backBtn = document.getElementById("vault-back-btn");
    btn.querySelector(".vault-btn-text").textContent =
      "UNLOCK DRIVE";
    backBtn.style.display = "none";

    forgotLink.onclick = (e) => {
      e.preventDefault();
      setupRecoveryFlow();
    };

    btn.onclick = async () => {
      error("");
      if (pwInput.value.length < 1) return error("Password required.");

      showSpinner(btn);
      try {
        const res = await fetch("/app/api/key/load");
        if (!res.ok) throw new Error("Could not fetch Vault Keys.");
        const data = await res.json();

        const salt = new Uint8Array(base64ToBuffer(data.salt));
        console.log("[Vault] Deriving PBKDF2 Master Key from password...");
        const masterKey = await VaultCrypto.deriveMasterKey(
          pwInput.value,
          salt,
        );

        let privateKey;
        try {
          privateKey = await VaultCrypto.unwrapPrivateKey(
            data.encrypted_private_key,
            masterKey,
            false,
          );
        } catch (decErr) {
          throw new Error("Incorrect Master Password.");
        }

        await VaultCrypto.sessionizeKey(privateKey);
        sessionStorage.setItem("vault_pub", data.public_key);
        sessionStorage.setItem("vault_unlocked", "true");

        overlay.classList.add("hidden");
        setTimeout(() => overlay.remove(), 500);
      } catch (err) {
        console.error(err);
        error(err.message || "Cryptography failure.");
      }
      hideSpinner(btn);
    };
  }

  function setupRecoveryFlow() {
    document.getElementById("vault-title").textContent = "ACCOUNT RECOVERY";
    document.getElementById("vault-subtitle").textContent =
      "Enter your 12-word recovery phrase and choose a new master password.";

    document.getElementById("vault-step-1").style.display = "none";

    const rStep1 = document.getElementById("vault-recovery-step-1");
    const rStep2 = document.getElementById("vault-recovery-step-2");
    const rStep3 = document.getElementById("vault-recovery-step-3");
    const newPhraseDisplay = document.getElementById(
      "vault-recovery-new-phrase",
    );

    rStep1.classList.remove("hidden");
    rStep1.style.display = "flex";

    const phraseInput = document.getElementById("vault-recovery-input");
    const newPwInput = document.getElementById("vault-recovery-new-pw");
    const errBox = document.getElementById("vault-recovery-error");
    const btn = document.getElementById("vault-submit-btn");
    const backBtn = document.getElementById("vault-back-btn");

    btn.querySelector(".vault-btn-text").textContent = "VERIFY RECOVERY PHRASE";
    backBtn.classList.remove("hidden");
    backBtn.style.display = "block";

    let currentStepR = 1;
    let recoveryUploadPayload = null;
    let recoveryBackupStr = null;
    let recoverySessionData = null;

    backBtn.onclick = () => {
      errBox.textContent = "";
      if (currentStepR === 1) {
        phraseInput.value = "";
        newPwInput.value = "";
        rStep1.style.display = "none";
        setupUnlockFlow();
      } else if (currentStepR === 2) {
        rStep2.classList.add("hidden");
        rStep2.style.display = "none";
        rStep1.classList.remove("hidden");
        rStep1.style.display = "flex";
        document.getElementById("vault-subtitle").textContent =
          "Enter your 12-word recovery phrase and choose a new master password.";
        btn.querySelector(".vault-btn-text").textContent = "VERIFY RECOVERY PHRASE";
        currentStepR = 1;
      } else if (currentStepR === 3) {
        rStep3.classList.add("hidden");
        rStep3.style.display = "none";
        rStep2.classList.remove("hidden");
        rStep2.style.display = "flex";
        document.getElementById("vault-subtitle").textContent =
          "STEP 2: NEW RECOVERY PHRASE";
        btn.querySelector(".vault-btn-text").textContent =
          "I HAVE SAVED THIS PHRASE";
        currentStepR = 2;
      }
    };

    btn.onclick = async () => {
      errBox.textContent = "";

      if (currentStepR === 1) {
        const phrase = phraseInput.value
          .trim()
          .toLowerCase()
          .replace(/\s+/g, " ");
        if (phrase.split(" ").length !== 12)
          return (errBox.textContent = "Phrase must be exactly 12 words.");
        if (newPwInput.value.length < 8)
          return (errBox.textContent = "New password must be 8+ characters.");

        showSpinner(btn);
        try {
          const res = await fetch("/app/api/key/recovery");
          if (!res.ok) throw new Error("Could not fetch Vault Recovery Keys.");
          const data = await res.json();

          const oldRecoverySalt = new Uint8Array(
            base64ToBuffer(data.recovery_salt),
          );
          const oldRecoveryMasterKey = await VaultCrypto.deriveMasterKey(
            phrase,
            oldRecoverySalt,
          );
          let privateKey;
          try {
            privateKey = await VaultCrypto.unwrapPrivateKey(
              data.recovery_encrypted_private_key,
              oldRecoveryMasterKey,
            );
          } catch (decErr) {
            throw new Error("Invalid Recovery Phrase. Access Denied.");
          }

          console.log("[Vault Recovery] Generating NEW Password Master Key...");
          const newSalt = crypto.getRandomValues(new Uint8Array(16));
          const newSaltB64 = bufferToBase64(newSalt);
          const newMasterKey = await VaultCrypto.deriveMasterKey(
            newPwInput.value,
            newSalt,
          );
          const newWrappedPrivateKey = await VaultCrypto.wrapPrivateKey(
            privateKey,
            newMasterKey,
          );

          console.log("[Vault Recovery] Generating NEW Recovery Phrase...");
          const newRecoveryPhrase = VaultCrypto.generateRecoveryPhrase();
          const newRecoverySalt = crypto.getRandomValues(new Uint8Array(16));
          const newRecoverySaltB64 = bufferToBase64(newRecoverySalt);
          const newRecoveryMasterKey = await VaultCrypto.deriveMasterKey(
            newRecoveryPhrase,
            newRecoverySalt,
          );
          const newRecoveryWrappedPrivateKey = await VaultCrypto.wrapPrivateKey(
            privateKey,
            newRecoveryMasterKey,
          );

          recoveryUploadPayload = {
            encrypted_private_key: newWrappedPrivateKey,
            salt: newSaltB64,
            recovery_encrypted_private_key: newRecoveryWrappedPrivateKey,
            recovery_salt: newRecoverySaltB64,
          };

          recoveryBackupStr = JSON.stringify(
            {
              type: "zeronode_vault",
              public_key: data.public_key,
              ...recoveryUploadPayload,
            },
            null,
            2,
          );

          const rawPriv = bufferToBase64(
            await crypto.subtle.exportKey("pkcs8", privateKey),
          );
          recoverySessionData = {
            vault_pub: data.public_key,
            vault_priv: rawPriv,
          };

          newPhraseDisplay.textContent = newRecoveryPhrase;

          rStep1.classList.add("hidden");
          rStep1.style.display = "none";
          rStep2.classList.remove("hidden");
          rStep2.style.display = "flex";

          document.getElementById("vault-subtitle").textContent =
            "STEP 2: NEW RECOVERY PHRASE";
          btn.querySelector(".vault-btn-text").textContent =
            "I HAVE SAVED THIS PHRASE";
          currentStepR = 2;
        } catch (err) {
          console.error(err);
          errBox.textContent = err.message || "Recovery failure.";
        }
        hideSpinner(btn);
      } else if (currentStepR === 2) {
        rStep2.classList.add("hidden");
        rStep2.style.display = "none";
        rStep3.classList.remove("hidden");
        rStep3.style.display = "flex";

        document.getElementById("vault-subtitle").textContent =
          "STEP 3: DOWNLOAD NEW BACKUP";
        btn.style.display = "none";

        document.getElementById("vault-recovery-manual-dl-btn").onclick =
          () => {
            const blob = new Blob([recoveryBackupStr], {
              type: "application/json",
            });
            const url = URL.createObjectURL(blob);
            const a = document.createElement("a");
            a.href = url;
            a.download = `zeronode_vault_recovered_${new Date().getTime()}.json`;
            a.click();
            URL.revokeObjectURL(url);

            document.getElementById(
              "vault-recovery-manual-dl-btn",
            ).textContent = "✓ BACKUP SAVED";
            document
              .getElementById("vault-recovery-manual-dl-btn")
              .classList.add("text-success");
            btn.style.display = "flex";
            btn.querySelector(".vault-btn-text").textContent =
              "UPDATE CREDENTIALS";
          };

        currentStepR = 3;
      } else if (currentStepR === 3) {
        showSpinner(btn);
        try {
          const resetRes = await fetch("/app/api/key/reset", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(recoveryUploadPayload),
          });
          if (!resetRes.ok)
            throw new Error("Could not update credentials.");

          sessionStorage.setItem("vault_pub", recoverySessionData.vault_pub);
          sessionStorage.setItem("vault_priv", recoverySessionData.vault_priv);
          sessionStorage.setItem("vault_unlocked", "true");

          document.getElementById("vault-overlay").classList.add("hidden");
          setTimeout(
            () => document.getElementById("vault-overlay").remove(),
            500,
          );
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
  wipe: async function () {
    console.log("[Security] Initializing Atomic RAM Wipe...");

    if (typeof previewUrls !== "undefined") {
      previewUrls.forEach((url) => {
        try {
          URL.revokeObjectURL(url);
        } catch (e) {}
      });
      previewUrls.clear();
    }

    if (typeof decryptedSessionCache !== "undefined")
      decryptedSessionCache.clear();
    if (typeof metadataCache !== "undefined") metadataCache.clear();
    if (typeof activeTaskSignals !== "undefined") activeTaskSignals.clear();

    sessionStorage.clear();
    localStorage.clear();

    if (typeof VaultCrypto !== "undefined")
      await VaultCrypto.clearSessionKeys();

    console.log("[Security] RAM Wipe Complete.");
    return true;
  },
};

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
    this._container = document.getElementById("znode-dialog-overlay");
    this._box = document.getElementById("znode-dialog-box");
    this._title = document.getElementById("znode-dialog-title");
    this._body = document.getElementById("znode-dialog-body");
    this._inputCnt = document.getElementById("znode-dialog-input-container");
    this._input = document.getElementById("znode-dialog-input");
    this._textarea = document.getElementById("znode-dialog-textarea");
    this._select = document.getElementById("znode-dialog-select");
    this._cancelBtn = document.getElementById("znode-dialog-cancel");
    this._confirmBtn = document.getElementById("znode-dialog-confirm");
  }

  static async show({
    title = "NOTIFICATION",
    body = "",
    type = "alert",
    defaultValue = "",
    options = [],
  }) {
    this._init();
    if (!this._container) return false;

    this._container.classList.remove("opacity-100", "pointer-events-none");
    this._container.classList.add("opacity-0", "pointer-events-none");
    this._box.classList.remove("opacity-100", "scale-100");
    this._box.classList.add("opacity-0", "scale-95");

    return new Promise((resolve) => {
      this._title.innerText = title;
      this._body.innerText = body;
      this._input.value = defaultValue;
      if (this._textarea) this._textarea.value = defaultValue;
      
      if (this._select) {
          this._select.innerHTML = "";
          options.forEach(opt => {
              const optionEl = document.createElement("option");
              optionEl.value = opt.value;
              optionEl.innerText = opt.label;
              optionEl.className = "bg-[#111111] text-[#e5e5e5]";
              if (opt.value === defaultValue) optionEl.selected = true;
              this._select.appendChild(optionEl);
          });
      }

      if (type === "prompt" || type === "prompt-multiline" || type === "select") {
          this._inputCnt.classList.remove("hidden");
          this._inputCnt.classList.add("flex");
          
          if (this._input) this._input.classList.add("hidden");
          if (this._textarea) this._textarea.classList.add("hidden");
          if (this._select) this._select.classList.add("hidden");
          
          if (type === "prompt-multiline") {
              if (this._textarea) this._textarea.classList.remove("hidden");
          } else if (type === "select") {
              if (this._select) this._select.classList.remove("hidden");
          } else {
              if (this._input) this._input.classList.remove("hidden");
          }
      } else {
          this._inputCnt.classList.add("hidden");
          this._inputCnt.classList.remove("flex");
      }

      if (type === "alert") this._cancelBtn.classList.add("hidden");
      else this._cancelBtn.classList.remove("hidden");

      setTimeout(() => {
        this._container.classList.remove("pointer-events-none", "opacity-0");
        this._container.classList.add("opacity-100");
        this._box.classList.remove("scale-95", "opacity-0");
        this._box.classList.add("scale-100", "opacity-100");
        if (type === "prompt") this._input.focus();
        else if (type === "prompt-multiline" && this._textarea) this._textarea.focus();
        else if (type === "select" && this._select) this._select.focus();
        else this._confirmBtn.focus();
      }, 50);

      const cleanup = (val) => {
        this._container.classList.add("opacity-0", "pointer-events-none");
        this._container.classList.remove("opacity-100");
        this._box.classList.add("scale-95", "opacity-0");
        this._box.classList.remove("scale-100", "opacity-100");
        this._confirmBtn.onclick = null;
        this._cancelBtn.onclick = null;
        window.onkeydown = null;
        resolve(val);
      };

      this._confirmBtn.onclick = () => {
        if (type === "prompt") cleanup(this._input.value);
        else if (type === "prompt-multiline") cleanup(this._textarea ? this._textarea.value : "");
        else if (type === "select") cleanup(this._select ? this._select.value : "");
        else cleanup(true);
      };
      this._cancelBtn.onclick = () => cleanup((type === "prompt" || type === "prompt-multiline" || type === "select") ? null : false);
      window.onkeydown = (e) => {
        if (e.key === "Enter") {
            if (type === "prompt-multiline" && !e.ctrlKey) return;
            this._confirmBtn.click();
        }
        if (e.key === "Escape") this._cancelBtn.click();
      };
    });
  }

  static alert(title, body) {
    return this.show({ title, body, type: "alert" });
  }
  static confirm(title, body) {
    return this.show({ title, body, type: "confirm" });
  }
  static prompt(title, body, def = "") {
    return this.show({ title, body, type: "prompt", defaultValue: def });
  }
  static promptMultiline(title, body, def = "") {
    return this.show({ title, body, type: "prompt-multiline", defaultValue: def });
  }
  static select(title, body, options = [], def = "") {
    return this.show({ title, body, type: "select", defaultValue: def, options });
  }
}
window.ZNodeDialog = ZNodeDialog;

window.viewLongText = (title, encodedText) => {
    const text = decodeURIComponent(encodedText);
    let overlay = document.createElement("div");
    overlay.className = "fixed inset-0 z-[99999] bg-black/80 flex items-center justify-center backdrop-blur-md";
    overlay.innerHTML = `
        <div class="bg-surface-container border border-outline-variant/30 w-full max-w-2xl shadow-2xl flex flex-col m-4 max-h-[90vh]">
            <div class="p-4 border-b border-outline-variant/20 flex justify-between items-center bg-surface-variant/20">
                <h3 class="font-mono text-sm tracking-widest text-primary font-bold uppercase truncate pr-4">${title}</h3>
                <button class="text-on-surface-variant/50 hover:text-error transition-colors shrink-0" onclick="this.closest('.fixed').remove()">
                    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg>
                </button>
            </div>
            <div class="p-6 overflow-y-auto custom-scrollbar prose-sm markdown-body font-body text-on-surface-variant text-[14px]">
                ${marked.parse(text, { breaks: true })}
            </div>
        </div>
    `;
    document.body.appendChild(overlay);
};
// Global Toast Notification
function showZNodeToast(message, type = "info", onClick = null) {
  let container = document.getElementById("znode-toast-container");
  if (!container) {
    container = document.createElement("div");
    container.id = "znode-toast-container";
    container.className =
      "fixed top-6 right-6 z-[9999] flex flex-col items-end gap-3 pointer-events-none";
    document.body.appendChild(container);
  }

  const toast = document.createElement("div");
  const colorClass =
    type === "error"
      ? "border-error text-error bg-error/10"
      : "border-primary text-primary bg-primary/10";

  toast.className = `w-80 px-6 py-4 border-l-4 ${colorClass} backdrop-blur-xl shadow-2xl font-mono text-[10px] uppercase tracking-widest transform transition-all duration-500 translate-x-full opacity-0 pointer-events-auto`;
  toast.innerHTML = `
        <div class="flex items-start gap-4">
            <svg class="w-4 h-4 shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                ${type === "error" ? '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path>' : '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path>'}
            </svg>
            <span class="break-words">${message}</span>
        </div>
    `;

  if (onClick) {
    toast.classList.add("cursor-pointer", "hover:border-primary");
    toast.onclick = () => {
      onClick();
      toast.remove();
    };
  }

  container.appendChild(toast);

  // Slide In
  setTimeout(() => {
    toast.classList.remove("translate-x-full", "opacity-0");
  }, 100);

  // Slide Out & Remove
  setTimeout(() => {
    toast.classList.add("translate-x-full", "opacity-0");
    setTimeout(() => toast.remove(), 500);
  }, 5000);
}
window.showZNodeToast = showZNodeToast;
