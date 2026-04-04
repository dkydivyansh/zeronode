// --- 1. Global State & Task Registry ---
let activeTransfers = 0;
const activeTaskSignals = new Map(); // uuid -> Promise
const decryptedSessionCache = new Map(); // uuid -> Blob
const metadataCache = new Map(); // uuid -> Object
const previewUrls = new Map(); // uuid -> objectURL

// Queue System
const uploadQueue = [];
let activeUploadCount = 0;
const MAX_CONCURRENT_UPLOADS = 2;

// --- 2. Drive Crypto Extender ---
class DriveCrypto {
  static async getVaultMasterKey() {
    const privKey = await VaultCrypto.getSessionKey();
    const pubB64 = sessionStorage.getItem("vault_pub");

    if (!privKey || !pubB64) {
      throw new Error("Vault not unlocked in session.");
    }

    const pubBuf = base64ToBuffer(pubB64);
    const publicKey = await crypto.subtle.importKey(
      "spki",
      pubBuf,
      { name: "ECDH", namedCurve: "P-256" },
      false,
      [],
    );

    return await crypto.subtle.deriveKey(
      { name: "ECDH", public: publicKey },
      privKey,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"],
    );
  }

  static async generateFileKey() {
    return await crypto.subtle.generateKey(
      { name: "AES-GCM", length: 256 },
      true,
      ["encrypt", "decrypt"],
    );
  }

  static async wrapFileKey(fileKeyObj, masterKey) {
    const raw = await crypto.subtle.exportKey("raw", fileKeyObj);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: iv },
      masterKey,
      raw,
    );

    const packed = new Uint8Array(iv.length + ciphertext.byteLength);
    packed.set(iv, 0);
    packed.set(new Uint8Array(ciphertext), iv.length);
    return bufferToBase64(packed);
  }

  static async unwrapFileKey(wrappedB64, masterKey) {
    const packed = new Uint8Array(base64ToBuffer(wrappedB64));
    const iv = packed.slice(0, 12);
    const ciphertext = packed.slice(12);

    const raw = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: iv },
      masterKey,
      ciphertext,
    );
    return await crypto.subtle.importKey(
      "raw",
      raw,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"],
    );
  }
}

// --- 3. E2EE Cache (IndexedDB) ---
const DB_NAME = "ZeroNodeVaultCache";
const STORE_NAME = "encrypted_blobs";
let _db = null;

async function openCacheDB() {
  if (_db) return _db;
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, 1);
    req.onupgradeneeded = (e) => {
      const db = e.target.result;
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        db.createObjectStore(STORE_NAME, { keyPath: "uuid" });
      }
    };
    req.onsuccess = (e) => {
      _db = e.target.result;
      resolve(_db);
    };
    req.onerror = (e) => reject(e.target.error);
  });
}

async function cacheFile(uuid, encryptedBlob, metadata = null) {
  const db = await openCacheDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, "readwrite");
    const store = tx.objectStore(STORE_NAME);
    
    // Merge metadata if provided, or keep existing if only updating blob
    const entry = { uuid: uuid, blob: encryptedBlob };
    if (metadata) entry.metadata = metadata;

    store.put(entry);
    tx.oncomplete = () => {
      resolve();
      updateCacheCountUI();
    };
    tx.onerror = reject;
  });
}

async function getCachedFile(uuid) {
  const db = await openCacheDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, "readonly");
    const store = tx.objectStore(STORE_NAME);
    const req = store.get(uuid);
    req.onsuccess = () => resolve(req.result || null);
    req.onerror = reject;
  });
}

async function clearCache() {
  const db = await openCacheDB();
  
  // 1. Flush RAM Previews (Essential for Privacy)
  previewUrls.forEach((url) => URL.revokeObjectURL(url));
  previewUrls.clear();
  
  // 2. Flush Decrypted RAM Fragments
  decryptedSessionCache.clear();
  metadataCache.clear();

  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, "readwrite");
    const store = tx.objectStore(STORE_NAME);
    store.clear();
    tx.oncomplete = () => {
      resolve();
      updateCacheCountUI();
      // 3. UI Sync - If we are in a preview, close it as the source is gone
      const previewModal = document.getElementById("drive-preview-modal");
      if (previewModal && !previewModal.classList.contains("hidden")) {
         closeLightbox();
      }
      // Reload drive to show "fresh" state
      if (document.getElementById("item-container")) fetchDrive(currentFolderId);
    };
    tx.onerror = reject;
  });
}

async function updateCacheCountUI() {
  try {
    const db = await openCacheDB();
    const tx = db.transaction(STORE_NAME, "readonly");
    const count = await new Promise((resolve, reject) => {
      const req = tx.objectStore(STORE_NAME).count();
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });

    const btn = document.getElementById("dynamic-cache");
    if (btn) {
      btn.innerHTML = `CACHE [${count}]`;
      btn.classList.remove("hidden");

      if (count > 0) {
        btn.className =
          "font-mono text-[9px] tracking-widest text-error border border-error/40 bg-error/5 px-2 py-0.5 hover:bg-error hover:text-black transition-all interactive-el uppercase ml-4";
      } else {
        btn.className =
          "font-mono text-[9px] tracking-widest text-primary/40 border border-primary/10 px-2 py-0.5 hover:bg-primary/20 hover:text-primary transition-all interactive-el uppercase ml-4";
      }

      btn.onclick = async () => {
        if (
          await ZNodeDialog.confirm(
            "VAULT CACHE",
            "Clear local encrypted persistent cache? This only affects local speeds, NOT your cloud files.",
          )
        ) {
          await clearCache();
        }
      };
    }
  } catch (e) {
    console.error("[CacheUI] Error:", e);
  }
}

// --- 4. Transfer Manager (Global Activity Manager) ---
function hasActivityHistory() {
  const active = document.getElementById("tm-active-list");
  const queued = document.getElementById("tm-queued-list");
  const failed = document.getElementById("tm-failed-list");
  const completed = document.getElementById("tm-completed-list");
  if (!active || !queued || !failed || !completed) return false;
  return (
    active.children.length +
      queued.children.length +
      failed.children.length +
      completed.children.length >
    0
  );
}

function toggleTM(show) {
  const tm = document.getElementById("transfer-manager");
  const body = document.getElementById("tm-body");
  if (!tm || !body) return;
  if (show || hasActivityHistory()) {
    tm.style.display = "flex";
    body.style.maxHeight = "380px";
  } else {
    body.style.maxHeight = "0px";
  }
}

function addTransfer(id, name, type) {
  activeTransfers++;
  toggleTM(true);
  const badge = document.getElementById("tm-badge");
  if (badge) badge.innerText = activeTransfers;

  let containerId = type === "QUEUED" ? "tm-queued-list" : "tm-active-list";
  if (type === "QUEUED") type = "ENCRYPT"; // Default type for queue visibility

  let container = document.getElementById(containerId);
  if (!container) return;

  const isEnc = type === "ENCRYPT";
  const typeColor = isEnc ? "text-primary" : "text-accent";
  const barClass =
    containerId === "tm-queued-list"
      ? "bg-surface-variant/30"
      : isEnc
        ? "bg-primary"
        : "bg-accent";

  let el = document.createElement("div");
  el.id = `tf-${id}`;
  el.className =
    "flex flex-col gap-1 p-3 border-b border-outline-variant/10 hover:bg-surface-variant transition-all";
  el.innerHTML = `
        <div class="flex justify-between items-center text-[9px] font-mono leading-none">
            <div class="flex items-center gap-1.5 status-row">
                <span class="tf-type ${typeColor} font-bold uppercase tracking-wider">[ ${type} ]</span>
                <span class="tf-status text-on-surface-variant/40 font-bold uppercase tracking-wider">[ PENDING ]</span>
            </div>
            <span id="tf-pct-${id}" class="tf-pct text-on-surface-variant/70 font-bold opacity-0">0%</span>
        </div>
        <div class="text-[11px] font-label text-on-surface truncate pr-2 mt-1 px-0.5">${name}</div>
        <div class="w-full bg-surface-variant h-[1px] mt-2 rounded-full overflow-hidden">
            <div id="tf-bar-${id}" class="h-full ${barClass} transition-all duration-300" style="width: 0%"></div>
        </div>
    `;
  container.appendChild(el);
}

function updateBadge() {
  const badge = document.getElementById("tm-badge");
  if (badge) {
    activeTransfers = Math.max(0, activeTransfers);
    badge.innerText = activeTransfers;
  }
}

function promoteTransfer(id, type) {
  const el = document.getElementById(`tf-${id}`);
  const activeList = document.getElementById("tm-active-list");
  if (!el || !activeList) return;

  const isEnc = type === "ENCRYPT";
  const typeColor = isEnc ? "text-primary" : "text-accent";
  const barClass = isEnc ? "bg-primary" : "bg-accent";

  const typeEl = el.querySelector(".tf-type");
  const statusEl = el.querySelector(".tf-status");
  const pctEl = el.querySelector(".tf-pct");
  const barEl = el.querySelector(`#tf-bar-${id}`);

  if (typeEl) {
    typeEl.className = `tf-type ${typeColor} font-bold uppercase tracking-wider`;
    typeEl.innerText = `[ ${type} ]`;
  }
  if (statusEl) {
    statusEl.innerText = "[ ACTIVE ]";
    statusEl.className = `tf-status ${typeColor} font-bold uppercase tracking-wider animate-pulse`;
  }
  if (pctEl) pctEl.classList.remove("opacity-0");
  if (barEl) barEl.className = `h-full ${barClass} transition-all duration-300`;

  // Priority Shift
  activeList.prepend(el);
}

async function fetchWithRetry(url, options, retries = 3) {
  for (let i = 0; i < retries; i++) {
    try {
      const res = await fetch(url, options);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return res;
    } catch (err) {
      if (i === retries - 1) throw err;
      await new Promise((r) => setTimeout(r, 1000 * (i + 1))); // Exponential backoff
    }
  }
}

function updateTransfer(id, pct) {
  const pctEl = document.getElementById(`tf-pct-${id}`);
  const barEl = document.getElementById(`tf-bar-${id}`);
  const clampedPct = Math.min(100, Math.max(0, pct));
  if (pctEl) {
    pctEl.innerText = `${Math.round(clampedPct)}%`;
    pctEl.classList.remove("opacity-0");
  }
  if (barEl) barEl.style.width = `${clampedPct}%`;
}

function completeTransfer(id) {
  const el = document.getElementById(`tf-${id}`);
  const completedList = document.getElementById("tm-completed-list");
  
  // Safety: Prevent double-counting or processing non-existent items
  if (!el || el.dataset.processed === "true") return;
  el.dataset.processed = "true";

  if (activeTransfers > 0) activeTransfers--;
  updateBadge();

  el.classList.add("bg-tertiary/10", "border-tertiary/10");
  el.classList.remove("hover:bg-surface-variant"); // Lock the success color
  const statusEl = el.querySelector(".tf-status");
  const barEl = el.querySelector(`#tf-bar-${id}`);

  if (statusEl) {
    statusEl.innerText = "[ COMPLETED ]";
    statusEl.className =
      "tf-status text-tertiary font-bold uppercase tracking-wider";
    statusEl.classList.remove("animate-pulse");
  }
  if (barEl) {
    barEl.className = "h-full bg-tertiary transition-all duration-300";
    barEl.style.width = "100%";
  }

  // Archive it
  completedList.prepend(el);
}

function failTransfer(id) {
  const el = document.getElementById(`tf-${id}`);
  const failedList = document.getElementById("tm-failed-list");
  
  // Safety: Prevent double-counting
  if (!el || el.dataset.processed === "true") return;
  el.dataset.processed = "true";

  if (activeTransfers > 0) activeTransfers--;
  updateBadge();

  const pctEl = document.getElementById(`tf-pct-${id}`);
  const barEl = document.getElementById(`tf-bar-${id}`);

  if (el && failedList) {
    el.classList.add("bg-error/5", "border-error/20");
    const statusEl = el.querySelector(".tf-status");
    if (statusEl) {
      statusEl.innerText = "[ FAILED ]";
      statusEl.className =
        "tf-status text-error font-bold uppercase tracking-wider";
      statusEl.classList.remove("animate-pulse");
    }
    failedList.prepend(el);
  }
  if (pctEl) {
    pctEl.innerHTML = `<span class="text-error font-bold">ERR</span>`;
    pctEl.classList.remove("opacity-0");
  }
  if (barEl) {
    barEl.className = "h-full bg-error transition-all duration-300";
    barEl.style.width = "100%";
  }
}

function showZNodeToast(message, type = "info") {
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

// --- 5. Drive Rendering & Logic (Conditional) ---
let currentFolderId = null;
let currentView = "grid"; // 'grid' | 'list'
let activeCtxItem = null;
let activePreviewItem = null;

async function fetchDrive(folderId = null) {
  currentFolderId = folderId;
  
  // 1. Immediate Visual Feedback
  const container = document.getElementById("item-container");
  if (container) {
      container.innerHTML = `
        <div class="col-span-full flex flex-col items-center justify-center py-28 text-on-surface-variant/30 animate-pulse">
            <div class="vault-spinner mb-4 border-on-surface-variant/30 border-t-primary" style="display: block;"></div>
            <span class="font-mono text-[10px] tracking-[0.5em] uppercase">FETCHING MANIFEST...</span>
        </div>`;
  }

  // Clear previews on navigation
  previewUrls.forEach((url) => URL.revokeObjectURL(url));
  previewUrls.clear();

  const url = folderId
    ? `/app/api/drive/list/${folderId}`
    : `/app/api/drive/list`;
  try {
    const res = await fetch(url);
    if (!res.ok) throw new Error("API Error");
    const data = await res.json();
    const mapped = [
      ...data.folders.map((f) => ({
        ...f,
        type: "folder",
        size: f.item_count || 0,
        modified: f.created_at || f.last_modified || new Date(),
      })),
      ...data.files.map((f) => ({
        ...f,
        id: f.uuid,
        name: f.file_name,
        type: "file",
        size: f.file_size,
        modified: f.last_modified,
      })),
    ];
    renderDrive(mapped);
    renderBreadcrumbs(data.path);
  } catch (err) {
    console.error("Failed to load drive:", err);
  }
}

function renderBreadcrumbs(pathArray) {
  const bc = document.getElementById("drive-breadcrumbs");
  if (!bc) return;
  bc.innerHTML = `<a href="#" class="hover:text-primary transition-colors interactive-el root-nav" data-id="">Drive</a>`;

  pathArray.forEach((seg, idx) => {
    bc.innerHTML += ` <span class="text-on-surface-variant/30">/</span> `;
    if (idx === pathArray.length - 1) {
      bc.innerHTML += `<span class="text-on-surface">${seg.name}</span>`;
      const label = document.getElementById("drive-current-folder");
      if (label) label.innerText = seg.name;
    } else {
      bc.innerHTML += `<a href="#" class="hover:text-primary transition-colors interactive-el bc-nav" data-id="${seg.id}">${seg.name}</a>`;
    }
  });

  if (pathArray.length === 0) {
    const label = document.getElementById("drive-current-folder");
    if (label) label.innerText = "ROOT DIRECTORY";
  }

  document.querySelectorAll(".root-nav, .bc-nav").forEach((el) => {
    el.onclick = (e) => {
      e.preventDefault();
      fetchDrive(e.target.getAttribute("data-id") || null);
    };
  });
}

function formatSize(bytes) {
  if (bytes === 0) return "0 B";
  const k = 1024,
    sizes = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + " " + sizes[i];
}

function getNameWithoutMD(name) {
  if (name && name.toLowerCase().endsWith(".md")) {
    return name.slice(0, -3);
  }
  return name || "";
}

async function createNewNote() {
  const title = await ZNodeDialog.prompt("NEW NOTE", "Enter note title:");
  if (!title) return;

  let fileName = title;
  if (!fileName.toLowerCase().endsWith(".md")) fileName += ".md";

  const initialContent = `# ${title}\n\n`;
  const tfId = Math.random().toString(36).substr(2, 9);
  addTransfer(tfId, fileName, "ENCRYPT");

  try {
    const masterKey = await DriveCrypto.getVaultMasterKey();
    const fileKey = await DriveCrypto.generateFileKey();
    const wrappedKey64 = await DriveCrypto.wrapFileKey(fileKey, masterKey);

    const initRes = await fetch("/app/api/file/init", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        file_name: fileName,
        aes_key: wrappedKey64,
        folder_id: currentFolderId,
      }),
    });
    const { uuid } = await initRes.json();

    const encoder = new TextEncoder();
    const arrayBuf = encoder.encode(initialContent);
    const iv = new Uint8Array(12);
    const enc = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: iv },
      fileKey,
      arrayBuf,
    );

    await fetch(`/app/api/file/${uuid}/chunk`, {
      method: "POST",
      headers: {
        "X-Chunk-Offset": "0",
        "Content-Type": "application/octet-stream",
      },
      body: enc,
    });

    await fetch(`/app/api/file/${uuid}/finalize`, { method: "POST" });

    completeTransfer(tfId);
    showZNodeToast(`NOTE CREATED: ${title}`, "info");
    await fetchDrive(currentFolderId);

    // Auto-open
    openLightbox({
      id: uuid,
      uuid: uuid,
      name: fileName,
      type: "file",
      size: arrayBuf.byteLength,
      sizeStr: formatSize(arrayBuf.byteLength),
      modifiedStr: new Date().toLocaleDateString(),
    });

    setTimeout(() => {
      const pb = document.getElementById("pv-preview-btn");
      if (pb) pb.click();
    }, 500);
  } catch (e) {
    console.error(e);
    failTransfer(tfId);
    showZNodeToast(`FAILED TO CREATE NOTE: ${e.message}`, "error");
  }
}

function initMarkdownEditor(uuid, fileName, content) {
  const pvContent = document.getElementById("pv-content");
  if (!pvContent) return;

  // Add Editor Styles if missing
  if (!document.getElementById("md-editor-styles")) {
    const style = document.createElement("style");
    style.id = "md-editor-styles";
    style.innerHTML = `
      .md-tool { 
        width: 32px; 
        height: 32px; 
        display: flex; 
        align-items: center; 
        justify-content: center;
        font-family: var(--font-label);
        font-size: 11px;
        border: 1px solid rgba(255,255,255,0.05);
      }
      #md-formatted h1 { font-family: var(--font-headline); font-size: 1.8rem; border-bottom: 1px solid rgba(255,255,255,0.1); padding-bottom: 0.5rem; margin-bottom: 1.5rem; }
      #md-formatted h2 { font-family: var(--font-headline); font-size: 1.4rem; margin-top: 2rem; margin-bottom: 1rem; }
      #md-formatted h3 { font-family: var(--font-headline); font-size: 1.1rem; margin-top: 1.5rem; margin-bottom: 0.8rem; text-transform: uppercase; letter-spacing: 0.1em; opacity: 0.8; }
      #md-formatted p { font-family: var(--font-body); line-height: 1.8; margin-bottom: 1.2rem; color: rgba(255,255,255,0.8); }
      #md-formatted ul { list-style: disc; padding-left: 1.5rem; margin-bottom: 1.2rem; }
      #md-formatted ol { list-style: decimal; padding-left: 1.5rem; margin-bottom: 1.2rem; }
      #md-formatted blockquote { border-left: 3px solid var(--color-primary); padding-left: 1.4rem; font-style: italic; opacity: 0.7; margin: 1.5rem 0; color: var(--color-primary-dim); }
      #md-formatted pre { background: rgba(255,255,255,0.03); padding: 1rem; border-radius: 4px; font-family: var(--font-mono); font-size: 11px; margin: 1rem 0; overflow-x: auto; border: 1px solid rgba(255,255,255,0.05); }
      #md-formatted code { background: rgba(255,255,255,0.1); padding: 0.2rem 0.4rem; font-family: var(--font-mono); font-size: 10px; border-radius: 2px; }
      #md-formatted a { color: var(--color-primary); text-decoration: underline; text-underline-offset: 4px; opacity: 0.8; }
    `;
    document.head.appendChild(style);
  }

  const editorHtml = `
      <div class="flex flex-col w-full h-full bg-surface-container overflow-hidden">
          <div class="flex border-b border-outline-variant/20 bg-surface-container-high h-[54px] shrink-0 items-center px-6 justify-between shadow-lg z-20">
              <div class="flex items-center gap-4">
                  <div class="flex items-center gap-1 border-r border-outline-variant/20 pr-4 mr-1" id="md-toolbar">
                      <button class="md-tool p-1.5 hover:bg-surface-variant text-on-surface-variant/60 hover:text-primary transition-all rounded" title="Heading 1" data-cmd="formatBlock" data-val="h1"><b>H1</b></button>
                      <button class="md-tool p-1.5 hover:bg-surface-variant text-on-surface-variant/60 hover:text-primary transition-all rounded" title="Heading 2" data-cmd="formatBlock" data-val="h2"><b>H2</b></button>
                      <button class="md-tool p-1.5 hover:bg-surface-variant text-on-surface-variant/60 hover:text-primary transition-all rounded text-[9px]" title="Heading 3" data-cmd="formatBlock" data-val="h3"><b>H3</b></button>
                      <div class="w-[1px] h-4 bg-outline-variant/20 mx-1"></div>
                      <button class="md-tool p-1.5 hover:bg-surface-variant text-on-surface-variant/60 hover:text-primary transition-all rounded" title="Bold" data-cmd="bold"><b>B</b></button>
                      <button class="md-tool p-1.5 hover:bg-surface-variant text-on-surface-variant/60 hover:text-primary transition-all rounded italic" title="Italic" data-cmd="italic">I</button>
                      <button class="md-tool p-1.5 hover:bg-surface-variant text-on-surface-variant/60 hover:text-primary transition-all rounded line-through" title="Strikethrough" data-cmd="strikeThrough">S</button>
                      <div class="w-[1px] h-4 bg-outline-variant/20 mx-1"></div>
                      <button class="md-tool p-1.5 hover:bg-surface-variant text-on-surface-variant/60 hover:text-primary transition-all rounded" title="Quote" data-cmd="formatBlock" data-val="blockquote">“</button>
                      <button class="md-tool p-1.5 hover:bg-surface-variant text-on-surface-variant/60 hover:text-primary transition-all rounded" title="Code" data-cmd="formatBlock" data-val="pre"><b>&lt;/&gt;</b></button>
                      <div class="w-[1px] h-4 bg-outline-variant/20 mx-1"></div>
                      <button class="md-tool p-1.5 hover:bg-surface-variant text-on-surface-variant/60 hover:text-primary transition-all rounded" title="Bullet List" data-cmd="insertUnorderedList">•</button>
                      <button class="md-tool p-1.5 hover:bg-surface-variant text-on-surface-variant/60 hover:text-primary transition-all rounded" title="Numbered List" data-cmd="insertOrderedList">1.</button>
                      <button class="md-tool p-1.5 hover:bg-surface-variant text-on-surface-variant/60 hover:text-primary transition-all rounded" title="Link" data-cmd="createLink">🔗</button>
                  </div>
                  <button id="md-toggle-raw" class="font-mono text-[9px] tracking-[0.2em] text-primary/40 hover:text-primary uppercase transition-colors px-3 py-1.5 border border-primary/10 hover:bg-primary/5">
                    SEE RAW
                  </button>
              </div>
              <div class="flex items-center gap-3">
                  <button id="md-save-btn" class="bg-primary/10 border border-primary/30 text-primary hover:bg-primary hover:text-black font-label text-[10px] tracking-[0.2em] px-8 py-2.5 uppercase transition-all flex items-center gap-2 group">
                     <span id="md-save-text">SAVE TO VAULT</span>
                     <svg class="w-3 h-3 group-hover:animate-bounce" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M9 19l3 3m0 0l3-3m-3 3V10"></path></svg>
                  </button>
                  <button id="md-close-btn" class="text-on-surface-variant/30 hover:text-error transition-all p-2" title="Exit Note Studio">
                      <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M6 18L18 6M6 6l12 12"></path></svg>
                  </button>
              </div>
          </div>
          <div class="flex-1 flex overflow-hidden relative">
              <div id="md-formatted" contenteditable="true" class="flex-1 bg-surface p-16 md:px-24 lg:px-48 overflow-y-auto focus:outline-none leading-relaxed transition-all duration-300 selection:bg-primary/30 prose prose-invert max-w-none scroll-smooth h-full" spellcheck="true" placeholder="Vault Note Content..."></div>
              <textarea id="md-raw" class="flex-1 bg-[#020202] text-on-surface font-mono text-[11px] p-16 md:p-24 resize-none focus:outline-none focus:ring-0 leading-loose overflow-y-auto hidden selection:bg-primary/30 h-full border-l border-outline-variant/10"></textarea>
          </div>
      </div>
  `;

  pvContent.innerHTML = editorHtml;

  const formatted = document.getElementById("md-formatted");
  const raw = document.getElementById("md-raw");
  const toggleRawBtn = document.getElementById("md-toggle-raw");
  const saveBtn = document.getElementById("md-save-btn");
  const saveText = document.getElementById("md-save-text");

  // Initial Content Sync: MD -> HTML -> Editor
  if (window.marked) {
    formatted.innerHTML = window.marked.parse(content || "");
  } else {
    formatted.innerText = content;
  }

  // Setup Turndown for saving
  let turndown;
  if (window.TurndownService) {
    turndown = new window.TurndownService({
       headingStyle: 'atx',
       hr: '---',
       bulletListMarker: '-',
       codeBlockStyle: 'fenced'
    });
  }

  let isRawMode = false;
  toggleRawBtn.onclick = () => {
    isRawMode = !isRawMode;
    if (isRawMode) {
      // Formatted -> Raw
      raw.value = turndown ? turndown.turndown(formatted.innerHTML) : formatted.innerText;
      formatted.classList.add("hidden");
      raw.classList.remove("hidden");
      toggleRawBtn.innerText = "EXIT RAW";
      toggleRawBtn.classList.add("bg-primary/10", "text-primary");
      document.getElementById("md-toolbar").style.opacity = "0.3";
      document.getElementById("md-toolbar").style.pointerEvents = "none";
    } else {
      // Raw -> Formatted
      formatted.innerHTML = window.marked ? window.marked.parse(raw.value) : raw.value;
      raw.classList.add("hidden");
      formatted.classList.remove("hidden");
      toggleRawBtn.innerText = "SEE RAW";
      toggleRawBtn.classList.remove("bg-primary/10", "text-primary");
      document.getElementById("md-toolbar").style.opacity = "1";
      document.getElementById("md-toolbar").style.pointerEvents = "auto";
    }
  };

  // Toolbar Implementation
  document.querySelectorAll(".md-tool").forEach((btn) => {
    btn.onclick = (e) => {
      e.preventDefault();
      const cmd = btn.dataset.cmd;
      const val = btn.dataset.val || null;
      
      if (cmd === 'createLink') {
        const url = prompt("Enter URL:", "https://");
        if (url) document.execCommand(cmd, false, url);
      } else {
        document.execCommand(cmd, false, val);
      }
      formatted.focus();
    };
  });

  const internalCloseBtn = document.getElementById("md-close-btn");
  if (internalCloseBtn) internalCloseBtn.onclick = closeLightbox;

  if (saveBtn) {
    saveBtn.onclick = async () => {
      const tfId = Math.random().toString(36).substr(2, 9);
      addTransfer(tfId, fileName, "ENCRYPT");
      
      saveBtn.disabled = true;
      saveText.innerText = "ENCRYPTING...";

      try {
        const metadata = metadataCache.get(uuid);
        const masterKey = await DriveCrypto.getVaultMasterKey();
        const fileKey = await DriveCrypto.unwrapFileKey(metadata.aes_key, masterKey);

        saveText.innerText = "SAVING...";
        // Skip UPLOAD event for notes as requested, just keep ENCRYPT visible
        // promoteTransfer(tfId, "UPLOAD");
        
        // Final Sync to MD
        let mdOutput;
        if (isRawMode) {
            mdOutput = raw.value;
        } else {
            mdOutput = turndown ? turndown.turndown(formatted.innerHTML) : formatted.innerText;
        }

        const encoder = new TextEncoder();
        const arrayBuf = encoder.encode(mdOutput);
        const iv = new Uint8Array(12);
        const enc = await crypto.subtle.encrypt(
          { name: "AES-GCM", iv: iv },
          fileKey,
          arrayBuf,
        );

        const res = await fetch(`/app/api/file/${uuid}/content`, {
          method: "PUT",
          headers: { "Content-Type": "application/octet-stream" },
          body: enc,
        });

        if (!res.ok) throw new Error("Save Error");

        saveText.innerText = "SAVED TO VAULT";
        completeTransfer(tfId);
        
        // Skip session caching for .md files as requested
        // decryptedSessionCache.set(uuid, new Blob([arrayBuf], { type: "text/markdown" }));

        setTimeout(() => {
          saveText.innerText = "SAVE TO VAULT";
          saveBtn.disabled = false;
        }, 1500);
      } catch (err) {
        console.error(err);
        failTransfer(tfId);
        saveText.innerText = "ERROR";
        setTimeout(() => {
          saveText.innerText = "SAVE TO VAULT";
          saveBtn.disabled = false;
        }, 3000);
      }
    };
  }
}

function getFileIcon(name, type, sizeClass = "w-8 h-8") {
  if (type === "folder") {
    return `<svg class="${sizeClass} text-primary/80 mb-2" fill="currentColor" viewBox="0 0 20 20"><path d="M2 6a2 2 0 012-2h5l2 2h5a2 2 0 012 2v6a2 2 0 01-2 2H4a2 2 0 01-2-2V6z"></path></svg>`;
  }

  const ext = name.split(".").pop().toLowerCase();
  const commonClasses = `${sizeClass} text-on-surface-variant/80 mb-2`;

  // Icon Mapping
  if (["jpg", "jpeg", "png", "gif", "webp", "svg", "bmp"].includes(ext)) {
    // Image Icon
    return `<svg class="${commonClasses}" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M4 16l4.586-4.586a2 2 0 012.828 0L16 16m-2-2l1.586-1.586a2 2 0 012.828 0L20 14m-6-6h.01M6 20h12a2 2 0 002-2V6a2 2 0 00-2-2H6a2 2 0 00-2 2v12a2 2 0 002 2z"></path></svg>`;
  }
  if (["mp4", "webm", "mov", "avi", "mkv"].includes(ext)) {
    // Video Icon
    return `<svg class="${commonClasses}" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M15 10l4.553-2.276A1 1 0 0121 8.618v6.764a1 1 0 01-1.447.894L15 14M5 18h8a2 2 0 002-2V8a2 2 0 00-2-2H5a2 2 0 00-2 2v8a2 2 0 002 2z"></path></svg>`;
  }
  if (["mp3", "wav", "flac", "m4a", "ogg"].includes(ext)) {
    // Audio Icon
    return `<svg class="${commonClasses}" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M9 19V6l12-3v13M9 19c0 1.105-1.343 2-3 2s-3-.895-3-2 1.343-2 3-2 3 .895 3 2zm12-3c0 1.105-1.343 2-3 2s-3-.895-3-2 1.343-2 3-2 3 .895 3 2zM9 10l12-3"></path></svg>`;
  }
  if (["zip", "rar", "7z", "tar", "gz", "bz2"].includes(ext)) {
    // Archive Icon
    return `<svg class="${commonClasses}" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4"></path></svg>`;
  }
  if (
    [
      "js",
      "ts",
      "html",
      "css",
      "py",
      "c",
      "cpp",
      "java",
      "go",
      "rs",
      "php",
      "json",
      "sql",
    ].includes(ext)
  ) {
    // Code Icon
    return `<svg class="${commonClasses} text-secondary/60" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M8 9l3 3-3 3m5 0h3M5 20h14a2 2 0 002-2V6a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z"></path></svg>`;
  }
  if (ext === "pdf") {
    // PDF Icon
    return `<svg class="${commonClasses} text-error/60" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M7 21h10a2 2 0 002-2V9.414a1 1 0 00-.293-.707l-5.414-5.414A1 1 0 0012.586 3H7a2 2 0 00-2 2v14a2 2 0 002 2z"></path><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M9 9h1m2 0h1m-3 3h4m-4 3h4"></path></svg>`;
  }
  if (["csv", "xls", "xlsx"].includes(ext)) {
    // Spreadsheet Icon
    return `<svg class="${commonClasses}" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M3 10h18M3 14h18m-9-4v8m-7 0h14a2 2 0 002-2V6a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z"></path></svg>`;
  }
  if (["txt", "md", "rtf", "log"].includes(ext)) {
    // Text Icon
    return `<svg class="${commonClasses}" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path></svg>`;
  }

  // Default File Icon
  return `<svg class="${commonClasses}" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M7 21h10a2 2 0 002-2V9.414a1 1 0 00-.293-.707l-5.414-5.414A1 1 0 0012.586 3H7a2 2 0 00-2 2v14a2 2 0 002 2z"></path></svg>`;
}

function renderItem(item) {
  const isFolder = item.type === "folder";
  const iconGrid = getFileIcon(
    item.name || item.file_name,
    item.type,
    "w-8 h-8",
  );
  const iconList = getFileIcon(
    item.name || item.file_name,
    item.type,
    "w-5 h-5",
  );

  const sizeStr = isFolder ? `${item.size} items` : formatSize(item.size);
  const hasPreview = previewUrls.has(item.uuid || item.id);
  const previewStyle = hasPreview
    ? `style="background-image: url('${previewUrls.get(item.uuid || item.id)}'); background-size: cover; background-position: center;"`
    : "";

  if (currentView === "grid") {
    const iconHtml = hasPreview ? "" : iconGrid;
    const bgLayer = hasPreview
      ? `<div class="absolute inset-0 bg-black/40 group-hover:bg-black/20 transition-colors z-0"></div>`
      : "";

    return `
        <div class="col-span-1 min-h-[160px] border border-outline-variant/20 bg-surface-container-high hover:bg-surface-variant transition-colors p-4 flex flex-col items-center justify-center cursor-pointer interactive-el group relative drive-item overflow-hidden" data-id="${isFolder ? item.id : item.uuid || item.id}" data-type="${item.type}" data-name="${item.name || item.file_name}" data-size="${item.size}" data-size-str="${sizeStr}" data-modified-str="${new Date(item.modified).toLocaleDateString()}" ${previewStyle}>
            ${bgLayer}
            <div class="relative z-10 flex flex-col items-center justify-center w-full">
                ${iconHtml}
                <span class="font-label text-xs tracking-wider text-on-surface w-full text-center truncate group-hover:text-primary transition-colors ${hasPreview ? "drop-shadow-lg" : ""}">${getNameWithoutMD(item.name || item.file_name)}</span>
                <span class="font-mono text-[9px] text-on-surface-variant/40 mt-1 ${hasPreview ? "text-white/70" : ""}">${sizeStr}</span>
            </div>
        </div>`;
  }

  return `
    <div class="col-span-full border-b border-outline-variant/10 hover:bg-surface-variant transition-colors py-2 px-4 flex items-center justify-between cursor-pointer interactive-el drive-item" data-id="${isFolder ? item.id : item.uuid || item.id}" data-type="${item.type}" data-name="${item.name || item.file_name}" data-size="${item.size}" data-size-str="${sizeStr}" data-modified-str="${new Date(item.modified).toLocaleDateString()}">
        <div class="flex items-center gap-3 w-1/2">
            ${iconList}
            <span class="font-label text-sm tracking-wide text-on-surface truncate">${getNameWithoutMD(item.name || item.file_name)}</span>
        </div>
        <div class="font-mono text-[10px] text-on-surface-variant/40 w-1/4 text-right">${sizeStr}</div>
        <div class="font-mono text-[10px] text-on-surface-variant/40 w-1/4 text-right">${new Date(item.modified).toLocaleDateString()}</div>
    </div>`;
}

function renderDrive(contents) {
  const container = document.getElementById("item-container");
  if (!container) return;
  container.className =
    currentView === "grid"
      ? "grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 xl:grid-cols-8 gap-4 w-full content-start"
      : "flex flex-col w-full content-start";

  const folders = contents
    .filter((c) => c.type === "folder")
    .sort((a, b) => a.name.localeCompare(b.name));
  const files = contents
    .filter((c) => c.type === "file")
    .sort((a, b) => a.name.localeCompare(b.name));

  if (folders.length === 0 && files.length === 0) {
    container.innerHTML = `<div class="col-span-full text-center py-20 font-mono text-xs text-on-surface-variant/30 uppercase tracking-widest">Directory is Empty</div>`;
    return;
  }

  container.innerHTML = [...folders, ...files].map(renderItem).join("");

  document.querySelectorAll(".drive-item").forEach((el) => {
    el.addEventListener("click", () => {
      if (el.dataset.type === "folder") fetchDrive(el.dataset.id);
      else openLightbox(el.dataset);
    });
    el.addEventListener("contextmenu", (e) => {
      e.preventDefault();
      showContextMenu(e.pageX, e.pageY, el.dataset);
    });
  });
}

function showContextMenu(x, y, dataset) {
  const ctxMenu = document.getElementById("context-menu");
  const ctxHeader = document.getElementById("ctx-header");
  const ctxDl = document.getElementById("ctx-download");
  if (!ctxMenu) return;
  activeCtxItem = dataset;
  if (ctxHeader) ctxHeader.innerText = dataset.name;
  if (ctxDl) ctxDl.style.display = dataset.type === "folder" ? "none" : "block";
  ctxMenu.style.left = `${x}px`;
  ctxMenu.style.top = `${y}px`;
  ctxMenu.classList.remove("hidden");
  ctxMenu.classList.add("flex");
}

function openLightbox(dataset) {
  activePreviewItem = dataset;
  const previewModal = document.getElementById("drive-preview-modal");
  const pvName = document.getElementById("pv-name");
  const pvSize = document.getElementById("pv-size");
  const pvType = document.getElementById("pv-type");
  const pvDate = document.getElementById("pv-date");
  const pvContent = document.getElementById("pv-content");
  const pvLoader = document.getElementById("pv-loader");
  const pvPreviewBtn = document.getElementById("pv-preview-btn");

  if (!previewModal) return;

  if (pvName) pvName.innerText = dataset.name;
  if (pvSize) pvSize.innerText = dataset.sizeStr || "0 B";
  if (pvType) pvType.innerText = dataset.name.split(".").pop().toUpperCase();
  if (pvDate)
    pvDate.innerText = dataset.modifiedStr || new Date().toLocaleDateString();

  if (pvContent) {
    pvContent.innerHTML = "";
    pvContent.className =
      "w-full h-full flex items-center justify-center transition-all duration-700 scale-100 opacity-100";
  }
  if (pvLoader) {
    pvLoader.classList.add("opacity-0", "pointer-events-none");
  }

  toggleLightboxButtons(false);
  previewModal.classList.remove("hidden", "opacity-0");
  previewModal.classList.add("flex");
  setTimeout(() => previewModal.classList.add("opacity-100"), 10);

  const ext = dataset.name.split(".").pop().toLowerCase();
  const isMedia = [
    "jpg",
    "jpeg",
    "png",
    "gif",
    "webp",
    "mp4",
    "webm",
    "mp3",
    "wav",
    "pdf",
    "txt",
    "md",
    "js",
    "py",
    "css",
    "html",
  ].includes(ext);
  const isSmall = parseInt(dataset.size || 0) < 100 * 1024 * 1024;

  const footer = document.getElementById("pv-footer");
  if (footer) footer.style.display = ext === "md" ? "none" : "flex";

  if (pvPreviewBtn) {
    pvPreviewBtn.style.display = isMedia && isSmall ? "flex" : "none";
    if (ext === "md") {
      setTimeout(() => pvPreviewBtn.click(), 100);
    }
  }

  if (activeTaskSignals.has(dataset.id)) {
    toggleLightboxButtons(true);
    if (pvLoader) pvLoader.classList.remove("opacity-0", "pointer-events-none");
    activeTaskSignals.get(dataset.id).then(() => {
      if (activePreviewItem && activePreviewItem.id === dataset.id) {
        toggleLightboxButtons(false);
        if (pvLoader)
          pvLoader.classList.add("opacity-0", "pointer-events-none");
      }
    });
  }
}

function closeLightbox() {
  const previewModal = document.getElementById("drive-preview-modal");
  if (!previewModal) return;
  previewModal.classList.remove("opacity-100");
  previewModal.classList.add("opacity-0");
  setTimeout(() => {
    previewModal.classList.add("hidden");
    previewModal.classList.remove("flex");
    const content = document.getElementById("pv-content");
    if (content) content.innerHTML = "";
  }, 500);
}

function toggleLightboxButtons(disabled) {
  const pb = document.getElementById("pv-preview-btn");
  const db = document.getElementById("pv-download-btn");
  [pb, db].forEach((btn) => {
    if (!btn) return;
    btn.disabled = disabled;
    btn.style.opacity = disabled ? "0.5" : "1";
    btn.style.pointerEvents = disabled ? "none" : "auto";
  });
}

function initDriveControls() {
  const itemContainer = document.getElementById("item-container");
  if (!itemContainer) return;

  // Standard Buttons
  const gridBtn = document.getElementById("view-grid-btn");
  const listBtn = document.getElementById("view-list-btn");
  if (gridBtn)
    gridBtn.onclick = () => {
      currentView = "grid";
      fetchDrive(currentFolderId);
    };
  if (listBtn)
    listBtn.onclick = () => {
      currentView = "list";
      fetchDrive(currentFolderId);
    };

  const newNoteBtn = document.getElementById("drive-new-note");
  if (newNoteBtn) {
    newNoteBtn.onclick = createNewNote;
  }

  const newFolderBtn = document.getElementById("dynamic-new-folder");
  if (newFolderBtn)
    newFolderBtn.onclick = () =>
      document.getElementById("modal-new-folder").classList.remove("hidden");

  document
    .querySelectorAll(".modal-close")
    .forEach(
      (b) =>
        (b.onclick = () =>
          document.getElementById("modal-new-folder").classList.add("hidden")),
    );

  const createBtn = document.getElementById("btn-create-folder");
  if (createBtn) {
    createBtn.onclick = async () => {
      const nb = document.getElementById("new-folder-name");
      if (!nb.value || createBtn.disabled) return;

      createBtn.disabled = true;
      const loader = createBtn.querySelector(".btn-loader");
      const text = createBtn.querySelector(".btn-text");
      if (loader) loader.classList.remove("hidden");
      if (text) text.innerText = "HOLD...";

      try {
        await fetch("/app/api/drive/folder", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ name: nb.value, parent_id: currentFolderId }),
        });
        document.getElementById("modal-new-folder").classList.add("hidden");
        nb.value = "";
        fetchDrive(currentFolderId);
      } catch (e) {
        console.error(e);
        showZNodeToast("FAILED TO CREATE ENCRYPTED FOLDER", "error");
      } finally {
        createBtn.disabled = false;
        if (loader) loader.classList.add("hidden");
        if (text) text.innerText = "CREATE";
      }
    };
  }

  // Move Modal
  const moveModal = document.getElementById("modal-move-item");
  const moveBox = document.getElementById("move-modal-box");
  const moveSearch = document.getElementById("move-folder-search");
  const moveCloseBtns = document.querySelectorAll(".move-modal-close");

  const closeMoveModal = () => {
    if (moveBox) moveBox.classList.add("scale-95", "opacity-0");
    setTimeout(() => moveModal.classList.add("hidden"), 300);
  };

  moveCloseBtns.forEach((b) => (b.onclick = closeMoveModal));

  if (moveSearch) {
    moveSearch.oninput = (e) => {
      const q = e.target.value.toLowerCase();
      document.querySelectorAll(".move-folder-item").forEach((el) => {
        const name = el.getAttribute("data-name").toLowerCase();
        el.style.display = name.includes(q) ? "flex" : "none";
      });
    };
  }

  // Search
  let searchTimeout;
  const searchInput = document.getElementById("drive-search");
  if (searchInput) {
    searchInput.oninput = (e) => {
      clearTimeout(searchTimeout);
      searchTimeout = setTimeout(async () => {
        const q = e.target.value;
        if (!q) {
          fetchDrive(currentFolderId);
          return;
        }
        const res = await fetch(
          `/app/api/drive/search?q=${encodeURIComponent(q)}`,
        );
        const data = await res.json();
        const mapped = [
          ...data.folders.map((f) => ({
            ...f,
            type: "folder",
            size: f.item_count || 0,
            modified: new Date(),
          })),
          ...data.files.map((f) => ({
            ...f,
            id: f.uuid,
            type: "file",
            size: f.file_size,
            modified: f.last_modified,
          })),
        ];
        renderDrive(mapped);
        const cur = document.getElementById("drive-current-folder");
        if (cur) cur.innerText = `SEARCH '${q.toUpperCase()}'`;
      }, 400);
    };
  }

  // Context Menu Auto-Hide
  window.addEventListener("click", (e) => {
    const ctxMenu = document.getElementById("context-menu");
    if (ctxMenu && !ctxMenu.classList.contains("hidden")) {
      // Only hide if we're clicking outside the menu
      if (!ctxMenu.contains(e.target)) {
        ctxMenu.classList.add("hidden");
        ctxMenu.classList.remove("flex");
      }
    }
  });

  // Drag and Drop Upload
  const canvas = document.getElementById("drive-canvas");
  const overlay = document.getElementById("drag-overlay");
  if (canvas && overlay) {
    ["dragenter", "dragover", "dragleave", "drop"].forEach((evt) => {
      canvas.addEventListener(
        evt,
        (e) => {
          e.preventDefault();
          e.stopPropagation();
        },
        false,
      );
    });

    canvas.addEventListener(
      "dragenter",
      () => overlay.classList.remove("hidden"),
      false,
    );
    canvas.addEventListener(
      "dragover",
      () => overlay.classList.remove("hidden"),
      false,
    );
    canvas.addEventListener(
      "dragleave",
      (e) => {
        if (!e.relatedTarget || !canvas.contains(e.relatedTarget)) {
          overlay.classList.add("hidden");
        }
      },
      false,
    );

    canvas.addEventListener(
      "drop",
      (e) => {
        overlay.classList.add("hidden");
        const files = e.dataTransfer.files;
        if (files.length > 0) {
          for (let i = 0; i < files.length; i++) {
            processUploadQueue(files[i]);
          }
        }
      },
      false,
    );
  }

  const bulkBtn = document.getElementById("drive-bulk-preview");
  if (bulkBtn) {
    bulkBtn.onclick = async () => {
      const confirmed = await ZNodeDialog.confirm(
        "BULK DECRYPTION",
        "Decrypt all media previews for this folder? This will use bandwidth and local processing.",
      );
      if (confirmed) decryptFolderMedia();
    };
  }

  // Modal Close
  const ct = document.getElementById("pv-close-top");
  const cb = document.getElementById("pv-close-btn");
  if (ct) ct.onclick = closeLightbox;
  if (cb) cb.onclick = closeLightbox;

  // Context Actions
  document.querySelectorAll(".ctx-btn").forEach((btn) => {
    btn.onclick = async () => {
      const action = btn.dataset.action;
      const id = activeCtxItem.id;
      const type = activeCtxItem.type;
      const menu = document.getElementById("context-menu");
      if (menu) {
        menu.classList.remove("flex");
        menu.classList.add("hidden");
      }

      if (action === "delete") {
        if (
          await ZNodeDialog.confirm(
            "PERMANENT DELETION",
            `Are you sure you want to delete this ${type}? This cannot be undone.`,
          )
        ) {
          await fetch(
            type === "folder"
              ? `/app/api/drive/delete/folder/${id}`
              : `/app/api/drive/delete/file/${id}`,
            { method: "POST" },
          );
          showZNodeToast(
            `${type.toUpperCase()} DELETED: ${activeCtxItem.name}`,
            "info",
          );
          fetchDrive(currentFolderId);
        }
      } else if (action === "rename") {
        const isMdNote = type === "file" && (activeCtxItem.name || "").toLowerCase().endsWith(".md");
        const displayName = isMdNote ? activeCtxItem.name.slice(0, -3) : activeCtxItem.name;

        let nn = await ZNodeDialog.prompt(
          "RENAME ITEM",
          `Enter new name for this ${type}:`,
          displayName,
        );
        
        if (nn && nn !== displayName) {
          // Re-append .md if it's a note and user didn't manually add it
          if (isMdNote && !nn.toLowerCase().endsWith(".md")) {
            nn += ".md";
          }
          const endpoint =
            type === "folder"
              ? `/app/api/drive/folder/${id}`
              : `/app/api/file/${id}/meta`;
          const field = type === "folder" ? "name" : "file_name";
          await fetch(endpoint, {
            method: "PATCH",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ [field]: nn }),
          });
          fetchDrive(currentFolderId);
        }
      } else if (action === "download") {
        downloadFile(id, activeCtxItem.name);
      } else if (action === "move") {
        moveItem(id, type, activeCtxItem.name);
      }
    };
  });

  const pvDownloadBtn = document.getElementById("pv-download-btn");
  if (pvDownloadBtn) {
    pvDownloadBtn.onclick = async () => {
      if (!activePreviewItem) return;
      toggleLightboxButtons(true);
      const loader = document.getElementById("pv-loader");
      if (loader) loader.classList.remove("opacity-0", "pointer-events-none");
      try {
        await downloadFile(activePreviewItem.id, activePreviewItem.name);
      } finally {
        toggleLightboxButtons(false);
        if (loader) loader.classList.add("opacity-0", "pointer-events-none");
      }
    };
  }

  const pvPreviewBtn = document.getElementById("pv-preview-btn");
  if (pvPreviewBtn) {
    pvPreviewBtn.onclick = async () => {
      if (!activePreviewItem) return;
      toggleLightboxButtons(true);
      const loader = document.getElementById("pv-loader");
      if (loader) loader.classList.remove("opacity-0", "pointer-events-none");
      try {
        const blob = await downloadFile(
          activePreviewItem.id,
          activePreviewItem.name,
          true,
        );
        if (!blob || blob.size === 0) {
          throw new Error("The decrypted file is empty or corrupted.");
        }
        const url = URL.createObjectURL(blob);
        const ext = activePreviewItem.name.split(".").pop().toLowerCase();
        let el;
        if (["jpg", "jpeg", "png", "gif", "webp"].includes(ext)) {
          el = document.createElement("img");
          el.src = url;
          el.className = "max-w-full max-h-full object-contain shadow-2xl";
        } else if (["mp4", "webm"].includes(ext)) {
          el = document.createElement("video");
          el.src = url;
          el.controls = true;
          el.className = "max-w-full max-h-full shadow-2xl";
        } else if (["pdf"].includes(ext)) {
          // Custom but secure container
          const wrapper = document.createElement("div");
          wrapper.className = "flex flex-col w-full h-full bg-surface-container overflow-hidden";
          wrapper.innerHTML = `
            <div class="px-6 py-3 border-b border-outline-variant/20 flex items-center justify-between bg-surface-container-high">
                <div class="flex items-center gap-3">
                    <svg class="w-4 h-4 text-primary" fill="currentColor" viewBox="0 0 20 20"><path d="M9 2a2 2 0 00-2 2v8a2 2 0 002 2h6a2 2 0 002-2V6.414A2 2 0 0016.414 5L14 2.586A2 2 0 0012.586 2H9z"></path><path d="M3 8a2 2 0 012-2v10h8a2 2 0 01-2 2H5a2 2 0 01-2-2V8z"></path></svg>
                    <span class="font-mono text-[9px] tracking-[0.2em] text-on-surface-variant uppercase">PREVIEWING SECURE DOCUMENT // ${activePreviewItem.name.toUpperCase()}</span>
                </div>
            </div>
            <div id="pdf-viewer-canvas" class="flex-grow flex flex-col items-center gap-6 p-8 overflow-auto bg-surface-container-high/30 scroll-smooth">
                <div class="vault-spinner mb-4 border-on-surface-variant/30 border-t-primary" id="pdf-load-spinner"></div>
            </div>
          `;
          el = wrapper;
          // Trigger Custom Render
          setTimeout(() => renderPDF(url, "pdf-viewer-canvas"), 100);
        } else if (["txt", "md", "js", "ts", "html", "css", "py", "json", "sql", "log", "rtf", "c", "cpp", "java", "php", "sh"].includes(ext)) {
          const t = await blob.text();
          if (ext === "md") {
            initMarkdownEditor(activePreviewItem.id, activePreviewItem.name, t);
            return;
          }
          el = document.createElement("pre");
          el.innerText = t;
          el.className =
            "text-on-surface font-mono text-[10px] leading-relaxed p-8 bg-surface-container-highest/20 w-full h-full overflow-auto whitespace-pre-wrap selection:bg-primary selection:text-black";
        } else {
          el = document.createElement("div");
          el.className = "flex flex-col items-center justify-center p-12 text-on-surface-variant/40";
          el.innerHTML = `
            <svg class="w-12 h-12 mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path></svg>
            <span class="font-mono text-[10px] tracking-widest text-center">PREVIEW NOT AVAILABLE<br>FOR THIS FILE TYPE</span>
          `;
        }
        const content = document.getElementById("pv-content");
        if (content) {
          content.innerHTML = "";
          content.appendChild(el);
        }
      } catch (e) {
        console.error(e);
        await ZNodeDialog.alert(
          "PREVIEW ERROR",
          "Failed to decrypt and render this file for preview.",
        );
      } finally {
        toggleLightboxButtons(false);
        if (loader) loader.classList.add("opacity-0", "pointer-events-none");
      }
    };
  }

  // Uploads
  const upBtn = document.getElementById("dynamic-upload");
  const upInput = document.getElementById("hidden-file-input");
  if (upBtn && upInput) {
    upBtn.onclick = () => upInput.click();
    upInput.onchange = (e) => {
      for (let i = 0; i < e.target.files.length; i++)
        uploadFile(e.target.files[i]);
      e.target.value = "";
    };
  }
}

async function decryptFolderMedia() {
  const items = document.querySelectorAll('.drive-item[data-type="file"]');
  const mediaExts = ["jpg", "jpeg", "png", "gif", "webp"];

  for (const el of items) {
    const id = el.dataset.id;
    const name = el.dataset.name;
    const ext = name.split(".").pop().toLowerCase();

    if (!mediaExts.includes(ext)) continue;
    if (previewUrls.has(id)) continue;

    // 1. Check if we already have it decrypted in the session
    if (decryptedSessionCache.has(id)) {
      const url = URL.createObjectURL(decryptedSessionCache.get(id));
      previewUrls.set(id, url);
      applyPreview(el, url);
      continue;
    }

    try {
      const blob = await downloadFile(id, name, true);
      if (blob) {
        const url = URL.createObjectURL(blob);
        previewUrls.set(id, url);
        applyPreview(el, url);
      }
    } catch (e) {
      console.error(`Preview failed for ${name}:`, e);
      applyFailure(el);
    }
  }
}

function applyPreview(el, url) {
  el.style.backgroundImage = `url('${url}')`;
  el.style.backgroundSize = "cover";
  el.style.backgroundPosition = "center";

  // Hide icon if in grid
  const icon = el.querySelector(".relative.z-10 svg");
  if (icon) icon.style.display = "none";

  // Add a marker to the element
  el.dataset.hasPreview = "true";
}

function applyFailure(el) {
  // Mark text as failed red
  const nameEl = el.querySelector("span.font-label");
  const sizeEl = el.querySelector("span.font-mono");

  if (nameEl) nameEl.classList.add("text-error");
  if (sizeEl) sizeEl.classList.add("text-error/60");

  // Add red border
  el.classList.add("border-error/40");
  el.classList.remove("border-outline-variant/20");
}

// --- 6. File Operations ---
const CHUNK_SIZE = 1024 * 1024 * 5;
async function processUploadQueue(file) {
  if (file) {
    const tfId = Math.random().toString(36).substr(2, 9);
    file._tfId = tfId; // Attach tracking ID
    uploadQueue.push(file);
    addTransfer(tfId, file.name, "QUEUED");
  }

  if (activeUploadCount >= MAX_CONCURRENT_UPLOADS) return;

  const nextFile = uploadQueue.shift();
  if (!nextFile) return;

  activeUploadCount++;
  try {
    promoteTransfer(nextFile._tfId, "ENCRYPT");
    await uploadFile(nextFile, nextFile._tfId);
  } finally {
    activeUploadCount--;
    processUploadQueue(); // Try to start next in line
  }
}

async function uploadFile(file, tfId) {
  if (!file) return;
  if (file.size === 0 && !file.name.endsWith(".md")) {
    failTransfer(tfId);
    showZNodeToast(`ABORTED: ${file.name} is an empty file (0 bytes).`, "error");
    return;
  }
  const isLarge = file.size > 500 * 1024 * 1024; // 500MB threshold
  const ext = file.name.split(".").pop().toLowerCase();

  // Status already added by processUploadQueue
  try {
    const masterKey = await DriveCrypto.getVaultMasterKey();
    const fileKey = await DriveCrypto.generateFileKey();
    const wrappedKey64 = await DriveCrypto.wrapFileKey(fileKey, masterKey);

    const initRes = await fetchWithRetry("/app/api/file/init", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        file_name: file.name,
        aes_key: wrappedKey64,
        folder_id: currentFolderId,
      }),
    });
    const { uuid } = await initRes.json();

    let offset = 0,
      idx = 0,
      cOff = 0;
    const cipherChunks = [];

    while (offset < file.size) {
      const chunk = file.slice(offset, offset + CHUNK_SIZE);
      const arrayBuf = await chunk.arrayBuffer();
      const iv = new Uint8Array(12);
      new DataView(iv.buffer).setUint32(8, idx, false);

      const enc = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv },
        fileKey,
        arrayBuf,
      );

      // Only cache in RAM/IndexedDB if it's a manageable size
      if (!isLarge) cipherChunks.push(enc);

      await fetchWithRetry(`/app/api/file/${uuid}/chunk`, {
        method: "POST",
        headers: {
          "X-Chunk-Offset": cOff.toString(),
          "Content-Type": "application/octet-stream",
        },
        body: enc,
      });

      offset += chunk.size;
      cOff += enc.byteLength;
      idx++;
      updateTransfer(tfId, (offset / file.size) * 100);
    }

    await fetchWithRetry(`/app/api/file/${uuid}/finalize`, { method: "POST" });

    if (!isLarge && ext !== "md") {
      try {
        await cacheFile(uuid, new Blob(cipherChunks));
      } catch (e) {}
    }

    completeTransfer(tfId);
    showZNodeToast(`UPLOADED: ${file.name}`, "info");
    if (document.getElementById("item-container")) fetchDrive(currentFolderId);
  } catch (err) {
    console.error(err);
    failTransfer(tfId);
    showZNodeToast(`FAILED: ${file.name} - ${err.message}`, "error");
  }
}

async function downloadFile(uuid, name, returnBlob = false) {
  if (decryptedSessionCache.has(uuid)) {
    const b = decryptedSessionCache.get(uuid);
    if (returnBlob) return b;
    saveBlobToDisk(b, name);
    return;
  }
  if (activeTaskSignals.has(uuid)) return await activeTaskSignals.get(uuid);

    const task = (async () => {
      let tfId = Math.random().toString(36).substr(2, 9);
      const ext = (name || "").split(".").pop().toLowerCase();
      try {
        addTransfer(tfId, name, "DECRYPT");
      let encryptedBytes;
      let metadata = metadataCache.get(uuid);

      const diskCached = await getCachedFile(uuid);
      if (diskCached) {
        encryptedBytes = await diskCached.blob.arrayBuffer();
        if (diskCached.metadata) {
          metadata = diskCached.metadata;
          metadataCache.set(uuid, metadata); // Hydrate RAM cache
        }
      } else {
        const res = await fetch(`/app/api/file/${uuid}`);
        const reader = res.body.getReader();
        let received = 0,
          chunks = [];
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          chunks.push(value);
          received += value.length;
          updateTransfer(
            tfId,
            (received / res.headers.get("Content-Length")) * 100,
          );
        }
        const full = new Uint8Array(received);
        let pos = 0;
        for (let c of chunks) {
          full.set(c, pos);
          pos += c.length;
        }
        encryptedBytes = full.buffer;
        // Don't cache here yet, wait until metadata is also fetched below
      }

      if (!metadata) {
        const r = await fetch(`/app/api/file/${uuid}/meta`);
        if (!r.ok)
          throw new Error(
            r.status === 404
              ? "File missing from vault storage."
              : "Metadata fetch failed.",
          );
        metadata = await r.json();
        metadataCache.set(uuid, metadata);
      }

      // If we downloaded it fresh, cache it with the metadata now (unless it's an .md file)
      if (!diskCached && ext !== "md") {
         await cacheFile(uuid, new Blob([encryptedBytes]), metadata);
      }
      if (!encryptedBytes || encryptedBytes.byteLength === 0) {
        throw new Error("Vault stream is empty. The file may be missing from storage.");
      }

      const masterKey = await DriveCrypto.getVaultMasterKey();
      const fileKey = await DriveCrypto.unwrapFileKey(
        metadata.aes_key,
        masterKey,
      );
      let decryptedChunks = [];
      for (let i = 0; i * (CHUNK_SIZE + 16) < encryptedBytes.byteLength; i++) {
        const iv = new Uint8Array(12);
        new DataView(iv.buffer).setUint32(8, i, false);
        const chunk = encryptedBytes.slice(
          i * (CHUNK_SIZE + 16),
          (i + 1) * (CHUNK_SIZE + 16),
        );
        decryptedChunks.push(
          await crypto.subtle.decrypt(
            { name: "AES-GCM", iv: iv },
            fileKey,
            chunk,
          ),
        );
      }
      const mimeTypes = {
        pdf: "application/pdf",
        txt: "text/plain",
        html: "text/html",
        css: "text/css",
        js: "application/javascript",
        json: "application/json",
        jpg: "image/jpeg",
        jpeg: "image/jpeg",
        png: "image/png",
        gif: "image/gif",
        webp: "image/webp",
        mp4: "video/mp4",
        webm: "video/webm",
      };
      const finalMime = mimeTypes[ext] || "application/octet-stream";

      const finalBlob = new Blob(decryptedChunks, { type: finalMime });
      if (ext !== "md") {
        decryptedSessionCache.set(uuid, finalBlob);
      }
      completeTransfer(tfId);
      return finalBlob;
    } catch (err) {
      // Signal failure to UI card if it exists in current view
      const el = document.querySelector(`.drive-item[data-id="${uuid}"]`);
      if (el) applyFailure(el);

      // Signal failure to Transfer Manager
      failTransfer(tfId);
      showZNodeToast(`FAILED: ${name} - ${err.message}`, "error");

      throw err;
    } finally {
      activeTaskSignals.delete(uuid);
    }
  })();
  activeTaskSignals.set(uuid, task);
  const result = await task;
  if (!returnBlob) saveBlobToDisk(result, name);
  return result;
}

async function renderPDF(url, containerId) {
  const container = document.getElementById(containerId);
  if (!container) return;

  // 1. Wait for pdfjsLib to load (Retry logic for async scripts)
  let retries = 0;
  while (!window.pdfjsLib && retries < 20) {
    await new Promise(r => setTimeout(r, 200));
    retries++;
  }

  if (!window.pdfjsLib) {
    container.innerHTML = `<div class="flex flex-col items-center justify-center p-12 text-error"><span class="font-mono text-[10px]">RENDER ENGINE OFFLINE // LIBRARY_MISSING</span></div>`;
    return;
  }

  try {
    // Force worker initialization if missed (LOCAL)
    if (!window.pdfjsLib.GlobalWorkerOptions.workerSrc) {
       window.pdfjsLib.GlobalWorkerOptions.workerSrc = '/static/js/pdf.worker.min.js';
    }

    const params = {
      url: url,
      cMapUrl: '/static/js/cmaps/',
      cMapPacked: true,
    };

    const loadingTask = window.pdfjsLib.getDocument(params);
    const pdf = await loadingTask.promise;
    
    // Clear spinner
    const spinner = document.getElementById('pdf-load-spinner');
    if (spinner) spinner.remove();

    for (let pageNum = 1; pageNum <= pdf.numPages; pageNum++) {
      const page = await pdf.getPage(pageNum);
      const scale = 1.6;
      const viewport = page.getViewport({ scale });

      const canvas = document.createElement('canvas');
      const ctx = canvas.getContext('2d');
      canvas.height = viewport.height;
      canvas.width = viewport.width;
      canvas.className = "shadow-2xl mb-12 max-w-full h-auto bg-white transition-opacity duration-700 opacity-0 rounded-sm";
      
      container.appendChild(canvas);

      const renderContext = {
        canvasContext: ctx,
        viewport: viewport,
        enableWebGL: true
      };
      
      await page.render(renderContext).promise;
      canvas.classList.remove('opacity-0');
    }
  } catch (e) {
    console.error("PDF.js Render Failed, falling back to iframe:", e);
    // FALLBACK: Use iframe if PDF.js fails
    container.innerHTML = `
      <div class="absolute inset-0 flex flex-col items-center justify-center pointer-events-none p-12 opacity-5">
          <span class="font-mono text-4xl font-bold tracking-[2em] uppercase origin-center -rotate-12">NATIVE FALLBACK</span>
      </div>
      <iframe src="${url}" class="w-full h-full border-none bg-white relative z-10" type="application/pdf"></iframe>
    `;
  }
}

function saveBlobToDisk(blob, name) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  URL.revokeObjectURL(url);
}

async function moveItem(id, type, name) {
  const modal = document.getElementById("modal-move-item");
  const box = document.getElementById("move-modal-box");
  const nameLabel = document.getElementById("move-item-name");
  const container = document.getElementById("move-folder-list");
  const breadcrumbs = document.getElementById("move-breadcrumbs");
  const targetLabel = document.getElementById("move-current-target");
  const moveBtn = document.getElementById("btn-finalize-move");

  if (!modal || !container) return;

  let movePath = [{ id: null, name: "Root" }];
  let currentTargetId = null;

  nameLabel.innerText = name;
  modal.classList.remove("hidden");
  setTimeout(() => box.classList.remove("scale-95", "opacity-0"), 10);

  const loadMoveDir = async (folderId, folderName) => {
    currentTargetId = folderId;
    targetLabel.innerText = folderName || "Root Directory";
    container.innerHTML = `<div class="p-8 text-center font-mono text-[9px] text-on-surface-variant/30 uppercase tracking-widest">NAVIGATING...</div>`;

    try {
      const res = await fetch(
        folderId ? `/app/api/drive/list/${folderId}` : "/app/api/drive/list",
      );
      const data = await res.json();

      // We only care about folders that aren't the one we are currently moving
      const folders = data.folders.filter((f) => f.id !== id);

      if (folders.length === 0) {
        container.innerHTML = `<div class="p-12 flex flex-col items-center justify-center opacity-40">
                    <svg class="w-8 h-8 mb-2" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z"></path></svg>
                    <span class="font-mono text-[9px] uppercase tracking-widest">No subfolders found</span>
                </div>`;
      } else {
        container.innerHTML = folders
          .map(
            (f) => `
                    <div class="move-folder-item flex items-center justify-between p-3 hover:bg-primary/5 cursor-pointer border-b border-outline-variant/10 transition-all interactive-el" data-id="${f.id}" data-name="${f.name}">
                        <div class="flex items-center gap-3">
                            <svg class="w-4 h-4 text-primary/60" fill="currentColor" viewBox="0 0 20 20"><path d="M2 6a2 2 0 012-2h5l2 2h5a2 2 0 012 2v6a2 2 0 01-2 2H4a2 2 0 01-2-2V6z"></path></svg>
                            <span class="font-label text-xs text-on-surface uppercase tracking-wide">${f.name}</span>
                        </div>
                        <svg class="w-3 h-3 text-on-surface-variant/30" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"></path></svg>
                    </div>
                `,
          )
          .join("");

        container.querySelectorAll(".move-folder-item").forEach((el) => {
          el.onclick = () => {
            movePath.push({ id: el.dataset.id, name: el.dataset.name });
            updateBreadcrumbs();
            loadMoveDir(el.dataset.id, el.dataset.name);
          };
        });
      }
    } catch (err) {
      container.innerHTML = `<div class="p-8 text-center font-mono text-[9px] text-error uppercase tracking-widest">Failed to load directory</div>`;
    }
  };

  const updateBreadcrumbs = () => {
    breadcrumbs.innerHTML = movePath
      .map(
        (p, i) => `
            <span class="breadcrumb-item cursor-pointer hover:text-primary transition-colors ${i === movePath.length - 1 ? "text-primary" : ""}" data-idx="${i}">${p.name}</span>
            ${i < movePath.length - 1 ? "<span>/</span>" : ""}
        `,
      )
      .join("");

    breadcrumbs.querySelectorAll(".breadcrumb-item").forEach((el) => {
      el.onclick = () => {
        const idx = parseInt(el.dataset.idx);
        if (idx === movePath.length - 1) return;
        movePath = movePath.slice(0, idx + 1);
        const target = movePath[idx];
        updateBreadcrumbs();
        loadMoveDir(target.id, target.name);
      };
    });
  };

  const finalizeMove = async () => {
    const endpoint =
      type === "folder"
        ? `/app/api/drive/folder/${id}`
        : `/app/api/drive/file/${id}/move`;
    const payload =
      type === "folder"
        ? { parent_id: currentTargetId }
        : { folder_id: currentTargetId };

    moveBtn.disabled = true;
    moveBtn.innerText = "MOVING...";

    try {
      const moveRes = await fetch(endpoint, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      const moveData = await moveRes.json();
      if (!moveRes.ok) throw new Error(moveData.error || "Move failed");

      showZNodeToast(`Moved '${name}' successfully`, "info");
      box.classList.add("scale-95", "opacity-0");
      setTimeout(() => modal.classList.add("hidden"), 300);
      fetchDrive(currentFolderId);
    } catch (err) {
      showZNodeToast(err.message, "error");
    } finally {
      moveBtn.disabled = false;
      moveBtn.innerText = "MOVE HERE";
    }
  };

  moveBtn.onclick = finalizeMove;
  updateBreadcrumbs();
  loadMoveDir(null, "Root");
}

// --- 7. Boot ---
document.addEventListener("DOMContentLoaded", () => {
  updateCacheCountUI();
  const tmHdr = document.getElementById("tm-header");
  if (tmHdr) {
    tmHdr.addEventListener("click", () => {
      const body = document.getElementById("tm-body");
      if (body)
        body.style.maxHeight =
          body.style.maxHeight === "0px" || !body.style.maxHeight
            ? "16rem"
            : "0px";
    });
  }
  if (document.getElementById("item-container")) {
    initDriveControls();
    fetchDrive();
  }

  // Activity lock — prevent reload/closing during active work
  window.addEventListener("beforeunload", (e) => {
    if (activeTransfers > 0) {
      e.preventDefault();
      e.returnValue = "";
    }
  });
});
