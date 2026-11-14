const FILE_API = '/app/api/file';

// --- 1. Global State & Task Registry ---
let activeTransfers = 0;
const activeTaskSignals = new Map(); // uuid -> Promise
const decryptedSessionCache = new Map(); // uuid -> Blob
const metadataCache = new Map(); // uuid -> Object
const previewUrls = new Map(); // uuid -> objectURL
let readyToSaveBlob = null; // Staged for download
const OPFS_WORKER_LIMIT = 4;
const OPFS_CHUNK_SIZE = 1024 * 1024 * 5; // 5MB

// --- 2. OPFS Helpers ---
async function initOPFSWorkspace() {
  try {
    const root = await navigator.storage.getDirectory();
    for await (const entry of root.values()) {
      if (entry.name.startsWith("temp_decrypted_")) {
        await root.removeEntry(entry.name);
        console.log(`[OPFS] Cleaned orphaned file: ${entry.name}`);
      }
    }
  } catch (err) {
    console.error("[OPFS] Workspace init error:", err);
  }
}

async function createOPFSTempFile(uuid) {
  const root = await navigator.storage.getDirectory();
  const fileName = `temp_decrypted_${uuid}`;
  return await root.getFileHandle(fileName, { create: true });
}

async function cleanupOPFS(uuid) {
  try {
    const root = await navigator.storage.getDirectory();
    const fileName = `temp_decrypted_${uuid}`;
    await root.removeEntry(fileName);
    console.log(`[OPFS] Cleaned up: ${fileName}`);
  } catch (err) {
    // If it's already gone, that's fine
  }
}

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
      throw new Error("Session not unlocked.");
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

  // 3. Wipe OPFS Cache
  try {
    const root = await navigator.storage.getDirectory();
    for await (const entry of root.values()) {
      if (entry.kind === "file") {
        await root.removeEntry(entry.name);
      }
    }
    console.log("[OPFS] Cache wiped.");
  } catch (e) {
    console.error("[OPFS] OPFS Wipe failed:", e);
  }

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
      if (document.getElementById("item-container"))
        fetchDrive(currentFolderId);
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

    const btns = document.querySelectorAll(".dynamic-cache-btn");
    btns.forEach(btn => {
      btn.innerHTML = `CACHE [${count}]`;
      btn.classList.remove("hidden");

      if (count > 0) {
        btn.className =
          "dynamic-cache-btn font-mono text-[9px] tracking-widest text-error border border-error/40 bg-error/5 px-2 py-0.5 hover:bg-error hover:text-black transition-all interactive-el uppercase md:ml-4";
      } else {
        btn.className =
          "dynamic-cache-btn font-mono text-[9px] tracking-widest text-primary/40 border border-primary/10 px-2 py-0.5 hover:bg-primary/20 hover:text-primary transition-all interactive-el uppercase md:ml-4";
      }

      btn.onclick = async () => {
        if (
          await ZNodeDialog.confirm(
            "CLEAR CACHE",
            "Clear local cached files? This will free local storage without affecting your files on the server.",
          )
        ) {
          await clearCache();
        }
      };
    });
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

// Removed showZNodeToast, now in main.js

// --- 5. Drive Rendering & Logic (Conditional) ---
let currentFolderId = null;
let currentView = "grid"; // 'grid' | 'list'
let activeCtxItem = null;
let activePreviewItem = null;

// --- Bulk Selection State & Actions ---
let isBulkMode = false;
const selectedItems = new Map(); // id -> { id, type, name }

function updateBulkUI() {
  const count = selectedItems.size;
  const bar = document.getElementById("drive-bulk-bar");
  const countLabel = document.getElementById("bulk-selected-count");
  const selectAllBtn = document.getElementById("drive-select-all-btn");
  const toggleSelectAll = document.getElementById("bulk-select-all-toggle");
  const bulkModeBtn = document.getElementById("drive-bulk-mode-btn");
  const bulkModeText = document.getElementById("bulk-mode-btn-text");
  const dynamicBulkBtn = document.getElementById("dynamic-bulk-btn");
  const dynamicBulkText = document.getElementById("dynamic-bulk-text");

  if (countLabel) {
    countLabel.innerText = count > 0 ? `${count} SELECTED` : (isBulkMode ? "SELECT ITEMS" : "0 SELECTED");
  }

  // Update button texts
  const labelText = isBulkMode ? "EXIT SELECT" : "BULK EDIT";
  if (bulkModeText) bulkModeText.innerText = labelText;
  if (dynamicBulkText) dynamicBulkText.innerText = labelText;

  // Toggle active styling on toolbar & dynamic buttons
  if (bulkModeBtn) {
    if (isBulkMode) {
      bulkModeBtn.classList.add("border-primary", "bg-primary/20", "text-primary");
      bulkModeBtn.classList.remove("border-outline-variant/40", "text-on-surface-variant/80");
    } else {
      bulkModeBtn.classList.remove("border-primary", "bg-primary/20", "text-primary");
      bulkModeBtn.classList.add("border-outline-variant/40", "text-on-surface-variant/80");
    }
  }
  if (dynamicBulkBtn) {
    if (isBulkMode) {
      dynamicBulkBtn.classList.add("border-primary", "bg-primary/20", "text-primary");
      dynamicBulkBtn.classList.remove("border-outline-variant/40");
    } else {
      dynamicBulkBtn.classList.remove("border-primary", "bg-primary/20", "text-primary");
      dynamicBulkBtn.classList.add("border-outline-variant/40");
    }
  }

  if (bar) {
    if (count > 0 || isBulkMode) {
      bar.classList.remove("hidden");
      requestAnimationFrame(() => {
        bar.classList.remove("translate-y-8", "translate-y-12", "opacity-0");
        bar.classList.add("flex", "translate-y-0", "opacity-100");
      });
    } else {
      bar.classList.remove("translate-y-0", "opacity-100");
      bar.classList.add("translate-y-8", "opacity-0");
      setTimeout(() => {
        if (selectedItems.size === 0 && !isBulkMode) {
          bar.classList.add("hidden");
          bar.classList.remove("flex");
        }
      }, 250);
    }
  }

  const allCards = document.querySelectorAll(".drive-item");
  allCards.forEach((card) => {
    const id = card.dataset.id;
    const isSelected = selectedItems.has(id);
    const chk = card.querySelector(".drive-item-checkbox");
    if (chk) {
      chk.checked = isSelected;
      if (isSelected || isBulkMode) {
        chk.classList.remove("opacity-0", "opacity-30");
        chk.classList.add("opacity-100");
      } else {
        chk.classList.remove("opacity-100");
        if (currentView === "grid") {
          chk.classList.remove("opacity-30");
          chk.classList.add("opacity-0");
        } else {
          chk.classList.remove("opacity-0");
          chk.classList.add("opacity-30");
        }
      }
    }

    if (isSelected) {
      card.classList.add("ring-2", "ring-primary", "bg-primary/10", "border-primary/60");
    } else {
      card.classList.remove("ring-2", "ring-primary", "bg-primary/10", "border-primary/60");
    }
  });

  if (toggleSelectAll && allCards.length > 0) {
    toggleSelectAll.innerText = count === allCards.length ? "DESELECT ALL" : "SELECT ALL";
  }

  if (selectAllBtn) {
    if (count > 0 && count === allCards.length) {
      selectAllBtn.classList.add("text-primary");
      selectAllBtn.classList.remove("text-on-surface-variant/40");
    } else {
      selectAllBtn.classList.remove("text-primary");
      selectAllBtn.classList.add("text-on-surface-variant/40");
    }
  }
}

function clearSelection() {
  selectedItems.clear();
  isBulkMode = false;
  updateBulkUI();
}

function toggleSelectItem(id, type, name, forceState = null) {
  const shouldSelect = forceState !== null ? forceState : !selectedItems.has(id);
  if (shouldSelect) {
    selectedItems.set(id, { id, type, name });
  } else {
    selectedItems.delete(id);
  }
  updateBulkUI();
}

function selectAllVisible() {
  const allCards = document.querySelectorAll(".drive-item");
  if (allCards.length === 0) return;
  const allSelected = selectedItems.size === allCards.length;

  if (allSelected) {
    selectedItems.clear();
  } else {
    allCards.forEach((card) => {
      const id = card.dataset.id;
      const type = card.dataset.type;
      const name = card.dataset.name;
      selectedItems.set(id, { id, type, name });
    });
  }
  updateBulkUI();
}

function getMimeType(fileName) {
  const ext = (fileName || "").split(".").pop().toLowerCase();
  const map = {
    // Audio
    mp3: "audio/mpeg",
    wav: "audio/wav",
    ogg: "audio/ogg",
    oga: "audio/ogg",
    opus: "audio/opus",
    m4a: "audio/mp4",
    aac: "audio/aac",
    flac: "audio/flac",
    weba: "audio/webm",
    wma: "audio/x-ms-wma",
    mid: "audio/midi",
    midi: "audio/midi",

    // Video
    mp4: "video/mp4",
    webm: "video/webm",
    ogv: "video/ogg",
    mov: "video/quicktime",
    m4v: "video/x-m4v",
    mkv: "video/x-matroska",
    avi: "video/x-msvideo",
    "3gp": "video/3gpp",
    ts: "video/mp2t",

    // Images
    jpg: "image/jpeg",
    jpeg: "image/jpeg",
    png: "image/png",
    gif: "image/gif",
    webp: "image/webp",
    svg: "image/svg+xml",
    ico: "image/x-icon",
    bmp: "image/bmp",
    avif: "image/avif",
    apng: "image/apng",
    tif: "image/tiff",
    tiff: "image/tiff",

    // Documents & Code
    pdf: "application/pdf",
    txt: "text/plain",
    md: "text/markdown",
    json: "application/json",
    csv: "text/csv",
    xml: "application/xml",
    html: "text/html",
    css: "text/css",
    js: "text/javascript",
    ts: "text/typescript",
    py: "text/x-python",
  };
  return map[ext] || "application/octet-stream";
}

async function fetchDrive(folderId = null) {
  currentFolderId = folderId;
  clearSelection();

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
  const title = await ZNodeDialog.prompt("New Note", "Enter note title:");
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

    const initRes = await fetch(`${FILE_API}/init`, {
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

    await fetch(`${FILE_API}/${uuid}/chunk`, {
      method: "POST",
      headers: {
        "X-Chunk-Offset": "0",
        "Content-Type": "application/octet-stream",
      },
      body: enc,
    });

    await fetch(`${FILE_API}/${uuid}/finalize`, { method: "POST" });

    completeTransfer(tfId);
    showZNodeToast(`Note created: ${title}`, "info");
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
    showZNodeToast(`Failed to create note: ${e.message}`, "error");
  }
}

function initMarkdownEditor(uuid, fileName, content) {
  const pvContent = document.getElementById("pv-content");
  if (!pvContent) return;

  // Hide the lightbox's own header and footer so the editor is the only UI
  const pvTopBar = document.querySelector('#drive-preview-modal > div:first-child');
  const pvSurface = document.getElementById('pv-surface');
  if (pvTopBar) pvTopBar.style.display = 'none';
  const pvFooter = document.getElementById('pv-footer');
  if (pvFooter) pvFooter.style.display = 'none';
  // Let the surface fill without padding when in editor mode
  if (pvSurface) pvSurface.style.padding = '0';

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

  const displayTitle = getNameWithoutMD(fileName);

  const editorHtml = `
      <div class="flex flex-col w-full h-full bg-surface-container overflow-hidden">
          <div class="flex border-b border-outline-variant/20 bg-surface-container-high shrink-0 items-center px-6 justify-between shadow-lg z-20 py-3 gap-4">
              <div class="flex items-center gap-4 overflow-hidden">
                  <div class="flex items-center gap-2 shrink-0">
                      <svg class="w-4 h-4 text-primary/60 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path></svg>
                      <span class="font-headline text-sm tracking-widest text-on-surface uppercase truncate max-w-[200px]">${displayTitle}</span>
                  </div>
                  <div class="w-[1px] h-5 bg-outline-variant/20 shrink-0"></div>
                  <div class="flex items-center gap-1 shrink-0" id="md-toolbar">
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
                  <div class="w-[1px] h-5 bg-outline-variant/20 shrink-0"></div>
                  <button id="md-toggle-raw" class="font-mono text-[9px] tracking-[0.2em] text-primary/40 hover:text-primary uppercase transition-colors px-3 py-1.5 border border-primary/10 hover:bg-primary/5 shrink-0">
                    SEE RAW
                  </button>
              </div>
              <div class="flex items-center gap-3 shrink-0">
                  <button id="md-save-btn" class="bg-primary/10 border border-primary/30 text-primary hover:bg-primary hover:text-black font-label text-[10px] tracking-[0.2em] px-6 py-2.5 uppercase transition-all flex items-center gap-2 group">
                     <span id="md-save-text">SAVE</span>
                     <svg class="w-3 h-3 group-hover:animate-bounce" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M9 19l3 3m0 0l3-3m-3 3V10"></path></svg>
                  </button>
                  <button id="md-disk-btn" class="border border-outline-variant/30 text-on-surface-variant/60 hover:text-primary hover:border-primary/30 font-label text-[10px] tracking-[0.2em] px-6 py-2.5 uppercase transition-all flex items-center gap-2" title="Download as .md file">
                     <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"></path></svg>
                     <span>DISK</span>
                  </button>
                  <button id="md-close-btn" class="text-on-surface-variant/30 hover:text-error transition-all p-2" title="Exit Note Studio">
                      <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M6 18L18 6M6 6l12 12"></path></svg>
                  </button>
              </div>
          </div>
          <div class="flex-1 flex overflow-hidden relative">
              <div id="md-formatted" contenteditable="true" class="flex-1 bg-surface p-16 md:px-24 lg:px-48 overflow-y-auto focus:outline-none leading-relaxed transition-all duration-300 selection:bg-primary/30 prose prose-invert max-w-none scroll-smooth h-full" spellcheck="true" placeholder="Note content..."></div>
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
    // 1. Safe Chunking by Markdown Block boundaries
    const blocks = (content || "").split(/\n\n+/);
    let currentBlock = 0;
    const BATCH_SIZE = 50; // Process 50 paragraphs per frame

    formatted.innerHTML = ""; // Clear initial state

    const processBatch = () => {
      let htmlChunk = "";
      let processed = 0;

      // 2. Process a small batch
      while (currentBlock < blocks.length && processed < BATCH_SIZE) {
        try {
          // Re-add the double newline so Marked knows it's a block
          htmlChunk += window.marked.parse(blocks[currentBlock] + "\n\n");
        } catch (err) {
          console.warn(
            "[Markdown] Block parse error. Falling back to raw text for this segment.",
          );
          htmlChunk += `<p class="text-error font-mono text-[10px]">${blocks[currentBlock]}</p>`;
        }
        currentBlock++;
        processed++;
      }

      // 3. Inject directly into the DOM
      formatted.insertAdjacentHTML("beforeend", htmlChunk);

      // 4. Yield to the main thread, then process next batch
      if (currentBlock < blocks.length) {
        requestAnimationFrame(processBatch);
      }
    };

    // Start the chunking engine
    requestAnimationFrame(processBatch);
  } else {
    formatted.innerText = content;
  }

  // Setup Turndown for saving
  let turndown;
  if (window.TurndownService) {
    turndown = new window.TurndownService({
      headingStyle: "atx",
      hr: "---",
      bulletListMarker: "-",
      codeBlockStyle: "fenced",
    });
  }

  let isRawMode = false;
  toggleRawBtn.onclick = () => {
    isRawMode = !isRawMode;
    if (isRawMode) {
      // Formatted -> Raw
      raw.value = turndown
        ? turndown.turndown(formatted.innerHTML)
        : formatted.innerText;
      formatted.classList.add("hidden");
      raw.classList.remove("hidden");
      toggleRawBtn.innerText = "EXIT RAW";
      toggleRawBtn.classList.add("bg-primary/10", "text-primary");
      document.getElementById("md-toolbar").style.opacity = "0.3";
      document.getElementById("md-toolbar").style.pointerEvents = "none";
    } else {
      // Raw -> Formatted
      if (window.marked) {
        const blocks = (raw.value || "").split(/\n\n+/);
        let currentBlock = 0;
        const BATCH_SIZE = 50;
        formatted.innerHTML = "";
        const processBatch = () => {
          let htmlChunk = "";
          let processed = 0;
          while (currentBlock < blocks.length && processed < BATCH_SIZE) {
            try {
              htmlChunk += window.marked.parse(blocks[currentBlock] + "\n\n");
            } catch (err) {
              htmlChunk += `<p class="text-error font-mono text-[10px]">${blocks[currentBlock]}</p>`;
            }
            currentBlock++;
            processed++;
          }
          formatted.insertAdjacentHTML("beforeend", htmlChunk);
          if (currentBlock < blocks.length) {
            requestAnimationFrame(processBatch);
          }
        };
        requestAnimationFrame(processBatch);
      } else {
        formatted.innerText = raw.value;
      }
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

      if (cmd === "createLink") {
        const url = prompt("Enter URL:", "https://");
        if (url) document.execCommand(cmd, false, url);
      } else {
        document.execCommand(cmd, false, val);
      }
      formatted.focus();
    };
  });

  const internalCloseBtn = document.getElementById("md-close-btn");
  if (internalCloseBtn) internalCloseBtn.onclick = () => {
    // Restore lightbox chrome before closing
    const pvTopBar = document.querySelector('#drive-preview-modal > div:first-child');
    const pvSurface = document.getElementById('pv-surface');
    const pvFooter = document.getElementById('pv-footer');
    if (pvTopBar) pvTopBar.style.display = '';
    if (pvFooter) pvFooter.style.display = '';
    if (pvSurface) pvSurface.style.padding = '';
    closeLightbox();
  };

  // Save to Disk handler
  const diskBtn = document.getElementById("md-disk-btn");
  if (diskBtn) {
    diskBtn.onclick = () => {
      let mdOutput;
      if (isRawMode) {
        mdOutput = raw.value;
      } else {
        mdOutput = turndown
          ? turndown.turndown(formatted.innerHTML)
          : formatted.innerText;
      }
      const blob = new Blob([mdOutput], { type: "text/markdown;charset=utf-8" });
      saveBlobToDisk(blob, fileName);
      showZNodeToast(`EXPORTED: ${fileName}`, "info");
    };
  }

  if (saveBtn) {
    saveBtn.onclick = async () => {
      if (saveBtn.disabled) return; // Guard against double-clicks

      const tfId = Math.random().toString(36).substr(2, 9);
      addTransfer(tfId, fileName, "ENCRYPT");

      saveBtn.disabled = true;
      saveText.innerText = "ENCRYPTING...";

      try {
        // Fetch metadata (with server fallback if cache is stale/missing)
        let metadata = metadataCache.get(uuid);
        if (!metadata || !metadata.aes_key) {
          const metaRes = await fetch(`${FILE_API}/${uuid}/meta`);
          if (!metaRes.ok) throw new Error("Failed to retrieve file metadata.");
          metadata = await metaRes.json();
          metadataCache.set(uuid, metadata);
        }

        const masterKey = await DriveCrypto.getVaultMasterKey();
        const fileKey = await DriveCrypto.unwrapFileKey(
          metadata.aes_key,
          masterKey,
        );

        saveText.innerText = "SAVING...";

        // Final Sync to MD
        let mdOutput;
        if (isRawMode) {
          mdOutput = raw.value;
        } else {
          mdOutput = turndown
            ? turndown.turndown(formatted.innerHTML)
            : formatted.innerText;
        }

        const encoder = new TextEncoder();
        const arrayBuf = encoder.encode(mdOutput);
        const iv = new Uint8Array(12);
        const enc = await crypto.subtle.encrypt(
          { name: "AES-GCM", iv: iv },
          fileKey,
          arrayBuf,
        );

        const res = await fetch(`${FILE_API}/${uuid}/content`, {
          method: "PUT",
          headers: { "Content-Type": "application/octet-stream" },
          body: enc,
        });

        if (!res.ok) throw new Error("Save Error");

        // Update cached metadata with new size from server
        try {
          const result = await res.json();
          if (metadata) {
            metadata.file_size = result.size;
            metadata.last_modified = result.last_modified;
          }
        } catch (_) {
          // Non-critical: metadata sync failed, save itself succeeded
        }

        saveText.innerText = "SAVED";
        completeTransfer(tfId);

        // Refresh the drive listing so the UI reflects updated file size
        if (document.getElementById("item-container")) {
          fetchDrive(currentFolderId);
        }

        setTimeout(() => {
          saveText.innerText = "SAVE";
        }, 1500);
      } catch (err) {
        console.error(err);
        failTransfer(tfId);
        saveText.innerText = "ERROR";
        setTimeout(() => {
          saveText.innerText = "SAVE";
        }, 3000);
      } finally {
        // Always re-enable the button regardless of success/failure
        saveBtn.disabled = false;
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
  if (["jpg", "jpeg", "png", "gif", "webp", "svg", "bmp", "ico", "avif", "apng", "tif", "tiff"].includes(ext)) {
    // Image Icon
    return `<svg class="${commonClasses} text-primary/70" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M4 16l4.586-4.586a2 2 0 012.828 0L16 16m-2-2l1.586-1.586a2 2 0 012.828 0L20 14m-6-6h.01M6 20h12a2 2 0 002-2V6a2 2 0 00-2-2H6a2 2 0 00-2 2v12a2 2 0 002 2z"></path></svg>`;
  }
  if (["mp4", "webm", "mov", "avi", "mkv", "ogv", "ogg", "m4v", "3gp", "ts"].includes(ext)) {
    // Video Icon
    return `<svg class="${commonClasses} text-primary/80" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M15 10l4.553-2.276A1 1 0 0121 8.618v6.764a1 1 0 01-1.447.894L15 14M5 18h8a2 2 0 002-2V8a2 2 0 00-2-2H5a2 2 0 00-2 2v8a2 2 0 002 2z"></path></svg>`;
  }
  if (["mp3", "wav", "flac", "m4a", "ogg", "oga", "opus", "aac", "weba", "wma", "mid", "midi"].includes(ext)) {
    // Audio Icon
    return `<svg class="${commonClasses} text-primary" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M9 19V6l12-3v13M9 19c0 1.105-1.343 2-3 2s-3-.895-3-2 1.343-2 3-2 3 .895 3 2zm12-3c0 1.105-1.343 2-3 2s-3-.895-3-2 1.343-2 3-2 3 .895 3 2zM9 10l12-3"></path></svg>`;
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
  const itemId = isFolder ? item.id : item.uuid || item.id;
  const itemName = item.name || item.file_name;
  const isSelected = selectedItems.has(itemId);

  const iconGrid = getFileIcon(
    itemName,
    item.type,
    "w-8 h-8",
  );
  const iconList = getFileIcon(
    itemName,
    item.type,
    "w-5 h-5",
  );

  const sizeStr = isFolder ? `${item.size} items` : formatSize(item.size);
  const hasPreview = previewUrls.has(itemId);
  const previewStyle = hasPreview
    ? `style="background-image: url('${previewUrls.get(itemId)}'); background-size: cover; background-position: center;"`
    : "";

  if (currentView === "grid") {
    const iconHtml = hasPreview ? "" : iconGrid;
    const bgLayer = hasPreview
      ? `<div class="absolute inset-0 bg-black/40 group-hover:bg-black/20 transition-colors z-0"></div>`
      : "";

    const selectedClasses = isSelected
      ? "ring-2 ring-primary bg-primary/10 border-primary/60"
      : "border-outline-variant/20 bg-surface-container-high hover:bg-surface-variant";

    const chkOpacity = (isSelected || isBulkMode) ? "opacity-100" : "opacity-30 md:opacity-0 group-hover:opacity-100";

    return `
        <div class="col-span-1 min-h-[160px] border ${selectedClasses} transition-all p-4 flex flex-col items-center justify-center cursor-pointer interactive-el group relative drive-item overflow-hidden" data-id="${itemId}" data-type="${item.type}" data-name="${itemName}" data-size="${item.size}" data-size-str="${sizeStr}" data-modified-str="${new Date(item.modified).toLocaleDateString()}" ${previewStyle}>
            <!-- Checkbox -->
            <div class="drive-checkbox-wrapper absolute top-2 left-2 z-20" onclick="event.stopPropagation()">
                <input type="checkbox" class="drive-item-checkbox w-4 h-4 rounded border-outline-variant/40 bg-surface-container-highest/90 accent-primary cursor-pointer transition-all ${chkOpacity}" ${isSelected ? 'checked' : ''} data-id="${itemId}" data-type="${item.type}" data-name="${itemName}" />
            </div>

            <button class="ctx-btn absolute top-2 right-2 p-1 md:opacity-0 group-hover:opacity-100 transition-opacity z-20 text-on-surface-variant hover:text-primary bg-surface-container-highest/80 rounded backdrop-blur-sm" onclick="event.stopPropagation()">
                <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 5v.01M12 12v.01M12 19v.01M12 6a1 1 0 110-2 1 1 0 010 2zm0 7a1 1 0 110-2 1 1 0 010 2zm0 7a1 1 0 110-2 1 1 0 010 2z"></path></svg>
            </button>
            ${bgLayer}
            <div class="relative z-10 flex flex-col items-center justify-center w-full pointer-events-none">
                ${iconHtml}
                <span class="font-label text-xs tracking-wider text-on-surface w-full text-center truncate group-hover:text-primary transition-colors ${hasPreview ? "drop-shadow-lg" : ""}">${getNameWithoutMD(itemName)}</span>
                <span class="font-mono text-[9px] text-on-surface-variant/40 mt-1 ${hasPreview ? "text-white/70" : ""}">${sizeStr}</span>
            </div>
        </div>`;
  }

  const listSelectedClasses = isSelected
    ? "bg-primary/10 border-primary/50"
    : "hover:bg-surface-variant";

  return `
    <div class="col-span-full border-b border-outline-variant/10 ${listSelectedClasses} transition-all py-2 px-4 flex items-center justify-between cursor-pointer interactive-el drive-item relative group" data-id="${itemId}" data-type="${item.type}" data-name="${itemName}" data-size="${item.size}" data-size-str="${sizeStr}" data-modified-str="${new Date(item.modified).toLocaleDateString()}">
        <div class="flex items-center gap-3 w-[60%] md:w-1/2">
            <!-- Checkbox -->
            <div class="drive-checkbox-wrapper shrink-0 flex items-center mr-2" onclick="event.stopPropagation()">
                <input type="checkbox" class="drive-item-checkbox w-4 h-4 rounded border-outline-variant/40 bg-surface-container-highest/90 accent-primary cursor-pointer transition-all ${(isSelected || isBulkMode) ? 'opacity-100' : 'opacity-30 group-hover:opacity-100'}" ${isSelected ? 'checked' : ''} data-id="${itemId}" data-type="${item.type}" data-name="${itemName}" />
            </div>
            ${iconList}
            <span class="font-label text-sm tracking-wide text-on-surface truncate pr-2">${getNameWithoutMD(itemName)}</span>
        </div>
        <div class="hidden md:block font-mono text-[10px] text-on-surface-variant/40 w-1/4 text-right">${sizeStr}</div>
        <div class="hidden md:block font-mono text-[10px] text-on-surface-variant/40 w-1/4 text-right">${new Date(item.modified).toLocaleDateString()}</div>
        <button class="ctx-btn md:absolute right-4 p-2 md:opacity-0 group-hover:opacity-100 transition-opacity z-20 text-on-surface-variant hover:text-primary" onclick="event.stopPropagation()">
            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 5v.01M12 12v.01M12 19v.01M12 6a1 1 0 110-2 1 1 0 010 2zm0 7a1 1 0 110-2 1 1 0 010 2zm0 7a1 1 0 110-2 1 1 0 010 2z"></path></svg>
        </button>
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
    updateBulkUI();
    return;
  }

  container.innerHTML = [...folders, ...files].map(renderItem).join("");

  // Attach change listeners to checkboxes
  container.querySelectorAll(".drive-item-checkbox").forEach((chk) => {
    chk.addEventListener("change", (e) => {
      e.stopPropagation();
      const id = chk.dataset.id;
      const type = chk.dataset.type;
      const name = chk.dataset.name;
      if (chk.checked) isBulkMode = true;
      toggleSelectItem(id, type, name, chk.checked);
    });
  });

  document.querySelectorAll(".drive-item").forEach((el) => {
    const ctxBtn = el.querySelector(".ctx-btn");
    if (ctxBtn) {
      ctxBtn.addEventListener("click", (e) => {
        e.preventDefault();
        e.stopPropagation();
        
        // Calculate dropdown position
        const rect = ctxBtn.getBoundingClientRect();
        // Fallback to pageX if needed, but rect is safer for touch
        const x = e.pageX || rect.left;
        const y = e.pageY || rect.bottom;
        showContextMenu(x, y, el.dataset);
      });
    }

    el.addEventListener("click", (e) => {
      // If in bulk selection mode or clicked with Ctrl/Cmd or Shift key, toggle selection
      if (isBulkMode || e.ctrlKey || e.metaKey || e.shiftKey) {
        e.preventDefault();
        toggleSelectItem(el.dataset.id, el.dataset.type, el.dataset.name);
        return;
      }

      if (el.dataset.type === "folder") fetchDrive(el.dataset.id);
      else openLightbox(el.dataset);
    });
    el.addEventListener("contextmenu", (e) => {
      e.preventDefault();
      showContextMenu(e.pageX, e.pageY, el.dataset);
    });
  });

  updateBulkUI();
}

function showContextMenu(x, y, dataset) {
  const ctxMenu = document.getElementById("context-menu");
  const ctxHeader = document.getElementById("ctx-header");
  const ctxDl = document.getElementById("ctx-download");
  const ctxSelect = document.getElementById("ctx-select");
  if (!ctxMenu) return;
  activeCtxItem = dataset;
  if (ctxHeader) ctxHeader.innerText = dataset.name;
  if (ctxDl) ctxDl.style.display = dataset.type === "folder" ? "none" : "block";
  if (ctxSelect) {
    ctxSelect.innerText = selectedItems.has(dataset.id) ? "DESELECT ITEM" : "SELECT ITEM";
  }
  ctxMenu.classList.remove("hidden");
  ctxMenu.classList.add("flex");
}

function openLightbox(dataset) {
  activePreviewItem = dataset;
  readyToSaveBlob = decryptedSessionCache.get(dataset.id) || null;

  const db = document.getElementById("pv-download-btn");
  if (db) {
    db.classList.remove(
      "bg-tertiary",
      "text-on-tertiary",
      "bg-error",
      "text-on-error",
      "bg-surface-variant",
    );
    db.classList.add("bg-primary", "text-on-primary");
    const span = db.querySelector("span");
    if (span) span.innerText = "Save To Disk";
  }
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
  const isImage = [
    "jpg", "jpeg", "png", "gif", "webp", "svg", "bmp", "ico", "avif", "apng", "tif", "tiff"
  ].includes(ext);
  const isVideo = [
    "mp4", "webm", "ogg", "ogv", "mov", "m4v", "mkv", "avi", "3gp", "ts"
  ].includes(ext);
  const isAudio = [
    "mp3", "wav", "ogg", "oga", "opus", "m4a", "aac", "flac", "weba", "wma", "mid", "midi"
  ].includes(ext);
  const isText = [
    "txt", "md", "js", "ts", "py", "css", "html", "json", "sql", "log", "rtf", "c", "cpp", "java", "php", "sh", "xml", "yaml", "yml", "ini", "conf", "env"
  ].includes(ext);
  const isPdf = ext === "pdf";

  const isMedia = isImage || isVideo || isAudio || isText || isPdf;
  const sizeNum = parseInt(dataset.size || 0);
  const isSmall = sizeNum < 250 * 1024 * 1024;

  if (pvType) {
    let typeDesc = ext.toUpperCase();
    if (isImage) typeDesc = `${ext.toUpperCase()} IMAGE`;
    else if (isVideo) typeDesc = `${ext.toUpperCase()} VIDEO`;
    else if (isAudio) typeDesc = `${ext.toUpperCase()} AUDIO`;
    else if (isPdf) typeDesc = "PDF DOCUMENT";
    else if (ext === "md") typeDesc = "MARKDOWN NOTE";
    pvType.innerText = typeDesc;
  }

  const footer = document.getElementById("pv-footer");
  if (footer) footer.style.display = ext === "md" ? "none" : "flex";

  if (pvPreviewBtn) {
    pvPreviewBtn.style.display = isMedia && isSmall ? "flex" : "none";

    const shouldAutoLoad =
      ext === "md" ||
      isImage ||
      isAudio ||
      (isVideo && sizeNum < 150 * 1024 * 1024) ||
      (isText && sizeNum < 5 * 1024 * 1024) ||
      (isPdf && sizeNum < 25 * 1024 * 1024);

    if (shouldAutoLoad) {
      setTimeout(() => {
        if (activePreviewItem && activePreviewItem.id === dataset.id) {
          pvPreviewBtn.click();
        }
      }, 50);
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

  // Immediately pause and unload any media elements
  const mediaElements = previewModal.querySelectorAll("video, audio");
  mediaElements.forEach((m) => {
    try {
      m.pause();
      m.currentTime = 0;
      m.src = "";
      m.load();
    } catch (e) {}
  });

  // Restore any hidden lightbox chrome (in case MD editor hid them)
  const pvTopBar = previewModal.querySelector(':scope > div:first-child');
  const pvSurface = document.getElementById('pv-surface');
  const pvFooter = document.getElementById('pv-footer');
  if (pvTopBar) pvTopBar.style.display = '';
  if (pvFooter) pvFooter.style.display = '';
  if (pvSurface) pvSurface.style.padding = '';

  // Reset PDF zoom state
  _pdfState = null;

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
        showZNodeToast("Failed to create folder", "error");
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

  // Bulk Selection & Action Controls
  const toggleBulkMode = () => {
    isBulkMode = !isBulkMode;
    if (!isBulkMode) {
      clearSelection();
    } else {
      updateBulkUI();
    }
  };

  const bulkModeBtn = document.getElementById("drive-bulk-mode-btn");
  if (bulkModeBtn) {
    bulkModeBtn.onclick = toggleBulkMode;
  }

  const dynamicBulkBtn = document.getElementById("dynamic-bulk-btn");
  if (dynamicBulkBtn) {
    dynamicBulkBtn.onclick = toggleBulkMode;
  }

  const selectAllBtn = document.getElementById("drive-select-all-btn");
  if (selectAllBtn) {
    selectAllBtn.onclick = () => selectAllVisible();
  }

  const bulkSelectAllToggle = document.getElementById("bulk-select-all-toggle");
  if (bulkSelectAllToggle) {
    bulkSelectAllToggle.onclick = () => selectAllVisible();
  }

  const bulkClearBtn = document.getElementById("bulk-clear-btn");
  if (bulkClearBtn) {
    bulkClearBtn.onclick = () => clearSelection();
  }

  const bulkMoveBtn = document.getElementById("bulk-move-btn");
  if (bulkMoveBtn) {
    bulkMoveBtn.onclick = () => {
      if (selectedItems.size === 0) return;
      openMoveModal(Array.from(selectedItems.values()));
    };
  }

  const bulkDeleteBtn = document.getElementById("bulk-delete-btn");
  if (bulkDeleteBtn) {
    bulkDeleteBtn.onclick = async () => {
      if (selectedItems.size === 0) return;
      const items = Array.from(selectedItems.values());
      const foldersCount = items.filter((i) => i.type === "folder").length;
      const filesCount = items.filter((i) => i.type === "file").length;

      let details = [];
      if (foldersCount > 0) details.push(`${foldersCount} folder${foldersCount > 1 ? "s" : ""}`);
      if (filesCount > 0) details.push(`${filesCount} file${filesCount > 1 ? "s" : ""}`);

      const confirmed = await ZNodeDialog.confirm(
        "BULK DELETE",
        `Are you sure you want to permanently delete ${items.length} selected item${items.length > 1 ? "s" : ""} (${details.join(", ")})? All nested files and data will be permanently deleted. This action cannot be undone.`,
      );

      if (confirmed) {
        const file_ids = items.filter((i) => i.type === "file").map((i) => i.id);
        const folder_ids = items.filter((i) => i.type === "folder").map((i) => i.id);

        try {
          const res = await fetch("/app/api/drive/bulk/delete", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ file_ids, folder_ids }),
          });
          const data = await res.json();
          if (!res.ok) throw new Error(data.error || "Bulk delete failed");

          showZNodeToast(
            `Permanently deleted ${items.length} items`,
            "info",
          );
          clearSelection();
          fetchDrive(currentFolderId);
        } catch (err) {
          showZNodeToast(`Delete failed: ${err.message}`, "error");
        }
      }
    };
  }

  // Multi-selection keyboard shortcuts (Esc = clear, Del = bulk delete)
  window.addEventListener("keydown", (e) => {
    if (selectedItems.size === 0) return;
    const tag = (document.activeElement && document.activeElement.tagName) || "";
    if (["INPUT", "TEXTAREA"].includes(tag) || (document.activeElement && document.activeElement.isContentEditable)) {
      return;
    }

    if (e.key === "Escape") {
      clearSelection();
    } else if (e.key === "Delete" || e.key === "Backspace") {
      if (bulkDeleteBtn) bulkDeleteBtn.click();
    }
  });

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
    const ctxBox = document.getElementById("context-menu-box");
    if (ctxMenu && !ctxMenu.classList.contains("hidden")) {
      // If they clicked the overlay background (ctxMenu) or anything outside the box
      if (e.target === ctxMenu || (ctxBox && !ctxBox.contains(e.target) && !e.target.closest('.ctx-btn'))) {
        ctxMenu.classList.add("hidden");
        ctxMenu.classList.remove("flex");
      }
    }
  });

  const ctxCloseBtn = document.getElementById("ctx-close-btn");
  if (ctxCloseBtn) {
    ctxCloseBtn.onclick = () => {
      const ctxMenu = document.getElementById("context-menu");
      if (ctxMenu) {
        ctxMenu.classList.add("hidden");
        ctxMenu.classList.remove("flex");
      }
    };
  }

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
      async (e) => {
        overlay.classList.add("hidden");
        const { files, emptyDirs } = await extractFilesFromDataTransfer(e.dataTransfer);
        if (files.length > 0 || emptyDirs.length > 0) {
          const hasFolders = emptyDirs.length > 0 || files.some((f) => (f.webkitRelativePath || f._relPath || "").includes("/"));
          if (hasFolders) {
            processFolderUpload(files, emptyDirs);
          } else {
            for (let i = 0; i < files.length; i++) {
              processUploadQueue(files[i]);
            }
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
        "LOAD ALL PREVIEWS",
        "Decrypt and load media previews for all files in this folder? This will use bandwidth and local processing.",
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
  document.querySelectorAll("#context-menu .ctx-btn").forEach((btn) => {
    btn.onclick = async () => {
      const action = btn.dataset.action;
      if (!action || !activeCtxItem) return;
      const id = activeCtxItem.id;
      const type = activeCtxItem.type;
      const menu = document.getElementById("context-menu");
      if (menu) {
        menu.classList.remove("flex");
        menu.classList.add("hidden");
      }

      if (action === "select") {
        toggleSelectItem(id, type, activeCtxItem.name);
      } else if (action === "delete") {
        if (
          await ZNodeDialog.confirm(
            "DELETE",
            `Are you sure you want to permanently delete this ${type}? This action cannot be undone.`,
          )
        ) {
          await fetch(
            type === "folder"
              ? `/app/api/drive/delete/folder/${id}`
              : `/app/api/drive/delete/file/${id}`,
            { method: "POST" },
          );
          showZNodeToast(
            `Deleted: ${activeCtxItem.name}`,
            "info",
          );
          fetchDrive(currentFolderId);
        }
      } else if (action === "rename") {
        const isMdNote =
          type === "file" &&
          (activeCtxItem.name || "").toLowerCase().endsWith(".md");
        const displayName = isMdNote
          ? activeCtxItem.name.slice(0, -3)
          : activeCtxItem.name;

        let nn = await ZNodeDialog.prompt(
          "RENAME",
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
      } else if (action === "select") {
        isBulkMode = true;
        toggleSelectItem(id, type, activeCtxItem.name);
      }
    };
  });

  const pvDownloadBtn = document.getElementById("pv-download-btn");
  if (pvDownloadBtn) {
    pvDownloadBtn.onclick = async () => {
      if (!activePreviewItem) return;
      const btnSpan = pvDownloadBtn.querySelector("span");

      // Already saved or staged in this look? just re-trigger download
      if (readyToSaveBlob) {
        saveBlobToDisk(readyToSaveBlob, activePreviewItem.name);
        btnSpan.innerText = "SAVED";
        pvDownloadBtn.classList.remove("bg-primary", "bg-surface-variant");
        pvDownloadBtn.classList.add("bg-tertiary", "text-on-tertiary");
        return;
      }

      toggleLightboxButtons(true);
      const loader = document.getElementById("pv-loader");
      if (loader) loader.classList.remove("opacity-0", "pointer-events-none");

      btnSpan.innerText = "DECRYPTING...";
      pvDownloadBtn.classList.remove("bg-primary");
      pvDownloadBtn.classList.add("bg-surface-variant");

      try {
        readyToSaveBlob = await downloadFile(
          activePreviewItem.id,
          activePreviewItem.name,
          true,
        );

        // Instant Auto-Download Handshake
        saveBlobToDisk(readyToSaveBlob, activePreviewItem.name);

        btnSpan.innerText = "SAVED";
        pvDownloadBtn.classList.remove("bg-surface-variant");
        pvDownloadBtn.classList.add("bg-tertiary", "text-on-tertiary");
      } catch (e) {
        btnSpan.innerText = "FAILED";
        pvDownloadBtn.classList.remove("bg-primary", "bg-surface-variant");
        pvDownloadBtn.classList.add("bg-error", "text-on-error");
        console.error(e);
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

      // 1. Hide the preview button immediately so it doesn't clutter the UI
      pvPreviewBtn.style.display = "none";

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
        readyToSaveBlob = blob;
        const mime = getMimeType(activePreviewItem.name);
        const playBlob = blob.type && blob.type !== "application/octet-stream"
          ? blob
          : new Blob([blob], { type: mime });
        const url = URL.createObjectURL(playBlob);
        const ext = activePreviewItem.name.split(".").pop().toLowerCase();
        let el;

        if (
          ["jpg", "jpeg", "png", "gif", "webp", "svg", "bmp", "ico", "avif", "apng", "tif", "tiff"].includes(ext)
        ) {
          el = document.createElement("img");
          el.src = url;
          el.alt = activePreviewItem.name;
          el.className = "max-w-full max-h-[75vh] object-contain shadow-2xl rounded border border-outline-variant/20";
        } else if (
          ["mp4", "webm", "ogg", "ogv", "mov", "m4v", "mkv", "avi", "3gp", "ts"].includes(ext)
        ) {
          const wrapper = document.createElement("div");
          wrapper.className = "flex flex-col items-center justify-center max-w-5xl w-full max-h-full";
          wrapper.innerHTML = `
            <div class="relative w-full flex items-center justify-center bg-black/60 rounded overflow-hidden">
              <video controls playsinline preload="auto" class="max-w-full max-h-[72vh] rounded border border-outline-variant/30 shadow-2xl bg-black object-contain focus:outline-none w-full">
                  <source src="${url}" type="${mime}">
                  Your browser does not support native playback for this video format.
              </video>
            </div>
            <div class="mt-3 flex items-center justify-between w-full max-w-full px-2">
                <span class="font-mono text-[10px] text-on-surface-variant/60 uppercase tracking-widest truncate max-w-[70%]">${activePreviewItem.name}</span>
                <span class="font-mono text-[10px] text-primary uppercase tracking-widest px-2 py-0.5 bg-primary/10 border border-primary/20 rounded">${ext.toUpperCase()} VIDEO</span>
            </div>
          `;
          const vid = wrapper.querySelector("video");
          if (vid) {
            vid.src = url;
            try {
              vid.load();
            } catch (e) {}
            vid.addEventListener("error", () => {
              const notice = document.createElement("div");
              notice.className = "mt-3 p-3 bg-error/10 border border-error/30 text-error font-mono text-[10px] text-center uppercase tracking-wider rounded w-full";
              notice.innerText = "Notice: This video format or codec cannot be decoded natively by your browser. Use 'Save To Disk' to play in VLC or another media player.";
              wrapper.appendChild(notice);
            });
          }
          el = wrapper;
        } else if (
          ["mp3", "wav", "ogg", "oga", "opus", "m4a", "aac", "flac", "weba", "wma", "mid", "midi"].includes(ext)
        ) {
          const wrapper = document.createElement("div");
          wrapper.className = "flex flex-col items-center justify-center p-6 md:p-10 max-w-lg w-full bg-surface-container-high/90 border border-outline-variant/30 shadow-2xl backdrop-blur-md rounded";
          wrapper.innerHTML = `
            <div class="w-28 h-28 md:w-36 md:h-36 rounded-full bg-gradient-to-tr from-surface-container-highest to-surface-variant border-2 border-primary/40 flex items-center justify-center mb-6 shadow-inner relative group overflow-hidden">
                <div class="absolute inset-0 bg-primary/10 rounded-full animate-ping opacity-25"></div>
                <svg class="w-14 h-14 md:w-16 md:h-16 text-primary relative z-10 transition-transform group-hover:scale-110" fill="currentColor" viewBox="0 0 24 24">
                    <path d="M12 3v10.55c-.59-.34-1.27-.55-2-.55-2.21 0-4 1.79-4 4s1.79 4 4 4 4-1.79 4-4V7h4V3h-6z"/>
                </svg>
            </div>
            <div class="text-center w-full mb-6 px-4">
                <h3 class="font-headline text-base md:text-lg tracking-wider text-on-surface uppercase truncate w-full" title="${activePreviewItem.name}">${activePreviewItem.name}</h3>
                <div class="flex items-center justify-center gap-3 mt-2 font-mono text-[10px] text-on-surface-variant/60 uppercase tracking-widest">
                    <span class="px-2 py-0.5 bg-primary/10 text-primary border border-primary/20 rounded">${ext.toUpperCase()} AUDIO</span>
                    <span>${activePreviewItem.sizeStr || formatSize(blob.size)}</span>
                </div>
            </div>
            <div class="w-full">
                <audio controls class="w-full h-11 focus:outline-none accent-primary rounded" preload="auto">
                    <source src="${url}" type="${mime}">
                    Your browser does not support audio playback.
                </audio>
            </div>
          `;
          const aud = wrapper.querySelector("audio");
          if (aud) {
            aud.src = url;
            try {
              aud.load();
            } catch (e) {}
            aud.addEventListener("error", () => {
              const notice = document.createElement("div");
              notice.className = "mt-3 p-3 bg-error/10 border border-error/30 text-error font-mono text-[10px] text-center uppercase tracking-wider rounded w-full";
              notice.innerText = "Notice: This audio format cannot be decoded natively by your browser. Use 'Save To Disk' to play locally.";
              wrapper.appendChild(notice);
            });
          }
          el = wrapper;
        } else if (["pdf"].includes(ext)) {
          // Custom but secure container with zoom controls
          const wrapper = document.createElement("div");
          wrapper.className =
            "flex flex-col w-full h-full bg-surface-container overflow-hidden";
          wrapper.innerHTML = `
            <div class="px-6 py-3 border-b border-outline-variant/20 flex items-center justify-between bg-surface-container-high">
                <div class="flex items-center gap-3">
                    <svg class="w-4 h-4 text-primary" fill="currentColor" viewBox="0 0 20 20"><path d="M9 2a2 2 0 00-2 2v8a2 2 0 002 2h6a2 2 0 002-2V6.414A2 2 0 0016.414 5L14 2.586A2 2 0 0012.586 2H9z"></path><path d="M3 8a2 2 0 012-2v10h8a2 2 0 01-2 2H5a2 2 0 01-2-2V8z"></path></svg>
                    <span class="font-mono text-[9px] tracking-[0.2em] text-on-surface-variant uppercase">PREVIEWING SECURE DOCUMENT // ${activePreviewItem.name.toUpperCase()}</span>
                </div>
                <div class="flex items-center gap-2">
                    <button id="pdf-zoom-out" class="w-8 h-8 flex items-center justify-center text-on-surface-variant/60 hover:text-primary hover:bg-surface-variant border border-outline-variant/20 transition-all font-mono text-sm font-bold" title="Zoom Out">−</button>
                    <span id="pdf-zoom-level" class="font-mono text-[9px] tracking-widest text-on-surface-variant/60 min-w-[50px] text-center uppercase">100%</span>
                    <button id="pdf-zoom-in" class="w-8 h-8 flex items-center justify-center text-on-surface-variant/60 hover:text-primary hover:bg-surface-variant border border-outline-variant/20 transition-all font-mono text-sm font-bold" title="Zoom In">＋</button>
                    <button id="pdf-zoom-reset" class="ml-2 font-mono text-[9px] tracking-widest text-primary/40 hover:text-primary uppercase transition-colors px-3 py-1.5 border border-primary/10 hover:bg-primary/5" title="Reset Zoom">FIT</button>
                </div>
            </div>
            <div id="pdf-viewer-canvas" class="flex-grow flex flex-col items-center gap-6 p-8 overflow-auto bg-surface-container-high/30 scroll-smooth">
                <div class="vault-spinner mb-4 border-on-surface-variant/30 border-t-primary" id="pdf-load-spinner"></div>
            </div>
          `;
          el = wrapper;
          // Trigger Custom Render with zoom support
          setTimeout(() => renderPDF(url, "pdf-viewer-canvas"), 100);
        } else if (
          [
            "txt",
            "md",
            "js",
            "ts",
            "html",
            "css",
            "py",
            "json",
            "sql",
            "log",
            "rtf",
            "c",
            "cpp",
            "java",
            "php",
            "sh",
          ].includes(ext)
        ) {
          const MAX_RICH_RENDER_SIZE = 500 * 1024; // 500 KB Limit for Rich Editor
          const MAX_RAW_READ_SIZE = 5 * 1024 * 1024; // 5 MB Limit for RAM

          // 1. SAFE MARKDOWN: Open in standard Rich Editor
          if (ext === "md" && blob.size <= MAX_RICH_RENDER_SIZE) {
            const t = await blob.text();
            initMarkdownEditor(activePreviewItem.id, activePreviewItem.name, t);
            return;
          }

          // 2. RAW FALLBACK: File is too large for Rich Editor or is a standard code/text file
          if (ext === "md") {
            showZNodeToast(
              "FILE TOO LARGE FOR EDITOR. OPENING IN RAW VIEW.",
              "info",
            );
          }

          let t = "";
          let isTruncated = false;

          // 3. RAM PROTECTION: Slice the blob if it's massive
          if (blob.size > MAX_RAW_READ_SIZE) {
            const chunk = blob.slice(0, MAX_RAW_READ_SIZE);
            t = await chunk.text();
            isTruncated = true;
            showZNodeToast("Preview truncated due to file size.", "info");
          } else {
            t = await blob.text();
          }

          // 4. Render the optimized Raw Textarea
          el = document.createElement("textarea");
          el.value =
            t +
            (isTruncated
              ? "\n\n... [FILE TRUNCATED. PLEASE DOWNLOAD TO VIEW FULL CONTENT] ..."
              : "");
          el.readOnly = true;
          el.spellcheck = false; // Prevents dictionary from freezing the tab on 5MB files
          el.className =
            "text-on-surface font-mono text-[11px] leading-relaxed p-16 md:p-24 bg-[#020202] w-full h-full resize-none focus:outline-none selection:bg-primary/30 selection:text-white border-none";

          const content = document.getElementById("pv-content");
          if (content) {
            content.innerHTML = "";
            content.appendChild(el);
          }

          // Ensure the footer with the Download button is visible
          const footer = document.getElementById("pv-footer");
          if (footer) footer.style.display = "flex";
        } else {
          el = document.createElement("div");
          el.className =
            "flex flex-col items-center justify-center p-12 text-on-surface-variant/40";
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

        // 2. If it fails to load, bring the preview button back so they can try again
        pvPreviewBtn.style.display = "flex";

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
  const triggerUpload = () => {
    const upInput = document.getElementById("hidden-file-input");
    if (upInput) upInput.click();
  };

  const triggerFolderUpload = () => {
    const folderInput = document.getElementById("hidden-folder-input");
    if (folderInput) folderInput.click();
  };

  const upBtn = document.getElementById("dynamic-upload");
  if (upBtn) upBtn.onclick = triggerUpload;

  const headerUpBtn = document.getElementById("drive-upload-btn");
  if (headerUpBtn) headerUpBtn.onclick = triggerUpload;

  const folderUpBtn = document.getElementById("dynamic-upload-folder");
  if (folderUpBtn) folderUpBtn.onclick = triggerFolderUpload;

  const headerFolderUpBtn = document.getElementById("drive-upload-folder-btn");
  if (headerFolderUpBtn) headerFolderUpBtn.onclick = triggerFolderUpload;

  const upInput = document.getElementById("hidden-file-input");
  if (upInput) {
    upInput.onchange = (e) => {
      for (let i = 0; i < e.target.files.length; i++) {
        processUploadQueue(e.target.files[i]);
      }
      e.target.value = "";
    };
  }

  const folderInput = document.getElementById("hidden-folder-input");
  if (folderInput) {
    folderInput.onchange = (e) => {
      if (e.target.files && e.target.files.length > 0) {
        processFolderUpload(e.target.files);
      }
      e.target.value = "";
    };
  }
}

function formatFileSize(bytes) {
  if (!bytes || bytes <= 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  return (bytes / Math.pow(1024, i)).toFixed(i > 0 ? 1 : 0) + ' ' + units[i];
}

// --- Folder Operations & Hierarchy Ingestion ---
async function createZeroNodeFolder(name, parentId = null) {
  const res = await fetch("/app/api/drive/folder", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ name: name, parent_id: parentId || null }),
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || `Failed creating folder '${name}'`);
  return data.id;
}

async function extractFilesFromDataTransfer(dataTransfer) {
  const items = dataTransfer.items;
  const files = [];
  const emptyDirs = [];

  if (items && items.length > 0 && items[0].webkitGetAsEntry) {
    const queue = [];
    for (let i = 0; i < items.length; i++) {
      const entry = items[i].webkitGetAsEntry();
      if (entry) queue.push(entry);
    }

    async function traverseEntry(entry, path = "") {
      if (entry.isFile) {
        return new Promise((resolve) => {
          entry.file(
            (file) => {
              file._relPath = path ? `${path}/${file.name}` : file.name;
              files.push(file);
              resolve();
            },
            () => resolve()
          );
        });
      } else if (entry.isDirectory) {
        const dirReader = entry.createReader();
        const dirPath = path ? `${path}/${entry.name}` : entry.name;
        let entryCount = 0;

        const readAllEntries = async () => {
          return new Promise((resolve) => {
            dirReader.readEntries(
              async (entries) => {
                if (!entries || entries.length === 0) {
                  resolve();
                } else {
                  entryCount += entries.length;
                  for (const subEntry of entries) {
                    await traverseEntry(subEntry, dirPath);
                  }
                  await readAllEntries();
                  resolve();
                }
              },
              () => resolve()
            );
          });
        };
        await readAllEntries();
        if (entryCount === 0) {
          emptyDirs.push(dirPath);
        }
      }
    }

    for (const entry of queue) {
      await traverseEntry(entry);
    }

    return { files, emptyDirs };
  }

  if (dataTransfer.files && dataTransfer.files.length > 0) {
    return { files: Array.from(dataTransfer.files), emptyDirs: [] };
  }
  return { files: [], emptyDirs: [] };
}

async function processFolderUpload(fileList, emptyDirs = []) {
  const files = fileList ? Array.from(fileList) : [];
  if (files.length === 0 && emptyDirs.length === 0) return;

  const rootDestId = currentFolderId || null;
  const folderCache = new Map(); // relativePath -> serverFolderId

  showZNodeToast(`Uploading folder structure (${files.length} file${files.length === 1 ? '' : 's'})...`, "info");

  // Pre-seed folderCache with existing folders under current view to allow smooth merging
  try {
    const listRes = await fetch(`/app/api/drive/list${rootDestId ? '/' + rootDestId : ''}`);
    if (listRes.ok) {
      const data = await listRes.json();
      if (Array.isArray(data.folders)) {
        for (const ef of data.folders) {
          if (ef.name && ef.id) {
            folderCache.set(ef.name, ef.id);
          }
        }
      }
    }
  } catch (e) {
    console.warn("Could not pre-fetch folders:", e);
  }

  let createdNewFolder = false;

  // Process empty directory structures first if any
  for (const emptyDir of emptyDirs) {
    const parts = emptyDir.split("/").filter(Boolean);
    let currentPathAcc = "";
    for (let i = 0; i < parts.length; i++) {
      const seg = parts[i];
      currentPathAcc = currentPathAcc ? `${currentPathAcc}/${seg}` : seg;
      if (!folderCache.has(currentPathAcc)) {
        const parentId = (i === 0) ? rootDestId : folderCache.get(parts.slice(0, i).join("/"));
        try {
          const newId = await createZeroNodeFolder(seg, parentId);
          folderCache.set(currentPathAcc, newId);
          createdNewFolder = true;
        } catch (err) {
          console.error(`Failed to create empty folder ${seg}:`, err);
        }
      }
    }
  }

  // Sort files so shallow directories are created before nested subdirectories
  files.sort((a, b) => {
    const pathA = a.webkitRelativePath || a._relPath || a.name || "";
    const pathB = b.webkitRelativePath || b._relPath || b.name || "";
    const depthA = (pathA.match(/\//g) || []).length;
    const depthB = (pathB.match(/\//g) || []).length;
    return depthA - depthB;
  });

  for (const file of files) {
    const relPath = file.webkitRelativePath || file._relPath || file.name;
    const parts = relPath.split("/").filter(Boolean);

    let targetFolderId = rootDestId;

    if (parts.length > 1) {
      const dirParts = parts.slice(0, -1);
      let currentPathAcc = "";

      for (let i = 0; i < dirParts.length; i++) {
        const seg = dirParts[i];
        currentPathAcc = currentPathAcc ? `${currentPathAcc}/${seg}` : seg;

        if (folderCache.has(currentPathAcc)) {
          targetFolderId = folderCache.get(currentPathAcc);
        } else {
          const parentId = (i === 0) ? rootDestId : folderCache.get(dirParts.slice(0, i).join("/"));
          try {
            const newId = await createZeroNodeFolder(seg, parentId);
            targetFolderId = newId;
            folderCache.set(currentPathAcc, newId);
            createdNewFolder = true;
          } catch (err) {
            console.error(`Failed to create folder ${seg}:`, err);
          }
        }
      }
    }

    file._targetFolderId = targetFolderId;
    processUploadQueue(file);
  }

  if (createdNewFolder && document.getElementById("item-container")) {
    fetchDrive(currentFolderId);
  }
}


async function decryptFolderMedia() {
  const items = document.querySelectorAll('.drive-item[data-type="file"]');
  const mediaExts = ["jpg", "jpeg", "png", "gif", "webp", "svg", "bmp", "avif", "apng"];

  for (const el of items) {
    const id = el.dataset.id;
    const name = el.dataset.name;
    const ext = name.split(".").pop().toLowerCase();

    if (!mediaExts.includes(ext)) continue;
    if (previewUrls.has(id)) continue;

    const size = parseInt(el.dataset.size || 0);
    const BULK_LIMIT = 15 * 1024 * 1024; // Skip files over 15MB in bulk preview

    if (size > BULK_LIMIT) {
      console.warn(`Skipping bulk preview for ${name} (Too large)`);
      showZNodeToast(`Skipping bulk preview for ${name} (Too large)`, "error");
      continue;
    }

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
    await uploadFile(nextFile, nextFile._tfId, nextFile._targetFolderId);
  } finally {
    activeUploadCount--;
    processUploadQueue(); // Try to start next in line
  }
}

async function uploadFile(file, tfId, targetFolderId = null) {
  if (!file) return;
  if (file.size === 0 && !file.name.endsWith(".md")) {
    failTransfer(tfId);
    showZNodeToast(
      `Cannot upload empty file: ${file.name}`,
      "error",
    );
    return;
  }
  const isLarge = file.size > 100 * 1024 * 1024; // 100MB threshold
  const ext = file.name.split(".").pop().toLowerCase();

  // Status already added by processUploadQueue
  try {
    const masterKey = await DriveCrypto.getVaultMasterKey();
    const fileKey = await DriveCrypto.generateFileKey();
    const wrappedKey64 = await DriveCrypto.wrapFileKey(fileKey, masterKey);

    const destFolder = (file && file._targetFolderId !== undefined)
      ? file._targetFolderId
      : (targetFolderId !== null ? targetFolderId : (currentFolderId || null));

    const initRes = await fetchWithRetry(`${FILE_API}/init`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        file_name: file.name,
        aes_key: wrappedKey64,
        folder_id: destFolder || null,
      }),
    });
    const { uuid } = await initRes.json();

    let offset = 0,
      idx = 0,
      cOff = 0;
    const cipherChunks = [];
    
    // Concurrent Upload Pool to defeat Cloudflare network latency
    const MAX_CONCURRENT = 4;
    const activeUploads = [];
    let totalUploadedBytes = 0;

    while (offset < file.size) {
      const chunk = file.slice(offset, offset + OPFS_CHUNK_SIZE);
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

      const currentCOff = cOff;
      const currentChunkSize = chunk.size;

      const p = fetchWithRetry(`${FILE_API}/${uuid}/chunk`, {
        method: "POST",
        headers: {
          "X-Chunk-Offset": currentCOff.toString(),
          "Content-Type": "application/octet-stream",
        },
        body: enc,
      }).then(() => {
        totalUploadedBytes += currentChunkSize;
        updateTransfer(tfId, (totalUploadedBytes / file.size) * 100);
      });

      activeUploads.push(p);
      p.finally(() => {
        const index = activeUploads.indexOf(p);
        if (index > -1) activeUploads.splice(index, 1);
      });

      if (activeUploads.length >= MAX_CONCURRENT) {
        await Promise.race(activeUploads);
      }

      offset += chunk.size;
      cOff += enc.byteLength;
      idx++;
    }

    // Await any remaining active chunk uploads in the pool
    await Promise.all(activeUploads);

    await fetchWithRetry(`${FILE_API}/${uuid}/finalize`, { method: "POST" });

    if (!isLarge && ext !== "md") {
      try {
        await cacheFile(uuid, new Blob(cipherChunks));
      } catch (e) {}
    }

    completeTransfer(tfId);
    showZNodeToast(`Uploaded: ${file.name}`, "info");
    if (!file._skipDriveRefresh && document.getElementById("item-container")) fetchDrive(currentFolderId);
    return uuid;
  } catch (err) {
    console.error(err);
    failTransfer(tfId);
    showZNodeToast(`Upload failed: ${file.name} - ${err.message}`, "error");
  }
}

async function downloadFile(uuid, name, returnBlob = false) {
  // 1. Session RAM Cache Check
  if (decryptedSessionCache.has(uuid)) {
    const b = decryptedSessionCache.get(uuid);
    if (returnBlob) return b;
    saveBlobToDisk(b, name);
    return;
  }

  // 2. Active Task Check
  if (activeTaskSignals.has(uuid)) return await activeTaskSignals.get(uuid);

  const task = (async () => {
    let tfId = Math.random().toString(36).substr(2, 9);
    const ext = (name || "").split(".").pop().toLowerCase();

    try {
      addTransfer(tfId, name, "DECRYPT");

      // STEP 1: The Gatekeeper (Metadata First)
      let metadata = metadataCache.get(uuid);
      if (!metadata) {
        const r = await fetch(`${FILE_API}/${uuid}/meta`);
        if (!r.ok)
          throw new Error(
            r.status === 404
              ? "File missing from storage."
              : "Metadata fetch failed.",
          );
        metadata = await r.json();
        metadataCache.set(uuid, metadata);
      }

      const fileSize = metadata.file_size;
      const isMd = ext === "md";

      // If file is large (>100MB) or isn't a simple note, use OPFS Parallel Engine
      if (fileSize > 100 * 1024 * 1024 || (!isMd && !returnBlob)) {
        return await downloadFileOPFSEngine(
          uuid,
          name,
          metadata,
          tfId,
          returnBlob,
        );
      }

      // Legacy/Small File Logic (RAM-based)
      const diskCached = await getCachedFile(uuid);
      let encryptedBytes;
      if (diskCached) {
        encryptedBytes = await diskCached.blob.arrayBuffer();
      } else {
        const res = await fetch(`${FILE_API}/${uuid}`);
        const reader = res.body.getReader();
        let received = 0,
          chunks = [];
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          chunks.push(value);
          received += value.length;
          updateTransfer(tfId, (received / fileSize) * 100);
        }
        const full = new Uint8Array(received);
        let pos = 0;
        for (let c of chunks) {
          full.set(c, pos);
          pos += c.length;
        }
        encryptedBytes = full.buffer;
        if (ext !== "md")
          await cacheFile(uuid, new Blob([encryptedBytes]), metadata);
      }

      const masterKey = await DriveCrypto.getVaultMasterKey();
      const fileKey = await DriveCrypto.unwrapFileKey(
        metadata.aes_key,
        masterKey,
      );
      let decryptedChunks = [];
      const CHUNK_WITH_TAG = OPFS_CHUNK_SIZE + 16;

      for (let i = 0; i * CHUNK_WITH_TAG < encryptedBytes.byteLength; i++) {
        const iv = new Uint8Array(12);
        new DataView(iv.buffer).setUint32(8, i, false);
        const chunk = encryptedBytes.slice(
          i * CHUNK_WITH_TAG,
          (i + 1) * CHUNK_WITH_TAG,
        );
        decryptedChunks.push(
          await crypto.subtle.decrypt(
            { name: "AES-GCM", iv: iv },
            fileKey,
            chunk,
          ),
        );
      }

      const finalMime = getMimeType(name);
      const finalBlob = new Blob(decryptedChunks, { type: finalMime });

      const CACHE_RAM_LIMIT = 10 * 1024 * 1024; // 10MB
      if (ext !== "md" && finalBlob.size <= CACHE_RAM_LIMIT) {
        decryptedSessionCache.set(uuid, finalBlob);
      }

      completeTransfer(tfId);
      if (!returnBlob) saveBlobToDisk(finalBlob, name);
      return finalBlob;
    } catch (err) {
      const el = document.querySelector(`.drive-item[data-id="${uuid}"]`);
      if (el) applyFailure(el);
      failTransfer(tfId);
      showZNodeToast(`FAILED: ${name} - ${err.message}`, "error");
      throw err;
    } finally {
      activeTaskSignals.delete(uuid);
    }
  })();

  activeTaskSignals.set(uuid, task);
  return await task;
}

/**
 * PHASE 3: The OPFS Parallel Engine (The Speed Boost)
 * Fetches and decrypts in parallel using HTTP Range requests and local OPFS staging.
 */
/**
 * PHASE 3: The OPFS Parallel Engine (The Speed Boost)
 * Fetches and decrypts in parallel using HTTP Range requests and local OPFS staging.
 */
async function downloadFileOPFSEngine(uuid, name, metadata, tfId, returnBlob) {
  const masterKey = await DriveCrypto.getVaultMasterKey();
  const fileKey = await DriveCrypto.unwrapFileKey(metadata.aes_key, masterKey);
  const fileSize = metadata.file_size; // This is the total ENCRYPTED size on the server

  // Setup OPFS
  const fileHandle = await createOPFSTempFile(uuid);
  const writable = await fileHandle.createWritable();

  const CHUNK_WITH_TAG = OPFS_CHUNK_SIZE + 16;

  // FIX 1: Math Bug. Must divide by the chunk size WITH the encryption tag,
  // otherwise it tries to fetch a non-existent chunk at the end of the file.
  const numChunks = Math.ceil(fileSize / CHUNK_WITH_TAG);
  const tasks = Array.from({ length: numChunks }, (_, i) => i);

  let completedChunks = 0;
  let isWriting = false; // FIX 2: Write Lock to prevent Chrome crashing from concurrent writes

  const pvLoader = document.getElementById("pv-loader");
  const pvLoaderText = pvLoader ? pvLoader.querySelector("span") : null;

  if (pvLoader) pvLoader.classList.remove("opacity-0", "pointer-events-none");

  const runWorker = async () => {
    while (tasks.length > 0) {
      const chunkIdx = tasks.shift();
      const start = chunkIdx * CHUNK_WITH_TAG;
      const end = Math.min((chunkIdx + 1) * CHUNK_WITH_TAG - 1, fileSize - 1);

      try {
        const res = await fetch(`${FILE_API}/${uuid}`, {
          headers: { Range: `bytes=${start}-${end}` },
        });
        if (!res.ok) throw new Error(`Chunk ${chunkIdx} fetch failed`);

        const encryptedBuffer = await res.arrayBuffer();
        const iv = new Uint8Array(12);
        new DataView(iv.buffer).setUint32(8, chunkIdx, false);

        const decryptedData = await crypto.subtle.decrypt(
          { name: "AES-GCM", iv: iv },
          fileKey,
          encryptedBuffer,
        );

        // Wait for turn to write (prevents InvalidStateError)
        while (isWriting) await new Promise((r) => setTimeout(r, 10));
        isWriting = true;
        try {
          await writable.write({
            type: "write",
            position: chunkIdx * OPFS_CHUNK_SIZE,
            data: decryptedData,
          });
        } finally {
          isWriting = false; // Release lock
        }

        completedChunks++;
        const pct = (completedChunks / numChunks) * 100;
        updateTransfer(tfId, pct);
        if (pvLoaderText)
          pvLoaderText.innerText = `DECRYPTING ${Math.round(pct)}%...`;
      } catch (err) {
        console.error(`[Worker] Error on chunk ${chunkIdx}:`, err);
        throw err;
      }
    }
  };

  try {
    // Establishing Worker Pool
    const workers = Array.from({ length: OPFS_WORKER_LIMIT }, () =>
      runWorker(),
    );
    await Promise.all(workers);
    await writable.close();

    completeTransfer(tfId);

    // Handshake: OPFS -> Disk
    const finalFile = await fileHandle.getFile();

    // Return the OPFS-backed File directly — it's already a Blob subclass.
    // DO NOT wrap in `new Blob([finalFile])` — that copies the entire file into RAM and OOMs on large files.
    // DO NOT cleanup OPFS immediately — the File object needs its backing store alive until the browser finishes saving.
    const OPFS_CLEANUP_DELAY = 5 * 60 * 1000; // 5 minutes

    if (returnBlob) {
      if (pvLoader) pvLoader.classList.add("opacity-0", "pointer-events-none");
      setTimeout(() => cleanupOPFS(uuid), OPFS_CLEANUP_DELAY);
      const mime = getMimeType(name);
      // OPFS-backed File handles cause MEDIA_ERR_SRC_NOT_SUPPORTED in Chromium/WebKit media players
      // because OPFS URLs do not support range seeks/demuxing.
      // Convert to in-memory Blob so video/audio players can stream and seek natively.
      const arrayBuf = await finalFile.arrayBuffer();
      return new Blob([arrayBuf], { type: mime || finalFile.type });
    }

    // "Regular Download Trigger"
    const url = URL.createObjectURL(finalFile);
    const a = document.createElement("a");
    a.href = url;
    a.download = name;
    a.click();
    URL.revokeObjectURL(url);

    // Cleanup after delay to let the browser finish streaming
    setTimeout(() => cleanupOPFS(uuid), OPFS_CLEANUP_DELAY);
    if (pvLoader) pvLoader.classList.add("opacity-0", "pointer-events-none");

    return finalFile;
  } catch (err) {
    await writable.abort();
    await cleanupOPFS(uuid);
    if (pvLoader) pvLoader.classList.add("opacity-0", "pointer-events-none");
    throw err;
  }
}

let _pdfState = null; // Module-level state for active PDF viewer

async function renderPDF(url, containerId) {
  const container = document.getElementById(containerId);

  // 1. Wait for pdfjsLib to load (Retry logic for async scripts)
  let retries = 0;
  while (!window.pdfjsLib && retries < 20) {
    await new Promise((r) => setTimeout(r, 200));
    retries++;
  }

  if (!window.pdfjsLib) {
    container.innerHTML = `<div class="flex flex-col items-center justify-center p-12 text-error"><span class="font-mono text-[10px]">RENDER ENGINE OFFLINE // LIBRARY_MISSING</span></div>`;
    return;
  }

  try {
    // Force worker initialization if missed (LOCAL)
    if (!window.pdfjsLib.GlobalWorkerOptions.workerSrc) {
      window.pdfjsLib.GlobalWorkerOptions.workerSrc =
        "/static/js/pdf.worker.min.js";
    }

    const params = {
      url: url,
      cMapUrl: "/static/js/cmaps/",
      cMapPacked: true,
    };

    const loadingTask = window.pdfjsLib.getDocument(params);
    const pdf = await loadingTask.promise;

    // Clear spinner
    const spinner = document.getElementById("pdf-load-spinner");
    if (spinner) spinner.remove();

    const MAX_SAFE_PAGES = Math.min(pdf.numPages, 50); // Increased safe limit

    // Store state for zoom controls
    _pdfState = {
      pdf: pdf,
      containerId: containerId,
      url: url,
      scale: 1.6,
      maxPages: MAX_SAFE_PAGES,
    };

    // Render at initial scale
    await _renderPDFPages(pdf, container, 1.6, MAX_SAFE_PAGES);

    // Update zoom label
    const zoomLabel = document.getElementById("pdf-zoom-level");
    if (zoomLabel) zoomLabel.innerText = '100%';

    // Bind zoom controls
    const zoomIn = document.getElementById("pdf-zoom-in");
    const zoomOut = document.getElementById("pdf-zoom-out");
    const zoomReset = document.getElementById("pdf-zoom-reset");

    if (zoomIn) zoomIn.onclick = () => _pdfZoom(0.25);
    if (zoomOut) zoomOut.onclick = () => _pdfZoom(-0.25);
    if (zoomReset) zoomReset.onclick = () => _pdfZoomTo(1.6);

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

async function _renderPDFPages(pdf, container, scale, maxPages) {
  container.innerHTML = ''; // Clear previous renders
  for (let pageNum = 1; pageNum <= maxPages; pageNum++) {
    const page = await pdf.getPage(pageNum);
    const viewport = page.getViewport({ scale });

    const canvas = document.createElement("canvas");
    const ctx = canvas.getContext("2d");
    canvas.height = viewport.height;
    canvas.width = viewport.width;
    canvas.className =
      "shadow-2xl mb-12 max-w-full h-auto bg-white transition-opacity duration-500 opacity-0 rounded-sm";

    container.appendChild(canvas);

    const renderContext = {
      canvasContext: ctx,
      viewport: viewport,
      enableWebGL: true,
    };

    await page.render(renderContext).promise;
    canvas.classList.remove("opacity-0");
  }
}

async function _pdfZoom(delta) {
  if (!_pdfState) return;
  const newScale = Math.max(0.4, Math.min(5.0, _pdfState.scale + delta));
  if (newScale === _pdfState.scale) return;
  await _pdfZoomTo(newScale);
}

async function _pdfZoomTo(newScale) {
  if (!_pdfState) return;
  _pdfState.scale = newScale;
  const container = document.getElementById(_pdfState.containerId);
  if (!container) return;

  // Update label
  const zoomLabel = document.getElementById("pdf-zoom-level");
  const pct = Math.round((newScale / 1.6) * 100);
  if (zoomLabel) zoomLabel.innerText = `${pct}%`;

  await _renderPDFPages(_pdfState.pdf, container, newScale, _pdfState.maxPages);
}

function saveBlobToDisk(blob, name) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  URL.revokeObjectURL(url);
}

async function openMoveModal(items) {
  let itemsList = [];
  if (Array.isArray(items)) {
    itemsList = items;
  } else if (typeof items === "string") {
    itemsList = [{ id: arguments[0], type: arguments[1], name: arguments[2] }];
  } else if (items && items.id) {
    itemsList = [items];
  }

  if (itemsList.length === 0) return;

  const modal = document.getElementById("modal-move-item");
  const box = document.getElementById("move-modal-box");
  const modalTitle = document.getElementById("move-modal-title");
  const nameLabel = document.getElementById("move-item-name");
  const container = document.getElementById("move-folder-list");
  const breadcrumbs = document.getElementById("move-breadcrumbs");
  const targetLabel = document.getElementById("move-current-target");
  const moveBtn = document.getElementById("btn-finalize-move");

  if (!modal || !container) return;

  const folderIdsToExclude = new Set(
    itemsList.filter((i) => i.type === "folder").map((i) => i.id)
  );

  let movePath = [{ id: null, name: "Root" }];
  let currentTargetId = null;

  if (itemsList.length === 1) {
    if (modalTitle) modalTitle.innerText = "MOVE ITEM";
    if (nameLabel) nameLabel.innerText = itemsList[0].name;
  } else {
    if (modalTitle) modalTitle.innerText = "MOVE SELECTED ITEMS";
    const foldersCount = itemsList.filter((i) => i.type === "folder").length;
    const filesCount = itemsList.filter((i) => i.type === "file").length;
    let label = [];
    if (foldersCount > 0) label.push(`${foldersCount} FOLDER${foldersCount > 1 ? "S" : ""}`);
    if (filesCount > 0) label.push(`${filesCount} FILE${filesCount > 1 ? "S" : ""}`);
    if (nameLabel) nameLabel.innerText = `${itemsList.length} ITEMS (${label.join(", ")})`;
  }

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

      // We only care about folders that aren't in the list of folders being moved
      const folders = data.folders.filter((f) => !folderIdsToExclude.has(f.id));

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
    const file_ids = itemsList.filter((i) => i.type === "file").map((i) => i.id);
    const folder_ids = itemsList.filter((i) => i.type === "folder").map((i) => i.id);

    moveBtn.disabled = true;
    moveBtn.innerText = "MOVING...";

    try {
      const moveRes = await fetch("/app/api/drive/bulk/move", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          file_ids: file_ids,
          folder_ids: folder_ids,
          target_folder_id: currentTargetId,
        }),
      });
      const moveData = await moveRes.json();
      if (!moveRes.ok) throw new Error(moveData.error || "Move failed");

      showZNodeToast(
        itemsList.length === 1
          ? `Moved '${itemsList[0].name}' successfully`
          : `Moved ${itemsList.length} items successfully`,
        "info",
      );
      box.classList.add("scale-95", "opacity-0");
      setTimeout(() => modal.classList.add("hidden"), 300);
      clearSelection();
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

function moveItem(id, type, name) {
  openMoveModal([{ id, type, name }]);
}

// --- 7. Boot & Global Delegated Actions ---
function bootDrive() {
  initOPFSWorkspace();
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
}

// Resilient Bootstrapping (handles both regular load and cached/PWA/deferred DOM readiness)
if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", bootDrive);
} else {
  bootDrive();
}

// Global delegated click handler for File & Folder Upload triggers
document.addEventListener("click", (e) => {
  const folderUploadTrigger = e.target.closest("#drive-upload-folder-btn, #dynamic-upload-folder, .trigger-folder-upload-btn");
  if (folderUploadTrigger) {
    e.preventDefault();
    const folderInput = document.getElementById("hidden-folder-input");
    if (folderInput) folderInput.click();
    return;
  }

  const uploadTrigger = e.target.closest("#drive-upload-btn, #dynamic-upload, .trigger-upload-btn");
  if (uploadTrigger) {
    e.preventDefault();
    const upInput = document.getElementById("hidden-file-input");
    if (upInput) upInput.click();
    return;
  }
});
