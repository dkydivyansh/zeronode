// Zero-Knowledge People Graph Engine

const graphState = {
    masterKey: null,
    subjects: [],
    groups: [],
    activeTab: 'subject', // 'subject' or 'group'
    activeBlobUrls: []
};

// SHA-256 helper for exact blind indices
async function sha256Hash(message) {
    if (!message) return null;
    const msgBuffer = new TextEncoder().encode(message.trim().toLowerCase());
    const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

function base64ToUtf8(b64) {
    try { return decodeURIComponent(escape(atob(b64 || ""))); } catch(e) { return ""; }
}

// AES-GCM Encrypt helper
async function encryptPayload(dataObj, masterKey) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encoded = new TextEncoder().encode(JSON.stringify(dataObj));
    const ciphertext = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv },
        masterKey,
        encoded
    );
    const packed = new Uint8Array(iv.length + ciphertext.byteLength);
    packed.set(iv, 0);
    packed.set(new Uint8Array(ciphertext), iv.length);
    return bufferToBase64(packed);
}

// AES-GCM Decrypt helper
async function decryptPayload(b64Data, masterKey) {
    if (!b64Data) return {};
    const packed = new Uint8Array(base64ToBuffer(b64Data));
    const iv = packed.slice(0, 12);
    const ciphertext = packed.slice(12);
    try {
        const pt = await crypto.subtle.decrypt(
            { name: "AES-GCM", iv: iv },
            masterKey,
            ciphertext
        );
        return JSON.parse(new TextDecoder().decode(pt));
    } catch (e) {
        console.error("Decryption failed", e);
        return { _error: "Decryption Failed" };
    }
}

function updateGraphCacheUI() {
    const count = graphState.activeBlobUrls.length;
    const btn = document.getElementById("dynamic-cache");
    if (!btn) return;
    
    btn.innerHTML = `CACHE [${count}]`;
    if (count > 0) {
        btn.className = "font-mono text-[9px] tracking-widest text-error border border-error/40 bg-error/5 px-2 py-0.5 hover:bg-error hover:text-black transition-all interactive-el uppercase ml-4";
    } else {
        btn.className = "font-mono text-[9px] tracking-widest text-primary/40 border border-primary/10 px-2 py-0.5 hover:bg-primary/20 hover:text-primary transition-all interactive-el uppercase ml-4";
    }
    
    btn.onclick = async () => {
        if (count === 0) return;
        if (await ZNodeDialog.confirm("PURGE GRAPH MEMORY", "Clear all decrypted visual data from local memory?")) {
            for (let url of graphState.activeBlobUrls) {
                URL.revokeObjectURL(url);
            }
            graphState.activeBlobUrls = [];
            
            // Revert images to placeholder
            document.querySelectorAll('img[src^="blob:"]').forEach(img => {
                img.src = '/static/profile.avif';
                img.classList.add('filter', 'blur-sm', 'grayscale', 'opacity-50');
            });
            
            // Reset decrypt button if exists
            const btnDecryptVisuals = document.getElementById('btn-decrypt-visuals');
            if (btnDecryptVisuals) {
                btnDecryptVisuals.innerHTML = `
                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"></path><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"></path></svg>
                    <span>Decrypt Visuals</span>
                    <div class="btn-loader hidden w-3 h-3 border-2 border-primary/30 border-t-primary animate-spin rounded-full"></div>
                `;
            }
            
            updateGraphCacheUI();
            showZNodeToast("GRAPH MEMORY PURGED", "info");
        }
    };
}

async function loadProfilePhoto(uuid, imgElementId) {
    try {
        const blob = await downloadFile(uuid, "photo.bin", true);
        const url = URL.createObjectURL(blob);
        graphState.activeBlobUrls.push(url);
        updateGraphCacheUI();
        
        const img = document.getElementById(imgElementId);
        if (img) {
            img.src = url;
            img.classList.remove('filter', 'blur-sm', 'grayscale', 'opacity-50');
        }
    } catch (e) {
        console.error("Failed to load profile photo", e);
        const img = document.getElementById(imgElementId);
        if (img) img.src = '/static/profile.avif';
    }
}

document.addEventListener("DOMContentLoaded", async () => {
    const loader = document.getElementById('graph-loader');
    const container = document.getElementById('subject-container');
    const searchInput = document.getElementById('graph-search');
    
    // UI Elements for Modals
    const btnOpenNewSubj = document.getElementById('btn-open-new-subject');
    const modalNewSubj = document.getElementById('modal-new-subject');
    const modalNewSubjBox = document.getElementById('new-subject-box');
    const btnCreateSubj = document.getElementById('btn-create-subject');
    
    // Acquire Key
    try {
        graphState.masterKey = await DriveCrypto.getVaultMasterKey();
        if (!graphState.masterKey) throw new Error("No key in session.");
    } catch (e) {
        console.error("Graph requires unlocked vault.");
        loader.innerHTML = '<span class="text-error font-mono text-xs">VAULT LOCKED. PLEASE AUTHENTICATE.</span>';
        return;
    }

    // ─── INITIALIZATION ───────────────────────────────────────────
    async function loadSearchIndex() {
        try {
            const res = await fetch("/app/graph/api/search/index");
            if (!res.ok) throw new Error("Failed to fetch graph index");
            const data = await res.json();
            
            // Decrypt Subjects
            graphState.subjects = [];
            graphState.groups = [];
            const tfId = "idx-" + Math.random().toString(36).substr(2, 9);
            if (window.addTransfer) {
                window.addTransfer(tfId, "DECRYPTING GRAPH MAP", "DECRYPT");
                window.promoteTransfer(tfId, "DECRYPT");
            }
            
            let processed = 0;
            const total = data.subjects.length + data.groups.length;
            
            for (let sub of data.subjects) {
                let decrypted = await decryptPayload(sub.search_blob, graphState.masterKey);
                graphState.subjects.push({
                    uuid: sub.uuid,
                    name: decrypted.name || 'UNKNOWN',
                    note: decrypted.note || '',
                    photo: decrypted.photo || null,
                    gender: decrypted.gender || null
                });
                processed++;
                if (window.updateTransfer) window.updateTransfer(tfId, (processed/total)*100);
            }
            
            for (let grp of data.groups) {
                let decrypted = await decryptPayload(grp.search_blob, graphState.masterKey);
                graphState.groups.push({
                    uuid: grp.uuid,
                    name: decrypted.name || 'UNKNOWN',
                    note: decrypted.note || '',
                    photo: decrypted.photo || null,
                    gender: null
                });
                processed++;
                if (window.updateTransfer) window.updateTransfer(tfId, (processed/total)*100);
            }
            
            if (window.completeTransfer) window.completeTransfer(tfId);
            
            renderActiveTab();
            
            loader.style.opacity = '0';
            setTimeout(() => {
                loader.style.display = 'none';
                container.classList.remove('opacity-0');
            }, 300);
            
            updateGraphCacheUI();
            
        } catch (e) {
            console.error(e);
            loader.innerHTML = `<span class="text-error font-mono text-xs">SYNC FAILED: ${e.message}</span>`;
        }
    }

    // ─── RENDERING ────────────────────────────────────────────────
    function renderActiveTab() {
        if (graphState.activeTab === 'subject') {
            document.getElementById('tab-subjects').className = "font-headline text-3xl tracking-widest text-primary uppercase cursor-pointer transition-colors";
            document.getElementById('tab-groups').className = "font-headline text-3xl tracking-widest text-on-surface-variant/30 hover:text-on-surface-variant uppercase cursor-pointer transition-colors";
            renderEntities(graphState.subjects, 'subject');
        } else {
            document.getElementById('tab-groups').className = "font-headline text-3xl tracking-widest text-primary uppercase cursor-pointer transition-colors";
            document.getElementById('tab-subjects').className = "font-headline text-3xl tracking-widest text-on-surface-variant/30 hover:text-on-surface-variant uppercase cursor-pointer transition-colors";
            renderEntities(graphState.groups, 'group');
        }
    }
    
    document.getElementById('tab-subjects').addEventListener('click', () => {
        graphState.activeTab = 'subject';
        searchInput.value = '';
        renderActiveTab();
    });
    
    document.getElementById('tab-groups').addEventListener('click', () => {
        graphState.activeTab = 'group';
        searchInput.value = '';
        renderActiveTab();
    });

    function renderEntities(list, type) {
        container.innerHTML = '';
        if (list.length === 0) {
            container.innerHTML = `<div class="col-span-full py-10 text-on-surface-variant/40 font-mono text-xs tracking-widest uppercase">No ${type}s found in this sector.</div>`;
            return;
        }

        list.forEach(sub => {
            const card = document.createElement('div');
            card.className = "group relative bg-surface-container-high border border-outline-variant/20 p-3 hover:border-primary/50 transition-all cursor-pointer flex flex-col min-h-[120px]";
            card.onclick = () => { window.location.href = `/app/graph/${type === 'group' ? 'group' : 'view'}?id=${sub.uuid}`; };
            
            const isGroup = type === 'group';
            
            const imgWrapperClass = isGroup 
                ? "w-20 h-20 rounded border border-outline-variant/30 bg-surface flex items-center justify-center font-headline text-3xl text-primary shrink-0 overflow-hidden" // Square for groups
                : "w-[84px] h-[112px] rounded border border-outline-variant/30 bg-surface flex items-center justify-center font-headline text-3xl text-primary shrink-0 overflow-hidden"; // 3:4 ratio for subjects
            
            const photoHtml = sub.photo 
                ? `<img id="card-img-${sub.uuid}" src="/static/profile.avif" class="w-full h-full object-cover filter blur-sm grayscale opacity-50 transition-all duration-500">` 
                : sub.name.charAt(0);

            const genderHtml = (!isGroup) ? `<span class="font-mono text-[9px] text-primary/70 tracking-widest uppercase border border-primary/20 px-1.5 py-0.5 rounded bg-primary/5 mt-auto self-start">${sub.gender || 'UNKNOWN'}</span>` : '';

            card.innerHTML = `
                <div class="flex items-center gap-4 h-full">
                    <div class="${imgWrapperClass}">
                        ${photoHtml}
                    </div>
                    <div class="flex flex-col justify-center min-w-0 flex-1 h-full py-1 gap-1">
                        <span class="font-headline text-[#e5e5e5] text-[15px] truncate uppercase tracking-wider">${sub.name}</span>
                        <span class="font-mono text-[9px] text-on-surface-variant/50 tracking-widest uppercase mb-1">${sub.uuid.split('-')[0]}</span>
                        ${genderHtml}
                    </div>
                </div>
            `;
            container.appendChild(card);
        });
    }

    // Lazy Decryption Logic
    const btnDecryptVisuals = document.getElementById('btn-decrypt-visuals');
    if (btnDecryptVisuals) {
        btnDecryptVisuals.addEventListener('click', async () => {
            const confirmed = await ZNodeDialog.confirm("DECRYPT VISUALS", "This operation requires intensive memory allocation to securely decrypt all identity profile photos in real-time. Proceed?");
            if (!confirmed) return;
            
            showZNodeToast("DECRYPTING VISUAL DATA...", "info");
            btnDecryptVisuals.classList.add('loading', 'pointer-events-none', 'opacity-50');
            
            const allEntities = [...graphState.subjects, ...graphState.groups];
            for (let sub of allEntities) {
                if (sub.photo) {
                    await loadProfilePhoto(sub.photo, `card-img-${sub.uuid}`);
                }
            }
            
            btnDecryptVisuals.classList.remove('loading', 'pointer-events-none', 'opacity-50');
            btnDecryptVisuals.innerHTML = '<span class="font-mono text-[10px] uppercase tracking-widest text-primary">VISUALS DECRYPTED</span>';
        });
    }

    // ─── SEARCHING ────────────────────────────────────────────────
    let searchTimeout = null;
    searchInput.addEventListener('input', (e) => {
        const term = e.target.value.toLowerCase().trim();
        const activeList = graphState.activeTab === 'subject' ? graphState.subjects : graphState.groups;
        
        if (!term) {
            clearTimeout(searchTimeout);
            renderEntities(activeList, graphState.activeTab);
            return;
        }
        
        // 1. Normal Search (Instant)
        const filtered = activeList.filter(s => 
            s.name.toLowerCase().includes(term) || 
            s.note.toLowerCase().includes(term)
        );
        renderEntities(filtered, graphState.activeTab);
        
        // 2. Strict Search (Debounced via network)
        clearTimeout(searchTimeout);
        searchTimeout = setTimeout(async () => {
            try {
                const hash = await sha256Hash(term);
                const res = await fetch('/app/graph/api/search/exact', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ email_hash: hash, phone_hash: hash, dob_hash: hash })
                });
                if (res.ok) {
                    const data = await res.json();
                    if (data.uuids && data.uuids.length > 0) {
                        const exactMatches = activeList.filter(s => data.uuids.includes(s.uuid) && !filtered.some(f => f.uuid === s.uuid));
                        if (exactMatches.length > 0) {
                            filtered.unshift(...exactMatches); // put exact matches at the top!
                            // Only re-render if the search input hasn't changed
                            if (searchInput.value.toLowerCase().trim() === term) {
                                renderEntities(filtered, graphState.activeTab);
                            }
                        }
                    }
                }
            } catch (err) {
                console.error("Exact search failed", err);
            }
        }, 400);
    });

    // ─── DEEP SEARCH LOGIC ────────────────────────────────────────
    const btnDeepSearch = document.getElementById('btn-deep-search');
    const modalDeepSearch = document.getElementById('modal-deep-search');
    const deepSearchBox = document.getElementById('deep-search-box');
    const btnRunDeepSearch = document.getElementById('btn-run-deep-search');
    
    if (btnDeepSearch) {
        btnDeepSearch.addEventListener('click', () => {
            modalDeepSearch.classList.remove('hidden');
            setTimeout(() => { deepSearchBox.classList.remove('scale-95', 'opacity-0'); }, 10);
        });

        document.querySelectorAll('.deep-search-close').forEach(btn => {
            btn.addEventListener('click', () => {
                deepSearchBox.classList.add('scale-95', 'opacity-0');
                setTimeout(() => { modalDeepSearch.classList.add('hidden'); }, 300);
            });
        });

        btnRunDeepSearch.addEventListener('click', async () => {
            const searchKey = document.getElementById('ds-key').value.trim().toLowerCase();
            const searchVal = document.getElementById('ds-val').value.trim().toLowerCase();
            if (!searchKey && !searchVal) {
                showZNodeToast("Please provide at least a Key or Value to search.", "error");
                return;
            }

            // Show progress UI
            const progDiv = document.getElementById('deep-search-progress');
            const progBar = document.getElementById('deep-search-bar');
            progDiv.classList.remove('hidden');
            progBar.style.width = '0%';
            btnRunDeepSearch.disabled = true;
            btnRunDeepSearch.classList.add('opacity-50');

            try {
                const masterKey = await DriveCrypto.getVaultMasterKey();
                const matchedEntities = [];
                let offset = 0;
                const limit = 5000;
                let hasMore = true;
                
                const typeParam = graphState.activeTab; // 'subject' or 'group'

                while (hasMore) {
                    const res = await fetch('/app/graph/api/search/deep_fetch', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ entity_type: typeParam, limit: limit, offset: offset })
                    });
                    
                    if (!res.ok) throw new Error("Batch fetch failed");
                    const data = await res.json();
                    hasMore = data.has_more;
                    
                    for (const row of data.payloads) {
                        try {
                            const payload = await decryptPayload(row.blob, masterKey);
                            if (payload._error) throw new Error(payload._error);
                            
                            let match = false;

                            // 1. Check custom keys (Base64 decoded)
                            if (payload.custom_keys && typeof payload.custom_keys === 'object') {
                                for (const keyName of Object.keys(payload.custom_keys)) {
                                    const keyData = payload.custom_keys[keyName];
                                    const decodedVal = base64ToUtf8(keyData.value);
                                    
                                    let keyMatch = true;
                                    let valMatch = true;
                                    
                                    if (searchKey && !keyName.toLowerCase().includes(searchKey)) keyMatch = false;
                                    if (searchVal && !decodedVal.toLowerCase().includes(searchVal)) valMatch = false;
                                    
                                    if (keyMatch && valMatch) {
                                        match = true;
                                        break;
                                    }
                                }
                            }

                            // 2. Check standard properties if no match yet
                            if (!match) {
                                for (const keyName of Object.keys(payload)) {
                                    if (keyName === 'custom_keys' || keyName === 'file_metadata') continue; // Skip complex objects
                                    
                                    const val = String(payload[keyName] || '');
                                    
                                    let keyMatch = true;
                                    let valMatch = true;
                                    
                                    if (searchKey && !keyName.toLowerCase().includes(searchKey)) keyMatch = false;
                                    if (searchVal && !val.toLowerCase().includes(searchVal)) valMatch = false;
                                    
                                    if (keyMatch && valMatch) {
                                        match = true;
                                        break;
                                    }
                                }
                            }

                            if (match) {
                                // MATCH FOUND! Reconstruct lightweight object for renderEntities
                                const searchObj = {
                                    uuid: row.uuid,
                                    name: payload.name || payload.first_name + ' ' + (payload.last_name || ''),
                                    notes: payload.notes || payload.note || '',
                                    photo: payload.photo || payload.profile_photo || '',
                                    gender: payload.gender || null
                                };
                                matchedEntities.push(searchObj);
                            }
                        } catch (e) {
                            console.error("Failed to decrypt row", row.uuid);
                        }
                    }
                    
                    offset += limit;
                    // Mock progress (not totally accurate since we don't know total count, just cycle it)
                    progBar.style.width = '50%';
                }
                
                progBar.style.width = '100%';
                
                // Close modal
                deepSearchBox.classList.add('scale-95', 'opacity-0');
                setTimeout(() => { modalDeepSearch.classList.add('hidden'); }, 300);
                
                // Render results
                showZNodeToast(`Deep Search Complete: ${matchedEntities.length} found.`, "info");
                renderEntities(matchedEntities, graphState.activeTab);

            } catch (err) {
                console.error(err);
                showZNodeToast("Deep Search Error: " + err.message, "error");
            } finally {
                progDiv.classList.add('hidden');
                progBar.style.width = '0%';
                btnRunDeepSearch.disabled = false;
                btnRunDeepSearch.classList.remove('opacity-50');
            }
        });
    }

    // ─── MODAL LOGIC ──────────────────────────────────────────────
    if (btnOpenNewSubj) {
        btnOpenNewSubj.addEventListener('click', () => {
            modalNewSubj.classList.remove('hidden');
            setTimeout(() => {
                modalNewSubjBox.classList.remove('scale-95', 'opacity-0');
            }, 10);
        });
        
        const subjGenderSelect = document.getElementById('subj-gender');
        const subjGenderOther = document.getElementById('subj-gender-other');
        if (subjGenderSelect) {
            subjGenderSelect.addEventListener('change', (e) => {
                if (e.target.value === 'Other') {
                    subjGenderOther.classList.remove('hidden');
                    subjGenderOther.focus();
                } else {
                    subjGenderOther.classList.add('hidden');
                    subjGenderOther.value = '';
                }
            });
        }
    }

    document.querySelectorAll('.modal-close').forEach(btn => {
        btn.addEventListener('click', () => {
            modalNewSubjBox.classList.add('scale-95', 'opacity-0');
            setTimeout(() => {
                modalNewSubj.classList.add('hidden');
            }, 300);
            
            const grpModal = document.getElementById('modal-new-group');
            if(grpModal) {
                grpModal.classList.add('hidden');
                document.getElementById('new-group-box').classList.add('scale-95', 'opacity-0');
            }
        });
    });
    
    // Group Creation Logic
    const btnOpenNewGroup = document.getElementById('btn-open-new-group');
    if (btnOpenNewGroup) {
        btnOpenNewGroup.addEventListener('click', () => {
            document.getElementById('modal-new-group').classList.remove('hidden');
            setTimeout(() => {
                document.getElementById('new-group-box').classList.remove('scale-95', 'opacity-0');
                document.getElementById('group-name').focus();
            }, 10);
        });
    }

    const btnCreateGroup = document.getElementById('btn-create-group');
    if (btnCreateGroup) {
        btnCreateGroup.addEventListener('click', async () => {
            const btnText = btnCreateGroup.querySelector('.btn-text');
            const btnLoader = btnCreateGroup.querySelector('.btn-loader');
            const errBox = document.getElementById('group-error');
            
            errBox.classList.add('hidden');
            btnText.classList.add('hidden');
            btnLoader.classList.remove('hidden');
            btnCreateGroup.classList.add('pointer-events-none');
            
            const name = document.getElementById('group-name').value.trim();
            if (!name) {
                errBox.innerText = "Group Name is required.";
                errBox.classList.remove('hidden');
                resetBtn();
                return;
            }

            try {
                const searchBlob = { name, note: "" };
                const encrypted_search = await encryptPayload(searchBlob, graphState.masterKey);
                
                const mainBlob = { name, custom_keys: {} };
                const encrypted_main = await encryptPayload(mainBlob, graphState.masterKey);
                
                const payload = {
                    encrypted_search_blob: encrypted_search,
                    encrypted_blob: encrypted_main
                };

                const res = await fetch("/app/graph/api/group", {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload)
                });

                if (!res.ok) throw new Error("Server error saving group");
                const data = await res.json();
                
                window.location.href = `/app/graph/group?id=${data.uuid}`;
                
            } catch (e) {
                console.error(e);
                errBox.innerText = "Failed to encrypt/save group: " + e.message;
                errBox.classList.remove('hidden');
                resetBtn();
            }

            function resetBtn() {
                btnText.classList.remove('hidden');
                btnLoader.classList.add('hidden');
                btnCreateGroup.classList.remove('pointer-events-none');
            }
        });
    }
    
    // Load Search Index directly (auth is handled by Flask routes)
    loadSearchIndex();

    if (btnCreateSubj) {
        btnCreateSubj.addEventListener('click', async () => {
            const errBox = document.getElementById('subj-error');
            errBox.classList.add('hidden');
            
            const name = document.getElementById('subj-name').value.trim();
            const note = document.getElementById('subj-note').value.trim();
            const dob = document.getElementById('subj-dob').value.trim();
            const phone = document.getElementById('subj-phone').value.trim();
            const email = document.getElementById('subj-email').value.trim();
            
            const genderSelect = document.getElementById('subj-gender') ? document.getElementById('subj-gender').value : '';
            const genderOther = document.getElementById('subj-gender-other') ? document.getElementById('subj-gender-other').value.trim() : '';
            const gender = genderSelect === 'Other' ? genderOther : genderSelect;
            
            if (!name) {
                errBox.innerText = "NAME IS REQUIRED.";
                errBox.classList.remove('hidden');
                return;
            }

            btnCreateSubj.classList.add('loading');
            try {
                // 1. Blind Index Hashing (Using Vault Salt ideally, but falling back to simple SHA256 for PoC)
                // In production, prepend a persistent ZNode vault search_salt here.
                const emailHash = await sha256Hash(email);
                const phoneHash = await sha256Hash(phone);
                const dobHash = await sha256Hash(dob);
                
                // 2. Search Blob Encryption (Lightweight)
                const searchBlob = { name, note, photo: null, gender };
                const encSearchBlob = await encryptPayload(searchBlob, graphState.masterKey);
                
                // 3. Full Payload Encryption
                const fullBlob = { name, note, dob, phone, email, gender, photo: null, custom_fields: {} };
                const encFullBlob = await encryptPayload(fullBlob, graphState.masterKey);
                
                // 4. Send to API
                const payload = {
                    encrypted_search_blob: encSearchBlob,
                    encrypted_blob: encFullBlob,
                    email_hash: emailHash,
                    phone_hash: phoneHash,
                    dob_hash: dobHash
                };

                const res = await fetch("/app/graph/api/subject", {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload)
                });
                
                if (!res.ok) throw new Error("Server rejected identity registry.");
                
                // Reset UI & Reload
                document.getElementById('subj-name').value = '';
                document.getElementById('subj-note').value = '';
                document.getElementById('subj-dob').value = '';
                document.getElementById('subj-phone').value = '';
                document.getElementById('subj-email').value = '';
                if(document.getElementById('subj-gender')) {
                    document.getElementById('subj-gender').value = '';
                    document.getElementById('subj-gender-other').value = '';
                    document.getElementById('subj-gender-other').classList.add('hidden');
                }
                
                modalNewSubj.querySelector('.modal-close').click();
                showZNodeToast("IDENTITY ENCRYPTED AND STORED", "info");
                loadSearchIndex(); // Refresh graph
                
            } catch (e) {
                errBox.innerText = e.message;
                errBox.classList.remove('hidden');
                showZNodeToast(`FAILED: ${e.message}`, "error");
            } finally {
                btnCreateSubj.classList.remove('loading');
            }
        });
    }

    // Start Engine
    loadSearchIndex();
});
