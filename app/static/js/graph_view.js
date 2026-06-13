// Zero-Knowledge People Graph Engine - View Subject

let graphState = {
    masterKey: null,
    currentPhotoUuid: null,
    activeBlobUrls: [],
    currentSubjectPayload: {},
    subjectsCache: {},
    groupsCache: {},
    relationTargetType: 'subject'
};

// Cryptography Helpers (Redeclared from graph.js for simplicity, or ideally imported if ES modules were used)
async function sha256Hash(message) {
    if (!message) return null;
    const msgBuffer = new TextEncoder().encode(message.trim().toLowerCase());
    const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

function utf8ToBase64(str) {
    return btoa(unescape(encodeURIComponent(str || "")));
}
function base64ToUtf8(b64) {
    try { return decodeURIComponent(escape(atob(b64 || ""))); } catch(e) { return ""; }
}

async function encryptPayload(dataObj, masterKey) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encoded = new TextEncoder().encode(JSON.stringify(dataObj));
    const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv: iv }, masterKey, encoded);
    const packed = new Uint8Array(iv.length + ciphertext.byteLength);
    packed.set(iv, 0);
    packed.set(new Uint8Array(ciphertext), iv.length);
    return bufferToBase64(packed);
}

async function decryptPayload(b64Data, masterKey) {
    if (!b64Data) return {};
    const packed = new Uint8Array(base64ToBuffer(b64Data));
    const iv = packed.slice(0, 12);
    const ciphertext = packed.slice(12);
    try {
        const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: iv }, masterKey, ciphertext);
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
            });
            
            updateGraphCacheUI();
            showZNodeToast("GRAPH MEMORY PURGED", "info");
        }
    };
}

document.addEventListener("DOMContentLoaded", async () => {
    const urlParams = new URLSearchParams(window.location.search);
    window.currentSubjectUuid = urlParams.get('id');
    const currentSubjectUuid = window.currentSubjectUuid;
    
    if (!currentSubjectUuid) {
        document.getElementById('det-uuid-title').innerText = "SUBJECT NOT FOUND";
        return;
    }

    try {
        graphState.masterKey = await DriveCrypto.getVaultMasterKey();
        if (!graphState.masterKey) throw new Error("No key in session.");
        
        // Fetch Search Index globally for relations
        const indexRes = await fetch("/app/graph/api/search/index");
        if (indexRes.ok) {
            const indexData = await indexRes.json();
            
            const tfId = "idx-" + Math.random().toString(36).substr(2, 9);
            if (window.addTransfer) {
                window.addTransfer(tfId, "DECRYPTING GRAPH MAP", "DECRYPT");
                window.promoteTransfer(tfId, "DECRYPT");
            }
            
            let processed = 0;
            const total = indexData.subjects.length + indexData.groups.length;
            
            for (let sub of indexData.subjects) {
                if (sub.uuid === currentSubjectUuid) {
                    processed++;
                    continue;
                }
                let dec = await decryptPayload(sub.search_blob, graphState.masterKey);
                graphState.subjectsCache[sub.uuid] = {
                    name: dec.name || 'UNKNOWN',
                    uuid: sub.uuid
                };
                
                processed++;
                if (window.updateTransfer) window.updateTransfer(tfId, (processed/total)*100);
            }
            
            for (let grp of indexData.groups) {
                let dec = await decryptPayload(grp.search_blob, graphState.masterKey);
                graphState.groupsCache[grp.uuid] = {
                    name: dec.name || 'UNKNOWN',
                    uuid: grp.uuid
                };
                
                processed++;
                if (window.updateTransfer) window.updateTransfer(tfId, (processed/total)*100);
            }
            
            if (window.completeTransfer) window.completeTransfer(tfId);
        }
    } catch (e) {
        console.error("Graph requires unlocked vault.", e);
        document.getElementById('det-uuid-title').innerText = "VAULT LOCKED";
        return;
    }

    async function loadSubjectDetails() {
        document.getElementById('det-uuid').innerText = currentSubjectUuid;
        const errBox = document.getElementById('det-error');
        errBox.classList.add('hidden');
        
        try {
            const res = await fetch(`/app/graph/api/subject/${currentSubjectUuid}`);
            if (res.status === 404) throw new Error("404_NOT_FOUND");
            if (!res.ok) throw new Error("Failed to fetch subject");
            const data = await res.json();
            
            // Decrypt Identity Payload
            const tfSubj = "subj-" + Math.random().toString(36).substr(2, 9);
            if (window.addTransfer) {
                window.addTransfer(tfSubj, "DECRYPTING SUBJECT", "DECRYPT");
                window.promoteTransfer(tfSubj, "DECRYPT");
            }
            const decrypted = await decryptPayload(data.profile.encrypted_blob, graphState.masterKey);
            if (window.updateTransfer) window.updateTransfer(tfSubj, 100);
            if (window.completeTransfer) window.completeTransfer(tfSubj);
            
            graphState.currentSubjectPayload = decrypted;
            if (!graphState.currentSubjectPayload.file_metadata) {
                graphState.currentSubjectPayload.file_metadata = {};
            }
            
            document.getElementById('det-uuid-title').innerText = decrypted.name || 'UNKNOWN SUBJECT';
            document.getElementById('det-name').value = decrypted.name || '';
            document.getElementById('det-dob').value = decrypted.dob || '';
            document.getElementById('det-phone').value = decrypted.phone || '';
            document.getElementById('det-email').value = decrypted.email || '';
            
            // Gender Handling
            const genderSelect = document.getElementById('det-gender');
            const genderOther = document.getElementById('det-gender-other');
            const genderBadge = document.getElementById('det-gender-badge');
            const standardGenders = ['Male', 'Female', 'Transgender', 'Non-Binary'];
            
            function updateGenderBadge(val) {
                if (genderBadge) {
                    if (val && val.trim() !== '') {
                        genderBadge.innerText = val;
                        genderBadge.classList.remove('hidden');
                    } else {
                        genderBadge.classList.add('hidden');
                    }
                }
            }

            if (decrypted.gender) {
                updateGenderBadge(decrypted.gender);
                if (standardGenders.includes(decrypted.gender)) {
                    genderSelect.value = decrypted.gender;
                    genderOther.classList.add('hidden');
                } else {
                    genderSelect.value = 'Other';
                    genderOther.value = decrypted.gender;
                    genderOther.classList.remove('hidden');
                }
            } else {
                genderSelect.value = '';
                genderOther.classList.add('hidden');
            }
            
            
            genderSelect.addEventListener('change', (e) => {
                if (e.target.value === 'Other') {
                    genderOther.classList.remove('hidden');
                    genderOther.focus();
                    updateGenderBadge(genderOther.value);
                } else {
                    genderOther.classList.add('hidden');
                    genderOther.value = '';
                    updateGenderBadge(e.target.value);
                }
            });
            
            genderOther.addEventListener('input', (e) => {
                updateGenderBadge(e.target.value);
            });

            graphState.currentPhotoUuid = decrypted.photo || null;
            
            if (!graphState.currentSubjectPayload.custom_keys || Array.isArray(graphState.currentSubjectPayload.custom_keys)) {
                graphState.currentSubjectPayload.custom_keys = {};
            }
            
            // Auto-migrate old note to custom_keys
            if (decrypted.note) {
                if (!graphState.currentSubjectPayload.custom_keys["Intelligence Notes"]) {
                    graphState.currentSubjectPayload.custom_keys["Intelligence Notes"] = {
                        type: "long_text",
                        value: utf8ToBase64(decrypted.note)
                    };
                }
                delete graphState.currentSubjectPayload.note;
            }
            
            if (graphState.currentPhotoUuid) {
                loadProfilePhoto(graphState.currentPhotoUuid);
                document.getElementById('btn-delete-photo').classList.remove('hidden');
            } else {
                document.getElementById('det-photo-img').src = '/static/profile.avif';
                document.getElementById('btn-delete-photo').classList.add('hidden');
            }
            
            graphState.lastSavedPayloadStr = deterministicStringify(graphState.currentSubjectPayload);
            
            // Render custom keys
            window.renderCustomKeys = () => {
                const container = document.getElementById('custom-keys-container');
                container.innerHTML = '';
                const keys = graphState.currentSubjectPayload.custom_keys || {};
                
                Object.keys(keys).forEach(keyName => {
                    const keyData = keys[keyName];
                    const decodedVal = base64ToUtf8(keyData.value);
                    
                    const wrapper = document.createElement('div');
                    wrapper.className = "space-y-2 relative group p-3 border border-outline-variant/10 bg-surface-variant/5 hover:border-primary/30 hover:bg-surface-variant/10 rounded-lg transition-all";
                    
                    const keyType = keyData.type || 'short_text';
                    const labelHeader = document.createElement('div');
                    labelHeader.className = "flex justify-between items-center";
                    labelHeader.innerHTML = `
                        <label class="font-mono text-[10px] text-primary/90 uppercase tracking-widest font-semibold flex items-center gap-2">
                            ${keyName} 
                            <span class="text-on-surface-variant/50 text-[8px] font-normal tracking-wider uppercase px-1.5 py-0.5 border border-outline-variant/20 rounded bg-surface shadow-sm">${keyType.replace('_', ' ')}</span>
                        </label>
                        <button class="text-error/0 group-hover:text-error/80 hover:!text-error hover:bg-error/10 rounded text-[9px] font-mono tracking-widest uppercase transition-all px-2 py-1 flex items-center gap-1" onclick="deleteCustomKey('${keyName.replace(/'/g, "\\'")}')" title="Delete Attribute">
                            <svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"></path></svg>
                        </button>
                    `;
                    wrapper.appendChild(labelHeader);
                    
                    let inputEl;
                    if (keyType === 'long_text') {
                        inputEl = document.createElement('textarea');
                        inputEl.rows = 3;
                        inputEl.className = "custom-key-input w-full bg-surface border border-outline-variant/20 rounded text-[#e5e5e5] font-body text-sm px-3 py-2 focus:outline-none focus:border-primary/60 focus:ring-1 focus:ring-primary/30 transition-all resize-y placeholder-on-surface-variant/20";
                        inputEl.placeholder = "Enter text...";
                    } else {
                        inputEl = document.createElement('input');
                        inputEl.className = "custom-key-input w-full bg-surface border border-outline-variant/20 rounded text-[#e5e5e5] font-body text-sm px-3 py-2 focus:outline-none focus:border-primary/60 focus:ring-1 focus:ring-primary/30 transition-all placeholder-on-surface-variant/20";
                        if (keyType === 'short_text') inputEl.type = 'text';
                        else if (keyType === 'int' || keyType === 'float') inputEl.type = 'number';
                        else if (keyType === 'date') inputEl.type = 'date';
                        else if (keyType === 'time') inputEl.type = 'time';
                        else if (keyType === 'datetime') inputEl.type = 'datetime-local';
                        
                        if (keyType === 'float') inputEl.step = 'any';
                    }
                    
                    inputEl.dataset.keyName = keyName;
                    inputEl.dataset.keyType = keyType;
                    inputEl.value = decodedVal;
                    
                    inputEl.addEventListener('input', () => {
                        graphState.currentSubjectPayload.custom_keys[keyName].value = utf8ToBase64(inputEl.value);
                    });
                    inputEl.addEventListener('change', () => {
                        graphState.currentSubjectPayload.custom_keys[keyName].value = utf8ToBase64(inputEl.value);
                    });
                    
                    wrapper.appendChild(inputEl);
                    container.appendChild(wrapper);
                });
            };
            renderCustomKeys();
            
            // Render Files
            const filesList = document.getElementById('det-files-list');
            filesList.innerHTML = '';
            if (data.files && data.files.length > 0) {
                data.files.forEach(f => {
                    const isPhoto = f.uuid === graphState.currentPhotoUuid;
                    const meta = graphState.currentSubjectPayload.file_metadata[f.uuid] || {};
                    
                    const el = document.createElement('div');
                    el.className = "flex flex-col gap-2 p-3 border border-outline-variant/20 bg-surface hover:border-primary/50 transition-colors";
                    el.innerHTML = `
                        <div class="flex justify-between items-center gap-2">
                            <div class="flex items-center gap-2 min-w-0">
                                <span class="font-mono text-xs text-[#e5e5e5] truncate uppercase" title="${f.file_name}">${f.file_name}</span>
                                ${isPhoto ? '<span class="shrink-0 bg-primary/20 text-primary text-[8px] px-1.5 py-0.5 rounded border border-primary/30 uppercase tracking-widest">PHOTO</span>' : ''}
                            </div>
                            <div class="flex gap-2 shrink-0">
                                <button class="text-on-surface-variant/50 hover:text-primary transition-colors text-xs" onclick="editGraphFileDescription('${f.uuid}')" title="Edit Description">EDIT</button>
                                <button class="text-on-surface-variant/50 hover:text-primary transition-colors text-xs" onclick="downloadGraphFile('${f.uuid}', '${f.file_name.replace(/'/g, "\\'")}')" title="Download">DL</button>
                                ${!isPhoto ? `<button class="text-on-surface-variant/50 hover:text-error transition-colors text-xs" onclick="deleteGraphFile('${f.uuid}')" title="Delete">X</button>` : ''}
                            </div>
                        </div>
                        ${meta.description ? `<div class="font-body text-[13px] text-on-surface-variant/80 border-l-2 border-primary/30 pl-3 py-1 mt-1 prose-sm markdown-body overflow-hidden cursor-pointer hover:bg-surface-variant/30 transition-colors line-clamp-2" onclick="viewLongText('${f.file_name.replace(/'/g, "\\'")}', \`${encodeURIComponent(meta.description)}\`)">${marked.parse(meta.description)}</div>` : ''}
                    `;
                    filesList.appendChild(el);
                });
            } else {
                filesList.innerHTML = '<span class="font-mono text-[10px] text-on-surface-variant/40 uppercase tracking-widest text-center mt-4">NO INTEL ATTACHED</span>';
            }

            // Render Relations
            window.renderRelations = async (relations) => {
                graphState.existingRelationUuids = [];
                const container = document.getElementById('det-relations-list');
                container.innerHTML = '';
                if (!relations || relations.length === 0) {
                    container.innerHTML = '<span class="font-mono text-[10px] text-on-surface-variant/40 uppercase tracking-widest text-center mt-4">NO RELATIONS FOUND</span>';
                    return;
                }
                
                const tfId = "rel-" + Math.random().toString(36).substr(2, 9);
                if (window.addTransfer) {
                    window.addTransfer(tfId, "DECRYPTING RELATIONS", "DECRYPT");
                    window.promoteTransfer(tfId, "DECRYPT");
                }
                
                let processed = 0;
                for (let r of relations) {
                    const decRel = await decryptPayload(r.encrypted_blob, graphState.masterKey);
                    const isIncoming = (r.target_uuid === currentSubjectUuid);
                    const otherUuid = isIncoming ? r.source_uuid : r.target_uuid;
                    graphState.existingRelationUuids.push(otherUuid);
                    const otherType = isIncoming ? r.source_type : r.target_type;
                    
                    const cache = otherType === 'group' ? graphState.groupsCache : graphState.subjectsCache;
                    const otherSubj = cache[otherUuid] || { name: 'UNKNOWN' };
                    
                    const el = document.createElement('div');
                    el.className = "flex flex-col gap-2 p-3 border border-outline-variant/20 bg-surface hover:border-primary/50 transition-colors group cursor-pointer";
                    el.onclick = () => window.location.href = `/app/graph/${otherType === 'group' ? 'group' : 'view'}?id=${otherUuid}`;
                    
                    el.innerHTML = `
                        <div class="flex justify-between items-center gap-2">
                            <div class="flex items-center gap-2 min-w-0">
                                <span class="font-mono text-[9px] text-primary shrink-0 font-bold">${isIncoming ? '←' : '→'}</span>
                                <span class="font-mono text-xs text-[#e5e5e5] truncate uppercase" title="${otherSubj.name}">${otherSubj.name} <span class="text-on-surface-variant/40 text-[9px]">(${otherUuid.split('-')[0]})</span></span>
                                ${otherType === 'group' ? '<span class="shrink-0 bg-accent/10 text-accent text-[8px] px-1.5 py-0.5 rounded border border-accent/20 uppercase tracking-widest">GROUP</span>' : ''}
                                <span class="shrink-0 bg-primary/10 text-primary text-[8px] px-1.5 py-0.5 rounded border border-primary/20 uppercase tracking-widest">${decRel.type || 'LINKED'}</span>
                            </div>
                            <div class="flex gap-2 shrink-0">
                                <button class="text-on-surface-variant/20 group-hover:text-primary transition-colors text-xs" onclick="event.stopPropagation(); editRelation('${otherUuid}', '${(decRel.type || '').replace(/'/g, "\\'")}', '${(decRel.description || '').replace(/'/g, "\\'")}', '${otherType}')" title="Edit">EDIT</button>
                                <button class="text-on-surface-variant/20 group-hover:text-error transition-colors text-xs ml-1" onclick="event.stopPropagation(); deleteRelation('${r.source_uuid}', '${r.target_uuid}')" title="Purge">X</button>
                            </div>
                        </div>
                        ${decRel.description ? `<div class="font-body text-[11px] text-on-surface-variant/80 border-l-2 border-primary/30 pl-2 mt-1 line-clamp-2">${decRel.description}</div>` : ''}
                    `;
                    container.appendChild(el);
                    
                    processed++;
                    if (window.updateTransfer) window.updateTransfer(tfId, (processed/relations.length)*100);
                }
                if (window.completeTransfer) window.completeTransfer(tfId);
            };
            await renderRelations(data.relations);

        } catch (e) {
            console.error(e);
            if (e.message === "404_NOT_FOUND") {
                document.getElementById('det-uuid-title').innerText = "SUBJECT NOT FOUND";
                document.getElementById('det-name').value = "404 - Not Found";
                errBox.innerText = "This subject was deleted or does not exist.";
                errBox.classList.remove('hidden');
            } else {
                document.getElementById('det-uuid-title').innerText = "ERROR LOADING SUBJECT";
            }
        }
    }

    async function triggerSaveSubject() {
        const btn = document.getElementById('btn-update-subject');
        btn.classList.add('loading');
        try {
            const name = document.getElementById('det-name').value.trim();
            const dob = document.getElementById('det-dob').value.trim();
            const phone = document.getElementById('det-phone').value.trim();
            const email = document.getElementById('det-email').value.trim();

            const emailHash = await sha256Hash(email);
            const phoneHash = await sha256Hash(phone);
            const dobHash = await sha256Hash(dob);
            
            // Merge into payload
            const genderSelect = document.getElementById('det-gender').value;
            const genderOther = document.getElementById('det-gender-other').value.trim();
            const gender = genderSelect === 'Other' ? genderOther : genderSelect;

            const searchBlob = { name, photo: graphState.currentPhotoUuid, gender };
            
            // Explicitly sync all custom key inputs from the DOM right before saving
            // to catch any edge cases where input/change events didn't fire (e.g. autocomplete, date pickers)
            document.querySelectorAll('.custom-key-input').forEach(input => {
                const kName = input.dataset.keyName;
                if (kName && graphState.currentSubjectPayload.custom_keys[kName]) {
                    graphState.currentSubjectPayload.custom_keys[kName].value = utf8ToBase64(input.value);
                }
            });
            
            graphState.currentSubjectPayload.name = name;
            graphState.currentSubjectPayload.dob = dob;
            graphState.currentSubjectPayload.phone = phone;
            graphState.currentSubjectPayload.email = email;
            graphState.currentSubjectPayload.gender = gender;
            // Remove legacy note from payload to ensure pure migration
            delete graphState.currentSubjectPayload.note;
            graphState.currentSubjectPayload.photo = graphState.currentPhotoUuid;
            
            const newPayloadStr = deterministicStringify(graphState.currentSubjectPayload);
            
            const tfId = "enc-" + Math.random().toString(36).substr(2, 9);
            if (window.addTransfer) {
                window.addTransfer(tfId, "ENCRYPTING IDENTITY", "ENCRYPT");
                window.promoteTransfer(tfId, "ENCRYPT");
            }
            
            const encrypted_search = await encryptPayload(searchBlob, graphState.masterKey);
            if (window.updateTransfer) window.updateTransfer(tfId, 50);
            
            const encrypted_main = await encryptPayload(graphState.currentSubjectPayload, graphState.masterKey);
            if (window.updateTransfer) window.updateTransfer(tfId, 100);
            
            const payload = {
                encrypted_search_blob: encrypted_search,
                encrypted_blob: encrypted_main,
                email_hash: emailHash,
                phone_hash: phoneHash,
                dob_hash: dobHash
            };

            await fetch(`/app/graph/api/subject/${currentSubjectUuid}`, {
                method: 'PATCH',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });
            if (window.completeTransfer) window.completeTransfer(tfId);
            graphState.lastSavedPayloadStr = newPayloadStr;
            showZNodeToast("CHANGES SECURELY ENCRYPTED & SAVED", "info");
            document.getElementById('det-uuid-title').innerText = name.toUpperCase();
        } catch (e) {
            if (window.failTransfer) window.failTransfer(tfId);
            console.error(e);
            showZNodeToast("SAVE ERROR: " + e.message, "error");
        } finally {
            btn.classList.remove('loading');
        }
    }

    document.getElementById('btn-update-subject').addEventListener('click', triggerSaveSubject);

    document.getElementById('btn-delete-subject').addEventListener('click', async () => {
        if (!await ZNodeDialog.confirm("PURGE IDENTITY", "Are you sure you want to completely purge this identity? This action is irreversible.")) return;
        try {
            await fetch(`/app/graph/api/subject/${currentSubjectUuid}`, { method: 'DELETE' });
            window.location.href = '/app/graph';
        } catch(e) {
            console.error(e);
        }
    });

    document.getElementById('btn-add-custom-key').addEventListener('click', async () => {
        const keyName = await ZNodeDialog.prompt("ADD ATTRIBUTE", "Enter a unique name for this custom attribute:");
        if (!keyName) return;
        
        if (graphState.currentSubjectPayload.custom_keys && graphState.currentSubjectPayload.custom_keys[keyName]) {
            showZNodeToast("ATTRIBUTE ALREADY EXISTS", "error");
            return;
        }

        const typeOptions = [
            { label: "Short Text", value: "short_text" },
            { label: "Long Text", value: "long_text" },
            { label: "Integer Number", value: "int" },
            { label: "Floating Point", value: "float" },
            { label: "Date", value: "date" },
            { label: "Time", value: "time" },
            { label: "Date & Time", value: "datetime" }
        ];
        const mappedType = await ZNodeDialog.select("ATTRIBUTE TYPE", "Select the data type for this attribute:", typeOptions, "short_text");
        if (!mappedType) return;
        
        if (!graphState.currentSubjectPayload.custom_keys) graphState.currentSubjectPayload.custom_keys = {};
        graphState.currentSubjectPayload.custom_keys[keyName] = {
            type: mappedType,
            value: utf8ToBase64("")
        };
        renderCustomKeys();
        await triggerSaveSubject();
    });

    window.deleteCustomKey = async (keyName) => {
        if (!await ZNodeDialog.confirm("DELETE ATTRIBUTE", `Remove the attribute '${keyName}'?`)) return;
        delete graphState.currentSubjectPayload.custom_keys[keyName];
        renderCustomKeys();
        await triggerSaveSubject();
    };

    // Relation Modal Logic
    const relationModal = document.getElementById('relation-modal');
    const searchInput = document.getElementById('relation-search-input');
    const searchResults = document.getElementById('relation-search-results');
    const selectedTargetUI = document.getElementById('relation-selected-target');
    const targetUuidInput = document.getElementById('relation-target-uuid');
    const relTypeInput = document.getElementById('relation-type-input');
    const relDescInput = document.getElementById('relation-desc-input');
    const btnSaveRelation = document.getElementById('btn-save-relation');
    
    document.getElementById('btn-add-relation').addEventListener('click', () => {
        searchInput.value = '';
        searchResults.innerHTML = '';
        searchResults.classList.add('hidden');
        selectedTargetUI.innerText = 'NONE SELECTED';
        selectedTargetUI.classList.remove('text-[#e5e5e5]', 'opacity-100');
        selectedTargetUI.classList.add('text-primary', 'opacity-50');
        targetUuidInput.value = '';
        relTypeInput.value = '';
        relDescInput.value = '';
        btnSaveRelation.classList.add('pointer-events-none', 'opacity-50');
        
        relationModal.classList.remove('hidden');
        searchInput.focus();
    });
    
    document.getElementById('btn-cancel-relation').addEventListener('click', () => {
        relationModal.classList.add('hidden');
    });
    
    searchInput.addEventListener('input', (e) => {
        const query = e.target.value.toLowerCase().trim();
        searchResults.innerHTML = '';
        if (query.length < 2) {
            searchResults.classList.add('hidden');
            return;
        }
        
        const cache = graphState.relationTargetType === 'group' ? graphState.groupsCache : graphState.subjectsCache;
        const matches = Object.values(cache).filter(s => 
            (s.name.toLowerCase().includes(query) || s.uuid.toLowerCase().includes(query)) &&
            s.uuid !== currentSubjectUuid
        );
        
        if (matches.length > 0) {
            matches.forEach(sub => {
                const isAdded = graphState.existingRelationUuids && graphState.existingRelationUuids.includes(sub.uuid);
                const el = document.createElement('div');
                
                if (isAdded) {
                    el.className = "px-4 py-2 font-mono text-xs text-on-surface-variant/40 border-b border-outline-variant/10 cursor-not-allowed bg-surface-variant/5 flex justify-between items-center";
                    el.innerHTML = `<div><span class="uppercase">${sub.name}</span> <span class="text-[9px] ml-2">(${sub.uuid.split('-')[0]})</span></div><span class="text-[8px] bg-primary/10 text-primary px-1.5 py-0.5 rounded uppercase tracking-widest border border-primary/20">ALREADY ADDED</span>`;
                } else {
                    el.className = "px-4 py-2 hover:bg-primary/20 cursor-pointer font-mono text-xs text-[#e5e5e5] border-b border-outline-variant/10 flex justify-between items-center";
                    el.innerHTML = `<div><span class="uppercase">${sub.name}</span> <span class="text-on-surface-variant/40 text-[9px] ml-2">(${sub.uuid.split('-')[0]})</span></div>`;
                    el.onclick = () => {
                        targetUuidInput.value = sub.uuid;
                        selectedTargetUI.innerText = `${sub.name.toUpperCase()} (${sub.uuid})`;
                        selectedTargetUI.classList.remove('text-primary', 'opacity-50');
                        selectedTargetUI.classList.add('text-[#e5e5e5]', 'opacity-100');
                        searchResults.classList.add('hidden');
                        searchInput.value = '';
                        btnSaveRelation.classList.remove('pointer-events-none', 'opacity-50');
                        relTypeInput.focus();
                    };
                }
                searchResults.appendChild(el);
            });
            searchResults.classList.remove('hidden');
        } else {
            searchResults.classList.add('hidden');
        }
    });

    const btnRelPeople = document.getElementById('rel-target-people');
    const btnRelGroup = document.getElementById('rel-target-group');
    
    function updateRelationTargetTypeUI() {
        if (graphState.relationTargetType === 'subject') {
            btnRelPeople.className = "font-mono text-[9px] px-2 py-0.5 border border-primary/50 text-primary bg-primary/10 transition-colors uppercase";
            btnRelGroup.className = "font-mono text-[9px] px-2 py-0.5 border border-outline-variant/30 text-on-surface-variant/50 hover:text-on-surface transition-colors uppercase";
        } else {
            btnRelGroup.className = "font-mono text-[9px] px-2 py-0.5 border border-primary/50 text-primary bg-primary/10 transition-colors uppercase";
            btnRelPeople.className = "font-mono text-[9px] px-2 py-0.5 border border-outline-variant/30 text-on-surface-variant/50 hover:text-on-surface transition-colors uppercase";
        }
        searchInput.value = '';
        searchResults.classList.add('hidden');
        targetUuidInput.value = '';
        selectedTargetUI.innerText = "NONE SELECTED";
        selectedTargetUI.classList.remove('text-[#e5e5e5]', 'opacity-100');
        selectedTargetUI.classList.add('text-primary', 'opacity-50');
        btnSaveRelation.classList.add('pointer-events-none', 'opacity-50');
    }
    
    btnRelPeople.addEventListener('click', () => {
        graphState.relationTargetType = 'subject';
        updateRelationTargetTypeUI();
    });
    
    btnRelGroup.addEventListener('click', () => {
        graphState.relationTargetType = 'group';
        updateRelationTargetTypeUI();
    });

    btnSaveRelation.addEventListener('click', async () => {
        const targetUuid = targetUuidInput.value;
        const type = relTypeInput.value.trim() || 'LINKED';
        const description = relDescInput.value.trim();
        
        if (!targetUuid) return;
        
        btnSaveRelation.innerText = "SAVING...";
        
        const tfId = "rel-" + Math.random().toString(36).substr(2, 9);
        if (window.addTransfer) {
            window.addTransfer(tfId, "ENCRYPTING RELATION", "ENCRYPT");
            window.promoteTransfer(tfId, "ENCRYPT");
        }
        
        try {
            const relBlob = { type, description };
            const encRelBlob = await encryptPayload(relBlob, graphState.masterKey);
            if (window.updateTransfer) window.updateTransfer(tfId, 100);
            
            const payload = {
                source_uuid: currentSubjectUuid,
                target_uuid: targetUuid,
                encrypted_blob: encRelBlob,
                source_type: "subject",
                target_type: graphState.relationTargetType
            };
            
            const res = await fetch('/app/graph/api/relation', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });
            
            if (!res.ok) throw new Error("Failed to save relation");
            
            if (window.completeTransfer) window.completeTransfer(tfId);
            showZNodeToast("RELATION SAVED", "info");
            relationModal.classList.add('hidden');
            loadSubjectDetails(); // Reload to fetch and render relations
        } catch (e) {
            if (window.failTransfer) window.failTransfer(tfId);
            console.error(e);
            showZNodeToast("FAILED TO SAVE RELATION", "error");
        } finally {
            btnSaveRelation.innerText = "CONFIRM";
            btnSaveRelation.classList.remove('loading');
        }
    });
    
    window.editRelation = (targetUuid, type, desc, targetType) => {
        graphState.relationTargetType = targetType || 'subject';
        updateRelationTargetTypeUI();
        
        const cache = graphState.relationTargetType === 'group' ? graphState.groupsCache : graphState.subjectsCache;
        const sub = cache[targetUuid];
        if (!sub) return;
        
        searchInput.value = '';
        searchResults.classList.add('hidden');
        
        targetUuidInput.value = targetUuid;
        selectedTargetUI.innerText = `${sub.name.toUpperCase()} (${targetUuid})`;
        selectedTargetUI.classList.remove('text-primary', 'opacity-50');
        selectedTargetUI.classList.add('text-[#e5e5e5]', 'opacity-100');
        
        relTypeInput.value = type;
        relDescInput.value = desc;
        btnSaveRelation.classList.remove('pointer-events-none', 'opacity-50');
        
        relationModal.classList.remove('hidden');
        relTypeInput.focus();
    };

    window.deleteRelation = async (source, target) => {
        if (!await ZNodeDialog.confirm("PURGE RELATION", "Irreversibly sever this connection?")) return;
        const tfId = "rel-del-" + Math.random().toString(36).substr(2, 9);
        if (window.addTransfer) {
            window.addTransfer(tfId, "PURGING RELATION", "PURGE");
            window.promoteTransfer(tfId, "PURGE");
        }
        try {
            const res = await fetch('/app/graph/api/relation', {
                method: 'DELETE',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ source_uuid: source, target_uuid: target })
            });
            if (!res.ok) throw new Error("Save failed");
            
            if (window.completeTransfer) window.completeTransfer(tfId);
            showZNodeToast("IDENTITY SAVED", "info");
            loadSubjectDetails();
        } catch (e) {
            if (window.failTransfer) window.failTransfer(tfId);
            console.error(e);
            showZNodeToast("SAVE ERROR: " + e.message, "error");
        }
    };

    // File Upload Logic
    const fileInput = document.getElementById('graph-file-input');
    document.getElementById('btn-attach-file').addEventListener('click', () => {
        fileInput.click();
    });
    
    fileInput.addEventListener('change', async (e) => {
        if (!e.target.files.length || !currentSubjectUuid) return;
        const file = e.target.files[0];
        
        const desc = await ZNodeDialog.promptMultiline("INTEL DESCRIPTION", `Enter a brief description for ${file.name} (optional):`, "");
        if (desc === null) {
            fileInput.value = '';
            return;
        }
        
        const tfId = Math.random().toString(36).substr(2, 9);
        addTransfer(tfId, file.name, "ENCRYPT");
        
        try {
            const uuid = await uploadFile(file, tfId);
            
            // Save metadata
            if (uuid && desc) {
                graphState.currentSubjectPayload.file_metadata[uuid] = { description: desc };
                await triggerSaveSubject();
            }
            
            loadSubjectDetails();
        } catch (err) {
            console.error("Upload failed", err);
        }
        fileInput.value = '';
    });

    window.downloadGraphFile = async (uuid, fileName) => {
        const fMeta = graphState.currentSubjectPayload.file_metadata && graphState.currentSubjectPayload.file_metadata[uuid];
        // We do not know file name natively if it's not passed, but Vault UI will fetch it from /meta.
        await downloadFile(uuid, fileName || "attached_intel.bin", false);
    };
    
    window.deleteGraphFile = async (uuid) => {
        if (!await ZNodeDialog.confirm("PURGE FILE", "Irreversibly purge this intel attachment?")) return;
        await fetch(`/app/graph/api/file/${uuid}`, { method: 'DELETE' });
        loadSubjectDetails();
    };

    window.editGraphFileDescription = async (uuid) => {
        const meta = graphState.currentSubjectPayload.file_metadata[uuid] || {};
        const newDesc = await ZNodeDialog.promptMultiline("EDIT INTEL DESCRIPTION", `Update description:`, meta.description || "");
        if (newDesc !== null) {
            graphState.currentSubjectPayload.file_metadata[uuid] = { description: newDesc };
            await triggerSaveSubject();
            loadSubjectDetails();
        }
    };

    // Profile Photo Loading
    async function loadProfilePhoto(uuid) {
        try {
            const blob = await downloadFile(uuid, "photo.bin", true);
            const url = URL.createObjectURL(blob);
            graphState.activeBlobUrls.push(url);
            updateGraphCacheUI();
            
            document.getElementById('det-photo-img').src = url;
        } catch (e) {
            console.error("Failed to load profile photo", e);
            document.getElementById('det-photo-img').src = '/static/profile.avif';
        }
    }

    // Profile Photo Upload Logic
    const photoInput = document.getElementById('graph-photo-input');
    document.getElementById('btn-update-photo').addEventListener('click', () => {
        photoInput.click();
    });

    photoInput.addEventListener('change', async (e) => {
        if (!e.target.files.length || !currentSubjectUuid) return;
        
        if (graphState.currentPhotoUuid) {
            const confirmed = await ZNodeDialog.confirm("REPLACE PHOTO", "Are you sure you want to replace the current profile photo? The existing photo will be irreversibly purged.");
            if (!confirmed) {
                photoInput.value = '';
                return;
            }
            try {
                await fetch(`/app/graph/api/file/${graphState.currentPhotoUuid}`, { method: 'DELETE' });
            } catch (err) {
                console.error("Failed to delete old photo", err);
            }
        }
        
        const file = e.target.files[0];
        document.getElementById('det-photo-img').src = '/static/profile.avif'; // Placeholder while uploading
        
        const tfId = Math.random().toString(36).substr(2, 9);
        addTransfer(tfId, "PROFILE PHOTO", "ENCRYPT");
        
        try {
            const uuid = await uploadFile(file, tfId);
            if (uuid) {
                // Set photo and trigger save
                graphState.currentPhotoUuid = uuid;
                await triggerSaveSubject();
                
                // Load and display immediately
                await loadProfilePhoto(uuid);
                loadSubjectDetails(); // Refresh file list to show PHOTO tag
            }
        } catch (err) {
            console.error("Photo upload failed", err);
        }
        photoInput.value = '';
    });

    document.getElementById('btn-delete-photo').addEventListener('click', async () => {
        if (!graphState.currentPhotoUuid) return;
        const confirmed = await ZNodeDialog.confirm("PURGE PHOTO", "Are you sure you want to delete this profile photo?");
        if (!confirmed) return;
        
        try {
            await fetch(`/app/graph/api/file/${graphState.currentPhotoUuid}`, { method: 'DELETE' });
            graphState.currentPhotoUuid = null;
            document.getElementById('btn-delete-photo').classList.add('hidden');
            document.getElementById('det-photo-img').src = '/static/profile.avif';
            await triggerSaveSubject();
            loadSubjectDetails();
        } catch (err) {
            console.error("Failed to delete photo", err);
            showZNodeToast("Failed to delete photo", "error");
        }
    });

    // ─── REVISIONS ────────────────────────────────────────────────────────
    const btnShowRevisions = document.getElementById('btn-show-revisions');
    const btnCloseRevisions = document.getElementById('btn-close-revisions');
    const revisionsModal = document.getElementById('revisions-modal');
    const revisionsList = document.getElementById('revisions-list');
    const revisionsCompareContent = document.getElementById('revisions-compare-content');
    const btnRestoreRevision = document.getElementById('btn-restore-revision');
    let selectedRevisionPayload = null;

    if (btnShowRevisions) {
        btnShowRevisions.addEventListener('click', async () => {
            revisionsModal.classList.remove('hidden');
            revisionsList.innerHTML = '<div class="p-4 text-center font-mono text-[10px] text-on-surface-variant/50 uppercase">Loading Revisions...</div>';
            revisionsCompareContent.innerHTML = '<div class="flex h-full items-center justify-center text-on-surface-variant/40 font-mono text-[10px] uppercase tracking-widest mt-20">SELECT A REVISION TO COMPARE</div>';
            btnRestoreRevision.classList.add('hidden');
            
            try {
                const apiPath = window.location.pathname.includes('/group') ? 'group' : 'subject';
                const res = await fetch(`/app/graph/api/${apiPath}/${currentSubjectUuid}/revisions`);
                if (!res.ok) throw new Error("Failed to fetch revisions");
                const revisions = await res.json();
                
                revisionsList.innerHTML = '';
                if (revisions.length === 0) {
                    revisionsList.innerHTML = '<div class="p-4 text-center font-mono text-[10px] text-on-surface-variant/50 uppercase">NO HISTORY FOUND</div>';
                    return;
                }
                
                revisions.forEach((rev, idx) => {
                    const el = document.createElement('div');
                    el.className = "p-3 border-b border-outline-variant/10 hover:bg-surface-variant/20 cursor-pointer flex flex-col gap-1 transition-colors";
                    const d = new Date(rev.action_date + "Z");
                    el.innerHTML = `
                        <span class="font-mono text-xs text-[#e5e5e5]">${d.toLocaleDateString()}</span>
                        <span class="font-mono text-[9px] text-on-surface-variant/60">${d.toLocaleTimeString()}</span>
                        <span class="font-mono text-[8px] text-primary/50 uppercase tracking-widest mt-1">REV #${rev.history_id}</span>
                    `;
                    el.onclick = () => loadRevisionCompare(rev, el);
                    revisionsList.appendChild(el);
                });
            } catch (err) {
                console.error(err);
                revisionsList.innerHTML = '<div class="p-4 text-center font-mono text-[10px] text-error uppercase">Error loading history</div>';
            }
        });
    }

    if (btnCloseRevisions) {
        btnCloseRevisions.addEventListener('click', () => {
            revisionsModal.classList.add('hidden');
        });
    }

    async function loadRevisionCompare(rev, el) {
        document.querySelectorAll('#revisions-list > div').forEach(d => d.classList.remove('bg-primary/10', 'border-primary/30'));
        el.classList.add('bg-primary/10', 'border-primary/30');
        
        revisionsCompareContent.innerHTML = '<div class="flex h-full items-center justify-center text-on-surface-variant/40 font-mono text-[10px] uppercase tracking-widest mt-20">DECRYPTING...</div>';
        btnRestoreRevision.classList.add('hidden');
        selectedRevisionPayload = null;
        
        try {
            const oldPayload = await decryptPayload(rev.old_encrypted_blob, graphState.masterKey);
            selectedRevisionPayload = oldPayload;
            
            let html = '<div class="space-y-4">';
            const curr = graphState.currentSubjectPayload;
            
            function renderDiffRow(label, oldVal, newVal, isCustom = false) {
                if (oldVal === newVal) return '';
                let changeStr = '';
                if (oldVal === undefined || oldVal === null || oldVal === '') {
                    changeStr = `<span class="text-error line-through">[EMPTY]</span> <span class="text-on-surface-variant/40 mx-2">→</span> <span class="text-success">${newVal}</span>`;
                } else if (newVal === undefined || newVal === null || newVal === '') {
                    changeStr = `<span class="text-success">${oldVal}</span> <span class="text-on-surface-variant/40 mx-2">→</span> <span class="text-error line-through">[DELETED]</span>`;
                } else {
                    changeStr = `<span class="text-success">${oldVal}</span> <span class="text-on-surface-variant/40 mx-2">→</span> <span class="text-error">${newVal}</span>`;
                }
                
                return `
                    <div class="p-3 bg-surface-variant/5 border border-outline-variant/10 rounded">
                        <div class="font-mono text-[9px] text-on-surface-variant/60 uppercase tracking-widest mb-1">${label} ${isCustom ? '(CUSTOM ATTRIBUTE)' : ''}</div>
                        <div class="font-body text-sm">${changeStr}</div>
                    </div>
                `;
            }
            
            if (curr.name !== undefined) html += renderDiffRow('Name', oldPayload.name, curr.name);
            if (curr.note !== undefined) html += renderDiffRow('Note', oldPayload.note, curr.note);
            if (curr.dob !== undefined) html += renderDiffRow('DOB', oldPayload.dob, curr.dob);
            if (curr.phone !== undefined) html += renderDiffRow('Phone', oldPayload.phone, curr.phone);
            if (curr.email !== undefined) html += renderDiffRow('Email', oldPayload.email, curr.email);
            if (curr.gender !== undefined) html += renderDiffRow('Gender', oldPayload.gender, curr.gender);
            
            const oldKeys = oldPayload.custom_keys || {};
            const newKeys = curr.custom_keys || {};
            
            const allKeyNames = new Set([...Object.keys(oldKeys), ...Object.keys(newKeys)]);
            allKeyNames.forEach(k => {
                const oldK = oldKeys[k];
                const newK = newKeys[k];
                const oldV = oldK ? base64ToUtf8(oldK.value) : undefined;
                const newV = newK ? base64ToUtf8(newK.value) : undefined;
                html += renderDiffRow(k, oldV, newV, true);
            });
            
            html += '</div>';
            
            if (html === '<div class="space-y-4"></div>') {
                html = '<div class="flex h-full items-center justify-center text-on-surface-variant/40 font-mono text-[10px] uppercase tracking-widest mt-20">NO CHANGES FOUND</div>';
            } else {
                html = '<div class="p-3 bg-primary/10 border border-primary/20 rounded mb-4 font-mono text-[10px] text-primary uppercase tracking-widest">Note: The arrow points from the selected past revision to your current active state. Restoring will revert to the left side.</div>' + html;
            }
            
            revisionsCompareContent.innerHTML = html;
            btnRestoreRevision.classList.remove('hidden');
            
        } catch (err) {
            console.error(err);
            revisionsCompareContent.innerHTML = '<div class="flex h-full items-center justify-center text-error font-mono text-[10px] uppercase tracking-widest mt-20">FAILED TO DECRYPT REVISION</div>';
        }
    }

    if (btnRestoreRevision) {
        btnRestoreRevision.addEventListener('click', async () => {
            if (!selectedRevisionPayload) return;
            const confirmed = await ZNodeDialog.confirm("RESTORE REVISION", "Are you sure you want to restore this version? Your current state will be safely backed up into history.");
            if (!confirmed) return;
            
            btnRestoreRevision.innerText = "RESTORING...";
            btnRestoreRevision.classList.add('pointer-events-none', 'opacity-50');
            
            try {
                graphState.currentSubjectPayload = selectedRevisionPayload;
                await triggerSaveSubject();
                
                revisionsModal.classList.add('hidden');
                showZNodeToast("REVISION RESTORED", "success");
                loadSubjectDetails(); 
            } catch (err) {
                console.error(err);
                showZNodeToast("RESTORE FAILED", "error");
            } finally {
                btnRestoreRevision.innerText = "RESTORE THIS VERSION";
                btnRestoreRevision.classList.remove('pointer-events-none', 'opacity-50');
            }
        });
    }

    // Init
    loadSubjectDetails();
});
