/**
 * ZeroNode Real-Time Backup & Restore Live Progress Hub.
 * Dual-Engine Event System:
 *  1. WebSocket (/ws/backup) for instant real-time push events.
 *  2. Active HTTP Polling Fallback (every 800ms while active) guaranteeing 100% reliability
 *     across all WSGI servers (Werkzeug, Waitress, Gunicorn, proxies) even if WebSockets are unavailable.
 */
(function() {
    'use strict';

    class BackupLiveManager {
        constructor() {
            this.ws = null;
            this.wsHealthy = false;
            this.reconnectTimer = null;
            this.reconnectAttempts = 0;
            this.pingTimer = null;
            this.pollTimer = null;
            this.pollingActive = false;
            this.activeOperation = null; // { operation, targetType, targetTitle, taskId }
            this.modalEl = null;
            this.isModalVisible = false;
            this.eventLog = [];
            this.init();
        }

        init() {
            if (document.readyState === 'loading') {
                document.addEventListener('DOMContentLoaded', () => this.setup());
            } else {
                this.setup();
            }
        }

        setup() {
            this.ensureModalDOM();
            this.connectWebSocket();
            this.checkActiveTasksOnLoad();
        }

        async checkActiveTasksOnLoad() {
            // Check if there is an active restore or backup already running when page loads
            try {
                const isAdmin = window.location.pathname.includes('/admin');
                const endpoint = isAdmin ? '/app/admin/api/backup/status' : '/app/backup/api/user/status';
                const res = await fetch(endpoint);
                if (res.ok) {
                    const data = await res.json();
                    if (data.active_restore || data.global_active_restore || data.active_restore_task) {
                        const r = data.active_restore || data.global_active_restore || data.active_restore_task;
                        if (r && r.status === 'running') {
                            const title = r.target_type === 'server' ? 'System Database & Server Data' : 'User Account Drive';
                            this.startRestoreModal(r.target_type, title, r.task_id);
                        }
                    } else if (data.active_backup || data.active_task || data.global_active_task) {
                        const b = data.active_backup || data.active_task || data.global_active_task;
                        if (b && b.status === 'running') {
                            const title = b.target_type === 'server' ? 'System Server Data' : 'Your Account Drive';
                            this.startBackupModal(b.target_type, title, b.task_id);
                        }
                    }
                }
            } catch (e) {
                // Ignore silent load check
            }
        }

        connectWebSocket() {
            if (this.ws && (this.ws.readyState === WebSocket.OPEN || this.ws.readyState === WebSocket.CONNECTING)) {
                return;
            }

            const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
            const wsUrl = `${protocol}//${window.location.host}/ws/backup`;

            try {
                this.ws = new WebSocket(wsUrl);

                this.ws.onopen = () => {
                    this.wsHealthy = true;
                    this.reconnectAttempts = 0;
                    // Start heartbeat ping
                    clearInterval(this.pingTimer);
                    this.pingTimer = setInterval(() => {
                        if (this.ws && this.ws.readyState === WebSocket.OPEN) {
                            try { this.ws.send('ping'); } catch (e) {}
                        }
                    }, 25000);
                };

                this.ws.onmessage = (event) => {
                    try {
                        const data = JSON.parse(event.data);
                        this.handleMessage(data);
                    } catch (e) {
                        // Ignore non-json
                    }
                };

                this.ws.onclose = () => {
                    this.wsHealthy = false;
                    clearInterval(this.pingTimer);
                    this.scheduleReconnect();
                };

                this.ws.onerror = () => {
                    this.wsHealthy = false;
                    clearInterval(this.pingTimer);
                };
            } catch (err) {
                this.wsHealthy = false;
                this.scheduleReconnect();
            }
        }

        scheduleReconnect() {
            clearTimeout(this.reconnectTimer);
            this.reconnectAttempts++;
            // Exponential backoff: 3s, 6s, 12s, max 20s
            const delay = Math.min(20000, 3000 * Math.pow(1.5, Math.min(this.reconnectAttempts, 5)));
            this.reconnectTimer = setTimeout(() => {
                this.connectWebSocket();
            }, delay);
        }

        handleMessage(data) {
            if (data.type === 'pong') return;

            // Handle initial connection handshake
            if (data.type === 'connected') {
                const activeRestore = data.active_restore || data.global_restore;
                if (activeRestore && activeRestore.status === 'running') {
                    const title = activeRestore.target_type === 'server' ? 'System Database & Server Data' : 'User Account Drive';
                    this.startRestoreModal(activeRestore.target_type, title, activeRestore.task_id);
                }
                return;
            }

            // Dispatch global event for module listeners
            window.dispatchEvent(new CustomEvent('znode:backup:event', { detail: data }));

            // Route to appropriate handler
            if (data.operation === 'restore' || (data.type && data.type.startsWith('restore_'))) {
                this.onRestoreEvent(data);
            } else if (data.operation === 'backup' || (data.type && data.type.startsWith('backup_'))) {
                this.onBackupEvent(data);
            }
        }

        startPolling(taskId, operation, targetType) {
            this.stopPolling();
            this.pollingActive = true;
            this.pollOperation(taskId, operation, targetType);
        }

        stopPolling() {
            this.pollingActive = false;
            clearTimeout(this.pollTimer);
        }

        async pollOperation(taskId, operation, targetType) {
            if (!this.pollingActive) return;

            try {
                if (operation === 'restore') {
                    const isAdmin = targetType === 'server' || window.location.pathname.includes('/admin');
                    const endpoint = isAdmin
                        ? `/app/admin/api/backup/restore_task_status?task_id=${encodeURIComponent(taskId || '')}`
                        : `/app/backup/api/user/restore_task_status?task_id=${encodeURIComponent(taskId || '')}`;

                    const res = await fetch(endpoint);
                    if (res.ok) {
                        const data = await res.json();
                        const task = data.task;
                        if (task) {
                            const phase = this.guessRestorePhase(task.progress, task.current_step);
                            this.onRestoreEvent({
                                type: task.status === 'success' ? 'restore_completed' : (task.status === 'failed' ? 'restore_failed' : 'restore_progress'),
                                operation: 'restore',
                                task_id: task.task_id,
                                target_type: task.target_type,
                                target_id: task.target_id,
                                phase: phase,
                                progress: task.progress,
                                step: task.current_step,
                                error: task.error_message
                            });

                            if (task.status === 'success' || task.status === 'failed') {
                                this.stopPolling();
                                return;
                            }
                        }
                    }
                } else {
                    // Backup polling (using dedicated task status endpoint)
                    const isAdmin = targetType === 'server' || window.location.pathname.includes('/admin');
                    const endpoint = isAdmin
                        ? `/app/admin/api/backup/task_status?task_id=${encodeURIComponent(taskId || '')}`
                        : `/app/backup/api/user/task_status?task_id=${encodeURIComponent(taskId || '')}`;

                    const res = await fetch(endpoint);
                    if (res.ok) {
                        const data = await res.json();
                        const task = data.task;
                        if (task) {
                            if (!taskId || task.task_id === taskId) {
                                const phase = this.guessBackupPhase(task.progress, task.current_step);
                                this.onBackupEvent({
                                    type: task.status === 'success' ? 'backup_completed' : (task.status === 'failed' ? 'backup_failed' : 'backup_progress'),
                                    operation: 'backup',
                                    task_id: task.task_id,
                                    target_type: task.target_type,
                                    target_id: task.target_id,
                                    phase: phase,
                                    progress: task.progress,
                                    step: task.current_step,
                                    error: task.error_message
                                });

                                if (task.status === 'success' || task.status === 'failed') {
                                    this.stopPolling();
                                    return;
                                }
                            }
                        }
                    }
                }
            } catch (err) {
                // Ignore transient network errors
            }

            if (this.pollingActive) {
                this.pollTimer = setTimeout(() => this.pollOperation(taskId, operation, targetType), 800);
            }
        }

        guessRestorePhase(progress, step) {
            const s = (step || '').toLowerCase();
            if (s.includes('download')) return 'download';
            if (s.includes('manifest') || s.includes('integrity') || s.includes('validat') || s.includes('inspect')) return 'verify';
            if (s.includes('database') || s.includes('.db') || s.includes('sqlite')) return 'restore_db';
            if (s.includes('chunk') || s.includes('blob') || s.includes('file')) return 'restore_blobs';
            if (s.includes('clean') || s.includes('finaliz') || s.includes('purg')) return 'cleanup';
            if (progress >= 95) return 'cleanup';
            if (progress >= 65) return 'restore_blobs';
            if (progress >= 45) return 'restore_db';
            if (progress >= 20) return 'verify';
            return 'download';
        }

        guessBackupPhase(progress, step) {
            const s = (step || '').toLowerCase();
            if (s.includes('compress') || s.includes('snapshot')) return 'compress';
            if (s.includes('hash') || s.includes('init') || s.includes('checksum')) return 'init';
            if (s.includes('upload') || s.includes('chunk')) return 'upload';
            if (s.includes('verify') || s.includes('assembly')) return 'verify';
            if (s.includes('clean') || s.includes('delet') || s.includes('purg')) return 'cleanup';
            if (progress >= 95) return 'cleanup';
            if (progress >= 85) return 'verify';
            if (progress >= 28) return 'upload';
            return 'compress';
        }

        ensureModalDOM() {
            if (document.getElementById('znode-backup-live-modal')) {
                this.modalEl = document.getElementById('znode-backup-live-modal');
                return;
            }

            const modalHtml = `
            <div id="znode-backup-live-modal" class="fixed inset-0 z-[10000] flex items-center justify-center bg-black/80 backdrop-blur-md opacity-0 pointer-events-none transition-all duration-300">
                <div id="znode-backup-live-card" class="w-full max-w-xl mx-4 bg-[#0e0e0e] border border-outline-variant/30 shadow-2xl p-7 relative scale-95 transition-all duration-300">
                    <!-- Top glow accent bar -->
                    <div id="znode-live-glow" class="absolute top-0 left-0 w-full h-[2px] bg-gradient-to-r from-transparent via-primary to-transparent"></div>

                    <!-- Header -->
                    <div class="flex items-start justify-between gap-4 mb-6">
                        <div>
                            <p id="znode-live-op-tag" class="font-label text-[10px] tracking-[0.25em] text-primary/70 uppercase mb-1">
                                OPERATION IN PROGRESS
                            </p>
                            <h2 id="znode-live-title" class="font-headline text-xl text-on-surface uppercase tracking-wider font-bold">
                                Restore Operation
                            </h2>
                        </div>
                        <div class="flex items-center gap-3">
                            <span id="znode-live-status-badge" class="font-label text-[9px] px-2.5 py-1 tracking-widest border border-amber-500/40 text-amber-400 bg-amber-500/10 uppercase animate-pulse">
                                RUNNING
                            </span>
                            <button id="znode-live-btn-close" onclick="ZNodeBackupLive.hideModal()" class="text-on-surface-variant/40 hover:text-on-surface transition-colors p-1" title="Minimize / Run in background">
                                <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M6 18L18 6M6 6l12 12"></path>
                                </svg>
                            </button>
                        </div>
                    </div>

                    <!-- Pipeline Stepper -->
                    <div id="znode-live-stepper" class="grid grid-cols-5 gap-1.5 mb-6">
                        <!-- Injected dynamically based on op -->
                    </div>

                    <!-- Progress Section -->
                    <div class="mb-5 bg-surface-container/30 border border-outline-variant/15 p-4">
                        <div class="flex items-baseline justify-between mb-2">
                            <span id="znode-live-current-step" class="font-mono text-[11px] text-on-surface truncate pr-2">
                                Initializing operation...
                            </span>
                            <span id="znode-live-percent" class="font-mono text-2xl font-bold text-primary flex-shrink-0">
                                0%
                            </span>
                        </div>
                        <!-- Progress Bar -->
                        <div class="w-full bg-surface-container h-2 border border-outline-variant/20 overflow-hidden relative">
                            <div id="znode-live-bar" class="h-full bg-gradient-to-r from-primary via-primary to-emerald-400 transition-all duration-300 ease-out" style="width: 0%"></div>
                        </div>
                    </div>

                    <!-- Live Event Log -->
                    <div class="mb-6">
                        <div class="flex items-center justify-between mb-1.5">
                            <span class="font-label text-[9px] tracking-widest text-on-surface-variant/40 uppercase">ACTIVITY LOG</span>
                            <span id="znode-live-target-id" class="font-mono text-[9px] text-on-surface-variant/50 truncate max-w-xs"></span>
                        </div>
                        <div id="znode-live-log-box" class="bg-black/70 border border-outline-variant/20 p-2.5 font-mono text-[9px] text-on-surface-variant/80 max-h-24 overflow-y-auto space-y-1">
                            <div class="text-primary/60">[SYS] Ready for live updates...</div>
                        </div>
                    </div>

                    <!-- Action Footer -->
                    <div class="flex items-center justify-between pt-4 border-t border-outline-variant/10">
                        <span id="znode-live-footer-hint" class="font-label text-[9px] text-on-surface-variant/40 uppercase tracking-wider">
                            You may minimize this dialog; the background worker will continue uninterrupted.
                        </span>
                        <div class="flex items-center gap-3">
                            <button id="znode-live-btn-minimize" onclick="ZNodeBackupLive.hideModal()" class="px-4 py-2 border border-outline-variant/30 text-on-surface-variant/80 hover:text-on-surface hover:border-outline-variant/60 font-label text-[9px] tracking-widest uppercase transition-all">
                                Minimize
                            </button>
                            <button id="znode-live-btn-action" onclick="ZNodeBackupLive.handleAction()" class="px-5 py-2 border border-primary/40 bg-primary/10 text-primary hover:bg-primary hover:text-black font-label text-[9px] tracking-widest uppercase font-bold transition-all hidden">
                                Done
                            </button>
                        </div>
                    </div>
                </div>
            </div>`;

            const div = document.createElement('div');
            div.innerHTML = modalHtml;
            document.body.appendChild(div.firstElementChild);
            this.modalEl = document.getElementById('znode-backup-live-modal');
        }

        showModal(operation, title, targetInfo, taskId) {
            this.ensureModalDOM();
            this.activeOperation = { operation, title, targetInfo, taskId };

            const titleEl = document.getElementById('znode-live-title');
            const opTagEl = document.getElementById('znode-live-op-tag');
            const targetEl = document.getElementById('znode-live-target-id');
            const actionBtn = document.getElementById('znode-live-btn-action');
            const minimizeBtn = document.getElementById('znode-live-btn-minimize');
            const statusBadge = document.getElementById('znode-live-status-badge');

            if (titleEl) titleEl.textContent = title || (operation === 'restore' ? 'System Restore' : 'System Backup');
            if (opTagEl) opTagEl.textContent = operation === 'restore' ? 'RESTORE PIPELINE IN PROGRESS' : 'BACKUP PIPELINE IN PROGRESS';
            if (targetEl) targetEl.textContent = targetInfo ? `TARGET: ${targetInfo}` : '';

            if (actionBtn) actionBtn.classList.add('hidden');
            if (minimizeBtn) minimizeBtn.classList.remove('hidden');

            if (statusBadge) {
                statusBadge.className = "font-label text-[9px] px-2.5 py-1 tracking-widest border border-amber-500/40 text-amber-400 bg-amber-500/10 uppercase animate-pulse";
                statusBadge.textContent = "IN PROGRESS";
            }

            this.renderStepper(operation, null);

            this.modalEl.classList.remove('opacity-0', 'pointer-events-none');
            const card = document.getElementById('znode-backup-live-card');
            if (card) card.classList.remove('scale-95');
            this.isModalVisible = true;

            window.dispatchEvent(new CustomEvent('znode:backup:busy', { detail: { operation, taskId, targetInfo } }));

            // Start active HTTP polling fallback alongside WebSocket
            this.startPolling(taskId, operation, targetInfo);
        }

        isOperationRunning() {
            return Boolean(this.activeOperation && (this.pollingActive || (this.activeOperation.status === 'running')));
        }

        setTaskId(taskId) {
            if (this.activeOperation) {
                this.activeOperation.taskId = taskId;
                this.startPolling(taskId, this.activeOperation.operation, this.activeOperation.targetInfo);
            }
        }

        hideModal() {
            if (!this.modalEl) return;
            this.modalEl.classList.add('opacity-0', 'pointer-events-none');
            const card = document.getElementById('znode-backup-live-card');
            if (card) card.classList.add('scale-95');
            this.isModalVisible = false;
        }

        renderStepper(operation, currentPhase) {
            const stepper = document.getElementById('znode-live-stepper');
            if (!stepper) return;

            const backupSteps = [
                { id: 'compress', label: '1. COMPRESS' },
                { id: 'upload', label: '2. UPLOAD' },
                { id: 'verify', label: '3. VERIFY' },
                { id: 'cleanup', label: '4. FINALIZE' },
                { id: 'done', label: '5. DONE' }
            ];

            const restoreSteps = [
                { id: 'download', label: '1. DOWNLOAD' },
                { id: 'verify', label: '2. VERIFY' },
                { id: 'restore_db', label: '3. DB SNAPSHOT' },
                { id: 'restore_blobs', label: '4. RESTORE FILES' },
                { id: 'done', label: '5. DONE' }
            ];

            const steps = operation === 'restore' ? restoreSteps : backupSteps;
            const phaseOrder = steps.map(s => s.id);
            const activeIdx = currentPhase ? phaseOrder.indexOf(currentPhase) : 0;

            stepper.innerHTML = steps.map((s, idx) => {
                let stateClasses = "border-outline-variant/20 text-on-surface-variant/40 bg-surface-container/10";
                let icon = '';

                if (idx < activeIdx || currentPhase === 'done') {
                    // Completed step
                    stateClasses = "border-emerald-500/40 text-emerald-400 bg-emerald-500/10 font-bold";
                    icon = '✓ ';
                } else if (idx === activeIdx && currentPhase !== 'done' && currentPhase !== 'failed') {
                    // Active current step
                    stateClasses = "border-primary text-primary bg-primary/10 shadow-[0_0_12px_rgba(193,199,207,0.15)] font-bold animate-pulse";
                }

                return `
                    <div class="border ${stateClasses} p-2 text-center transition-all">
                        <p class="font-label text-[8px] tracking-wider uppercase truncate">${icon}${s.label}</p>
                    </div>
                `;
            }).join('');
        }

        addLog(msg) {
            const box = document.getElementById('znode-live-log-box');
            if (!box || !msg) return;
            const timeStr = new Date().toLocaleTimeString();
            const div = document.createElement('div');
            div.className = "truncate text-on-surface/80";
            div.innerHTML = `<span class="text-on-surface-variant/40">[${timeStr}]</span> ${msg}`;
            box.appendChild(div);
            box.scrollTop = box.scrollHeight;
        }

        onBackupEvent(ev) {
            const phase = ev.phase || 'upload';
            const progress = Math.min(100, Math.max(0, ev.progress || 0));
            const stepText = ev.step || 'Processing backup...';

            if (this.isModalVisible && this.activeOperation && this.activeOperation.operation === 'backup') {
                this.updateLiveUI(phase, progress, stepText, ev);
            }

            if (ev.type === 'backup_completed') {
                this.handleCompleted(ev);
            } else if (ev.type === 'backup_failed') {
                this.handleFailed(ev);
            }
        }

        onRestoreEvent(ev) {
            const phase = ev.phase || (ev.progress >= 95 ? 'done' : 'restore_db');
            const progress = Math.min(100, Math.max(0, ev.progress || 0));
            const stepText = ev.step || 'Restoring drive data...';

            // Auto-open modal if not already open
            if (!this.isModalVisible) {
                const targetLabel = ev.target_type === 'server' ? 'System Database & Server Data' : 'User Account Drive';
                this.showModal('restore', `Restoring ${targetLabel}`, ev.target_id, ev.task_id);
            }

            this.updateLiveUI(phase, progress, stepText, ev);

            if (ev.type === 'restore_completed' || phase === 'done') {
                this.handleCompleted(ev);
            } else if (ev.type === 'restore_failed' || phase === 'failed') {
                this.handleFailed(ev);
            }
        }

        updateLiveUI(phase, progress, stepText, ev) {
            const bar = document.getElementById('znode-live-bar');
            const pct = document.getElementById('znode-live-percent');
            const stepEl = document.getElementById('znode-live-current-step');
            const op = (this.activeOperation && this.activeOperation.operation) || (ev && ev.operation) || 'restore';

            if (bar) bar.style.width = `${progress}%`;
            if (pct) pct.textContent = `${progress}%`;
            if (stepEl) stepEl.textContent = stepText;

            this.renderStepper(op, phase);
            this.addLog(stepText);
        }

        handleCompleted(ev) {
            this.stopPolling();
            const statusBadge = document.getElementById('znode-live-status-badge');
            const actionBtn = document.getElementById('znode-live-btn-action');
            const minimizeBtn = document.getElementById('znode-live-btn-minimize');
            const bar = document.getElementById('znode-live-bar');
            const pct = document.getElementById('znode-live-percent');
            const stepEl = document.getElementById('znode-live-current-step');
            const glow = document.getElementById('znode-live-glow');

            if (statusBadge) {
                statusBadge.className = "font-label text-[9px] px-2.5 py-1 tracking-widest border border-emerald-500/40 text-emerald-400 bg-emerald-500/10 uppercase font-bold";
                statusBadge.textContent = "SUCCESS";
            }
            if (glow) glow.className = "absolute top-0 left-0 w-full h-[2px] bg-gradient-to-r from-transparent via-emerald-400 to-transparent";

            if (bar) bar.style.width = '100%';
            if (pct) pct.textContent = '100%';
            if (stepEl) stepEl.textContent = ev.step || 'Operation completed successfully.';

            this.renderStepper(ev.operation || (this.activeOperation && this.activeOperation.operation) || 'restore', 'done');
            this.addLog(`[DONE] ${ev.step || 'Operation completed successfully.'}`);

            window.dispatchEvent(new CustomEvent('znode:backup:idle', { detail: { status: 'completed', operation: ev.operation } }));

            if (minimizeBtn) minimizeBtn.classList.add('hidden');
            if (actionBtn) {
                actionBtn.classList.remove('hidden');
                actionBtn.textContent = ev.operation === 'restore' ? 'Reload Application' : 'Close';
                actionBtn.className = "px-5 py-2 border border-emerald-500/40 bg-emerald-500/10 text-emerald-400 hover:bg-emerald-500 hover:text-black font-label text-[9px] tracking-widest uppercase font-bold transition-all";
            }
        }

        handleFailed(ev) {
            this.stopPolling();
            if (this.activeOperation) {
                this.activeOperation.status = 'failed';
            }
            const statusBadge = document.getElementById('znode-live-status-badge');
            const actionBtn = document.getElementById('znode-live-btn-action');
            const minimizeBtn = document.getElementById('znode-live-btn-minimize');
            const stepEl = document.getElementById('znode-live-current-step');
            const glow = document.getElementById('znode-live-glow');

            if (statusBadge) {
                statusBadge.className = "font-label text-[9px] px-2.5 py-1 tracking-widest border border-error/40 text-error bg-error/10 uppercase font-bold";
                statusBadge.textContent = "FAILED";
            }
            if (glow) glow.className = "absolute top-0 left-0 w-full h-[2px] bg-gradient-to-r from-transparent via-error to-transparent";

            const errMsg = ev.error || ev.step || 'Operation encountered a critical failure.';
            if (stepEl) stepEl.textContent = errMsg;
            this.addLog(`[ERROR] ${errMsg}`);

            window.dispatchEvent(new CustomEvent('znode:backup:idle', { detail: { status: 'failed', error: errMsg } }));

            if (minimizeBtn) minimizeBtn.classList.add('hidden');
            if (actionBtn) {
                actionBtn.classList.remove('hidden');
                actionBtn.textContent = 'Dismiss';
                actionBtn.className = "px-5 py-2 border border-error/40 bg-error/10 text-error hover:bg-error hover:text-black font-label text-[9px] tracking-widest uppercase font-bold transition-all";
            }
        }

        handleAction() {
            const op = this.activeOperation ? this.activeOperation.operation : 'restore';
            this.activeOperation = null;
            window.dispatchEvent(new CustomEvent('znode:backup:idle', { detail: { status: 'dismissed' } }));
            this.hideModal();
            if (op === 'restore') {
                window.location.reload();
            }
        }

        // Public helper to open live modal when starting a backup or restore
        startBackupModal(targetType, targetTitle, taskId) {
            this.showModal('backup', `Backing Up: ${targetTitle}`, targetType, taskId);
            this.addLog(`[INIT] Initializing backup pipeline for ${targetTitle}...`);
        }

        startRestoreModal(targetType, targetTitle, taskId) {
            this.showModal('restore', `Restoring: ${targetTitle}`, targetType, taskId);
            this.addLog(`[INIT] Initializing restore pipeline for ${targetTitle}...`);
        }
    }

    // Attach to global window
    window.ZNodeBackupLive = new BackupLiveManager();
})();
