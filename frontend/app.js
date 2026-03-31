/* ═══════════════════════════════════════════════════════════════
   ufw2me — Application Logic
   ═══════════════════════════════════════════════════════════════ */

(function () {
    'use strict';

    // ─── State ──────────────────────────────────────────────────
    const state = {
        rules: [],
        originalRules: [],
        interfaces: [],
        ufwActive: false,
        hasChanges: false,
        activeTab: 'rules',
        theme: localStorage.getItem('ufw2me-theme') || 'dark',
        saving: false,
    };

    // ─── Constants ──────────────────────────────────────────────
    const THEME_CHOICES = ['dark', 'light', 'system'];
    const PROTOCOLS = ['TCP', 'UDP', 'ICMP', 'GRE', 'ESP'];
    const ACTIONS = [
        { label: 'Allow', value: 'allow' },
        { label: 'Deny', value: 'deny' },
        { label: 'Reject', value: 'reject' },
    ];
    const IP_PRESETS = [
        { label: 'Any IPv4', value: 'Any IPv4' },
        { label: 'Any IPv6', value: 'Any IPv6' },
    ];

    function isValidIPv4(ip) {
        const parts = ip.split('.');
        if (parts.length !== 4) return false;
        return parts.every(part => {
            const num = parseInt(part, 10);
            return !isNaN(num) && num >= 0 && num <= 255 && String(num) === part;
        });
    }

    function isValidIPv6(ip) {
        if (!ip.includes('::')) {
            const parts = ip.split(':');
            if (parts.length !== 8) return false;
            return parts.every(part => {
                const num = parseInt(part, 16);
                return !isNaN(num) && num >= 0 && num <= 0xffff;
            });
        }
        const parts = ip.split('::');
        if (parts.length > 2) return false;
        const left = parts[0] ? parts[0].split(':').filter(p => p) : [];
        const right = parts[1] ? parts[1].split(':').filter(p => p) : [];
        const totalParts = left.length + right.length;
        if (totalParts >= 8) return false;
        return true;
    }

    function isValidIP(ip) {
        return IP_PRESETS.some(p => p.value === ip) || isValidIPv4(ip) || isValidIPv6(ip);
    }

    // ─── Init ───────────────────────────────────────────────────
    document.addEventListener('DOMContentLoaded', init);

    function init() {
        applyTheme(state.theme);
        setupEventListeners();
        loadData();
    }

    // ─── Theme ──────────────────────────────────────────────────
    let systemThemeMedia = null;
    let systemThemeListener = null;

    function getSystemTheme() {
        if (!window.matchMedia) return 'dark';
        return window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
    }

    function applyTheme(theme) {
        state.theme = theme;
        localStorage.setItem('ufw2me-theme', theme);

        if (systemThemeMedia && systemThemeListener) {
            systemThemeMedia.removeEventListener('change', systemThemeListener);
        }

        const effectiveTheme = theme === 'system' ? getSystemTheme() : theme;
        document.documentElement.setAttribute('data-theme', effectiveTheme);

        if (theme === 'system' && window.matchMedia) {
            systemThemeMedia = window.matchMedia('(prefers-color-scheme: light)');
            systemThemeListener = () => {
                document.documentElement.setAttribute('data-theme', getSystemTheme());
            };
            systemThemeMedia.addEventListener('change', systemThemeListener);
        }

        const themeBtn = document.getElementById('theme-toggle');
        if (themeBtn) {
            const icons = {
                dark: '<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 12.79A9 9 0 1111.21 3 7 7 0 0021 12.79z"/></svg>',
                light: '<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="5"/><path d="M12 1v2M12 21v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M1 12h2M21 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/></svg>',
                system: '<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="3" width="20" height="14" rx="2"/><path d="M8 21h8M12 17v4"/></svg>',
            };
            themeBtn.innerHTML = icons[theme] || icons.dark;
        }
    }

    // ─── Event Listeners ────────────────────────────────────────
    function setupEventListeners() {
        // Theme toggle
        document.getElementById('theme-toggle').addEventListener('click', () => {
            const idx = THEME_CHOICES.indexOf(state.theme);
            const next = THEME_CHOICES[(idx + 1) % THEME_CHOICES.length];
            applyTheme(next);
        });

        // Tabs
        document.querySelectorAll('.tab').forEach(tab => {
            tab.addEventListener('click', () => switchTab(tab.dataset.tab));
        });

        // Dropdowns
        setupDropdown('actions-dropdown', 'actions-btn');
        setupDropdown('add-rule-dropdown', 'add-rule-btn');

        // Add rule dropdown items
        document.querySelectorAll('#add-rule-menu .dropdown-item').forEach(item => {
            item.addEventListener('click', () => {
                addNewRule(item.dataset.direction);
                closeAllDropdowns();
            });
        });

        // Inline add rule buttons
        document.querySelectorAll('.add-rule-inline').forEach(btn => {
            btn.addEventListener('click', () => addNewRule(btn.dataset.direction));
        });

        // Toggle UFW
        document.getElementById('toggle-ufw-btn').addEventListener('click', async () => {
            const enable = !state.ufwActive;
            try {
                await api('/api/ufw/toggle', { method: 'POST', body: JSON.stringify({ enable }) });
                showToast(enable ? 'Firewall enabled' : 'Firewall disabled', 'success');
                loadData();
            } catch (e) {
                showToast('Failed to toggle firewall: ' + e.message, 'error');
            }
            closeAllDropdowns();
        });

        // Reload
        document.getElementById('reload-btn').addEventListener('click', () => {
            loadData();
            closeAllDropdowns();
        });

        // Save / Cancel
        document.getElementById('save-btn').addEventListener('click', saveRules);
        document.getElementById('cancel-btn').addEventListener('click', cancelChanges);

        // Close dropdowns on outside click
        document.addEventListener('click', (e) => {
            if (!e.target.closest('.dropdown')) {
                closeAllDropdowns();
            }
        });
    }

    function setupDropdown(dropdownId, buttonId) {
        const btn = document.getElementById(buttonId);
        btn.addEventListener('click', (e) => {
            e.stopPropagation();
            const dropdown = document.getElementById(dropdownId);
            const wasOpen = dropdown.classList.contains('open');
            closeAllDropdowns();
            if (!wasOpen) dropdown.classList.add('open');
        });
    }

    function closeAllDropdowns() {
        document.querySelectorAll('.dropdown.open').forEach(d => d.classList.remove('open'));
    }

    // ─── Tab Switching ──────────────────────────────────────────
    function switchTab(tab) {
        state.activeTab = tab;
        document.querySelectorAll('.tab').forEach(t => t.classList.toggle('active', t.dataset.tab === tab));
        document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
        document.getElementById(tab + '-tab').classList.add('active');
    }

    // ─── API Helper ─────────────────────────────────────────────
    async function api(url, options = {}) {
        const resp = await fetch(url, {
            headers: { 'Content-Type': 'application/json' },
            ...options,
        });
        if (!resp.ok) {
            const err = await resp.json().catch(() => ({ error: 'Request failed' }));
            throw new Error(err.error || 'Request failed');
        }
        return resp.json();
    }

    // ─── Load Data ──────────────────────────────────────────────
    async function loadData() {
        try {
            const [statusData, rulesData] = await Promise.all([
                api('/api/status'),
                api('/api/rules'),
            ]);

            state.ufwActive = statusData.active;
            state.interfaces = statusData.interfaces || [];
            state.rules = rulesData || [];
            state.originalRules = JSON.parse(JSON.stringify(state.rules));
            state.hasChanges = false;

            updateStatusUI(statusData);
            renderRules();
            renderInterfaces();
            updateSaveBar();

            document.getElementById('rules-loading').style.display = 'none';
            document.getElementById('inbound-section').style.display = '';
            document.getElementById('outbound-section').style.display = '';
        } catch (e) {
            console.error('Failed to load data:', e);
            showToast('Failed to load firewall data: ' + e.message, 'error');
        }
    }

    // ─── Update Status UI ───────────────────────────────────────
    function updateStatusUI(status) {
        const badge = document.getElementById('status-badge');
        badge.className = 'status-badge ' + (status.active ? 'active' : 'inactive');
        badge.querySelector('.status-text').textContent = status.active ? 'Fully applied' : 'Inactive';

        document.getElementById('rule-count').textContent = `Rules ${status.rule_count}`;

        const ifaceNames = (status.interfaces || [])
            .filter(i => i.name !== 'lo')
            .map(i => i.name)
            .join(', ');
        document.getElementById('interface-info').textContent = ifaceNames
            ? `Interfaces: ${ifaceNames}`
            : 'Interfaces —';

        document.getElementById('toggle-ufw-text').textContent = status.active
            ? 'Disable Firewall'
            : 'Enable Firewall';
    }

    // ─── Render Rules ───────────────────────────────────────────
    function renderRules() {
        const inbound = state.rules.filter(r => r.direction === 'in');
        const outbound = state.rules.filter(r => r.direction === 'out');

        renderRuleList('inbound-rules', inbound);
        renderRuleList('outbound-rules', outbound);
    }

    function renderRuleList(containerId, rules) {
        const container = document.getElementById(containerId);
        container.innerHTML = '';

        rules.forEach((rule, index) => {
            container.appendChild(createRuleCard(rule, index));
        });
    }

    function createRuleCard(rule, index) {
        const card = document.createElement('div');
        card.className = 'rule-card' + (rule._isNew ? ' is-new' : '');
        card.dataset.ruleId = rule.id;
        card.draggable = true;

        // Drag handle
        const handle = document.createElement('div');
        handle.className = 'drag-handle';
        handle.title = 'Drag to reorder';
        card.appendChild(handle);

        // Delete button
        const deleteBtn = document.createElement('button');
        deleteBtn.className = 'rule-delete';
        deleteBtn.innerHTML = '×';
        deleteBtn.title = 'Remove rule';
        deleteBtn.addEventListener('click', () => deleteRule(rule.id));
        card.appendChild(deleteBtn);

        // Description input
        const descInput = document.createElement('input');
        descInput.type = 'text';
        descInput.className = 'rule-description';
        descInput.placeholder = 'Add description';
        descInput.value = rule.description || '';
        descInput.addEventListener('input', () => {
            rule.description = descInput.value;
            markChanged();
        });
        card.appendChild(descInput);

        // Rule body
        const body = document.createElement('div');
        body.className = 'rule-body';

        // IP tags area
        body.appendChild(createIPTagsArea(rule));

        // Action select
        body.appendChild(createActionSelect(rule));

        // Protocol select
        body.appendChild(createProtocolSelect(rule));

        // Interface select
        body.appendChild(createInterfaceSelect(rule));

        // Port inputs
        body.appendChild(createPortInputs(rule));

        card.appendChild(body);

        // Drag events
        setupDragEvents(card, rule);

        return card;
    }

    function createIPTagsArea(rule) {
        const wrapper = document.createElement('div');
        wrapper.style.position = 'relative';

        const area = document.createElement('div');
        area.className = 'ip-tags-area';

        // Render existing tags
        (rule.ips || []).forEach(ip => {
            area.appendChild(createIPTag(ip, rule));
        });

        // Input for new IPs
        const input = document.createElement('input');
        input.type = 'text';
        input.className = 'ip-input';
        input.placeholder = rule.ips && rule.ips.length ? '' : 'Type IP or select preset...';

        // Autocomplete
        const autocomplete = document.createElement('div');
        autocomplete.className = 'ip-autocomplete';

        let focusedIndex = -1;

        function showAutocomplete(filter = '') {
            autocomplete.innerHTML = '';
            const lower = filter.toLowerCase();
            const items = IP_PRESETS.filter(p =>
                p.label.toLowerCase().includes(lower) &&
                !(rule.ips || []).includes(p.value)
            );

            if (items.length === 0) {
                autocomplete.classList.remove('visible');
                return;
            }

            items.forEach((preset, idx) => {
                const item = document.createElement('button');
                item.className = 'ip-autocomplete-item';
                item.textContent = preset.label;
                item.addEventListener('mousedown', (e) => {
                    e.preventDefault();
                    addIP(rule, preset.value, area, input);
                    input.value = '';
                    autocomplete.classList.remove('visible');
                });
                autocomplete.appendChild(item);
            });

            focusedIndex = -1;
            autocomplete.classList.add('visible');
        }

        input.addEventListener('focus', () => showAutocomplete(input.value));
        input.addEventListener('input', () => showAutocomplete(input.value));
        input.addEventListener('blur', () => {
            setTimeout(() => autocomplete.classList.remove('visible'), 150);
        });

        input.addEventListener('keydown', (e) => {
            const items = autocomplete.querySelectorAll('.ip-autocomplete-item');

            if (e.key === 'ArrowDown') {
                e.preventDefault();
                focusedIndex = Math.min(focusedIndex + 1, items.length - 1);
                items.forEach((item, i) => item.classList.toggle('focused', i === focusedIndex));
            } else if (e.key === 'ArrowUp') {
                e.preventDefault();
                focusedIndex = Math.max(focusedIndex - 1, 0);
                items.forEach((item, i) => item.classList.toggle('focused', i === focusedIndex));
            } else if (e.key === 'Enter') {
                e.preventDefault();
                if (focusedIndex >= 0 && items[focusedIndex]) {
                    items[focusedIndex].dispatchEvent(new MouseEvent('mousedown'));
                } else if (input.value.trim()) {
                    addIP(rule, input.value.trim(), area, input);
                    input.value = '';
                    autocomplete.classList.remove('visible');
                }
            } else if (e.key === 'Backspace' && !input.value) {
                // Remove last tag
                if (rule.ips && rule.ips.length > 0) {
                    rule.ips.pop();
                    markChanged();
                    refreshIPTags(area, rule, input);
                }
            } else if (e.key === 'Escape') {
                autocomplete.classList.remove('visible');
            }
        });

        area.appendChild(input);
        area.addEventListener('click', () => input.focus());

        wrapper.appendChild(area);
        wrapper.appendChild(autocomplete);
        return wrapper;
    }

    function createIPTag(ip, rule) {
        const tag = document.createElement('span');
        tag.className = 'ip-tag';
        tag.textContent = ip;

        const removeBtn = document.createElement('button');
        removeBtn.className = 'remove-tag';
        removeBtn.innerHTML = '×';
        removeBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            rule.ips = (rule.ips || []).filter(i => i !== ip);
            markChanged();
            tag.remove();
        });
        tag.appendChild(removeBtn);
        return tag;
    }

    function addIP(rule, value, area, input) {
        if (!isValidIP(value)) {
            showToast('Invalid IP address. Use Any IPv4, Any IPv6, or a valid IPv4/IPv6', 'error');
            return;
        }
        if (!rule.ips) rule.ips = [];
        if (rule.ips.includes(value)) return;
        rule.ips.push(value);
        markChanged();

        // Insert tag before input
        area.insertBefore(createIPTag(value, rule), input);
        input.placeholder = '';
    }

    function refreshIPTags(area, rule, input) {
        // Remove all tags
        area.querySelectorAll('.ip-tag').forEach(t => t.remove());
        // Re-add
        (rule.ips || []).forEach(ip => {
            area.insertBefore(createIPTag(ip, rule), input);
        });
        input.placeholder = rule.ips && rule.ips.length ? '' : 'Type IP or select preset...';
    }

    function createProtocolSelect(rule) {
        const group = document.createElement('div');
        group.className = 'protocol-group';

        const label = document.createElement('span');
        label.className = 'field-label';
        label.innerHTML = 'Protocol <span class="required">*</span>';
        group.appendChild(label);

        const select = document.createElement('select');
        select.className = 'protocol-select';

        PROTOCOLS.forEach(proto => {
            const option = document.createElement('option');
            option.value = proto;
            option.textContent = proto;
            option.selected = (rule.protocol || 'TCP').toUpperCase() === proto;
            select.appendChild(option);
        });

        select.addEventListener('change', () => {
            rule.protocol = select.value;
            markChanged();
        });

        group.appendChild(select);
        return group;
    }

    function createActionSelect(rule) {
        const group = document.createElement('div');
        group.className = 'action-group';

        const label = document.createElement('span');
        label.className = 'field-label';
        label.textContent = 'Action';
        group.appendChild(label);

        const select = document.createElement('select');
        select.className = 'action-select';

        ACTIONS.forEach(a => {
            const option = document.createElement('option');
            option.value = a.value;
            option.textContent = a.label;
            option.selected = (rule.action || 'allow') === a.value;
            select.appendChild(option);
        });

        select.addEventListener('change', () => {
            rule.action = select.value;
            markChanged();
        });

        group.appendChild(select);
        return group;
    }

    function createInterfaceSelect(rule) {
        const group = document.createElement('div');
        group.className = 'interface-group';

        const label = document.createElement('span');
        label.className = 'field-label';
        label.textContent = 'Interface';
        group.appendChild(label);

        const select = document.createElement('select');
        select.className = 'interface-select';

        const anyOpt = document.createElement('option');
        anyOpt.value = '';
        anyOpt.textContent = 'Any';
        select.appendChild(anyOpt);

        const ifaceNames = (state.interfaces || [])
            .map(i => i.name)
            .filter(Boolean);
        ifaceNames.forEach(name => {
            const opt = document.createElement('option');
            opt.value = name;
            opt.textContent = name;
            opt.selected = (rule.interface || '') === name;
            select.appendChild(opt);
        });

        select.addEventListener('change', () => {
            rule.interface = select.value;
            markChanged();
        });

        group.appendChild(select);
        return group;
    }

    function createPortInputs(rule) {
        const group = document.createElement('div');
        group.className = 'port-group';

        // Port field
        const portField = document.createElement('div');
        portField.className = 'port-field';

        const portLabel = document.createElement('span');
        portLabel.className = 'field-label';
        portLabel.innerHTML = 'Start port <span class="required">*</span>';
        portField.appendChild(portLabel);

        const portInput = document.createElement('input');
        portInput.type = 'text';
        portInput.className = 'port-input';
        portInput.placeholder = 'Start *';
        portInput.value = rule.port || '';
        portInput.addEventListener('input', () => {
            const value = portInput.value;
            const portNum = parseInt(value, 10);
            const isValid = value === '' || (Number.isInteger(portNum) && portNum >= 0 && portNum <= 65535);
            portInput.classList.toggle('error', !isValid && value !== '');
            if (isValid || value === '') {
                rule.port = value;
                markChanged();
            } else {
                portInput.value = rule.port || '';
            }
            portInput.classList.toggle('error', !portInput.value && rule._isNew);
        });
        portField.appendChild(portInput);
        group.appendChild(portField);

        // Clear button
        const clearBtn = document.createElement('button');
        clearBtn.className = 'port-clear';
        clearBtn.innerHTML = '×';
        clearBtn.title = 'Clear port';
        clearBtn.addEventListener('click', () => {
            portInput.value = '';
            rule.port = '';
            markChanged();
        });
        group.appendChild(clearBtn);

        // Separator
        const sep = document.createElement('span');
        sep.className = 'port-separator';
        sep.textContent = '–';
        group.appendChild(sep);

        // Port range field
        const rangeField = document.createElement('div');
        rangeField.className = 'port-field';

        const rangeLabel = document.createElement('span');
        rangeLabel.className = 'field-label';
        rangeLabel.textContent = 'End port';
        rangeField.appendChild(rangeLabel);

        const rangeInput = document.createElement('input');
        rangeInput.type = 'text';
        rangeInput.className = 'port-input';
        rangeInput.placeholder = 'End';
        rangeInput.value = rule.port_range || '';
        rangeInput.addEventListener('input', () => {
            const value = rangeInput.value;
            if (value === '') {
                rule.port_range = '';
                markChanged();
                return;
            }
            const endPort = parseInt(value.trim(), 10);
            const isValid = Number.isInteger(endPort) && endPort >= 0 && endPort <= 65535;
            if (!isValid) {
                rangeInput.value = rule.port_range || '';
                rangeInput.classList.toggle('error', true);
                return;
            }

            if (rule.port) {
                const startPort = parseInt(rule.port.trim(), 10);
                if (!isNaN(startPort) && endPort < startPort) {
                    showToast('End port must be greater than or equal to start port', 'error');
                    rangeInput.value = rule.port_range || '';
                    rangeInput.classList.add('error');
                    return;
                }
            }

            rule.port_range = String(endPort);
            rangeInput.classList.toggle('error', false);
            markChanged();
        });
        rangeField.appendChild(rangeInput);
        group.appendChild(rangeField);

        return group;
    }

    // ─── Drag & Drop ────────────────────────────────────────────
    let draggedRuleId = null;

    function setupDragEvents(card, rule) {
        card.addEventListener('dragstart', (e) => {
            draggedRuleId = rule.id;
            card.classList.add('dragging');
            e.dataTransfer.effectAllowed = 'move';
            e.dataTransfer.setData('text/plain', rule.id);
        });

        card.addEventListener('dragend', () => {
            card.classList.remove('dragging');
            document.querySelectorAll('.drag-over').forEach(c => c.classList.remove('drag-over'));
            draggedRuleId = null;
        });

        card.addEventListener('dragover', (e) => {
            e.preventDefault();
            e.dataTransfer.dropEffect = 'move';
            if (rule.id !== draggedRuleId) {
                card.classList.add('drag-over');
            }
        });

        card.addEventListener('dragleave', () => {
            card.classList.remove('drag-over');
        });

        card.addEventListener('drop', (e) => {
            e.preventDefault();
            card.classList.remove('drag-over');

            if (!draggedRuleId || draggedRuleId === rule.id) return;

            const fromIdx = state.rules.findIndex(r => r.id === draggedRuleId);
            const toIdx = state.rules.findIndex(r => r.id === rule.id);

            if (fromIdx === -1 || toIdx === -1) return;

            // Only allow reorder within same direction
            if (state.rules[fromIdx].direction !== state.rules[toIdx].direction) {
                showToast('Cannot move rules between inbound and outbound', 'error');
                return;
            }

            const [moved] = state.rules.splice(fromIdx, 1);
            state.rules.splice(toIdx, 0, moved);

            markChanged();
            renderRules();
        });
    }

    // ─── Rule Actions ───────────────────────────────────────────
    function addNewRule(direction) {
        const newRule = {
            id: 'new-' + Date.now(),
            description: '',
            ips: ['Any IPv4', 'Any IPv6'],
            protocol: 'TCP',
            port: '',
            port_range: '',
            direction: direction,
            action: 'allow',
            interface: '',
            order: state.rules.length + 1,
            _isNew: true,
        };

        state.rules.push(newRule);
        markChanged();
        renderRules();

        // Scroll to new rule and focus port input
        requestAnimationFrame(() => {
            const card = document.querySelector(`[data-rule-id="${newRule.id}"]`);
            if (card) {
                card.scrollIntoView({ behavior: 'smooth', block: 'center' });
                const portInput = card.querySelector('.port-input');
                if (portInput) portInput.focus();
            }
        });
    }

    let pendingDeleteRuleId = null;

    function showConfirmDialog(message, onConfirm) {
        const modal = document.getElementById('confirm-dialog');
        const msgEl = modal.querySelector('.modal-message');
        const confirmBtn = document.getElementById('confirm-delete');
        const cancelBtn = document.getElementById('confirm-cancel');
        const backdrop = modal.querySelector('.modal-backdrop');

        msgEl.textContent = message;
        modal.classList.add('visible');

        const cleanup = () => {
            modal.classList.remove('visible');
            confirmBtn.removeEventListener('click', handleConfirm);
            cancelBtn.removeEventListener('click', handleCancel);
            backdrop.removeEventListener('click', handleCancel);
        };

        const handleConfirm = () => {
            cleanup();
            onConfirm();
        };

        const handleCancel = () => {
            cleanup();
            document.removeEventListener('keydown', handleEsc);
        };

        const handleEsc = (e) => {
            if (e.key === 'Escape') {
                handleCancel();
            }
        };

        confirmBtn.addEventListener('click', handleConfirm);
        cancelBtn.addEventListener('click', handleCancel);
        backdrop.addEventListener('click', handleCancel);
        document.addEventListener('keydown', handleEsc);
    }

    function deleteRule(ruleId) {
        const rule = state.rules.find(r => r.id === ruleId);
        const message = rule?.description
            ? `Are you sure you want to delete the rule "${rule.description}"? This action cannot be undone.`
            : 'Are you sure you want to delete this rule? This action cannot be undone.';

        showConfirmDialog(message, () => {
            state.rules = state.rules.filter(r => r.id !== ruleId);
            markChanged();
            renderRules();
        });
    }

    // ─── Change Tracking ────────────────────────────────────────
    function markChanged() {
        state.hasChanges = true;
        updateSaveBar();
    }

    function updateSaveBar() {
        const saveBar = document.getElementById('save-bar');
        saveBar.classList.toggle('visible', state.hasChanges);
    }

    // ─── Save / Cancel ──────────────────────────────────────────
    async function saveRules() {
        if (state.saving) return;

        // Validate
        const emptyPort = state.rules.find(r => !r.port && r.port !== 'any');
        if (emptyPort) {
            showToast('All rules must have a port specified', 'error');
            const card = document.querySelector(`[data-rule-id="${emptyPort.id}"]`);
            if (card) {
                card.scrollIntoView({ behavior: 'smooth', block: 'center' });
                const portInput = card.querySelector('.port-input');
                if (portInput) {
                    portInput.classList.add('error');
                    portInput.focus();
                }
            }
            return;
        }

        // Validate IP addresses
        for (const rule of state.rules) {
            if (rule.ips && rule.ips.length > 0) {
                for (const ip of rule.ips) {
                    if (!isValidIP(ip)) {
                        showToast(`Invalid IP address: ${ip}`, 'error');
                        return;
                    }
                }
            }
        }

        // Validate port vs end port
        for (const rule of state.rules) {
            if (rule.port && rule.port_range) {
                const port = parseInt(rule.port, 10);
                const endPort = parseInt(rule.port_range, 10);
                if (!Number.isInteger(endPort) || endPort < 0 || endPort > 65535) {
                    showToast(`Invalid end port: ${rule.port_range}`, 'error');
                    return;
                }
                if (!isNaN(port) && endPort < port) {
                    showToast(`End port (${rule.port_range}) cannot be less than start port (${rule.port})`, 'error');
                    const card = document.querySelector(`[data-rule-id="${rule.id}"]`);
                    if (card) {
                        card.scrollIntoView({ behavior: 'smooth', block: 'center' });
                        const rangeInput = card.querySelector('.port-input:last-of-type');
                        if (rangeInput) {
                            rangeInput.classList.add('error');
                            rangeInput.focus();
                        }
                    }
                    return;
                }
            }
        }

        state.saving = true;
        const saveBtn = document.getElementById('save-btn');
        saveBtn.textContent = 'Saving...';
        saveBtn.disabled = true;

        try {
            // Clean up _isNew flags before sending
            const cleanRules = state.rules.map(r => {
                const { _isNew, ...clean } = r;
                return clean;
            });

            await api('/api/rules/save', {
                method: 'POST',
                body: JSON.stringify({ rules: cleanRules }),
            });

            showToast('Firewall rules saved successfully!', 'success');
            state.hasChanges = false;
            state.rules.forEach(r => delete r._isNew);
            state.originalRules = JSON.parse(JSON.stringify(state.rules));
            updateSaveBar();
            renderRules();

            // Reload to verify
            setTimeout(() => loadData(), 1000);
        } catch (e) {
            showToast('Failed to save rules: ' + e.message, 'error');
        } finally {
            state.saving = false;
            saveBtn.textContent = 'Save changes';
            saveBtn.disabled = false;
        }
    }

    function cancelChanges() {
        state.rules = JSON.parse(JSON.stringify(state.originalRules));
        state.hasChanges = false;
        updateSaveBar();
        renderRules();
        showToast('Changes discarded', 'info');
    }

    // ─── Render Interfaces ──────────────────────────────────────
    function renderInterfaces() {
        const container = document.getElementById('interfaces-list');
        container.innerHTML = '';

        if (!state.interfaces || state.interfaces.length === 0) {
            container.innerHTML = '<p style="color: var(--text-muted); padding: 40px; text-align: center;">No network interfaces detected</p>';
            return;
        }

        state.interfaces.forEach(iface => {
            const card = document.createElement('div');
            card.className = 'interface-card';

            card.innerHTML = `
                <div class="interface-info">
                    <div class="interface-icon">
                        <svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M5 12.55a11 11 0 0114.08 0M1.42 9a16 16 0 0121.16 0M8.53 16.11a6 6 0 016.95 0M12 20h.01"/>
                        </svg>
                    </div>
                    <div class="interface-details">
                        <span class="interface-name">${escapeHTML(iface.name)}</span>
                        <span class="interface-addr">${escapeHTML(iface.addr || 'No address')}</span>
                    </div>
                </div>
                <span class="interface-status ${iface.status === 'up' ? 'up' : 'down'}">
                    <span class="status-dot"></span>
                    ${escapeHTML(iface.status || 'unknown')}
                </span>
            `;

            container.appendChild(card);
        });
    }

    // ─── Toast Notifications ────────────────────────────────────
    function showToast(message, type = 'info') {
        const container = document.getElementById('toast-container');
        const toast = document.createElement('div');
        toast.className = `toast ${type}`;

        const icons = {
            success: '<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="var(--success)" stroke-width="2"><path d="M22 11.08V12a10 10 0 11-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>',
            error: '<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="var(--danger)" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>',
            info: '<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="var(--accent-primary)" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>',
        };

        toast.innerHTML = `${icons[type] || icons.info}<span>${escapeHTML(message)}</span>`;
        container.appendChild(toast);

        setTimeout(() => {
            toast.style.animation = 'toastOut 0.3s ease-out forwards';
            setTimeout(() => toast.remove(), 300);
        }, 4000);
    }

    // ─── Utility ────────────────────────────────────────────────
    function escapeHTML(str) {
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }

})();
