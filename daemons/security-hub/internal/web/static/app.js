let currentTab = 'docker';
let currentNodeFilter = 'all';
let dashboardData = null;
let pendingUpdateReq = null;
let activeEventSource = null;
let activeScanEventSource = null;
let activeScanningNodes = new Set();
let scanPollTimer = null;
let failedStreamTaskIds = new Set();
let csrfToken = '';

function clearScanPollTimer() {
  if (scanPollTimer) {
    clearTimeout(scanPollTimer);
    scanPollTimer = null;
  }
}

function scheduleScanPoll(delayMs = 2000) {
  clearScanPollTimer();
  scanPollTimer = setTimeout(() => {
    scanPollTimer = null;
    loadDashboard();
  }, delayMs);
}

function isStreamableScanTaskId(taskId) {
  if (!taskId) return false;
  const id = String(taskId);
  if (id.startsWith('scan_') || id.startsWith('task_')) return false;
  return !failedStreamTaskIds.has(id);
}

function isNodeScanning(nodeName) {
  const target = String(nodeName || '').trim().toLowerCase();
  if (!target) return false;
  for (const n of activeScanningNodes) {
    if (String(n).trim().toLowerCase() === target) return true;
  }
  return false;
}

function removeActiveScanningNode(nodeName) {
  const target = String(nodeName || '').trim().toLowerCase();
  if (!target) return false;
  let removed = false;
  for (const n of Array.from(activeScanningNodes)) {
    if (String(n).trim().toLowerCase() === target) {
      activeScanningNodes.delete(n);
      removed = true;
    }
  }
  return removed;
}

function updateScanButtons(isScanning) {
  const btnScanNow = document.getElementById('btn-scan-now');
  const btnScanNode = document.getElementById('btn-scan-node');
  const btnConfirmNode = document.getElementById('btn-confirm-scan-node');
  const progressBox = document.getElementById('scan-progress-box');
  if (btnScanNow) {
    btnScanNow.disabled = isScanning;
    btnScanNow.textContent = isScanning ? '⟳ Scanning...' : '↻ Scan Now';
  }
  if (btnScanNode) {
    btnScanNode.disabled = isScanning;
  }
  if (btnConfirmNode) {
    const nodes = (dashboardData && dashboardData.nodes) || [{name: (dashboardData && dashboardData.hub_node) || 'local', role: 'hub', online: true}];
    const hasApproved = nodes.some(n => !n.status || n.status === 'approved');
    btnConfirmNode.disabled = isScanning || !hasApproved;
  }
  if (!isScanning) {
    if (progressBox) progressBox.style.display = 'none';
    const progressText = document.getElementById('scan-progress-text');
    if (progressText) progressText.textContent = '';
  }
}

function resetSessionClientState() {
  csrfToken = '';
  clearScanPollTimer();
  failedStreamTaskIds.clear();
  activeScanningNodes.clear();
  if (activeEventSource) {
    activeEventSource.close();
    activeEventSource = null;
  }
  if (activeScanEventSource) {
    activeScanEventSource.close();
    activeScanEventSource = null;
  }
  updateScanButtons(false);
  closeScanNodeModal();
  closeUpdateModal();
  closeNodesModal();
  closeBrokenLinkageModal();
  closeUserDropdown();
}

function getCsrfToken() {
  const m = document.cookie.match(/(?:^|;\s*)nal_csrf_token=([^;]+)/);
  if (m) return decodeURIComponent(m[1]);
  return csrfToken || '';
}

function apiFetch(url, options = {}) {
  const opts = {...options};
  const method = String(opts.method || 'GET').toUpperCase();
  if (method !== 'GET' && method !== 'HEAD' && method !== 'OPTIONS') {
    const tok = getCsrfToken();
    if (tok) {
      opts.headers = {...(opts.headers || {}), 'X-CSRF-Token': tok};
    }
  }
  return fetch(url, opts);
}

async function initApp() {
  const res = await fetch('/api/auth/session');
  const session = await res.json();
  if (!session.authenticated) {
    resetSessionClientState();
    document.getElementById('view-login').style.display = 'block';
    document.getElementById('view-dashboard').style.display = 'none';
    document.getElementById('header-actions').style.display = 'none';
    return;
  }
  csrfToken = session.csrf_token || getCsrfToken();
  document.getElementById('view-login').style.display = 'none';
  document.getElementById('view-dashboard').style.display = 'block';
  document.getElementById('header-actions').style.display = 'flex';

  const username = session.username || (session.subject ? session.subject.split('@')[0] : 'admin');
  const userBtn = document.getElementById('auth-username');
  if (userBtn) userBtn.textContent = username;
  const userDetail = document.getElementById('auth-user-detail');
  if (userDetail) userDetail.textContent = `${username} (${(session.method || 'sso').toUpperCase()})`;

  await loadDashboard();
}

function toggleUserDropdown(e) {
  if (e) e.stopPropagation();
  const menu = document.getElementById('user-menu');
  if (!menu) return;
  const isShown = menu.style.display === 'flex';
  menu.style.display = isShown ? 'none' : 'flex';
}

function closeUserDropdown() {
  const menu = document.getElementById('user-menu');
  if (menu) menu.style.display = 'none';
}

function openBrokenLinkageModal(pkgName, details) {
  const pkgEl = document.getElementById('modal-linkage-pkg');
  if (pkgEl) pkgEl.textContent = pkgName;
  const bodyEl = document.getElementById('modal-linkage-body');
  if (bodyEl) bodyEl.textContent = details || 'Missing shared library dependency';
  const modal = document.getElementById('modal-linkage');
  if (modal) modal.style.display = 'flex';
}

function closeBrokenLinkageModal() {
  const modal = document.getElementById('modal-linkage');
  if (modal) modal.style.display = 'none';
}

function openBrokenLinkageModalByIndex(idx) {
  const item = (window.currentRenderedItems || [])[idx];
  if (!item) return;
  openBrokenLinkageModal(item.name, item.linkage_details || 'Missing shared library dependency');
}

async function loadDashboard() {
  const res = await fetch('/api/dashboard');
  if (res.status === 401) {
    return initApp();
  }
  dashboardData = await res.json();
  if (dashboardData.scanning && Array.isArray(dashboardData.scanning_nodes)) {
    activeScanningNodes = new Set(dashboardData.scanning_nodes);
    updateScanButtons(true);
    const activeId = dashboardData.active_scan_task_id;
    if (!activeScanEventSource) {
      if (activeId && isStreamableScanTaskId(activeId)) {
        attachScanStream(activeId);
      } else {
        const progressBox = document.getElementById('scan-progress-box');
        const progressText = document.getElementById('scan-progress-text');
        if (progressBox) progressBox.style.display = 'inline-flex';
        if (progressText && !progressText.textContent) progressText.textContent = 'Scanning in progress...';
        scheduleScanPoll(2000);
      }
    }
  } else if (!activeScanEventSource) {
    clearScanPollTimer();
    activeScanningNodes.clear();
    updateScanButtons(false);
  }
  renderPendingNodesBanner();
  renderNodeBar();
  renderSummary();
  renderItemsTable();
  renderTaskList();
  const scanModal = document.getElementById('modal-scan-node');
  if (scanModal && scanModal.style.display === 'flex') {
    renderScanNodeModalList();
  }
}

function renderPendingNodesBanner() {
  const bannerContainer = document.getElementById('pending-nodes-container');
  const bannerCount = document.getElementById('pending-nodes-count');
  if (!bannerContainer) return;
  const nodes = (dashboardData && dashboardData.nodes) || [];
  const pending = nodes.filter(n => n.status === 'pending');
  if (pending.length > 0) {
    bannerContainer.style.display = 'inline-flex';
    if (bannerCount) bannerCount.textContent = pending.length;
  } else {
    bannerContainer.style.display = 'none';
  }
}

function getFilteredItems() {
  const all = (dashboardData && dashboardData.scan && dashboardData.scan.items) || [];
  if (currentNodeFilter === 'all') return all;
  return all.filter(i => (i.node || dashboardData.hub_node || 'local') === currentNodeFilter);
}

function selectNodeFilter(nodeName) {
  if (nodeName && nodeName !== 'all') {
    nodeName = decodeURIComponent(nodeName);
  }
  currentNodeFilter = nodeName;
  renderNodeBar();
  renderSummary();
  renderItemsTable();
  renderTaskList();
}

function encodeNodeArg(name) {
  return encodeURIComponent(name || '').replace(/'/g, '%27');
}

function renderNodeBar() {
  const container = document.getElementById('node-pills-container');
  if (!container) return;
  const nodes = (dashboardData && dashboardData.nodes) || [{name: (dashboardData && dashboardData.hub_node) || 'local', role: 'hub', online: true}];
  const approvedNodes = nodes.filter(n => !n.status || n.status === 'approved');
  const isAllScanning = approvedNodes.length > 0 && approvedNodes.every(n => isNodeScanning(n.name));
  let html = `<button class="node-pill ${currentNodeFilter === 'all' ? 'active' : ''} ${isAllScanning ? 'scanning' : ''}" onclick='selectNodeFilter("all")'>
    <span>All Nodes (${approvedNodes.length})</span>
    ${isAllScanning ? '<span class="node-scan-status">⟳ Scanning</span>' : ''}
  </button>`;
  approvedNodes.forEach(n => {
    const scanning = isNodeScanning(n.name);
    const dot = scanning ? 'scanning' : (n.online ? 'green' : 'amber');
    const roleTag = n.role === 'hub' ? 'Hub' : 'Agent';
    const title = scanning ? 'Scanning in progress...' : (n.last_error ? `Offline: ${n.last_error}` : (n.url || 'Local Host'));
    html += `
      <button class="node-pill ${currentNodeFilter === n.name ? 'active' : ''} ${scanning ? 'scanning' : ''}" title="${escapeHtml(title)}" onclick='selectNodeFilter("${encodeNodeArg(n.name)}")'>
        <span class="dot ${dot}"></span>
        <span>${escapeHtml(n.name)}</span>
        <span class="node-role">${roleTag}</span>
        ${scanning ? '<span class="node-scan-status">⟳ Scanning</span>' : ''}
      </button>
    `;
  });
  container.innerHTML = html;
}

function renderSummary() {
  const scan = dashboardData.scan || {};
  const tasks = dashboardData.recent_tasks || [];
  const items = getFilteredItems();

  let crit = 0, high = 0, eol = 0, outdated = 0, skipped = 0, broken = 0;
  items.forEach(it => {
    crit += (it.crit_count || 0);
    high += (it.high_count || 0);
    if (it.eol && (it.eol.status === 'expired' || it.eol.status === 'expiring_soon')) eol++;
    if (it.outdated) outdated++;
    if (it.skipped) skipped++;
    if (it.broken_linkage) broken++;
  });

  document.getElementById('stat-cves').textContent = `${crit} Critical / ${high} High`;
  document.getElementById('stat-eol').textContent = `${eol} Expiring/EoL`;
  document.getElementById('stat-outdated').textContent = `${outdated} Updates`;
  document.getElementById('stat-outdated-sub').textContent = `${skipped} Skipped · ${broken} Broken Linkage`;
  document.getElementById('stat-tasks').textContent = `${tasks.length} Runs`;
  const hasScanTime = scan.scanned_at && !String(scan.scanned_at).startsWith('0001-');
  document.getElementById('stat-last-scan').textContent = hasScanTime ? `Last scan: ${new Date(scan.scanned_at).toLocaleString()}` : 'Last scan: Not yet run';

  document.getElementById('badge-docker').textContent = items.filter(i => i.target_type === 'docker').length;
  document.getElementById('badge-brew').textContent = items.filter(i => i.target_type === 'brew' || i.target_type === 'apt').length;
  document.getElementById('badge-daemons').textContent = items.filter(i => i.target_type === 'daemon' || i.target_type === 'macos').length;
  document.getElementById('badge-logs').textContent = tasks.length;
}

function switchTab(tab) {
  currentTab = tab;
  ['docker', 'brew', 'daemons', 'logs'].forEach(t => {
    document.getElementById('tab-btn-' + t).classList.toggle('active', t === tab);
  });
  if (tab === 'logs') {
    document.getElementById('panel-items').style.display = 'none';
    document.getElementById('panel-logs').style.display = 'block';
    renderTaskList();
  } else {
    document.getElementById('panel-items').style.display = 'block';
    document.getElementById('panel-logs').style.display = 'none';
    renderItemsTable();
  }
}

function getItemSortRank(item) {
  // 1. Critical: crit_count > 0, broken_linkage, or eol expired
  if (item.crit_count > 0 || item.broken_linkage || (item.eol && item.eol.status === 'expired')) {
    return 0;
  }
  // 2. High: high_count > 0, or eol expiring soon
  if (item.high_count > 0 || (item.eol && item.eol.status === 'expiring_soon')) {
    return 1;
  }
  // 3. Update available: outdated
  if (item.outdated) {
    return 2;
  }
  // 4. Normal: everything else
  return 3;
}

function renderItemsTable() {
  const tbody = document.getElementById('items-tbody');
  tbody.innerHTML = '';
  const items = getFilteredItems().filter(item => {
    if (currentTab === 'docker') return item.target_type === 'docker';
    if (currentTab === 'brew') return item.target_type === 'brew' || item.target_type === 'apt';
    return item.target_type === 'daemon' || item.target_type === 'macos';
  });

  if (items.length === 0) {
    tbody.innerHTML = `<tr><td colspan="6" class="muted" style="text-align:center; padding:28px;">No components on this node/tab (uninstalled or stopped components are ignored automatically). Click <strong>↻ Scan Now</strong> to refresh.</td></tr>`;
    return;
  }

  // Sort list: 1. critical / high / update available / normal, 2. name order (ascending)
  items.sort((a, b) => {
    const rankA = getItemSortRank(a);
    const rankB = getItemSortRank(b);
    if (rankA !== rankB) {
      return rankA - rankB;
    }
    return (a.name || '').localeCompare(b.name || '', undefined, { sensitivity: 'base' });
  });

  window.currentRenderedItems = items;

  items.forEach((item, idx) => {
    const nodeName = item.node || (dashboardData && dashboardData.hub_node) || 'local';
    const tr = document.createElement('tr');
    const dotClass = (item.crit_count > 0 || item.broken_linkage || item.eol?.status === 'expired') ? 'red'
      : (item.high_count > 0 || item.eol?.status === 'expiring_soon' || item.outdated) ? 'amber' : 'green';

    let secHtml = `<span class="badge ok">✓ 0 CVEs</span>`;
    if (item.broken_linkage && (item.crit_count > 0 || item.high_count > 0)) {
      secHtml = `
        <div style="display:flex; flex-direction:column; gap:4px; align-items:flex-start;">
          <button class="badge crit badge-btn" onclick='openBrokenLinkageModalByIndex(${idx})'>⚠ Broken Linkage (Details)</button>
          <span class="badge crit">● ${item.crit_count} Crit / ${item.high_count} High</span>
        </div>
      `;
    } else if (item.broken_linkage) {
      secHtml = `<button class="badge crit badge-btn" onclick='openBrokenLinkageModalByIndex(${idx})' title="Click to view broken linkage details">⚠ Broken Linkage (Details)</button>`;
    } else if (item.crit_count > 0 || item.high_count > 0) {
      const firstId = item.vulnerabilities?.[0]?.id || 'CVE';
      secHtml = `<span class="badge crit">● ${item.crit_count} Crit / ${item.high_count} High (${escapeHtml(firstId)})</span>`;
    }

    let eolHtml = `<span class="badge ok">Supported</span>`;
    if (item.eol) {
      if (item.eol.status === 'expired') {
        const tooltipText = item.eol.message || (item.eol.eol_date ? `End of Life reached on ${item.eol.eol_date}` : 'End of Life reached');
        eolHtml = `
          <div class="tooltip-wrapper">
            <span class="badge crit">✖ EoL Expired</span>
            <div class="tooltip-box">${escapeHtml(tooltipText)}</div>
          </div>
        `;
      } else if (item.eol.status === 'expiring_soon') {
        const tooltipText = item.eol.message || `End of Life scheduled in ${item.eol.days_remaining}d (${item.eol.eol_date || 'soon'})`;
        eolHtml = `
          <div class="tooltip-wrapper">
            <span class="badge warn">⚠ EoL in ${item.eol.days_remaining}d</span>
            <div class="tooltip-box">${escapeHtml(tooltipText)}</div>
          </div>
        `;
      } else if (item.eol.status === 'unknown') {
        const tooltipText = item.eol.message || 'Lifecycle track not mapped';
        eolHtml = `
          <div class="tooltip-wrapper">
            <span class="badge skip">Not Tracked</span>
            <div class="tooltip-box">${escapeHtml(tooltipText)}</div>
          </div>
        `;
      } else if (item.eol.eol_date) {
        eolHtml = `
          <div class="tooltip-wrapper">
            <span class="badge ok">Supported</span>
            <div class="tooltip-box">Supported until ${escapeHtml(item.eol.eol_date)}</div>
          </div>
        `;
      }
    }

    const tags = (item.available_tags && item.available_tags.length > 0) ? item.available_tags : [item.latest_version || item.current_version];
    const selectId = `ver-select-${idx}`;
    const optionsHtml = tags.map(t => `<option value="${escapeHtml(t)}" ${t === item.latest_version ? 'selected' : ''}>${escapeHtml(t)}</option>`).join('');

    let actionsHtml = '';
    if (item.target_type === 'docker' || item.target_type === 'brew' || item.target_type === 'apt' || (item.target_type === 'daemon' && item.name === 'ollama')) {
      const btnClass = (item.crit_count > 0 || item.broken_linkage) ? 'btn-danger' : 'btn-primary';
      const btnLabel = item.broken_linkage ? 'Upgrade & Fix' : 'Update';
      actionsHtml += `<button class="btn ${btnClass}" onclick='openUpdateModalByIndex(${idx}, "${selectId}")'>${btnLabel}</button>`;
      if (item.skipped) {
        actionsHtml += `<span class="badge skip">Skipped ${escapeHtml(item.skipped_version)}</span>`;
        actionsHtml += `<button class="btn btn-ghost" onclick='unskipItem("${encodeNodeArg(nodeName)}", "${encodeNodeArg(item.target_type)}", "${encodeNodeArg(item.name)}")'>Unskip</button>`;
      } else if (item.outdated) {
        actionsHtml += `<button class="btn btn-ghost" onclick='skipItem("${encodeNodeArg(nodeName)}", "${encodeNodeArg(item.target_type)}", "${encodeNodeArg(item.name)}", "${selectId}")'>Skip</button>`;
      }
      if (item.has_rollback) {
        actionsHtml += `<button class="btn btn-ghost" onclick='rollbackService("${encodeNodeArg(nodeName)}", "${encodeNodeArg(item.name)}")'>Rollback (${escapeHtml(item.rollback_version)})</button>`;
      }
    }
    if (item.release_notes_url && isSafeHttpUrl(item.release_notes_url)) {
      actionsHtml += `<a class="btn btn-ghost" href="${escapeHtml(item.release_notes_url)}" target="_blank" rel="noopener noreferrer" style="text-decoration:none;">Notes ↗</a>`;
    }

    const subType = (item.target_type === 'brew' || item.target_type === 'apt') ? item.target_type : (item.image_ref || item.target_type);

    tr.innerHTML = `
      <td>
        <div class="svc-col">
          <div class="svc-tags">
            <span class="badge-node">${escapeHtml(nodeName)}</span>
            ${item.critical_path ? '<span class="badge warn" style="font-size:10px; padding:1px 6px;">Critical Path</span>' : ''}
          </div>
          <div class="svc-name-title">
            <span class="dot ${dotClass}"></span>
            <span>${escapeHtml(item.name)}</span>
          </div>
          <div class="svc-sub">${escapeHtml(subType)}</div>
        </div>
      </td>
      <td>
        <div>${escapeHtml(item.current_version)}</div>
        <div class="svc-sub">${escapeHtml((item.current_digest || '').slice(0, 19))}</div>
      </td>
      <td>${secHtml}</td>
      <td>${eolHtml}</td>
      <td><select id="${selectId}" class="ver-select">${optionsHtml}</select></td>
      <td><div class="actions">${actionsHtml}</div></td>
    `;
    tbody.appendChild(tr);
  });
}

function openUpdateModalByIndex(idx, selectId) {
  const item = (window.currentRenderedItems || [])[idx];
  if (!item) return;
  openUpdateModal(item, selectId);
}

function openUpdateModal(item, selectId) {
  const sel = document.getElementById(selectId);
  const targetVer = sel ? sel.value : item.latest_version;
  const nodeName = item.node || (dashboardData && dashboardData.hub_node) || 'local';
  const isDocker = item.target_type === 'docker';
  pendingUpdateReq = {
    node: nodeName,
    target_type: item.target_type,
    target_name: item.name,
    target_version: targetVer,
    broken_linkage: !!item.broken_linkage,
    stateful: !!item.stateful
  };
  document.getElementById('modal-title').textContent = `Confirm Update on [${nodeName}]: ${item.name}`;
  document.getElementById('modal-desc').textContent = `Updating ${item.name} on ${nodeName} from ${item.current_version} → ${targetVer}`;
  document.getElementById('chk-backup').checked = !!item.stateful;
  document.getElementById('lbl-backup').style.display = isDocker ? 'flex' : 'none';
  const chkSnapshot = document.getElementById('chk-snapshot');
  if (chkSnapshot) chkSnapshot.checked = true;
  const chkDeadman = document.getElementById('chk-deadman');
  if (chkDeadman) chkDeadman.checked = true;
  const critBadge = document.getElementById('modal-crit-badge');
  if (critBadge) critBadge.style.display = isDocker ? 'inline-flex' : 'none';
  const lblSnapshot = document.getElementById('lbl-snapshot');
  if (lblSnapshot) lblSnapshot.style.display = isDocker ? 'flex' : 'none';
  const lblDeadman = document.getElementById('lbl-deadman');
  if (lblDeadman) lblDeadman.style.display = isDocker ? 'flex' : 'none';
  const confirmBtn = document.getElementById('btn-confirm-update');
  if (confirmBtn) confirmBtn.textContent = isDocker ? 'Pull & Apply Update' : 'Apply Package Upgrade';
  document.getElementById('modal-update').style.display = 'flex';
}

function closeUpdateModal() {
  pendingUpdateReq = null;
  document.getElementById('modal-update').style.display = 'none';
}

async function confirmAndStartUpdate() {
  if (!pendingUpdateReq) return;
  const reqBody = {
    ...pendingUpdateReq,
    run_backup: document.getElementById('chk-backup').checked,
    enable_dead_man: document.getElementById('chk-deadman').checked
  };
  closeUpdateModal();
  const res = await apiFetch('/api/update', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(reqBody)
  });
  if (!res.ok) {
    const errData = await res.json().catch(() => ({}));
    alert(`Update failed: ${errData.error || res.statusText}`);
    return;
  }
  const task = await res.json();
  await loadDashboard();
  switchTab('logs');
  if (task && task.id) {
    streamTaskLogs(task.id);
  }
}

async function rollbackService(encodedNodeName, encodedServiceName) {
  const nodeName = decodeURIComponent(encodedNodeName || '');
  const serviceName = decodeURIComponent(encodedServiceName || '');
  if (!confirm(`Roll back ${serviceName} on ${nodeName} to its previous snapshot version and digest?`)) return;
  const res = await apiFetch('/api/rollback', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({node: nodeName, service_name: serviceName})
  });
  if (!res.ok) {
    const errData = await res.json().catch(() => ({}));
    alert(`Rollback failed: ${errData.error || res.statusText}`);
    return;
  }
  const task = await res.json();
  await loadDashboard();
  switchTab('logs');
  if (task && task.id) streamTaskLogs(task.id);
}

function openNodesModal() {
  const resBox = document.getElementById('test-node-result');
  if (resBox) {
    resBox.style.display = 'none';
    resBox.innerHTML = '';
  }
  renderNodesModalList();
  document.getElementById('modal-nodes').style.display = 'flex';
}

function closeNodesModal() {
  const resBox = document.getElementById('test-node-result');
  if (resBox) {
    resBox.style.display = 'none';
    resBox.innerHTML = '';
  }
  document.getElementById('modal-nodes').style.display = 'none';
}

function renderNodesModalList() {
  const box = document.getElementById('nodes-modal-list');
  const pendingSection = document.getElementById('pending-nodes-section');
  const pendingBox = document.getElementById('pending-nodes-list');
  const nodes = (dashboardData && dashboardData.nodes) || [];

  const pendingNodes = nodes.filter(n => n.status === 'pending');
  if (pendingSection && pendingBox) {
    if (pendingNodes.length > 0) {
      pendingSection.style.display = 'block';
      const countEl = document.getElementById('modal-pending-count');
      if (countEl) countEl.textContent = pendingNodes.length;
      pendingBox.innerHTML = pendingNodes.map(n => `
        <div style="display:flex; justify-content:space-between; align-items:center; padding:8px 0; border-bottom:1px solid var(--border);">
          <div>
            <div style="display:flex; align-items:center; gap:6px;">
              <span class="dot amber"></span>
              <strong>${escapeHtml(n.name)}</strong>
              <span class="badge warn" style="font-size:10px; padding:1px 6px;">PENDING</span>
              ${n.os_version ? `<span class="badge skip" style="font-size:10px; padding:1px 6px;">${escapeHtml(n.os_version)}</span>` : ''}
            </div>
            <div class="svc-sub" style="margin-top:2px;">${escapeHtml(n.url || 'LAN Node')}</div>
          </div>
          <div style="display:flex; gap:6px;">
            <button class="btn btn-primary" onclick='approveNode("${encodeNodeArg(n.name)}")'>Approve</button>
            <button class="btn btn-danger" onclick='rejectNode("${encodeNodeArg(n.name)}")'>Dismiss</button>
          </div>
        </div>
      `).join('');
    } else {
      pendingSection.style.display = 'none';
      pendingBox.innerHTML = '';
    }
  }

  const activeNodes = nodes.filter(n => !n.status || n.status === 'approved');
  const rejectedNodes = nodes.filter(n => n.status === 'rejected');
  if (box) {
    const activeHtml = activeNodes.map(n => `
      <div style="display:flex; justify-content:space-between; align-items:center; padding:6px 0; border-bottom:1px solid var(--border);">
        <div>
          <span class="dot ${n.online ? 'green' : 'amber'}"></span>
          <strong>${escapeHtml(n.name)}</strong>
          <span class="badge skip" style="margin-left:6px;">${escapeHtml(n.role)}</span>
          ${n.os_version ? `<span class="badge skip" style="margin-left:4px; font-size:10px;">${escapeHtml(n.os_version)}</span>` : ''}
          <div class="svc-sub">${escapeHtml(n.url || 'Local Hub Host')} ${n.last_error ? '· ' + escapeHtml(n.last_error) : ''}</div>
        </div>
        ${n.role !== 'hub' ? `<button class="btn btn-danger" onclick='deleteRemoteNode("${encodeNodeArg(n.name)}")'>Remove</button>` : ''}
      </div>
    `).join('');

    const rejectedHtml = rejectedNodes.length > 0 ? `
      <div style="margin-top:14px; padding-top:8px; border-top:1px dashed var(--border);">
        <div style="font-size:11px; font-weight:600; color:var(--text-dim); text-transform:uppercase; margin-bottom:6px;">Dismissed Nodes (${rejectedNodes.length})</div>
        ${rejectedNodes.map(n => `
          <div style="display:flex; justify-content:space-between; align-items:center; padding:6px 0; border-bottom:1px solid var(--border); opacity:0.8;">
            <div>
              <span class="dot red"></span>
              <strong>${escapeHtml(n.name)}</strong>
              <span class="badge warn" style="margin-left:6px; font-size:10px; padding:1px 5px;">REJECTED</span>
              <div class="svc-sub">${escapeHtml(n.url || 'LAN Node')}</div>
            </div>
            <div style="display:flex; gap:6px;">
              <button class="btn btn-primary" style="padding:2px 8px; font-size:11px;" onclick='approveNode("${encodeNodeArg(n.name)}")'>Re-Approve</button>
              <button class="btn btn-danger" style="padding:2px 8px; font-size:11px;" onclick='deleteRemoteNode("${encodeNodeArg(n.name)}")'>Remove</button>
            </div>
          </div>
        `).join('')}
      </div>
    ` : '';

    box.innerHTML = activeHtml + rejectedHtml;
  }
}

async function approveNode(encodedName) {
  const name = decodeURIComponent(encodedName || '');
  const res = await apiFetch(`/api/nodes/approve?name=${encodeURIComponent(name)}`, {method: 'POST'});
  if (!res.ok) {
    const data = await res.json().catch(() => ({}));
    alert(`Failed to approve node: ${data.error || res.statusText}`);
    return;
  }
  await loadDashboard();
  renderNodesModalList();
}

async function rejectNode(encodedName) {
  const name = decodeURIComponent(encodedName || '');
  if (!confirm(`Dismiss registration for "${name}"?`)) return;
  const res = await apiFetch(`/api/nodes/reject?name=${encodeURIComponent(name)}`, {method: 'POST'});
  if (!res.ok) {
    const data = await res.json().catch(() => ({}));
    alert(`Failed to dismiss node: ${data.error || res.statusText}`);
    return;
  }
  await loadDashboard();
  renderNodesModalList();
}

async function testRemoteNodeConnection() {
  const nameInp = document.getElementById('inp-node-name');
  const urlInp = document.getElementById('inp-node-url');
  const tokenInp = document.getElementById('inp-node-token');
  const resBox = document.getElementById('test-node-result');
  const btn = document.getElementById('btn-test-node');

  const url = urlInp ? urlInp.value.trim() : '';
  const token = tokenInp ? tokenInp.value.trim() : '';

  if (!url) {
    if (resBox) {
      resBox.style.display = 'block';
      resBox.innerHTML = `<div class="badge crit" style="width:100%; justify-content:flex-start; padding:8px 12px;">⚠ Please provide the LAN Agent URL to test.</div>`;
    }
    return;
  }

  if (btn) {
    btn.disabled = true;
    btn.textContent = '⚡ Testing...';
  }
  if (resBox) {
    resBox.style.display = 'block';
    resBox.innerHTML = `<div class="badge warn" style="width:100%; justify-content:flex-start; padding:8px 12px;">Connecting to ${escapeHtml(url)}...</div>`;
  }

  try {
    const res = await apiFetch('/api/nodes/test', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({url, token})
    });
    const data = await res.json();
    if (data.ok) {
      const osVer = data.os_version || (data.info && data.info.os_version) || 'Unknown OS';
      const latency = data.latency_ms !== undefined ? `${data.latency_ms}ms` : '';
      if (resBox) {
        resBox.style.display = 'block';
        resBox.innerHTML = `
          <div class="badge ok" style="width:100%; justify-content:flex-start; padding:8px 12px; gap:8px;">
            <span>✓ Connected!</span>
            ${latency ? `<span>(${escapeHtml(latency)})</span>` : ''}
            <span>OS: ${escapeHtml(osVer)}</span>
          </div>
        `;
      }
      // Auto-fill device name if empty
      if (nameInp && !nameInp.value.trim() && data.info && data.info.name) {
        nameInp.value = data.info.name;
      }
    } else {
      if (resBox) {
        resBox.style.display = 'block';
        resBox.innerHTML = `
          <div class="badge crit" style="width:100%; justify-content:flex-start; padding:8px 12px;">
            ✖ Connection failed: ${escapeHtml(data.error || 'Agent unreachable')}
          </div>
        `;
      }
    }
  } catch (err) {
    if (resBox) {
      resBox.style.display = 'block';
      resBox.innerHTML = `
        <div class="badge crit" style="width:100%; justify-content:flex-start; padding:8px 12px;">
          ✖ Error: ${escapeHtml(err.message)}
        </div>
      `;
    }
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.textContent = '⚡ Test Connection';
    }
  }
}

async function saveRemoteNode() {
  const name = document.getElementById('inp-node-name').value.trim();
  const url = document.getElementById('inp-node-url').value.trim();
  const token = document.getElementById('inp-node-token').value.trim();
  if (!name || !url) {
    alert('Please provide both the device name and the LAN Agent URL.');
    return;
  }
  const res = await apiFetch('/api/nodes', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({name, url, token})
  });
  if (!res.ok) {
    const data = await res.json().catch(() => ({}));
    alert(`Failed to save node: ${data.error || res.statusText}`);
    return;
  }
  document.getElementById('inp-node-name').value = '';
  document.getElementById('inp-node-url').value = '';
  document.getElementById('inp-node-token').value = '';
  const resBox = document.getElementById('test-node-result');
  if (resBox) {
    resBox.style.display = 'none';
    resBox.innerHTML = '';
  }
  await loadDashboard();
  renderNodesModalList();
}

async function deleteRemoteNode(encodedName) {
  const name = decodeURIComponent(encodedName || '');
  if (!confirm(`Remove compute node "${name}" from the registry?`)) return;
  const res = await apiFetch(`/api/nodes?name=${encodeURIComponent(name)}`, {method: 'DELETE'});
  if (!res.ok) {
    const data = await res.json().catch(() => ({}));
    alert(`Failed to remove node: ${data.error || res.statusText}`);
    return;
  }
  if (currentNodeFilter === name) currentNodeFilter = 'all';
  await loadDashboard();
  renderNodesModalList();
}

async function skipItem(encodedNode, encodedTargetType, encodedTargetName, selectId) {
  let nodeName = '';
  let targetType = '';
  let targetName = '';
  if (selectId === undefined) {
    // Backward-compatible 3-arg signature: (encodedTargetType, encodedTargetName, selectId)
    targetType = decodeURIComponent(encodedNode || '');
    targetName = decodeURIComponent(encodedTargetType || '');
    selectId = encodedTargetName;
  } else {
    nodeName = decodeURIComponent(encodedNode || '');
    targetType = decodeURIComponent(encodedTargetType || '');
    targetName = decodeURIComponent(encodedTargetName || '');
  }
  const sel = document.getElementById(selectId);
  const ver = sel ? sel.value : '';
  const res = await apiFetch('/api/skip', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({node: nodeName, target_type: targetType, target_name: targetName, version: ver})
  });
  if (!res.ok) {
    const data = await res.json().catch(() => ({}));
    alert(`Failed to skip version: ${data.error || res.statusText}`);
    return;
  }
  await loadDashboard();
}

async function unskipItem(encodedNode, encodedTargetType, encodedTargetName) {
  let nodeName = '';
  let targetType = '';
  let targetName = '';
  if (encodedTargetName === undefined) {
    targetType = decodeURIComponent(encodedNode || '');
    targetName = decodeURIComponent(encodedTargetType || '');
  } else {
    nodeName = decodeURIComponent(encodedNode || '');
    targetType = decodeURIComponent(encodedTargetType || '');
    targetName = decodeURIComponent(encodedTargetName || '');
  }
  const res = await apiFetch(`/api/skip?node=${encodeURIComponent(nodeName)}&target_type=${encodeURIComponent(targetType)}&target_name=${encodeURIComponent(targetName)}`, {method: 'DELETE'});
  if (!res.ok) {
    const data = await res.json().catch(() => ({}));
    alert(`Failed to unskip version: ${data.error || res.statusText}`);
    return;
  }
  await loadDashboard();
}

function openScanNodeModal() {
  const modal = document.getElementById('modal-scan-node');
  if (!modal) return;
  renderScanNodeModalList();
  modal.style.display = 'flex';
}

function closeScanNodeModal() {
  const modal = document.getElementById('modal-scan-node');
  if (modal) modal.style.display = 'none';
  const container = document.getElementById('scan-node-modal-list');
  if (container) container.innerHTML = '';
}

function renderScanNodeModalList() {
  const container = document.getElementById('scan-node-modal-list');
  if (!container) return;
  const confirmBtn = document.getElementById('btn-confirm-scan-node');
  const existingChecked = container.querySelector('input[name="scan-target-node"]:checked');
  const existingVal = existingChecked ? existingChecked.value : '';
  const nodes = (dashboardData && dashboardData.nodes) || [{name: (dashboardData && dashboardData.hub_node) || 'local', role: 'hub', online: true}];
  const approvedNodes = nodes.filter(n => !n.status || n.status === 'approved');

  if (confirmBtn) {
    confirmBtn.disabled = approvedNodes.length === 0 || !!activeScanEventSource || activeScanningNodes.size > 0 || Boolean(dashboardData && dashboardData.scanning);
  }

  if (approvedNodes.length === 0) {
    container.innerHTML = `<div class="muted" style="padding:12px; text-align:center;">No approved nodes available to scan.</div>`;
    return;
  }

  let preselect = approvedNodes[0].name;
  const existingMatch = existingVal ? approvedNodes.find(n => String(n.name).toLowerCase() === String(existingVal).toLowerCase()) : null;
  if (existingMatch) {
    preselect = existingMatch.name;
  } else if (currentNodeFilter && currentNodeFilter !== 'all') {
    const matched = approvedNodes.find(n => String(n.name).toLowerCase() === String(currentNodeFilter).toLowerCase());
    if (matched) preselect = matched.name;
  }

  container.innerHTML = approvedNodes.map((n, idx) => {
    const isChecked = n.name === preselect ? 'checked' : '';
    const dot = n.online ? 'green' : 'amber';
    const roleTag = n.role === 'hub' ? 'Hub' : 'Agent';
    const isScanning = isNodeScanning(n.name);
    return `
      <label class="scan-node-option" for="scan-node-radio-${idx}">
        <div class="scan-node-label">
          <input type="radio" id="scan-node-radio-${idx}" name="scan-target-node" value="${escapeHtml(n.name)}" ${isChecked} />
          <span class="dot ${isScanning ? 'scanning' : dot}"></span>
          <strong>${escapeHtml(n.name)}</strong>
          <span class="node-role">${roleTag}</span>
          ${n.os_version ? `<span class="badge skip" style="font-size:10px; padding:1px 6px;">${escapeHtml(n.os_version)}</span>` : ''}
          ${isScanning ? '<span class="node-scan-status">⟳ Scanning</span>' : ''}
        </div>
        <div class="svc-sub">${escapeHtml(n.url || 'Local Hub Host')}</div>
      </label>
    `;
  }).join('');
}

function confirmAndStartNodeScan() {
  const selected = document.querySelector('input[name="scan-target-node"]:checked');
  if (!selected || !selected.value) {
    alert('Please select a node to scan.');
    return;
  }
  const targetNode = selected.value;
  closeScanNodeModal();
  triggerScan(targetNode);
}

function updateActiveNodesFromLogLine(line) {
  if (!line || activeScanningNodes.size <= 1) return;
  let changed = false;
  if (/^\[Hub\] Scanned \d+ local\b/.test(line)) {
    const hubName = (dashboardData && dashboardData.hub_node) || 'local';
    changed = removeActiveScanningNode(hubName) || changed;
  } else {
    const m = line.match(/^\[([^\]]+)\] (?:Scanned \d+ remote\b|Remote agent unreachable\b)/);
    if (m && m[1]) {
      changed = removeActiveScanningNode(m[1]) || changed;
    }
  }
  if (changed) {
    renderNodeBar();
  }
}

function attachScanStream(taskId) {
  clearScanPollTimer();
  if (activeScanEventSource) {
    activeScanEventSource.close();
    activeScanEventSource = null;
  }

  const progressBox = document.getElementById('scan-progress-box');
  const progressText = document.getElementById('scan-progress-text');
  if (progressBox) progressBox.style.display = 'inline-flex';
  if (progressText && !progressText.textContent) progressText.textContent = 'Scanning in progress...';
  updateScanButtons(true);

  if (!isStreamableScanTaskId(taskId)) {
    scheduleScanPoll(2000);
    return;
  }

  activeScanEventSource = new EventSource(`/api/tasks/${encodeURIComponent(taskId)}/stream`);

  activeScanEventSource.onmessage = (e) => {
    failedStreamTaskIds.delete(String(taskId));
    let lineText = '';
    try {
      const parsed = JSON.parse(e.data);
      lineText = parsed.line || '';
    } catch (_) {
      lineText = e.data || '';
    }
    if (lineText) {
      if (progressText) progressText.textContent = lineText;
      updateActiveNodesFromLogLine(lineText);
    }
  };

  const handleDone = async () => {
    clearScanPollTimer();
    if (activeScanEventSource) {
      activeScanEventSource.close();
      activeScanEventSource = null;
    }
    activeScanningNodes.clear();
    if (dashboardData) {
      dashboardData.scanning = false;
      dashboardData.scanning_nodes = [];
    }
    updateScanButtons(false);
    renderNodeBar();
    if (progressBox) progressBox.style.display = 'none';
    if (progressText) progressText.textContent = '';
    await loadDashboard();
  };

  activeScanEventSource.addEventListener('done', handleDone);
  activeScanEventSource.onerror = () => {
    if (activeScanEventSource) {
      activeScanEventSource.close();
      activeScanEventSource = null;
    }
    failedStreamTaskIds.add(String(taskId));
    scheduleScanPoll(2000);
  };
}

async function triggerScan(targetNode = '') {
  clearScanPollTimer();
  const progressBox = document.getElementById('scan-progress-box');
  const progressText = document.getElementById('scan-progress-text');

  updateScanButtons(true);
  if (progressBox) progressBox.style.display = 'inline-flex';

  const nodes = (dashboardData && dashboardData.nodes) || [];
  const approvedNodes = nodes.filter(n => !n.status || n.status === 'approved');

  if (targetNode) {
    activeScanningNodes = new Set([targetNode]);
    if (progressText) progressText.textContent = `Initializing scan for [${targetNode}]...`;
  } else {
    activeScanningNodes = new Set(approvedNodes.map(n => n.name));
    if (progressText) progressText.textContent = 'Initializing full security scan...';
  }
  renderNodeBar();

  try {
    const fetchOpts = {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
    };
    if (targetNode) {
      fetchOpts.body = JSON.stringify({node: targetNode});
    }

    const res = await apiFetch('/api/scan', fetchOpts);
    const data = await res.json().catch(() => ({}));

    if (Array.isArray(data.scanning_nodes) && (res.status === 409 || data.scanning_nodes.length > 0)) {
      activeScanningNodes = new Set(data.scanning_nodes);
      renderNodeBar();
    }

    let taskId = data.task_id;
    if (res.status === 409) {
      if (progressText) progressText.textContent = 'Scan in progress; attaching to stream...';
    } else if (!res.ok) {
      alert(`Scan failed: ${data.error || res.statusText}`);
      activeScanningNodes.clear();
      updateScanButtons(false);
      renderNodeBar();
      return;
    }

    if (!taskId) {
      activeScanningNodes.clear();
      updateScanButtons(false);
      renderNodeBar();
      await loadDashboard();
      return;
    }

    attachScanStream(taskId);
  } catch (err) {
    alert(`Scan error: ${err.message}`);
    activeScanningNodes.clear();
    updateScanButtons(false);
    renderNodeBar();
  }
}

function renderTaskList() {
  const container = document.getElementById('task-list-container');
  const tasks = (dashboardData && dashboardData.recent_tasks) || [];
  if (tasks.length === 0) {
    container.innerHTML = `<div style="padding:20px;" class="muted">No tasks recorded yet.</div>`;
    return;
  }
  container.innerHTML = tasks.map(t => {
    const badgeClass = t.status === 'succeeded' ? 'ok' : (t.status === 'rolled_back' || t.status === 'running') ? 'warn' : 'crit';
    const nodeLabel = t.node ? `[${escapeHtml(t.node)}] ` : '';
    const hasVersions = Boolean(t.from_version || t.to_version);
    const subDetail = hasVersions
      ? `(${escapeHtml(t.from_version || '')} → ${escapeHtml(t.to_version || '')})`
      : (t.target_type ? `(${escapeHtml(t.target_type)})` : '');
    return `
      <div class="task-list-item" onclick='streamTaskLogs("${encodeNodeArg(t.id)}")'>
        <div style="display:flex; justify-content:space-between; align-items:center;">
          <strong>${escapeHtml(t.id)} · ${nodeLabel}${escapeHtml(t.task_type)}</strong>
          <span class="badge ${badgeClass}">${escapeHtml(t.status)}</span>
        </div>
        <div class="svc-sub" style="margin-top:4px;">${escapeHtml(t.target_name)}${subDetail ? ' ' + subDetail : ''}</div>
      </div>
    `;
  }).join('');
}

function streamTaskLogs(encodedTaskId) {
  const taskId = decodeURIComponent(encodedTaskId || '');
  if (activeEventSource) {
    activeEventSource.close();
  }
  document.getElementById('active-task-title').textContent = `Task ${taskId} — Execution Output`;
  const dl = document.getElementById('download-log-link');
  dl.href = `/api/tasks/${encodeURIComponent(taskId)}/download`;
  dl.style.display = 'inline-flex';

  const term = document.getElementById('terminal-output');
  term.innerHTML = '';

  activeEventSource = new EventSource(`/api/tasks/${encodeURIComponent(taskId)}/stream`);
  activeEventSource.onmessage = (e) => {
    try {
      const line = JSON.parse(e.data);
      const div = document.createElement('div');
      div.innerHTML = `<span class="log-ts">[${new Date(line.logged_at).toLocaleTimeString()}]</span> <span class="log-${escapeHtml(line.stream)}">[${escapeHtml(String(line.stream || '').toUpperCase())}]</span> ${escapeHtml(line.line)}`;
      term.appendChild(div);
      term.scrollTop = term.scrollHeight;
    } catch (_) {
      const div = document.createElement('div');
      div.textContent = e.data;
      term.appendChild(div);
    }
  };
  activeEventSource.addEventListener('done', () => {
    if (activeEventSource) {
      activeEventSource.close();
      activeEventSource = null;
    }
    loadDashboard();
  });
  activeEventSource.onerror = () => {
    if (activeEventSource) {
      activeEventSource.close();
      activeEventSource = null;
    }
  };
}

async function logout() {
  resetSessionClientState();
  await apiFetch('/api/auth/logout', {method: 'POST'});
  initApp();
}

function b64urlToUint8Array(b64url) {
  const padding = '='.repeat((4 - (b64url.length % 4)) % 4);
  const b64 = (b64url + padding).replace(/-/g, '+').replace(/_/g, '/');
  const raw = atob(b64);
  return Uint8Array.from(raw, c => c.charCodeAt(0));
}

function bufferToB64url(buf) {
  const bytes = new Uint8Array(buf);
  let binary = '';
  bytes.forEach(b => binary += String.fromCharCode(b));
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function registerPasskey() {
  const beginRes = await apiFetch('/api/auth/passkey/register/begin', {method: 'POST'});
  if (!beginRes.ok) {
    const errData = await beginRes.json().catch(() => ({}));
    alert(`Failed to start passkey registration: ${errData.error || beginRes.statusText}`);
    return;
  }
  const opts = await beginRes.json();
  const userId = new Uint8Array(16);
  crypto.getRandomValues(userId);
  const cred = await navigator.credentials.create({
    publicKey: {
      challenge: b64urlToUint8Array(opts.challenge),
      rp: {name: 'NAL Security Hub', id: opts.rp_id || window.location.hostname},
      user: {id: userId, name: opts.user, displayName: opts.user},
      pubKeyCredParams: [{type: 'public-key', alg: -7}],
      timeout: 60000
    }
  });
  const finRes = await apiFetch('/api/auth/passkey/register/finish', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({
      credential_id: cred.id,
      label: `${navigator.platform || 'Device'} Passkey`,
      attestation_object: bufferToB64url(cred.response.attestationObject),
      client_data_json: bufferToB64url(cred.response.clientDataJSON)
    })
  });
  if (finRes.ok) {
    alert('Passkey registered for offline emergency login!');
  } else {
    const errData = await finRes.json().catch(() => ({}));
    alert(`Passkey registration failed: ${errData.error || finRes.statusText}`);
  }
}

async function loginWithPasskey() {
  const beginRes = await fetch('/api/auth/passkey/login/begin', {method: 'POST'});
  if (!beginRes.ok) {
    const errData = await beginRes.json().catch(() => ({}));
    alert(`Passkey login unavailable: ${errData.error || beginRes.statusText}`);
    return;
  }
  const opts = await beginRes.json();
  if (!opts.allow_credentials || opts.allow_credentials.length === 0) {
    alert('No Passkey registered yet. Sign in via SSO or run "./security-hub auth login-link" first.');
    return;
  }
  const assertion = await navigator.credentials.get({
    publicKey: {
      challenge: b64urlToUint8Array(opts.challenge),
      rpId: opts.rp_id || window.location.hostname,
      allowCredentials: opts.allow_credentials.map(id => ({type: 'public-key', id: b64urlToUint8Array(id)})),
      timeout: 60000
    }
  });
  const finRes = await fetch('/api/auth/passkey/login/finish', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({
      credential_id: assertion.id,
      authenticator_data: bufferToB64url(assertion.response.authenticatorData),
      client_data_json: bufferToB64url(assertion.response.clientDataJSON),
      signature: bufferToB64url(assertion.response.signature)
    })
  });
  if (finRes.ok) {
    initApp();
  } else {
    const errData = await finRes.json().catch(() => ({}));
    alert(`Passkey verification failed: ${errData.error || finRes.statusText}`);
  }
}

function escapeHtml(s) {
  return String(s || '').replace(/[&<>"']/g, m => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]));
}

function isSafeHttpUrl(u) {
  return /^https?:\/\//i.test(String(u || '').trim());
}

window.addEventListener('click', (e) => {
  const dropdown = document.getElementById('user-dropdown');
  if (dropdown && !dropdown.contains(e.target)) {
    closeUserDropdown();
  }
});

window.addEventListener('DOMContentLoaded', initApp);
