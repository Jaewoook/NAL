let currentTab = 'docker';
let currentNodeFilter = 'all';
let dashboardData = null;
let pendingUpdateReq = null;
let activeEventSource = null;
let activeScanEventSource = null;

async function initApp() {
  const res = await fetch('/api/auth/session');
  const session = await res.json();
  if (!session.authenticated) {
    document.getElementById('view-login').style.display = 'block';
    document.getElementById('view-dashboard').style.display = 'none';
    document.getElementById('header-actions').style.display = 'none';
    return;
  }
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

async function loadDashboard() {
  const res = await fetch('/api/dashboard');
  if (res.status === 401) {
    return initApp();
  }
  dashboardData = await res.json();
  renderPendingNodesBanner();
  renderNodeBar();
  renderSummary();
  renderItemsTable();
  renderTaskList();
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
  let html = `<button class="node-pill ${currentNodeFilter === 'all' ? 'active' : ''}" onclick='selectNodeFilter("all")'>All Nodes (${approvedNodes.length})</button>`;
  approvedNodes.forEach(n => {
    const dot = n.online ? 'green' : 'amber';
    const roleTag = n.role === 'hub' ? 'Hub' : 'Agent';
    const title = n.last_error ? `Offline: ${n.last_error}` : (n.url || 'Local Host');
    html += `
      <button class="node-pill ${currentNodeFilter === n.name ? 'active' : ''}" title="${escapeHtml(title)}" onclick='selectNodeFilter("${encodeNodeArg(n.name)}")'>
        <span class="dot ${dot}"></span>
        <span>${escapeHtml(n.name)}</span>
        <span class="node-role">${roleTag}</span>
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
  document.getElementById('stat-last-scan').textContent = scan.scanned_at ? `Last scan: ${new Date(scan.scanned_at).toLocaleString()}` : 'Last scan: Not yet run';

  document.getElementById('badge-docker').textContent = items.filter(i => i.target_type === 'docker').length;
  document.getElementById('badge-brew').textContent = items.filter(i => i.target_type === 'brew').length;
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
    if (currentTab === 'brew') return item.target_type === 'brew';
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

  items.forEach((item, idx) => {
    const nodeName = item.node || (dashboardData && dashboardData.hub_node) || 'local';
    const tr = document.createElement('tr');
    const dotClass = (item.crit_count > 0 || item.broken_linkage || item.eol?.status === 'expired') ? 'red'
      : (item.high_count > 0 || item.eol?.status === 'expiring_soon' || item.outdated) ? 'amber' : 'green';

    let secHtml = `<span class="badge ok">✓ 0 CVEs</span>`;
    if (item.broken_linkage && (item.crit_count > 0 || item.high_count > 0)) {
      secHtml = `
        <div style="display:flex; flex-direction:column; gap:4px; align-items:flex-start;">
          <button class="badge crit badge-btn" onclick='openBrokenLinkageModal(${JSON.stringify(item.name)}, ${JSON.stringify(item.linkage_details || "Broken dylib dependency")})'>⚠ Broken Linkage (Details)</button>
          <span class="badge crit">● ${item.crit_count} Crit / ${item.high_count} High</span>
        </div>
      `;
    } else if (item.broken_linkage) {
      secHtml = `<button class="badge crit badge-btn" onclick='openBrokenLinkageModal(${JSON.stringify(item.name)}, ${JSON.stringify(item.linkage_details || "Broken dylib dependency")})' title="Click to view broken linkage details">⚠ Broken Linkage (Details)</button>`;
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
    if (item.target_type === 'docker' || item.target_type === 'brew' || (item.target_type === 'daemon' && item.name === 'ollama')) {
      const btnClass = (item.crit_count > 0 || item.broken_linkage) ? 'btn-danger' : 'btn-primary';
      const btnLabel = item.broken_linkage ? 'Upgrade & Fix' : 'Update';
      actionsHtml += `<button class="btn ${btnClass}" onclick='openUpdateModal(${JSON.stringify(item)}, "${selectId}")'>${btnLabel}</button>`;
      if (item.skipped) {
        actionsHtml += `<span class="badge skip">Skipped ${escapeHtml(item.skipped_version)}</span>`;
        actionsHtml += `<button class="btn btn-ghost" onclick='unskipItem("${item.target_type}", "${item.name}")'>Unskip</button>`;
      } else if (item.outdated) {
        actionsHtml += `<button class="btn btn-ghost" onclick='skipItem("${item.target_type}", "${item.name}", "${selectId}")'>Skip</button>`;
      }
      if (item.has_rollback) {
        actionsHtml += `<button class="btn btn-ghost" onclick='rollbackService("${encodeNodeArg(nodeName)}", "${item.name}")'>Rollback (${escapeHtml(item.rollback_version)})</button>`;
      }
    }
    if (item.release_notes_url) {
      actionsHtml += `<a class="btn btn-ghost" href="${escapeHtml(item.release_notes_url)}" target="_blank" style="text-decoration:none;">Notes ↗</a>`;
    }

    const subType = item.target_type === 'brew' ? 'brew' : (item.image_ref || item.target_type);

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

function openUpdateModal(item, selectId) {
  const sel = document.getElementById(selectId);
  const targetVer = sel ? sel.value : item.latest_version;
  const nodeName = item.node || (dashboardData && dashboardData.hub_node) || 'local';
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
  document.getElementById('lbl-backup').style.display = item.target_type === 'docker' ? 'flex' : 'none';
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
  const res = await fetch('/api/update', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(reqBody)
  });
  const task = await res.json();
  await loadDashboard();
  switchTab('logs');
  if (task && task.id) {
    streamTaskLogs(task.id);
  }
}

async function rollbackService(encodedNodeName, serviceName) {
  const nodeName = decodeURIComponent(encodedNodeName || '');
  if (!confirm(`Roll back ${serviceName} on ${nodeName} to its previous snapshot version and digest?`)) return;
  const res = await fetch('/api/rollback', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({node: nodeName, service_name: serviceName})
  });
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

  const activeNodes = nodes.filter(n => n.status !== 'pending');
  if (box) {
    box.innerHTML = activeNodes.map(n => `
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
  }
}

async function approveNode(encodedName) {
  const name = decodeURIComponent(encodedName || '');
  const res = await fetch(`/api/nodes/approve?name=${encodeURIComponent(name)}`, {method: 'POST'});
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
  const res = await fetch(`/api/nodes/reject?name=${encodeURIComponent(name)}`, {method: 'POST'});
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
    const res = await fetch('/api/nodes/test', {
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
  await fetch('/api/nodes', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({name, url, token})
  });
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
  await fetch(`/api/nodes?name=${encodeURIComponent(name)}`, {method: 'DELETE'});
  if (currentNodeFilter === name) currentNodeFilter = 'all';
  await loadDashboard();
  renderNodesModalList();
}

async function skipItem(targetType, targetName, selectId) {
  const sel = document.getElementById(selectId);
  const ver = sel ? sel.value : '';
  await fetch('/api/skip', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({target_type: targetType, target_name: targetName, version: ver})
  });
  await loadDashboard();
}

async function unskipItem(targetType, targetName) {
  await fetch(`/api/skip?target_type=${encodeURIComponent(targetType)}&target_name=${encodeURIComponent(targetName)}`, {method: 'DELETE'});
  await loadDashboard();
}

async function triggerScan() {
  const btn = document.getElementById('btn-scan-now');
  const progressBox = document.getElementById('scan-progress-box');
  const progressText = document.getElementById('scan-progress-text');

  if (btn) {
    btn.textContent = '⟳ Scanning...';
    btn.disabled = true;
  }
  if (progressBox) progressBox.style.display = 'inline-flex';
  if (progressText) progressText.textContent = 'Initializing scan...';

  try {
    const res = await fetch('/api/scan', {method: 'POST'});
    const data = await res.json().catch(() => ({}));

    let taskId = data.task_id;
    if (res.status === 409) {
      if (progressText) progressText.textContent = 'Scan in progress; attaching to stream...';
    } else if (!res.ok) {
      alert(`Scan failed: ${data.error || res.statusText}`);
      if (btn) {
        btn.textContent = '↻ Scan Now';
        btn.disabled = false;
      }
      if (progressBox) progressBox.style.display = 'none';
      return;
    }

    if (!taskId) {
      if (btn) {
        btn.textContent = '↻ Scan Now';
        btn.disabled = false;
      }
      if (progressBox) progressBox.style.display = 'none';
      await loadDashboard();
      return;
    }

    if (activeScanEventSource) {
      activeScanEventSource.close();
    }

    activeScanEventSource = new EventSource(`/api/tasks/${encodeURIComponent(taskId)}/stream`);

    activeScanEventSource.onmessage = (e) => {
      try {
        const parsed = JSON.parse(e.data);
        if (parsed.line && progressText) {
          progressText.textContent = parsed.line;
        }
      } catch (_) {
        if (e.data && progressText) {
          progressText.textContent = e.data;
        }
      }
    };

    activeScanEventSource.addEventListener('done', async () => {
      if (activeScanEventSource) {
        activeScanEventSource.close();
        activeScanEventSource = null;
      }
      if (progressBox) progressBox.style.display = 'none';
      if (progressText) progressText.textContent = '';
      if (btn) {
        btn.textContent = '↻ Scan Now';
        btn.disabled = false;
      }
      await loadDashboard();
    });

    activeScanEventSource.onerror = () => {
      if (activeScanEventSource) {
        activeScanEventSource.close();
        activeScanEventSource = null;
      }
      if (progressBox) progressBox.style.display = 'none';
      if (progressText) progressText.textContent = '';
      if (btn) {
        btn.textContent = '↻ Scan Now';
        btn.disabled = false;
      }
      loadDashboard();
    };
  } catch (err) {
    alert(`Scan error: ${err.message}`);
    if (btn) {
      btn.textContent = '↻ Scan Now';
      btn.disabled = false;
    }
    if (progressBox) progressBox.style.display = 'none';
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
    return `
      <div class="task-list-item" onclick='streamTaskLogs("${t.id}")'>
        <div style="display:flex; justify-content:space-between; align-items:center;">
          <strong>${escapeHtml(t.id)} · ${nodeLabel}${escapeHtml(t.task_type)}</strong>
          <span class="badge ${badgeClass}">${escapeHtml(t.status)}</span>
        </div>
        <div class="svc-sub" style="margin-top:4px;">${escapeHtml(t.target_name)} (${escapeHtml(t.from_version || '')} → ${escapeHtml(t.to_version || '')})</div>
      </div>
    `;
  }).join('');
}

function streamTaskLogs(taskId) {
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
    const line = JSON.parse(e.data);
    const div = document.createElement('div');
    div.innerHTML = `<span class="log-ts">[${new Date(line.logged_at).toLocaleTimeString()}]</span> <span class="log-${escapeHtml(line.stream)}">[${escapeHtml(line.stream.toUpperCase())}]</span> ${escapeHtml(line.line)}`;
    term.appendChild(div);
    term.scrollTop = term.scrollHeight;
  };
  activeEventSource.addEventListener('done', () => {
    activeEventSource.close();
    loadDashboard();
  });
}

async function logout() {
  await fetch('/api/auth/logout', {method: 'POST'});
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
  const beginRes = await fetch('/api/auth/passkey/register/begin', {method: 'POST'});
  const opts = await beginRes.json();
  const cred = await navigator.credentials.create({
    publicKey: {
      challenge: b64urlToUint8Array(opts.challenge),
      rp: {name: 'NAL Security Hub', id: window.location.hostname},
      user: {id: new Uint8Array([1, 2, 3, 4]), name: opts.user, displayName: opts.user},
      pubKeyCredParams: [{type: 'public-key', alg: -7}],
      timeout: 60000
    }
  });
  const spki = cred.response.getPublicKey();
  const finRes = await fetch('/api/auth/passkey/register/finish', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({
      credential_id: cred.id,
      label: `${navigator.platform || 'Device'} Passkey`,
      public_key_spki: bufferToB64url(spki),
      challenge: opts.challenge
    })
  });
  if (finRes.ok) alert('Passkey registered for offline emergency login!');
}

async function loginWithPasskey() {
  const beginRes = await fetch('/api/auth/passkey/login/begin', {method: 'POST'});
  const opts = await beginRes.json();
  if (!opts.allow_credentials || opts.allow_credentials.length === 0) {
    alert('No Passkey registered yet. Sign in via SSO or run "./security-hub auth login-link" first.');
    return;
  }
  const assertion = await navigator.credentials.get({
    publicKey: {
      challenge: b64urlToUint8Array(opts.challenge),
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
  if (finRes.ok) initApp();
  else alert('Passkey verification failed.');
}

function escapeHtml(s) {
  return String(s || '').replace(/[&<>"']/g, m => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]));
}

window.addEventListener('click', (e) => {
  const dropdown = document.getElementById('user-dropdown');
  if (dropdown && !dropdown.contains(e.target)) {
    closeUserDropdown();
  }
});

window.addEventListener('DOMContentLoaded', initApp);
