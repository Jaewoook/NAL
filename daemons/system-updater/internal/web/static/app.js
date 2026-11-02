let currentTab = 'docker';
let currentNodeFilter = 'all';
let dashboardData = null;
let pendingUpdateReq = null;
let activeEventSource = null;

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
  document.getElementById('auth-user-label').textContent = `${session.method.toUpperCase()}: ${session.subject}`;
  await loadDashboard();
}

async function loadDashboard() {
  const res = await fetch('/api/dashboard');
  if (res.status === 401) {
    return initApp();
  }
  dashboardData = await res.json();
  renderNodeBar();
  renderSummary();
  renderItemsTable();
  renderTaskList();
}

function getFilteredItems() {
  const all = (dashboardData && dashboardData.scan && dashboardData.scan.items) || [];
  if (currentNodeFilter === 'all') return all;
  return all.filter(i => (i.node || dashboardData.hub_node || 'Axis') === currentNodeFilter);
}

function selectNodeFilter(nodeName) {
  currentNodeFilter = nodeName;
  renderNodeBar();
  renderSummary();
  renderItemsTable();
  renderTaskList();
}

function renderNodeBar() {
  const container = document.getElementById('node-pills-container');
  if (!container) return;
  const nodes = (dashboardData && dashboardData.nodes) || [{name: 'Axis', role: 'hub', online: true}];
  let html = `<button class="node-pill ${currentNodeFilter === 'all' ? 'active' : ''}" onclick='selectNodeFilter("all")'>All Nodes (${nodes.length})</button>`;
  nodes.forEach(n => {
    const dot = n.online ? 'green' : 'amber';
    const roleTag = n.role === 'hub' ? 'Hub' : 'Agent';
    const title = n.last_error ? `Offline: ${n.last_error}` : (n.url || 'Local Host');
    html += `
      <button class="node-pill ${currentNodeFilter === n.name ? 'active' : ''}" title="${escapeHtml(title)}" onclick='selectNodeFilter("${escapeHtml(n.name)}")'>
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

  items.forEach((item, idx) => {
    const nodeName = item.node || (dashboardData && dashboardData.hub_node) || 'Axis';
    const tr = document.createElement('tr');
    const dotClass = (item.crit_count > 0 || item.broken_linkage || item.eol?.status === 'expired') ? 'red'
      : (item.high_count > 0 || item.eol?.status === 'expiring_soon' || item.outdated) ? 'amber' : 'green';

    let secHtml = `<span class="badge ok">✓ 0 CVEs</span>`;
    if (item.broken_linkage) {
      secHtml = `<span class="badge crit">Broken Linkage: ${escapeHtml(item.linkage_details || 'missing dylib')}</span>`;
    } else if (item.crit_count > 0 || item.high_count > 0) {
      const firstId = item.vulnerabilities?.[0]?.id || 'CVE';
      secHtml = `<span class="badge crit">● ${item.crit_count} Crit / ${item.high_count} High (${escapeHtml(firstId)})</span>`;
    }

    let eolHtml = `<span class="badge ok">Supported</span>`;
    if (item.eol) {
      if (item.eol.status === 'expired') {
        eolHtml = `<span class="badge crit">✖ EoL Expired (${escapeHtml(item.eol.eol_date || item.eol.message || '')})</span>`;
      } else if (item.eol.status === 'expiring_soon') {
        eolHtml = `<span class="badge warn">⚠ EoL in ${item.eol.days_remaining}d (${escapeHtml(item.eol.eol_date || '')})</span>`;
      } else if (item.eol.eol_date) {
        eolHtml = `<span class="badge ok">Supported until ${escapeHtml(item.eol.eol_date)}</span>`;
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
        actionsHtml += `<button class="btn btn-ghost" onclick='rollbackService("${escapeHtml(nodeName)}", "${item.name}")'>Rollback (${escapeHtml(item.rollback_version)})</button>`;
      }
    }
    if (item.release_notes_url) {
      actionsHtml += `<a class="btn btn-ghost" href="${escapeHtml(item.release_notes_url)}" target="_blank" style="text-decoration:none;">Notes ↗</a>`;
    }

    tr.innerHTML = `
      <td>
        <div class="svc-name">
          <span class="dot ${dotClass}"></span>
          <span class="badge skip" style="font-size:11px; padding:1px 6px;">${escapeHtml(nodeName)}</span>
          <span>${escapeHtml(item.name)}</span>
          ${item.critical_path ? '<span class="badge warn" style="font-size:10px;">Critical Path</span>' : ''}
        </div>
        <div class="svc-sub">${escapeHtml(item.image_ref || item.target_type)}</div>
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
  const nodeName = item.node || (dashboardData && dashboardData.hub_node) || 'Axis';
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

async function rollbackService(nodeName, serviceName) {
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
  renderNodesModalList();
  document.getElementById('modal-nodes').style.display = 'flex';
}

function closeNodesModal() {
  document.getElementById('modal-nodes').style.display = 'none';
}

function renderNodesModalList() {
  const box = document.getElementById('nodes-modal-list');
  const nodes = (dashboardData && dashboardData.nodes) || [];
  box.innerHTML = nodes.map(n => `
    <div style="display:flex; justify-content:space-between; align-items:center; padding:6px 0; border-bottom:1px solid var(--border);">
      <div>
        <span class="dot ${n.online ? 'green' : 'amber'}"></span>
        <strong>${escapeHtml(n.name)}</strong>
        <span class="badge skip" style="margin-left:6px;">${escapeHtml(n.role)}</span>
        <div class="svc-sub">${escapeHtml(n.url || 'Local Hub Host')} ${n.last_error ? '· ' + escapeHtml(n.last_error) : ''}</div>
      </div>
      ${n.role !== 'hub' ? `<button class="btn btn-danger" onclick='deleteRemoteNode("${escapeHtml(n.name)}")'>Remove</button>` : ''}
    </div>
  `).join('');
}

async function saveRemoteNode() {
  const name = document.getElementById('inp-node-name').value.trim();
  const url = document.getElementById('inp-node-url').value.trim();
  const token = document.getElementById('inp-node-token').value.trim();
  if (!name || !url) {
    alert('Please provide both the device name (e.g., Atlas) and the LAN Agent URL.');
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
  await loadDashboard();
  renderNodesModalList();
}

async function deleteRemoteNode(name) {
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
  btn.textContent = '⟳ Scanning...';
  btn.disabled = true;
  try {
    await fetch('/api/scan', {method: 'POST'});
    await loadDashboard();
  } finally {
    btn.textContent = '↻ Scan Now';
    btn.disabled = false;
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
      rp: {name: 'NAL System Updater', id: window.location.hostname},
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
    alert('No Passkey registered yet. Sign in via SSO or run "./system-updater auth login-link" first.');
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

window.addEventListener('DOMContentLoaded', initApp);
