const state = {
  token: localStorage.getItem('gravis_token') || '',
  user: null,
  users: [],
  threats: [],
  assets: [],
  summary: {},
  settings: null,
  accountSecurity: null,
  pendingLogin: null,
  homeFilter: 'ALL',
  selectedThreatId: null,
  socket: null,
  toastTimer: null
};

const $ = selector => document.querySelector(selector);
const $$ = selector => [...document.querySelectorAll(selector)];
const statusNames = { DETECTED: 'Detected', INVESTIGATING: 'Investigating', REPORTED: 'Reported', RESOLVED: 'Resolved' };
const channelNames = { SOCIAL_MEDIA: 'Social media', WEB_LINK: 'Web & phishing', APP_STORE: 'App store', BRAND_ASSET: 'Brand asset' };
const channelIcons = { SOCIAL_MEDIA: '◎', WEB_LINK: '⌘', APP_STORE: '▣', BRAND_ASSET: '◈' };
const severityColors = { CRITICAL: '#e26568', HIGH: '#e8a157', MEDIUM: '#e5c463', LOW: '#5cb489' };

function toast(message, isError = false) {
  const element = $('#toast');
  element.textContent = message;
  element.style.background = isError ? '#883d40' : '#143b2c';
  element.classList.add('show');
  clearTimeout(state.toastTimer);
  state.toastTimer = setTimeout(() => element.classList.remove('show'), 3000);
}
async function loadModeIndicator() {
  const label = $('#mode-indicator-label');
  try {
    const response = await fetch('/api/health');
    if (!response.ok) throw new Error('Health check unavailable');
    const health = await response.json();
    label.textContent = health.mode === 'production' ? 'PRODUCTION' : 'DEMO DATA';
  } catch {
    label.textContent = 'WORKSPACE';
  }
}
function authHeaders() {
  return { 'Content-Type': 'application/json', ...(state.token ? { Authorization: `Bearer ${state.token}` } : {}) };
}
async function api(path, options = {}) {
  const response = await fetch(path, { ...options, headers: { ...authHeaders(), ...(options.headers || {}) } });
  const data = await response.json().catch(() => ({}));
  if (response.status === 401 && path !== '/api/auth/login') {
    state.token = '';
    localStorage.removeItem('gravis_token');
    state.socket?.disconnect();
    if (!$('#login-dialog').open) $('#login-dialog').showModal();
    throw new Error(data.error || 'Sign in required');
  }
  if (!response.ok) throw new Error(data.error || 'Request failed');
  return data;
}
function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, character => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[character]);
}
function safeId(value) { return escapeHtml(value).replace(/`/g, '&#96;'); }
function timeAgo(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return 'Unknown';
  const minutes = Math.max(0, Math.floor((Date.now() - date.getTime()) / 60000));
  if (minutes < 1) return 'Just now';
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return days < 30 ? `${days}d ago` : date.toLocaleDateString();
}
function initials(name) {
  return String(name || 'User').trim().split(/\s+/).slice(0, 2).map(part => part[0]).join('').toUpperCase();
}
function threatRow(threat, caseRow = false) {
  const id = safeId(threat.id);
  if (caseRow) return `<tr><td><b>${id}</b></td><td><div class="threat-cell"><span class="threat-symbol ${iconType(threat)}">${channelIcons[threat.channel] || '◈'}</span><span><b>${escapeHtml(threat.targetName)}</b><small>${escapeHtml(threat.type)}</small></span></div></td><td><span class="severity ${threat.severity}">${threat.riskScore} · ${capitalize(threat.severity)}</span></td><td><select class="status-select" data-status-id="${id}" aria-label="Update status for ${id}">${Object.entries(statusNames).map(([value, label]) => `<option value="${value}"${threat.status === value ? ' selected' : ''}>${label}</option>`).join('')}</select></td><td>${(threat.notes || []).length}</td><td><span class="time-cell">${timeAgo(threat.updatedAt || threat.detectedAt)}</span></td><td><button class="row-open" data-open-threat="${id}">Open case →</button></td></tr>`;
  return `<tr><td><div class="threat-cell"><span class="threat-symbol ${iconType(threat)}">${channelIcons[threat.channel] || '◈'}</span><span><b>${escapeHtml(threat.targetName)}</b><small>${escapeHtml(threat.type)} · ${id}</small></span></div></td><td><span class="channel-badge">${escapeHtml(channelNames[threat.channel] || threat.channel)}</span></td><td><div class="risk-wrap"><span class="risk-number">${Number(threat.riskScore) || 0}</span><span class="risk-track"><i class="${String(threat.severity).toLowerCase()}-fill" style="width:${Math.max(0, Math.min(100, Number(threat.riskScore) || 0))}%"></i></span></div></td><td><span class="severity ${threat.severity}">${capitalize(threat.severity)}</span></td><td><span class="status ${threat.status}">${escapeHtml(statusNames[threat.status] || threat.status)}</span></td><td><span class="time-cell">${timeAgo(threat.detectedAt)}</span></td><td><button class="row-open" data-open-threat="${id}" aria-label="Review ${id}">Review →</button></td></tr>`;
}
function iconType(threat) {
  if (threat.channel === 'SOCIAL_MEDIA') return 'social';
  if (threat.channel === 'WEB_LINK') return 'web';
  if (threat.channel === 'APP_STORE') return 'app';
  return 'brand';
}
function capitalize(value) { return value ? value[0] + value.slice(1).toLowerCase() : ''; }
function renderRows(selector, items, caseRow = false) {
  const element = $(selector);
  if (!element) return;
  element.innerHTML = items.length ? items.map(item => threatRow(item, caseRow)).join('') : `<tr><td colspan="7" class="loading">${caseRow ? 'No cases match this filter.' : 'No threat records match these filters.'}</td></tr>`;
}
function filteredThreats() {
  const search = ($('#threat-search')?.value || '').trim().toLowerCase();
  const severity = $('#severity-filter')?.value || 'ALL';
  const channel = $('#channel-filter')?.value || 'ALL';
  const status = $('#status-filter')?.value || 'ALL';
  return state.threats.filter(threat => {
    const searchable = `${threat.id} ${threat.targetName} ${threat.type} ${threat.threatUrl || ''}`.toLowerCase();
    return (state.homeFilter === 'ALL' || threat.severity === state.homeFilter)
      && (!search || searchable.includes(search))
      && (severity === 'ALL' || threat.severity === severity)
      && (channel === 'ALL' || threat.channel === channel)
      && (status === 'ALL' || threat.status === status);
  }).sort((a, b) => new Date(b.detectedAt) - new Date(a.detectedAt));
}
function renderOverview() {
  const counts = Object.fromEntries(Object.keys(severityColors).map(severity => [severity, state.threats.filter(threat => threat.severity === severity).length]));
  const summary = state.summary;
  $('#total-threats').textContent = summary.totalThreats ?? state.threats.length;
  $('#critical-threats').textContent = String(summary.critical ?? counts.CRITICAL).padStart(2, '0');
  $('#open-cases').textContent = String(summary.openCases ?? state.threats.filter(threat => ['DETECTED', 'INVESTIGATING'].includes(threat.status)).length).padStart(2, '0');
  $('#resolved-cases').textContent = String(summary.resolved ?? state.threats.filter(threat => threat.status === 'RESOLVED').length).padStart(2, '0');
  $('#all-count').textContent = state.threats.length;
  $('#critical-count').textContent = counts.CRITICAL;
  $('#high-count').textContent = counts.HIGH;
  $('#nav-count').textContent = state.threats.length;
  $('#donut-total').textContent = String(state.threats.length).padStart(2, '0');
  for (const severity of Object.keys(severityColors)) $(`#legend-${severity.toLowerCase()}`).textContent = counts[severity];
  const total = Math.max(1, state.threats.length);
  let currentDegree = 0;
  const segments = Object.keys(severityColors).map(severity => {
    const end = currentDegree + counts[severity] / total * 360;
    const segment = `${severityColors[severity]} ${currentDegree}deg ${end}deg`;
    currentDegree = end;
    return segment;
  });
  $('.donut').style.background = `conic-gradient(${segments.join(',')})`;
  const filtered = [...state.threats].filter(threat => state.homeFilter === 'ALL' || threat.severity === state.homeFilter).sort((a, b) => new Date(b.detectedAt) - new Date(a.detectedAt));
  const recent = filtered.slice(0, 6);
  renderRows('#threat-rows', recent);
  $('#result-count').textContent = `Showing ${recent.length} of ${filtered.length} records`;
  const channelOrder = ['SOCIAL_MEDIA', 'WEB_LINK', 'APP_STORE', 'BRAND_ASSET'];
  const channelCounts = channelOrder.map(channel => state.threats.filter(threat => threat.channel === channel).length);
  const largest = Math.max(1, ...channelCounts);
  $('#channel-list').innerHTML = channelOrder.map((channel, index) => `<div class="channel-row"><span class="channel-icon ${iconType({ channel })}">${channelIcons[channel]}</span><span class="channel-name">${channelNames[channel]}</span><span class="channel-bar"><i style="width:${Math.max(8, channelCounts[index] / largest * 100)}%"></i></span><b>${channelCounts[index]}</b></div>`).join('');
  $('#exposure-note').textContent = `${counts.CRITICAL} critical · ${counts.HIGH} high · ${counts.MEDIUM} medium · ${counts.LOW} low in the current queue.`;
}
function renderQueue() {
  const rows = filteredThreats();
  renderRows('#queue-rows', rows);
  $('#queue-result-count').textContent = `${rows.length} ${rows.length === 1 ? 'record' : 'records'}`;
}
function renderCases() {
  const countBy = status => state.threats.filter(threat => threat.status === status).length;
  $('#case-summary').innerHTML = `<article class="case-summary-card critical"><small>Detected</small><b>${countBy('DETECTED')}</b></article><article class="case-summary-card in-progress"><small>Investigating</small><b>${countBy('INVESTIGATING')}</b></article><article class="case-summary-card reported"><small>Reported</small><b>${countBy('REPORTED')}</b></article><article class="case-summary-card resolved"><small>Resolved</small><b>${countBy('RESOLVED')}</b></article>`;
  const filter = $('#case-status-filter').value;
  renderRows('#case-rows', [...state.threats].filter(threat => filter === 'ALL' || threat.status === filter).sort((a, b) => new Date(b.updatedAt || b.detectedAt) - new Date(a.updatedAt || a.detectedAt)), true);
}
function renderAssets() {
  const target = $('#asset-grid');
  if (!state.assets.length) {
    target.innerHTML = '<div class="panel empty-assets"><b>No brand assets yet</b><p>Add a brand name and domain to organize your team’s tracking list.</p></div>';
    return;
  }
  target.innerHTML = state.assets.map(asset => `<article class="asset-card"><div class="asset-card-top"><span class="asset-mark">${escapeHtml(initials(asset.name)[0] || 'B')}</span><div><h2>${escapeHtml(asset.name)}</h2><p class="domain">${escapeHtml(asset.domain)}</p></div></div><div class="asset-tags">${(asset.keywords || []).length ? asset.keywords.map(word => `<span class="asset-tag">${escapeHtml(word)}</span>`).join('') : '<span class="asset-tag">No search terms</span>'}</div><div class="asset-card-footer"><span>Added ${new Date(asset.createdAt).toLocaleDateString()}</span><button class="asset-delete" data-delete-asset="${safeId(asset.id)}">Remove</button></div></article>`).join('');
}
function renderAll() {
  renderOverview();
  renderQueue();
  renderCases();
  renderAssets();
}
function setProfile(user) {
  state.user = user;
  const name = user?.name || 'Workspace member';
  $('#profile-name').textContent = name;
  $('#profile-role').textContent = user?.role === 'admin' ? 'Workspace administrator' : 'Security analyst';
  $('#profile-avatar').textContent = initials(name);
  $('#top-avatar').textContent = initials(name);
  const hour = new Date().getHours();
  $('#greeting').innerHTML = `${hour < 12 ? 'Good morning' : hour < 18 ? 'Good afternoon' : 'Good evening'}, ${escapeHtml(name.split(' ')[0])} <span class="wave">✳</span>`;
}
function updateWorkspaceName(name) {
  $('#workspace-name-side').textContent = name;
  $('#workspace-crumb').textContent = name;
}
function updateSettingsForm(settings) {
  state.settings = settings;
  $('#settings-workspace-name').value = settings.workspaceName;
  $('#settings-timezone').value = settings.timezone || 'Asia/Kolkata';
  for (const checkbox of $$('#notifications-form input[type="checkbox"]')) checkbox.checked = Boolean(settings.notifications[checkbox.name]);
  $('#policy-phone-enabled').checked = Boolean(settings.security?.phoneOtpEnabled);
  $('#policy-passkey-enabled').checked = Boolean(settings.security?.passkeyEnabled);
  $('#policy-phone-enabled').disabled = !settings.capabilities?.phoneOtpAvailable && !settings.security?.phoneOtpEnabled;
  $('#sms-provider-status').textContent = settings.capabilities?.phoneOtpAvailable
    ? 'Twilio Verify is configured and ready for phone checks.'
    : 'Twilio Verify is not configured on the server. Add its credentials there before enabling SMS verification.';
  updateWorkspaceName(settings.workspaceName);
}
function renderAccountSecurity(details) {
  state.accountSecurity = details;
  const phoneStatus = $('#phone-verification-status');
  phoneStatus.textContent = details.phoneVerified ? `Verified phone: ${details.phoneNumber}` : 'No verified phone number is linked to this account.';
  const phoneAvailable = details.capabilities?.phoneOtpAvailable && details.policy?.phoneOtpEnabled;
  $('#phone-number-input').disabled = !phoneAvailable;
  $('#send-phone-code').disabled = !phoneAvailable;
  $('#send-phone-code').textContent = details.capabilities?.phoneOtpAvailable ? (details.policy?.phoneOtpEnabled ? 'Send verification code' : 'Phone verification is disabled') : 'SMS provider not configured';
  $('#phone-enroll-controls').hidden = details.phoneVerified;
  $('#remove-phone').hidden = !details.phoneVerified;
  $('#passkey-availability').textContent = details.policy?.passkeyEnabled ? 'Passkey sign-in is enabled by the administrator.' : 'Passkeys are not enabled by the administrator.';
  $('#add-passkey').disabled = !details.capabilities?.passkeyAvailable || !details.policy?.passkeyEnabled;
  const list = $('#passkey-list');
  list.innerHTML = details.passkeys.length ? details.passkeys.map(item => `<div class="passkey-row"><span><b>${escapeHtml(item.name || 'Device passkey')}</b><small>Added ${new Date(item.createdAt).toLocaleDateString()}</small></span><button class="member-access-button" type="button" data-remove-passkey="${safeId(item.id)}">Remove</button></div>`).join('') : '<p class="security-help">No passkeys are registered.</p>';
}
async function loadAccountSecurity() {
  renderAccountSecurity(await api('/api/auth/security'));
}
function renderUsers() {
  const target = $('#users-list');
  if (!target) return;
  if (!state.users.length) { target.innerHTML = '<p class="member-empty">No member accounts found.</p>'; return; }
  target.innerHTML = '<div class="users-table-wrap"><table class="users-table"><thead><tr><th>MEMBER</th><th>ROLE</th><th>VERIFICATION</th><th>ACCESS</th><th></th></tr></thead><tbody>' + state.users.map(user => {
    const id = safeId(user.id);
    const self = user.id === state.user?.id;
    const verification = `${user.phoneVerified ? 'Phone verified' : 'Phone not set'} · ${user.passkeyCount || 0} passkeys`;
    return '<tr><td><b>' + escapeHtml(user.name) + '</b><small>' + escapeHtml(user.email) + (self ? ' · you' : '') + '</small></td><td><select data-user-role="' + id + '" aria-label="Role for ' + escapeHtml(user.name) + '"' + (self ? ' disabled' : '') + '><option value="analyst"' + (user.role === 'analyst' ? ' selected' : '') + '>Analyst</option><option value="admin"' + (user.role === 'admin' ? ' selected' : '') + '>Admin</option></select></td><td><small>' + verification + '</small></td><td><span class="member-status ' + (user.status === 'ACTIVE' ? 'member-active' : 'member-disabled') + '">' + (user.status === 'ACTIVE' ? 'Active' : 'Disabled') + '</span></td><td><button class="member-access-button" data-toggle-user="' + id + '"' + (self ? ' disabled' : '') + '>' + (user.status === 'ACTIVE' ? 'Disable' : 'Enable') + '</button></td></tr>';
  }).join('') + '</tbody></table></div>';
}
async function loadUsers() {
  state.users = await api('/api/users');
  renderUsers();
}
async function changeUserAccess(id, changes) {
  try {
    await api('/api/users/' + encodeURIComponent(id), { method: 'PATCH', body: JSON.stringify(changes) });
    await loadUsers();
    toast('Member access updated.');
  } catch (error) {
    toast(error.message, true);
    await loadUsers().catch(() => {});
  }
}
async function loadInitial() {
  if (!state.token) { $('#login-dialog').showModal(); return; }
  try {
    const [user, summary, threats, assets, settings, accountSecurity] = await Promise.all([
      api('/api/auth/me'), api('/api/dashboard/summary'), api('/api/threats'), api('/api/brands'), api('/api/settings'), api('/api/auth/security')
    ]);
    setProfile(user);
    const isAdmin = user.role === 'admin';
    $$('[data-admin-only-settings]').forEach(card => { card.hidden = !isAdmin; });
    $('#settings-admin-readonly').hidden = isAdmin;
    $('#users-admin-only').hidden = !isAdmin;
    $('#users-readonly').hidden = isAdmin;
    if (isAdmin) await loadUsers();
    state.summary = summary;
    state.threats = threats;
    state.assets = assets;
    updateSettingsForm(settings);
    renderAccountSecurity(accountSecurity);
    $('#today-label').textContent = new Date().toLocaleDateString(undefined, { weekday: 'long', month: 'long', day: 'numeric', year: 'numeric' }).toUpperCase();
    renderAll();
    if ($('.workspace-view.active')?.dataset.viewPanel === 'analytics') loadAnalytics();
    if (window.io) connectSocket();
  } catch (error) {
    if (state.token) toast(error.message, true);
  }
}
function connectSocket() {
  state.socket?.disconnect();
  state.socket = io({ auth: { token: state.token } });
  state.socket.on('new_threat_detected', threat => {
    state.threats = [threat, ...state.threats.filter(item => item.id !== threat.id)];
    loadSummary();
    renderAll();
    toast('A new threat record was added.');
  });
  state.socket.on('threat_updated', threat => {
    state.threats = state.threats.map(item => item.id === threat.id ? threat : item);
    loadSummary();
    renderAll();
    if (state.selectedThreatId === threat.id) renderThreatDetail(threat);
  });
  state.socket.on('connect_error', error => {
    if (!state.token) return;
    if (error.message === 'Authentication required') {
      state.token = '';
      localStorage.removeItem('gravis_token');
      state.socket?.disconnect();
      const dialog = $('#login-dialog');
      if (!dialog.open) dialog.showModal();
      $('#login-error').textContent = 'Your session expired or account is inactive. Sign in again.';
      return;
    }
    toast('Live updates are unavailable. Refresh to reconnect.', true);
  });
  state.socket.on('session_invalid', event => {
    state.token = '';
    localStorage.removeItem('gravis_token');
    state.socket?.disconnect();
    const dialog = $('#login-dialog');
    if (!dialog.open) dialog.showModal();
    $('#login-error').textContent = event?.message || 'Your session ended. Sign in again.';
  });
  state.socket.on('disconnect', reason => {
    if (reason !== 'io server disconnect' || !state.token) return;
    state.token = '';
    localStorage.removeItem('gravis_token');
    const dialog = $('#login-dialog');
    if (!dialog.open) dialog.showModal();
    $('#login-error').textContent = 'Your workspace access changed. Sign in again to continue.';
  });
}
async function loadSummary() {
  try { state.summary = await api('/api/dashboard/summary'); renderOverview(); renderCases(); }
  catch (error) { if (state.token) toast(error.message, true); }
}
function showView(name) {
  const view = ['overview', 'threats', 'cases', 'assets', 'analytics', 'settings'].includes(name) ? name : 'overview';
  $$('.workspace-view').forEach(section => section.classList.toggle('active', section.dataset.viewPanel === view));
  $$('.nav-item[data-view]').forEach(link => {
    link.classList.toggle('active', link.dataset.view === view);
    if (link.dataset.view === view) link.setAttribute('aria-current', 'page'); else link.removeAttribute('aria-current');
  });
  const labels = { overview: 'Overview', threats: 'Threat intelligence', cases: 'Cases', assets: 'Brand assets', analytics: 'Analytics', settings: 'Settings' };
  $('#page-crumb').textContent = labels[view];
  if (view === 'analytics' && state.token) loadAnalytics();
  if (view === 'threats') renderQueue();
}
function setMobileNavOpen(open) {
  const sidebar = $('#workspace-sidebar');
  const toggle = $('#mobile-nav-toggle');
  sidebar.classList.toggle('expanded', open);
  toggle.setAttribute('aria-expanded', String(open));
  toggle.setAttribute('aria-label', open ? 'Close navigation' : 'Open navigation');
  toggle.textContent = open ? '×' : '☰';
}
async function updateStatus(id, status) {
  if (!statusNames[status]) return;
  try {
    const updated = await api(`/api/threats/${encodeURIComponent(id)}/status`, { method: 'PATCH', body: JSON.stringify({ status }) });
    state.threats = state.threats.map(threat => threat.id === id ? updated : threat);
    await loadSummary();
    renderAll();
    toast(`Case ${id} moved to ${statusNames[status].toLowerCase()}.`);
  } catch (error) { toast(error.message, true); renderAll(); }
}
function csvCell(value) {
  let cell = String(value ?? '');
  if (/^[\s]*[=+\-@]/.test(cell)) cell = `'${cell}`;
  return `"${cell.replaceAll('"', '""')}"`;
}
function exportThreats(rows = state.threats, filename = 'gravis-threat-report.csv') {
  const values = [['ID', 'Target', 'Channel', 'Threat type', 'Evidence URL', 'Risk score', 'Severity', 'Status', 'Notes', 'Detected at'], ...rows.map(threat => [threat.id, threat.targetName, channelNames[threat.channel] || threat.channel, threat.type, threat.threatUrl, threat.riskScore, threat.severity, statusNames[threat.status] || threat.status, (threat.notes || []).map(note => note.text).join(' | '), threat.detectedAt])];
  const csv = values.map(row => row.map(csvCell).join(',')).join('\r\n');
  const url = URL.createObjectURL(new Blob([`\uFEFF${csv}`], { type: 'text/csv;charset=utf-8' }));
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  document.body.append(anchor);
  anchor.click();
  anchor.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
  toast('CSV report exported.');
}
function openThreat(id) {
  const threat = state.threats.find(item => item.id === id);
  if (!threat) { toast('This record is no longer available.', true); return; }
  state.selectedThreatId = threat.id;
  renderThreatDetail(threat);
  $('#threat-dialog').showModal();
}
function renderThreatDetail(threat) {
  $('#detail-title').textContent = `${threat.id} · ${threat.targetName}`;
  $('#detail-body').innerHTML = `<div class="detail-facts"><div><small>Threat type</small><b>${escapeHtml(threat.type)}</b></div><div><small>Channel</small><b>${escapeHtml(channelNames[threat.channel] || threat.channel)}</b></div><div><small>Risk score</small><b><span class="severity ${threat.severity}">${threat.riskScore} · ${capitalize(threat.severity)}</span></b></div><div><small>Current status</small><b>${escapeHtml(statusNames[threat.status] || threat.status)}</b></div><div><small>Evidence URL</small>${threat.threatUrl ? `<a href="${escapeHtml(threat.threatUrl)}" target="_blank" rel="noopener noreferrer">${escapeHtml(threat.threatUrl)}</a>` : '<b>No URL recorded</b>'}</div><div><small>Record source</small><b>${escapeHtml(threat.source || 'Unknown')}</b></div><div><small>Detected</small><b>${new Date(threat.detectedAt).toLocaleString()}</b></div><div><small>Recorded by</small><b>${escapeHtml(threat.createdBy || 'System')}</b></div></div><div class="detail-status"><label for="detail-status-select">Update case status</label><select class="status-select" id="detail-status-select" data-status-id="${safeId(threat.id)}">${Object.entries(statusNames).map(([value, label]) => `<option value="${value}"${threat.status === value ? ' selected' : ''}>${label}</option>`).join('')}</select></div><h3 class="signal-heading">Risk signals</h3><div class="signal-list"><span class="signal-chip">Brand similarity: ${Number(threat.signals?.brandSimilarity) || 0}%</span><span class="signal-chip">Logo similarity: ${Number(threat.signals?.logoSimilarity) || 0}%</span><span class="signal-chip">Account age: ${Number(threat.signals?.accountAgeDays) || 0} days</span><span class="signal-chip">${threat.signals?.suspiciousUrl ? 'Suspicious URL flagged' : 'No suspicious URL flag'}</span></div>`;
  const notes = threat.notes || [];
  $('#detail-notes').innerHTML = notes.length ? [...notes].reverse().map(note => `<article class="note-item"><p>${escapeHtml(note.text)}</p><small>${escapeHtml(note.author)} · ${new Date(note.createdAt).toLocaleString()}</small></article>`).join('') : '<p class="empty-note">No notes have been added to this case.</p>';
}
async function loadAnalytics() {
  const days = $('#analytics-range').value;
  try {
    const [analytics, summary] = await Promise.all([api(`/api/analytics?days=${days}`), api('/api/dashboard/summary')]);
    $('#analytics-total').textContent = analytics.total;
    $('#analytics-open').textContent = summary.openCases;
    $('#analytics-brands').textContent = summary.brandAssets;
    $('#analytics-resolved').textContent = analytics.status.RESOLVED || 0;
    const daily = analytics.daily || [];
    const peak = Math.max(1, ...daily.map(day => day.count));
    $('#daily-chart').innerHTML = daily.map((day, index) => {
      const height = Math.max(2, day.count / peak * 100);
      const displayLabel = index % Math.ceil(daily.length / 8) === 0 || index === daily.length - 1 ? new Date(`${day.date}T00:00:00`).toLocaleDateString(undefined, { month: 'short', day: 'numeric' }) : '';
      return `<div class="bar-column" title="${day.date}: ${day.count} record${day.count === 1 ? '' : 's'}"><i style="height:${height}%"></i><span>${escapeHtml(displayLabel)}</span></div>`;
    }).join('');
    renderBreakdown('#analytics-severity', analytics.severity, Object.keys(severityColors), severityColors);
    const channels = ['SOCIAL_MEDIA', 'WEB_LINK', 'APP_STORE', 'BRAND_ASSET'];
    renderBreakdown('#analytics-channels', analytics.channel, channels, { SOCIAL_MEDIA: '#8b69bf', WEB_LINK: '#6594dc', APP_STORE: '#56a87e', BRAND_ASSET: '#d09a58' }, channelNames);
  } catch (error) { toast(error.message, true); }
}
function renderBreakdown(selector, values, keys, colors, labels = {}) {
  const maximum = Math.max(1, ...keys.map(key => values[key] || 0));
  $(selector).innerHTML = `<div class="breakdown-list">${keys.map(key => `<div class="breakdown-row"><span>${escapeHtml(labels[key] || capitalize(key))}</span><span class="breakdown-track"><i style="width:${Math.max(3, (values[key] || 0) / maximum * 100)}%;background:${colors[key]}"></i></span><b>${values[key] || 0}</b></div>`).join('')}</div>`;
}

$$('[data-view]').forEach(element => element.addEventListener('click', event => {
  event.preventDefault();
  showView(element.dataset.view);
  if (element.tagName === 'A') history.replaceState(null, '', `#${element.dataset.view}`);
  setMobileNavOpen(false);
}));
$('#mobile-nav-toggle').addEventListener('click', () => setMobileNavOpen(!$('#workspace-sidebar').classList.contains('expanded')));
$('#main-content').addEventListener('click', () => {
  if ($('#workspace-sidebar').classList.contains('expanded')) setMobileNavOpen(false);
});
document.addEventListener('keydown', event => {
  if (event.key === 'Escape' && $('#workspace-sidebar').classList.contains('expanded')) setMobileNavOpen(false);
});
$$('[data-open-investigation]').forEach(button => button.addEventListener('click', () => $('#investigation-dialog').showModal()));
$$('[data-close-dialog]').forEach(button => button.addEventListener('click', () => $(`#${button.dataset.closeDialog}`).close()));
$('#export-btn').addEventListener('click', () => exportThreats());
$('#queue-export').addEventListener('click', () => exportThreats(filteredThreats(), 'gravis-threat-queue.csv'));
$('#notifications-button').addEventListener('click', () => showView('settings'));
$('#add-asset-button').addEventListener('click', () => $('#asset-dialog').showModal());
$('#threat-search').addEventListener('input', renderQueue);
$('#severity-filter').addEventListener('change', renderQueue);
$('#channel-filter').addEventListener('change', renderQueue);
$('#status-filter').addEventListener('change', renderQueue);
$('#case-status-filter').addEventListener('change', renderCases);
$('#analytics-range').addEventListener('change', loadAnalytics);
$('#clear-filters').addEventListener('click', () => {
  $('#threat-search').value = '';
  $('#severity-filter').value = 'ALL';
  $('#channel-filter').value = 'ALL';
  $('#status-filter').value = 'ALL';
  renderQueue();
});
$$('.filter[data-filter]').forEach(button => button.addEventListener('click', () => {
  $$('.filter[data-filter]').forEach(item => item.classList.toggle('active', item === button));
  state.homeFilter = button.dataset.filter;
  renderOverview();
}));
document.addEventListener('click', event => {
  const openButton = event.target.closest('[data-open-threat]');
  if (openButton) openThreat(openButton.dataset.openThreat);
  const deleteButton = event.target.closest('[data-delete-asset]');
  if (deleteButton) removeAsset(deleteButton.dataset.deleteAsset);
});
document.addEventListener('change', event => {
  const statusSelect = event.target.closest('[data-status-id]');
  if (statusSelect) updateStatus(statusSelect.dataset.statusId, statusSelect.value);
});

function decodeBase64url(value) {
  const base64 = String(value).replace(/-/g, '+').replace(/_/g, '/');
  const binary = atob(base64 + '='.repeat((4 - base64.length % 4) % 4));
  return Uint8Array.from(binary, character => character.charCodeAt(0));
}
function encodeBase64url(value) {
  const bytes = new Uint8Array(value);
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}
function publicKeyOptions(options, registration = false) {
  const converted = { ...options, challenge: decodeBase64url(options.challenge) };
  if (registration) converted.user = { ...options.user, id: decodeBase64url(options.user.id) };
  for (const name of ['allowCredentials', 'excludeCredentials']) {
    if (options[name]) converted[name] = options[name].map(item => ({ ...item, id: decodeBase64url(item.id) }));
  }
  return converted;
}
function credentialPayload(credential) {
  const response = credential.response;
  const result = { id: credential.id, rawId: encodeBase64url(credential.rawId), type: credential.type, authenticatorAttachment: credential.authenticatorAttachment, clientExtensionResults: credential.getClientExtensionResults() };
  if ('attestationObject' in response) {
    result.response = { clientDataJSON: encodeBase64url(response.clientDataJSON), attestationObject: encodeBase64url(response.attestationObject), transports: response.getTransports?.() || [] };
  } else {
    result.response = { authenticatorData: encodeBase64url(response.authenticatorData), clientDataJSON: encodeBase64url(response.clientDataJSON), signature: encodeBase64url(response.signature), userHandle: response.userHandle ? encodeBase64url(response.userHandle) : null };
  }
  return result;
}
function showLoginChallenge(data) {
  state.pendingLogin = { challengeId: data.challengeId, requiredFactors: data.requiredFactors, verifiedFactors: data.verifiedFactors || [] };
  $('#login-form').hidden = true;
  $('#login-factor-step').hidden = false;
  const phonePending = data.requiredFactors.includes('phone') && !state.pendingLogin.verifiedFactors.includes('phone');
  const passkeyPending = data.requiredFactors.includes('passkey') && !state.pendingLogin.verifiedFactors.includes('passkey');
  $('#login-phone-factor').hidden = !phonePending;
  $('#login-passkey-button').hidden = !passkeyPending;
  $('#login-factor-instructions').textContent = [phonePending ? 'Enter the code sent to your verified phone.' : '', passkeyPending ? 'Use a registered passkey on this device.' : ''].filter(Boolean).join(' ');
  $('#login-verification-error').textContent = '';
}
async function acceptLoginResult(data) {
  if (!data.token) { showLoginChallenge(data); return; }
  state.pendingLogin = null;
  state.token = data.token;
  localStorage.setItem('gravis_token', data.token);
  $('#login-factor-step').hidden = true;
  $('#login-form').hidden = false;
  $('#login-form').reset();
  $('#login-dialog').close();
  await loadInitial();
}

$('#login-form').addEventListener('submit', async event => {
  event.preventDefault();
  const values = new FormData(event.currentTarget);
  $('#login-error').textContent = '';
  const submit = event.currentTarget.querySelector('button[type="submit"],button:not([type])');
  if (submit) submit.disabled = true;
  try {
    const data = await api('/api/auth/login', { method: 'POST', body: JSON.stringify({ email: values.get('email'), password: values.get('password') }) });
    await acceptLoginResult(data);
  } catch (error) { $('#login-error').textContent = error.message; }
  finally { if (submit) submit.disabled = false; }
});
$('#submit-login-phone-code').addEventListener('click', async () => {
  if (!state.pendingLogin) return;
  const button = $('#submit-login-phone-code');
  button.disabled = true;
  $('#login-verification-error').textContent = '';
  try {
    const data = await api('/api/auth/login/phone-check', { method: 'POST', body: JSON.stringify({ challengeId: state.pendingLogin.challengeId, code: $('#login-phone-code').value.trim() }) });
    await acceptLoginResult(data);
  } catch (error) { $('#login-verification-error').textContent = error.message; }
  finally { button.disabled = false; }
});
$('#login-passkey-button').addEventListener('click', async () => {
  if (!state.pendingLogin || !window.PublicKeyCredential || !navigator.credentials?.get) { $('#login-verification-error').textContent = 'Passkeys are not supported by this browser.'; return; }
  const button = $('#login-passkey-button');
  button.disabled = true;
  $('#login-verification-error').textContent = '';
  try {
    const options = await api('/api/auth/login/passkey-options', { method: 'POST', body: JSON.stringify({ challengeId: state.pendingLogin.challengeId }) });
    const credential = await navigator.credentials.get({ publicKey: publicKeyOptions(options) });
    if (!credential) throw new Error('Passkey verification was cancelled.');
    const data = await api('/api/auth/login/passkey-check', { method: 'POST', body: JSON.stringify({ challengeId: state.pendingLogin.challengeId, ...credentialPayload(credential) }) });
    await acceptLoginResult(data);
  } catch (error) { $('#login-verification-error').textContent = error.message || 'Passkey verification failed.'; }
  finally { button.disabled = false; }
});
$('#restart-login').addEventListener('click', () => {
  state.pendingLogin = null;
  $('#login-factor-step').hidden = true;
  $('#login-form').hidden = false;
  $('#login-form').reset();
  $('#login-error').textContent = '';
});
$('#signout').addEventListener('click', () => {
  state.socket?.disconnect();
  state.token = '';
  localStorage.removeItem('gravis_token');
  location.reload();
});

$('#investigation-form').addEventListener('submit', async event => {
  event.preventDefault();
  const data = new FormData(event.currentTarget);
  const payload = {
    targetName: data.get('targetName'), channel: data.get('channel'), type: data.get('type'), threatUrl: data.get('threatUrl'),
    signals: { brandSimilarity: Number(data.get('brandSimilarity')), logoSimilarity: Number(data.get('logoSimilarity')), suspiciousUrl: data.get('suspiciousUrl') === 'on', accountAgeDays: Number(data.get('accountAgeDays')) }
  };
  const submit = event.currentTarget.querySelector('button[type="submit"],button:not([type])');
  if (submit) submit.disabled = true;
  try {
    const threat = await api('/api/threats', { method: 'POST', body: JSON.stringify(payload) });
    state.threats = [threat, ...state.threats.filter(item => item.id !== threat.id)];
    state.summary = await api('/api/dashboard/summary');
    renderAll();
    event.currentTarget.reset();
    $('#investigation-dialog').close();
    toast(`Investigation ${threat.id} saved with a ${threat.severity.toLowerCase()} score.`);
  } catch (error) { toast(error.message, true); }
  finally { if (submit) submit.disabled = false; }
});
$('#asset-form').addEventListener('submit', async event => {
  event.preventDefault();
  const data = new FormData(event.currentTarget);
  const payload = { name: data.get('name'), domain: data.get('domain'), keywords: String(data.get('keywords') || '').split(',').map(word => word.trim()).filter(Boolean) };
  const submit = event.currentTarget.querySelector('button[type="submit"],button:not([type])');
  if (submit) submit.disabled = true;
  try {
    state.assets.push(await api('/api/brands', { method: 'POST', body: JSON.stringify(payload) }));
    state.summary = await api('/api/dashboard/summary');
    renderAssets();
    event.currentTarget.reset();
    $('#asset-dialog').close();
    toast('Brand asset added to the workspace.');
  } catch (error) { toast(error.message, true); }
  finally { if (submit) submit.disabled = false; }
});
async function removeAsset(id) {
  if (!window.confirm('Remove this brand asset from the workspace?')) return;
  try {
    await api(`/api/brands/${encodeURIComponent(id)}`, { method: 'DELETE' });
    state.assets = state.assets.filter(asset => asset.id !== id);
    renderAssets();
    toast('Brand asset removed.');
  } catch (error) { toast(error.message, true); }
}
$('#note-form').addEventListener('submit', async event => {
  event.preventDefault();
  const text = new FormData(event.currentTarget).get('text');
  const id = state.selectedThreatId;
  if (!id) return;
  try {
    await api(`/api/threats/${encodeURIComponent(id)}/notes`, { method: 'POST', body: JSON.stringify({ text }) });
    const threat = await api(`/api/threats/${encodeURIComponent(id)}`);
    state.threats = state.threats.map(item => item.id === threat.id ? threat : item);
    event.currentTarget.reset();
    renderThreatDetail(threat);
    renderAll();
    toast('Case note saved.');
  } catch (error) { toast(error.message, true); }
});
$('#settings-form').addEventListener('submit', async event => {
  event.preventDefault();
  const button = event.currentTarget.querySelector('button');
  button.disabled = true;
  try {
    const settings = await api('/api/settings', { method: 'PATCH', body: JSON.stringify({ workspaceName: $('#settings-workspace-name').value.trim(), notifications: state.settings.notifications }) });
    updateSettingsForm(settings);
    $('#settings-save-state').textContent = 'Saved';
    setTimeout(() => { $('#settings-save-state').textContent = ''; }, 2500);
    toast('Workspace settings saved.');
  } catch (error) { toast(error.message, true); }
  finally { button.disabled = false; }
});
$('#notifications-form').addEventListener('submit', async event => {
  event.preventDefault();
  const button = event.currentTarget.querySelector('button');
  button.disabled = true;
  const notifications = Object.fromEntries([...event.currentTarget.querySelectorAll('input[type="checkbox"]')].map(input => [input.name, input.checked]));
  try {
    const settings = await api('/api/settings', { method: 'PATCH', body: JSON.stringify({ workspaceName: $('#settings-workspace-name').value.trim(), notifications }) });
    updateSettingsForm(settings);
    $('#notifications-save-state').textContent = 'Saved';
    setTimeout(() => { $('#notifications-save-state').textContent = ''; }, 2500);
    toast('Notification preferences saved.');
  } catch (error) { toast(error.message, true); }
  finally { button.disabled = false; }
});
$('#security-policy-form').addEventListener('submit', async event => {
  event.preventDefault();
  const button = event.currentTarget.querySelector('button');
  button.disabled = true;
  const security = { phoneOtpEnabled: $('#policy-phone-enabled').checked, passkeyEnabled: $('#policy-passkey-enabled').checked };
  try {
    const settings = await api('/api/settings', { method: 'PATCH', body: JSON.stringify({ workspaceName: $('#settings-workspace-name').value.trim(), notifications: state.settings.notifications, security }) });
    updateSettingsForm(settings);
    await loadAccountSecurity();
    $('#security-policy-state').textContent = 'Saved';
    setTimeout(() => { $('#security-policy-state').textContent = ''; }, 2500);
    toast('Verification policy saved.');
  } catch (error) { toast(error.message, true); }
  finally { button.disabled = false; }
});
$('#send-phone-code').addEventListener('click', async () => {
  const button = $('#send-phone-code');
  button.disabled = true;
  $('#account-security-state').textContent = '';
  try {
    await api('/api/auth/phone/send', { method: 'POST', body: JSON.stringify({ phoneNumber: $('#phone-number-input').value.trim() }) });
    $('#phone-code-controls').hidden = false;
    $('#phone-code-input').focus();
    $('#account-security-state').textContent = 'Code sent. It expires in 10 minutes.';
  } catch (error) { $('#account-security-state').textContent = error.message; }
  finally { button.disabled = !state.accountSecurity?.capabilities?.phoneOtpAvailable || !state.accountSecurity?.policy?.phoneOtpEnabled; }
});
$('#verify-phone-code').addEventListener('click', async () => {
  const button = $('#verify-phone-code');
  button.disabled = true;
  try {
    await api('/api/auth/phone/check', { method: 'POST', body: JSON.stringify({ code: $('#phone-code-input').value.trim() }) });
    $('#phone-code-controls').hidden = true;
    $('#phone-number-input').value = '';
    await loadAccountSecurity();
    if (state.user?.role === 'admin') await loadUsers();
    $('#account-security-state').textContent = 'Phone number verified.';
  } catch (error) { $('#account-security-state').textContent = error.message; }
  finally { button.disabled = false; }
});
$('#remove-phone').addEventListener('click', async () => {
  try {
    await api('/api/auth/phone', { method: 'DELETE' });
    await loadAccountSecurity();
    if (state.user?.role === 'admin') await loadUsers();
    $('#account-security-state').textContent = 'Verified phone removed.';
  } catch (error) { toast(error.message, true); }
});
$('#add-passkey').addEventListener('click', async () => {
  const button = $('#add-passkey');
  if (!window.PublicKeyCredential || !navigator.credentials?.create) { $('#account-security-state').textContent = 'This browser does not support device passkeys.'; return; }
  button.disabled = true;
  $('#account-security-state').textContent = '';
  try {
    const options = await api('/api/auth/passkeys/register-options', { method: 'POST', body: JSON.stringify({}) });
    const credential = await navigator.credentials.create({ publicKey: publicKeyOptions(options, true) });
    if (!credential) throw new Error('Passkey setup was cancelled.');
    await api('/api/auth/passkeys/register', { method: 'POST', body: JSON.stringify({ ...credentialPayload(credential), name: 'Device passkey' }) });
    await loadAccountSecurity();
    if (state.user?.role === 'admin') await loadUsers();
    $('#account-security-state').textContent = 'Passkey added to your account.';
  } catch (error) { $('#account-security-state').textContent = error.message || 'Passkey setup failed.'; }
  finally { button.disabled = !state.accountSecurity?.capabilities?.passkeyAvailable || !state.accountSecurity?.policy?.passkeyEnabled; }
});
$('#passkey-list').addEventListener('click', async event => {
  const button = event.target.closest('[data-remove-passkey]');
  if (!button) return;
  button.disabled = true;
  try {
    await api(`/api/auth/passkeys/${encodeURIComponent(button.dataset.removePasskey)}`, { method: 'DELETE' });
    await loadAccountSecurity();
    if (state.user?.role === 'admin') await loadUsers();
    $('#account-security-state').textContent = 'Passkey removed.';
  } catch (error) { toast(error.message, true); button.disabled = false; }
});
$('#password-form').addEventListener('submit', async event => {
  event.preventDefault();
  const button = event.currentTarget.querySelector('button');
  button.disabled = true;
  const values = new FormData(event.currentTarget);
  try {
    await api('/api/auth/change-password', { method: 'POST', body: JSON.stringify({ currentPassword: values.get('currentPassword'), newPassword: values.get('newPassword') }) });
    event.currentTarget.reset();
    $('#password-save-state').textContent = 'Updated · sign in again';
    setTimeout(() => { $('#password-save-state').textContent = ''; }, 2500);
    state.token = '';
    localStorage.removeItem('gravis_token');
    state.socket?.disconnect();
    const dialog = $('#login-dialog');
    if (!dialog.open) dialog.showModal();
    $('#login-error').textContent = 'Password updated. Sign in again to continue.';
  } catch (error) { toast(error.message, true); }
  finally { button.disabled = false; }
});
$('#user-create-form').addEventListener('submit', async event => {
  event.preventDefault();
  const form = event.currentTarget;
  const button = form.querySelector('button');
  const values = new FormData(form);
  button.disabled = true;
  try {
    await api('/api/users', { method: 'POST', body: JSON.stringify({ name: values.get('name'), email: values.get('email'), password: values.get('password'), role: values.get('role') }) });
    form.reset();
    $('#user-create-state').textContent = 'Created';
    setTimeout(() => { $('#user-create-state').textContent = ''; }, 2500);
    await loadUsers();
    toast('Member account created. They can sign in with the details you set.');
  } catch (error) { toast(error.message, true); }
  finally { button.disabled = false; }
});
$('#users-list').addEventListener('change', event => {
  const select = event.target.closest('[data-user-role]');
  if (select) changeUserAccess(select.dataset.userRole, { role: select.value });
});
$('#users-list').addEventListener('click', event => {
  const button = event.target.closest('[data-toggle-user]');
  if (!button) return;
  const user = state.users.find(row => row.id === button.dataset.toggleUser);
  if (user) changeUserAccess(user.id, { status: user.status === 'ACTIVE' ? 'DISABLED' : 'ACTIVE' });
});
$('#threat-dialog').addEventListener('close', () => { state.selectedThreatId = null; });

if (location.hash.startsWith('#')) showView(location.hash.slice(1));
loadModeIndicator();
loadInitial();
