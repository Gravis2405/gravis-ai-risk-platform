const express = require('express');
const http = require('http');
const helmet = require('helmet');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const morgan = require('morgan');
const { Server } = require('socket.io');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { Pool } = require('pg');

const envFile = path.join(__dirname, '.env');
if (fs.existsSync(envFile)) {
  for (const line of fs.readFileSync(envFile, 'utf8').split(/\r?\n/)) {
    const match = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)\s*$/);
    if (!match || match[1] in process.env) continue;
    const value = match[2].replace(/^(['"])(.*)\1$/, '$2').trim();
    process.env[match[1]] = value;
  }
}

const app = express();
const server = http.createServer(app);
const PORT = Number(process.env.PORT || 5000);
const production = process.env.NODE_ENV === 'production';
const JWT_SECRET = process.env.JWT_SECRET || (!production ? 'local-demo-only-change-before-deploy-please' : '');
if (!JWT_SECRET || (production && JWT_SECRET.length < 32)) throw new Error('Set a JWT_SECRET of at least 32 characters before production startup.');
if (production && !process.env.APP_ORIGIN) throw new Error('Set APP_ORIGIN to the deployed HTTPS origin before production startup.');
if (production && (!process.env.INGEST_API_KEY || process.env.INGEST_API_KEY.length < 32)) throw new Error('Set a separate INGEST_API_KEY of at least 32 characters before production startup.');
const productionOrigins = String(process.env.APP_ORIGIN || '').split(',').map(value => value.trim()).filter(Boolean);
if (production && productionOrigins.some(origin => {
  try { const parsed = new URL(origin); return parsed.protocol !== 'https:' || parsed.origin !== origin; }
  catch { return true; }
})) throw new Error('APP_ORIGIN must contain only exact HTTPS origins, without paths or trailing slashes.');

const allowedOrigins = (process.env.APP_ORIGIN || `http://localhost:${PORT}`).split(',').map(value => value.trim()).filter(Boolean);
const io = new Server(server, { cors: { origin: allowedOrigins } });
const dataDirectory = path.join(__dirname, 'data');
const dataFile = process.env.DATA_FILE || path.join(dataDirectory, 'gravis.json');
const postgresPool = process.env.DATABASE_URL ? new Pool({ connectionString: process.env.DATABASE_URL, max: 3, idleTimeoutMillis: 10000 }) : null;
const now = Date.now();
const seedThreats = [
  { id: 'GR-1042', targetName: 'Northstar Bank', channel: 'SOCIAL_MEDIA', type: 'Impersonation account', threatUrl: 'https://social.example/northstar_support', signals: { brandSimilarity: 91, logoSimilarity: 88, suspiciousUrl: true, accountAgeDays: 3 }, riskScore: 94, severity: 'CRITICAL', status: 'DETECTED', source: 'Demo seed', notes: [], detectedAt: new Date(now - 8 * 60000).toISOString() },
  { id: 'GR-1041', targetName: 'Aster Cloud', channel: 'WEB_LINK', type: 'Credential phishing', threatUrl: 'https://aster-cloud-login.example', signals: { brandSimilarity: 84, logoSimilarity: 79, suspiciousUrl: true, accountAgeDays: 12 }, riskScore: 79, severity: 'HIGH', status: 'INVESTIGATING', source: 'Demo seed', notes: [], detectedAt: new Date(now - 43 * 60000).toISOString() },
  { id: 'GR-1040', targetName: 'LumenPay', channel: 'APP_STORE', type: 'Look-alike application', threatUrl: 'https://apps.example/lumen-wallet-pro', signals: { brandSimilarity: 73, logoSimilarity: 81, suspiciousUrl: false, accountAgeDays: 25 }, riskScore: 56, severity: 'MEDIUM', status: 'DETECTED', source: 'Demo seed', notes: [], detectedAt: new Date(now - 2 * 3600000).toISOString() },
  { id: 'GR-1039', targetName: 'Northstar Bank', channel: 'BRAND_ASSET', type: 'Logo misuse', threatUrl: 'https://cdn.example/northstar-mark.png', signals: { brandSimilarity: 61, logoSimilarity: 70, suspiciousUrl: false, accountAgeDays: 90 }, riskScore: 39, severity: 'MEDIUM', status: 'REPORTED', source: 'Demo seed', notes: [], detectedAt: new Date(now - 5 * 3600000).toISOString() },
  { id: 'GR-1038', targetName: 'Aster Cloud', channel: 'SOCIAL_MEDIA', type: 'Impersonation account', threatUrl: 'https://social.example/astercloud_help', signals: { brandSimilarity: 49, logoSimilarity: 52, suspiciousUrl: false, accountAgeDays: 48 }, riskScore: 30, severity: 'LOW', status: 'RESOLVED', source: 'Demo seed', notes: [], detectedAt: new Date(now - 20 * 3600000).toISOString() }
];
const seedAssets = [
  { id: 'asset-northstar', name: 'Northstar Bank', domain: 'northstar.example', keywords: ['Northstar', 'Northstar Bank', 'Northstar Support'], assetType: 'Brand', createdAt: new Date(now - 28 * 86400000).toISOString() },
  { id: 'asset-aster', name: 'Aster Cloud', domain: 'aster.example', keywords: ['Aster Cloud', 'AsterCloud', 'Aster Support'], assetType: 'Brand', createdAt: new Date(now - 17 * 86400000).toISOString() },
  { id: 'asset-lumen', name: 'LumenPay', domain: 'lumenpay.example', keywords: ['LumenPay', 'Lumen Pay', 'Lumen Wallet'], assetType: 'Brand', createdAt: new Date(now - 9 * 86400000).toISOString() }
];

if (!postgresPool) fs.mkdirSync(path.dirname(dataFile), { recursive: true });
const demoUser = { id: 'demo-analyst', email: 'analyst@gravis.demo', name: 'Alex Morgan', role: 'admin', passwordHash: bcrypt.hashSync('GravisDemo!2026', 10), status: 'ACTIVE' };
const defaultSettings = () => ({ workspaceName: 'GRAVIS AI Workspace', timezone: 'Asia/Kolkata', notifications: { critical: true, dailyDigest: false, caseUpdates: true } });
function prepareDb(state) {
  if (!state || !Array.isArray(state.users) || !Array.isArray(state.threats) || !Array.isArray(state.brandAssets)) throw new Error('Invalid data structure');
  if (!Array.isArray(state.registrations)) state.registrations = [];
  if (!state.settings || typeof state.settings !== 'object') state.settings = defaultSettings();
  if (!state.settings.notifications) state.settings.notifications = defaultSettings().notifications;
  if (production) {
    state.users = state.users.filter(user => user.email !== demoUser.email);
    state.threats = state.threats.filter(threat => threat.source !== 'Demo seed');
    state.brandAssets = state.brandAssets.filter(asset => !String(asset.id).startsWith('asset-'));
    if (!state.users.length) {
      const email = String(process.env.INITIAL_ADMIN_EMAIL || '').trim().toLowerCase();
      const password = process.env.INITIAL_ADMIN_PASSWORD;
      if (!/^\S+@\S+\.\S+$/.test(email) || !isStrongPassword(password)) throw new Error('For first production startup, set INITIAL_ADMIN_EMAIL and a strong INITIAL_ADMIN_PASSWORD. Remove both variables after the administrator is created.');
      state.users.push({ id: crypto.randomUUID(), email, name: 'Workspace Administrator', role: 'admin', passwordHash: bcrypt.hashSync(password, 12), status: 'ACTIVE', createdAt: new Date().toISOString() });
    }
    if (!state.users.some(user => user.role === 'admin' && user.status === 'ACTIVE')) throw new Error('Production startup requires at least one active workspace administrator.');
  } else if (!state.users.some(user => user.email === demoUser.email)) {
    state.users.push(demoUser);
  }
  for (const threat of state.threats) if (!Array.isArray(threat.notes)) threat.notes = [];
  return state;
}

function emptyDb() {
  return { version: 1, users: [], registrations: [], threats: production ? [] : seedThreats, brandAssets: production ? [] : seedAssets, settings: defaultSettings() };
}

let db;
if (postgresPool) {
  db = prepareDb(emptyDb());
} else if (fs.existsSync(dataFile)) {
  try {
    db = prepareDb(JSON.parse(fs.readFileSync(dataFile, 'utf8')));
  } catch (error) {
    throw new Error(`Could not read ${dataFile}: ${error.message}`);
  }
} else {
  db = prepareDb(emptyDb());
}
let saveQueue = Promise.resolve();
function persist() {
  const snapshot = JSON.stringify(db);
  saveQueue = saveQueue.catch(() => {}).then(async () => {
    if (postgresPool) {
      await postgresPool.query(
        'INSERT INTO gravis_workspace_state (id, state) VALUES (1, $1::jsonb) ON CONFLICT (id) DO UPDATE SET state = EXCLUDED.state, updated_at = NOW()',
        [snapshot]
      );
      return;
    }
    const temporary = `${dataFile}.${process.pid}.tmp`;
    await fs.promises.writeFile(temporary, JSON.stringify(db, null, 2), { mode: 0o600 });
    await fs.promises.rename(temporary, dataFile);
  });
  return saveQueue;
}

app.use(helmet({ contentSecurityPolicy: { directives: { defaultSrc: ["'self'"], scriptSrc: ["'self'"], styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'], fontSrc: ["'self'", 'https://fonts.gstatic.com', 'data:'], connectSrc: ["'self'", 'ws:', 'wss:'], imgSrc: ["'self'", 'data:'], objectSrc: ["'none'"], frameAncestors: ["'none'"] } } }));
app.use(express.json({ limit: '32kb' }));
app.use(morgan('tiny'));
if (production) app.set('trust proxy', 1);
app.use(express.static(path.join(__dirname, 'public')));

const loginAttempts = new Map();
const channels = new Set(['SOCIAL_MEDIA', 'APP_STORE', 'WEB_LINK', 'BRAND_ASSET']);
const severities = new Set(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']);
const statuses = new Set(['DETECTED', 'INVESTIGATING', 'REPORTED', 'RESOLVED']);
const safeText = (value, max = 180) => typeof value === 'string' ? value.trim().slice(0, max) : '';
const publicUser = user => ({ email: user.email, name: user.name, role: user.role });
function isStrongPassword(value) {
  return typeof value === 'string' && value.length >= 12 && value.length <= 128 && /[a-z]/.test(value) && /[A-Z]/.test(value) && /[0-9]/.test(value) && /[^A-Za-z0-9]/.test(value);
}
const userListItem = user => ({ id: user.id, email: user.email, name: user.name, role: user.role, status: user.status, createdAt: user.createdAt || null });

function scoreRisk(signals = {}) {
  const bounded = (value, name) => {
    const number = Number(value ?? 0);
    if (!Number.isFinite(number) || number < 0 || number > 100) throw new Error(`${name} must be a number from 0 to 100`);
    return number;
  };
  const brand = bounded(signals.brandSimilarity, 'brandSimilarity');
  const logo = bounded(signals.logoSimilarity, 'logoSimilarity');
  const age = Number(signals.accountAgeDays ?? 9999);
  if (!Number.isFinite(age) || age < 0 || age > 36500) throw new Error('accountAgeDays must be a number from 0 to 36500');
  const suspicious = signals.suspiciousUrl === true;
  const agePoints = age <= 7 ? 20 : age <= 30 ? 10 : 0;
  const riskScore = Math.min(100, Math.round(brand * 0.35 + logo * 0.25 + (suspicious ? 20 : 0) + agePoints));
  const severity = riskScore >= 85 ? 'CRITICAL' : riskScore >= 71 ? 'HIGH' : riskScore >= 31 ? 'MEDIUM' : 'LOW';
  return { riskScore, severity };
}
function authenticate(req, res, next) {
  const token = (req.headers.authorization || '').match(/^Bearer\s+(.+)$/i)?.[1];
  if (!token) return res.status(401).json({ error: 'Sign in to continue.' });
  try {
    const payload = jwt.verify(token, JWT_SECRET, { issuer: 'gravis-ai' });
    const user = db.users.find(row => row.id === payload.sub && row.status === 'ACTIVE');
    if (!user) return res.status(401).json({ error: 'Your account is not active.' });
    req.user = user;
    next();
  } catch { return res.status(401).json({ error: 'Your session is invalid or expired.' }); }
}
function requireAdmin(req, res, next) {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Workspace administrator access is required.' });
  next();
}
function validUrl(value) {
  if (!value) return true;
  try { return ['http:', 'https:'].includes(new URL(value).protocol); } catch { return false; }
}
function summary() {
  const count = severity => db.threats.filter(threat => threat.severity === severity).length;
  return {
    totalThreats: db.threats.length,
    critical: count('CRITICAL'),
    high: count('HIGH'),
    openCases: db.threats.filter(threat => ['DETECTED', 'INVESTIGATING'].includes(threat.status)).length,
    resolved: db.threats.filter(threat => threat.status === 'RESOLVED').length,
    reported: db.threats.filter(threat => threat.status === 'REPORTED').length,
    brandAssets: db.brandAssets.length,
    trend: null
  };
}
function validateThreat(body = {}) {
  const targetName = safeText(body.targetName, 100);
  const channel = body.channel;
  const type = safeText(body.type, 120);
  const threatUrl = safeText(body.threatUrl, 1000);
  if (!targetName || !channels.has(channel) || !type || !validUrl(threatUrl)) throw new Error('Provide a target, supported channel, threat type, and valid HTTP or HTTPS URL.');
  const signals = body.signals || {};
  const scored = scoreRisk(signals);
  return { targetName, channel, type, threatUrl, signals: { brandSimilarity: Number(signals.brandSimilarity || 0), logoSimilarity: Number(signals.logoSimilarity || 0), suspiciousUrl: signals.suspiciousUrl === true, accountAgeDays: Number(signals.accountAgeDays ?? 9999) }, ...scored };
}
async function addThreat(body, source, user) {
  const validated = validateThreat(body);
  const id = `GR-${String(Date.now()).slice(-6)}${crypto.randomInt(10, 99)}`;
  const threat = { id, ...validated, source, status: 'DETECTED', notes: [], detectedAt: new Date().toISOString(), createdBy: user?.name || 'Ingestion API' };
  db.threats.unshift(threat);
  await persist();
  io.emit('new_threat_detected', threat);
  return threat;
}

app.get('/api/health', (_req, res) => res.json({ status: 'ok', mode: production ? 'production' : 'demo', storage: postgresPool ? 'postgresql' : 'persistent-json' }));
app.post('/api/auth/login', async (req, res) => {
  const ip = req.ip || 'unknown';
  const window = loginAttempts.get(ip) || { count: 0, resetAt: Date.now() + 15 * 60 * 1000 };
  if (window.resetAt <= Date.now()) { window.count = 0; window.resetAt = Date.now() + 15 * 60 * 1000; }
  if (window.count >= 10) return res.status(429).json({ error: 'Too many sign-in attempts. Wait a few minutes and try again.' });
  const email = safeText(req.body?.email, 254).toLowerCase();
  const password = req.body?.password;
  const user = db.users.find(row => row.email === email && row.status === 'ACTIVE');
  if (!user || typeof password !== 'string' || !(await bcrypt.compare(password, user.passwordHash))) {
    window.count += 1; loginAttempts.set(ip, window);
    return res.status(401).json({ error: 'Email or password is incorrect.' });
  }
  loginAttempts.delete(ip);
  const token = jwt.sign({ sub: user.id, role: user.role }, JWT_SECRET, { expiresIn: '8h', issuer: 'gravis-ai' });
  res.json({ token, user: publicUser(user) });
});
app.post('/api/auth/register', async (req, res) => {
  if (production) return res.status(403).json({ error: 'Self-registration is disabled. Ask a workspace administrator to create an account.' });
  const name = safeText(req.body?.name, 100);
  const email = safeText(req.body?.email, 254).toLowerCase();
  const password = req.body?.password;
  if (!name || !/^\S+@\S+\.\S+$/.test(email) || typeof password !== 'string' || password.length < 12 || !/[a-z]/.test(password) || !/[A-Z]/.test(password) || !/[0-9]/.test(password) || !/[^A-Za-z0-9]/.test(password)) return res.status(422).json({ error: 'Use a valid email and a 12-character password with upper, lower, number, and symbol.' });
  if (db.users.some(user => user.email === email) || db.registrations.some(user => user.email === email)) return res.status(409).json({ error: 'An account with that email already exists.' });
  db.registrations.push({ id: crypto.randomUUID(), name, email, passwordHash: await bcrypt.hash(password, 12), status: 'PENDING_VERIFICATION', createdAt: new Date().toISOString() });
  await persist();
  res.status(201).json({ status: 'PENDING_VERIFICATION', message: 'Registration received. Email verification is not connected in this demo, so this account cannot sign in yet.' });
});
app.get('/api/auth/me', authenticate, (req, res) => res.json(publicUser(req.user)));
app.post('/api/auth/change-password', authenticate, async (req, res) => {
  const current = req.body?.currentPassword;
  const next = req.body?.newPassword;
  if (typeof current !== 'string' || !(await bcrypt.compare(current, req.user.passwordHash))) return res.status(401).json({ error: 'Current password is incorrect.' });
  if (typeof next !== 'string' || next.length < 12 || !/[a-z]/.test(next) || !/[A-Z]/.test(next) || !/[0-9]/.test(next) || !/[^A-Za-z0-9]/.test(next)) return res.status(422).json({ error: 'Use a 12-character password with upper, lower, number, and symbol.' });
  req.user.passwordHash = await bcrypt.hash(next, 12);
  await persist();
  res.json({ message: 'Password updated. Sign in again on your next session.' });
});

app.get('/api/dashboard/summary', authenticate, (_req, res) => res.json(summary()));
app.get('/api/threats', authenticate, (req, res) => {
  const allowedChannels = channels;
  const severity = safeText(req.query.severity, 12).toUpperCase();
  const channel = safeText(req.query.channel, 20).toUpperCase();
  const status = safeText(req.query.status, 20).toUpperCase();
  const query = safeText(req.query.q, 120).toLowerCase();
  const rows = db.threats.filter(threat => (!severities.has(severity) || threat.severity === severity) && (!allowedChannels.has(channel) || threat.channel === channel) && (!statuses.has(status) || threat.status === status) && (!query || `${threat.id} ${threat.targetName} ${threat.type} ${threat.threatUrl}`.toLowerCase().includes(query))).sort((a, b) => new Date(b.detectedAt) - new Date(a.detectedAt));
  res.json(rows);
});
app.get('/api/threats/:id', authenticate, (req, res) => {
  const threat = db.threats.find(row => row.id === req.params.id);
  if (!threat) return res.status(404).json({ error: 'Threat not found.' });
  res.json(threat);
});
app.post('/api/threats', authenticate, async (req, res, next) => {
  try { res.status(201).json(await addThreat(req.body, 'Analyst entered', req.user)); }
  catch (error) { if (error.message.includes('must be a number') || error.message.startsWith('Provide ')) return res.status(422).json({ error: error.message }); next(error); }
});
app.patch('/api/threats/:id/status', authenticate, async (req, res) => {
  if (!statuses.has(req.body?.status)) return res.status(422).json({ error: 'Choose a valid case status.' });
  const threat = db.threats.find(row => row.id === req.params.id);
  if (!threat) return res.status(404).json({ error: 'Threat not found.' });
  threat.status = req.body.status;
  threat.updatedAt = new Date().toISOString();
  await persist();
  io.emit('threat_updated', threat);
  res.json(threat);
});
app.post('/api/threats/:id/notes', authenticate, async (req, res) => {
  const threat = db.threats.find(row => row.id === req.params.id);
  const text = safeText(req.body?.text, 2000);
  if (!threat) return res.status(404).json({ error: 'Threat not found.' });
  if (!text) return res.status(422).json({ error: 'Write a note before saving.' });
  const note = { id: crypto.randomUUID(), text, author: req.user.name, createdAt: new Date().toISOString() };
  threat.notes.push(note);
  await persist();
  io.emit('threat_updated', threat);
  res.status(201).json(note);
});
app.post('/api/threats/ingest', async (req, res, next) => {
  const supplied = Buffer.from(String(req.headers['x-ingest-key'] || ''));
  const expected = Buffer.from(process.env.INGEST_API_KEY || '');
  if (!process.env.INGEST_API_KEY || supplied.length !== expected.length || !crypto.timingSafeEqual(supplied, expected)) return res.status(401).json({ error: 'Ingestion credentials are invalid.' });
  try { res.status(201).json(await addThreat(req.body, 'External ingestion', null)); }
  catch (error) { if (error.message.includes('must be a number') || error.message.startsWith('Provide ')) return res.status(422).json({ error: error.message }); next(error); }
});

app.get('/api/brands', authenticate, (_req, res) => res.json(db.brandAssets));
app.post('/api/brands', authenticate, async (req, res) => {
  const name = safeText(req.body?.name, 100);
  const domain = safeText(req.body?.domain, 253).toLowerCase().replace(/^https?:\/\//, '').replace(/\/$/, '');
  const keywords = Array.isArray(req.body?.keywords) ? [...new Set(req.body.keywords.map(value => safeText(value, 60)).filter(Boolean))].slice(0, 20) : [];
  if (!name || !/^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/i.test(domain)) return res.status(422).json({ error: 'Provide a brand name and valid domain, such as brand.example.' });
  if (db.brandAssets.some(asset => asset.domain === domain)) return res.status(409).json({ error: 'That domain is already being tracked in this workspace.' });
  const asset = { id: crypto.randomUUID(), name, domain, keywords, assetType: 'Brand', createdAt: new Date().toISOString() };
  db.brandAssets.push(asset);
  await persist();
  res.status(201).json(asset);
});
app.delete('/api/brands/:id', authenticate, async (req, res) => {
  const index = db.brandAssets.findIndex(asset => asset.id === req.params.id);
  if (index < 0) return res.status(404).json({ error: 'Brand asset not found.' });
  const [asset] = db.brandAssets.splice(index, 1);
  await persist();
  res.json(asset);
});

app.get('/api/analytics', authenticate, (req, res) => {
  const days = Math.min(365, Math.max(7, Number(req.query.days) || 30));
  const cutoff = Date.now() - days * 86400000;
  const recent = db.threats.filter(threat => {
    const timestamp = new Date(threat.detectedAt).getTime();
    return timestamp >= cutoff && timestamp <= Date.now();
  });
  const group = (field, values) => Object.fromEntries(values.map(value => [value, recent.filter(threat => threat[field] === value).length]));
  const daily = Array.from({ length: days }, (_, index) => {
    const start = new Date(Date.now() - (days - index - 1) * 86400000);
    start.setHours(0, 0, 0, 0);
    const end = new Date(start.getTime() + 86400000);
    const localDate = `${start.getFullYear()}-${String(start.getMonth() + 1).padStart(2, '0')}-${String(start.getDate()).padStart(2, '0')}`;
    return { date: localDate, count: recent.filter(threat => new Date(threat.detectedAt) >= start && new Date(threat.detectedAt) < end).length };
  });
  res.json({ days, total: recent.length, severity: group('severity', [...severities]), channel: group('channel', [...channels]), status: group('status', [...statuses]), daily });
});
app.get('/api/settings', authenticate, (_req, res) => res.json(db.settings));
app.patch('/api/settings', authenticate, requireAdmin, async (req, res) => {
  const name = safeText(req.body?.workspaceName, 80);
  const notifications = req.body?.notifications;
  if (!name) return res.status(422).json({ error: 'Workspace name cannot be empty.' });
  if (!notifications || ['critical', 'dailyDigest', 'caseUpdates'].some(key => typeof notifications[key] !== 'boolean')) return res.status(422).json({ error: 'Choose a value for each notification preference.' });
  db.settings.workspaceName = name;
  db.settings.notifications = { critical: notifications.critical, dailyDigest: notifications.dailyDigest, caseUpdates: notifications.caseUpdates };
  await persist();
  res.json(db.settings);
});

app.get('/api/users', authenticate, requireAdmin, (_req, res) => {
  res.json(db.users.map(userListItem).sort((a, b) => a.name.localeCompare(b.name)));
});
app.post('/api/users', authenticate, requireAdmin, async (req, res) => {
  const name = safeText(req.body?.name, 100);
  const email = safeText(req.body?.email, 254).toLowerCase();
  const password = req.body?.password;
  const role = req.body?.role === 'admin' ? 'admin' : 'analyst';
  if (!name || !/^\S+@\S+\.\S+$/.test(email)) return res.status(422).json({ error: 'Provide a name and valid email address.' });
  if (!isStrongPassword(password)) return res.status(422).json({ error: 'Use a 12–128 character password with upper, lower, number, and symbol.' });
  if (db.users.some(user => user.email === email) || db.registrations.some(user => user.email === email)) return res.status(409).json({ error: 'An account with that email already exists.' });
  const user = { id: crypto.randomUUID(), name, email, role, passwordHash: await bcrypt.hash(password, 12), status: 'ACTIVE', createdAt: new Date().toISOString() };
  db.users.push(user);
  await persist();
  res.status(201).json(userListItem(user));
});
app.patch('/api/users/:id', authenticate, requireAdmin, async (req, res) => {
  const user = db.users.find(row => row.id === req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found.' });
  const nextRole = req.body?.role === undefined ? user.role : req.body.role;
  const nextStatus = req.body?.status === undefined ? user.status : req.body.status;
  if (!['admin', 'analyst'].includes(nextRole) || !['ACTIVE', 'DISABLED'].includes(nextStatus)) return res.status(422).json({ error: 'Choose a valid role and account status.' });
  if (user.id === req.user.id && (nextRole !== 'admin' || nextStatus !== 'ACTIVE')) return res.status(422).json({ error: 'You cannot remove administrator access or disable your own account.' });
  const removesActiveAdmin = user.role === 'admin' && user.status === 'ACTIVE' && (nextRole !== 'admin' || nextStatus !== 'ACTIVE');
  if (removesActiveAdmin && db.users.filter(row => row.role === 'admin' && row.status === 'ACTIVE').length <= 1) return res.status(409).json({ error: 'The workspace must retain at least one active administrator.' });
  user.role = nextRole;
  user.status = nextStatus;
  await persist();
  res.json(userListItem(user));
});

io.use((socket, next) => {
  try {
    const payload = jwt.verify(socket.handshake.auth?.token || '', JWT_SECRET, { issuer: 'gravis-ai' });
    const user = db.users.find(row => row.id === payload.sub && row.status === 'ACTIVE');
    if (!user) return next(new Error('Authentication required'));
    socket.user = publicUser(user);
    next();
  } catch { next(new Error('Authentication required')); }
});
io.on('connection', socket => socket.emit('stream_ready', { connected: true }));
app.use('/api', (_req, res) => res.status(404).json({ error: 'API endpoint not found.' }));
app.use((err, _req, res, _next) => {
  if (err.type === 'entity.parse.failed') return res.status(400).json({ error: 'Request body must contain valid JSON.' });
  if (err.type === 'entity.too.large') return res.status(413).json({ error: 'Request body is too large.' });
  console.error(err);
  res.status(500).json({ error: 'Something went wrong. Please try again.' });
});

async function startServer() {
  if (postgresPool) {
    await postgresPool.query(`
      CREATE TABLE IF NOT EXISTS gravis_workspace_state (
        id SMALLINT PRIMARY KEY CHECK (id = 1),
        state JSONB NOT NULL,
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);
    const result = await postgresPool.query('SELECT state FROM gravis_workspace_state WHERE id = 1');
    if (result.rows.length) db = prepareDb(result.rows[0].state);
  }
  await persist();
  server.listen(PORT, '0.0.0.0', () => {
    console.log(`GRAVIS AI running on port ${PORT} (${production ? 'production' : 'demo'} mode)`);
  });
}

startServer().catch(async error => {
  console.error('Could not start GRAVIS AI:', error);
  if (postgresPool) await postgresPool.end().catch(() => {});
  process.exitCode = 1;
});

