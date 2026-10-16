// HostX — mini static hosting platform
// Run:  BASE_DOMAIN=host.example.com SERVER_IP=1.2.3.4 node server.js
// Env:  PORT(3000) HOST(127.0.0.1) BASE_DOMAIN SERVER_IP ALLOW_SIGNUP(true) MAX_UPLOAD_MB(100) MAX_SITE_MB(300) MAX_SITES(10)
const express = require('express'), fs = require('fs'), path = require('path'), dns = require('dns').promises, crypto = require('crypto');
const multer = require('multer'), AdmZip = require('adm-zip'), bcrypt = require('bcryptjs'), jwt = require('jsonwebtoken'), cookieParser = require('cookie-parser');

const PORT = +process.env.PORT || 3000;
const HOST = process.env.HOST || '127.0.0.1';
const BASE = (process.env.BASE_DOMAIN || 'localhost').toLowerCase();
const SERVER_IP = process.env.SERVER_IP || '';
const ALLOW_SIGNUP = process.env.ALLOW_SIGNUP !== 'false';
const MAX_UPLOAD = (+process.env.MAX_UPLOAD_MB || 100) * 1048576;
const MAX_SITE = (+process.env.MAX_SITE_MB || 300) * 1048576;
const MAX_SITES = +process.env.MAX_SITES || 10;

const DATA = path.join(__dirname, 'data'), SITES = path.join(DATA, 'sites'), TMP = path.join(DATA, 'tmp'), DBF = path.join(DATA, 'db.json'), SF = path.join(DATA, 'secret');
[DATA, SITES, TMP].forEach(d => fs.mkdirSync(d, { recursive: true }));
if (!fs.existsSync(SF)) fs.writeFileSync(SF, crypto.randomBytes(48).toString('hex'), { mode: 0o600 });
const SECRET = fs.readFileSync(SF, 'utf8');

let db = fs.existsSync(DBF) ? JSON.parse(fs.readFileSync(DBF, 'utf8')) : { users: {}, sites: {} };
const save = () => { fs.writeFileSync(DBF + '.tmp', JSON.stringify(db, null, 2)); fs.renameSync(DBF + '.tmp', DBF); };

// ---------- helpers ----------
const siteDir = s => path.join(SITES, s);
function safeJoin(root, rel) {
  const p = path.resolve(root, './' + String(rel).replace(/\\/g, '/'));
  if (p !== root && !p.startsWith(root + path.sep)) throw new Error('Invalid path');
  return p;
}
function walk(dir, base = dir, out = []) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const f = path.join(dir, e.name);
    if (e.isDirectory()) walk(f, base, out);
    else if (e.isFile()) out.push({ path: path.relative(base, f).split(path.sep).join('/'), size: fs.statSync(f).size });
  }
  return out;
}
const dirSize = d => walk(d).reduce((a, f) => a + f.size, 0);
const isIP = h => /^\d{1,3}(\.\d{1,3}){3}$/.test(h) || h.includes(':');

// find which site a Host header belongs to
function siteFor(host) {
  if (host.endsWith('.' + BASE)) { const s = host.slice(0, -BASE.length - 1); return db.sites[s] ? s : null; }
  for (const s of Object.values(db.sites)) {
    const d = s.domain;
    if (d && d.verified && (host === d.name || host === 'www.' + d.name)) return s.slug;
  }
  return null;
}

const app = express();
app.set('trust proxy', 'loopback');
app.disable('x-powered-by');

// Caddy asks this before issuing an HTTPS certificate for a domain
app.get('/_caddy/check', (req, res) => {
  if (req.headers['x-forwarded-for']) return res.sendStatus(403);
  const d = String(req.query.domain || '').toLowerCase();
  res.sendStatus(d === BASE || d === 'www.' + BASE || siteFor(d) ? 200 : 404);
});

// ---------- serve hosted sites (any host that is not the dashboard) ----------
const statics = {};
app.use((req, res, next) => {
  const host = (req.hostname || '').toLowerCase();
  if (host === BASE || host === 'www.' + BASE || host === 'localhost' || isIP(host)) return next();
  const slug = siteFor(host);
  if (!slug) return res.status(404).send('No site is connected to this domain.');
  res.set('X-Content-Type-Options', 'nosniff');
  const st = statics[slug] || (statics[slug] = express.static(siteDir(slug), { dotfiles: 'ignore', extensions: ['html'], maxAge: '5m' }));
  st(req, res, () => {
    const nf = path.join(siteDir(slug), '404.html');
    res.status(404);
    fs.existsSync(nf) ? res.sendFile(nf) : res.send('404 - Page not found');
  });
});

// ---------- dashboard API ----------
app.use(express.json({ limit: '50kb' }));
app.use(cookieParser());

const hits = {};
const limit = (max, ms) => (req, res, next) => {
  const k = req.ip + req.path, n = Date.now();
  const b = (hits[k] = (hits[k] || []).filter(t => n - t < ms));
  if (b.length >= max) return res.status(429).json({ error: 'Too many attempts. Try again later.' });
  b.push(n); next();
};
const give = (req, res, u) => res.cookie('t', jwt.sign({ e: u.email }, SECRET, { expiresIn: '30d' }), { httpOnly: true, sameSite: 'lax', secure: req.secure, maxAge: 30 * 864e5 });
function auth(req, res, next) {
  try { const { e } = jwt.verify(req.cookies.t, SECRET); if (!db.users[e]) throw 0; req.user = db.users[e]; next(); }
  catch { res.status(401).json({ error: 'Please log in.' }); }
}
const owned = (req, res, next) => {
  const s = db.sites[req.params.slug];
  if (!s || s.owner !== req.user.email) return res.status(404).json({ error: 'Site not found.' });
  req.s = s; next();
};
const pub = s => ({ slug: s.slug, domain: s.domain, created: s.created });

app.post('/api/register', limit(10, 3600e3), async (req, res) => {
  if (!ALLOW_SIGNUP) return res.status(403).json({ error: 'Sign-up is closed.' });
  const email = String(req.body.email || '').trim().toLowerCase(), pw = String(req.body.password || '');
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return res.status(400).json({ error: 'Enter a valid email.' });
  if (pw.length < 8) return res.status(400).json({ error: 'Password needs at least 8 characters.' });
  if (db.users[email]) return res.status(409).json({ error: 'This email is already registered.' });
  const u = db.users[email] = { email, hash: await bcrypt.hash(pw, 10), created: Date.now() };
  save(); give(req, res, u); res.json({ email });
});
app.post('/api/login', limit(10, 600e3), async (req, res) => {
  const u = db.users[String(req.body.email || '').trim().toLowerCase()];
  if (!u || !(await bcrypt.compare(String(req.body.password || ''), u.hash))) return res.status(401).json({ error: 'Wrong email or password.' });
  give(req, res, u); res.json({ email: u.email });
});
app.post('/api/logout', (req, res) => { res.clearCookie('t'); res.json({ ok: true }); });
app.get('/api/me', auth, (req, res) => res.json({ email: req.user.email, base: BASE, ip: SERVER_IP, maxSiteMb: MAX_SITE / 1048576 }));

// sites
const RESERVED = new Set(['www', 'api', 'app', 'admin', 'mail', 'ftp', 'dashboard', 'static', 'assets', 'ns1', 'ns2']);
const STARTER = '<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>New site</title><body style="font:18px system-ui;display:grid;place-items:center;height:100vh;margin:0"><p>This site is live. Upload your files from the dashboard.</p>';

app.get('/api/sites', auth, (req, res) => res.json(Object.values(db.sites).filter(s => s.owner === req.user.email).map(pub)));
app.post('/api/sites', auth, (req, res) => {
  const slug = String(req.body.name || '').toLowerCase().trim();
  if (!/^[a-z0-9][a-z0-9-]{1,28}[a-z0-9]$/.test(slug) || RESERVED.has(slug)) return res.status(400).json({ error: 'Use 3-30 letters, numbers or dashes.' });
  if (db.sites[slug]) return res.status(409).json({ error: 'That name is taken. Try another.' });
  if (Object.values(db.sites).filter(s => s.owner === req.user.email).length >= MAX_SITES) return res.status(403).json({ error: `Limit reached: ${MAX_SITES} sites per account.` });
  fs.mkdirSync(siteDir(slug), { recursive: true });
  fs.writeFileSync(path.join(siteDir(slug), 'index.html'), STARTER);
  db.sites[slug] = { slug, owner: req.user.email, domain: null, created: Date.now() };
  save(); res.json(pub(db.sites[slug]));
});
app.delete('/api/sites/:slug', auth, owned, (req, res) => {
  fs.rmSync(siteDir(req.s.slug), { recursive: true, force: true });
  delete db.sites[req.s.slug]; delete statics[req.s.slug]; save(); res.json({ ok: true });
});

// files
app.get('/api/sites/:slug/files', auth, owned, (req, res) => {
  const files = walk(siteDir(req.s.slug)).sort((a, b) => a.path.localeCompare(b.path));
  res.json({ files, used: files.reduce((a, f) => a + f.size, 0) });
});
app.delete('/api/sites/:slug/files', auth, owned, (req, res) => {
  const root = siteDir(req.s.slug), p = safeJoin(root, req.query.path || '');
  if (p === root) return res.status(400).json({ error: 'Nothing to delete.' });
  fs.rmSync(p, { recursive: true, force: true }); res.json({ ok: true });
});

const upload = multer({ dest: TMP, limits: { fileSize: MAX_UPLOAD, files: 500 } });
function writeFile(root, rel, buf, st) {
  st.used += buf.length;
  if (st.used > MAX_SITE) throw new Error(`Site size limit is ${MAX_SITE / 1048576} MB.`);
  const p = safeJoin(root, rel);
  if (p === root) throw new Error('Invalid file name.');
  fs.mkdirSync(path.dirname(p), { recursive: true });
  fs.writeFileSync(p, buf);
}
function unzip(file, root, st) {
  const zip = new AdmZip(file);
  const entries = zip.getEntries().filter(e => !e.isDirectory && !e.entryName.startsWith('__MACOSX/') && !/(^|\/)\.DS_Store$/.test(e.entryName));
  if (st.used + entries.reduce((a, e) => a + e.header.size, 0) > MAX_SITE) throw new Error(`Zip is too large (limit ${MAX_SITE / 1048576} MB unzipped).`);
  const tops = new Set(entries.map(e => e.entryName.split('/')[0]));
  const strip = tops.size === 1 && entries.every(e => e.entryName.includes('/')); // zip contained one wrapper folder
  for (const e of entries) writeFile(root, strip ? e.entryName.split('/').slice(1).join('/') : e.entryName, e.getData(), st);
  return entries.length;
}
app.post('/api/sites/:slug/upload', auth, owned, upload.array('files'), (req, res) => {
  const root = siteDir(req.s.slug), files = req.files || [], paths = [].concat(req.body.paths || []);
  const extract = req.body.extract === '1';
  try {
    const st = { used: dirSize(root) };
    let n = 0;
    files.forEach((f, i) => {
      const rel = paths[i] || f.originalname;
      if (extract && /\.zip$/i.test(rel)) n += unzip(f.path, root, st);
      else { writeFile(root, rel, fs.readFileSync(f.path), st); n++; }
    });
    res.json({ added: n });
  } catch (e) { res.status(400).json({ error: e.message }); }
  finally { files.forEach(f => fs.rmSync(f.path, { force: true })); }
});

// custom domain
app.post('/api/sites/:slug/domain', auth, owned, (req, res) => {
  const d = String(req.body.domain || '').toLowerCase().trim().replace(/^https?:\/\//, '').replace(/[\/?#].*$/, '');
  if (!/^(?=.{4,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/.test(d) || d === BASE || d.endsWith('.' + BASE)) return res.status(400).json({ error: 'Enter a valid domain, like mysite.com.' });
  if (Object.values(db.sites).some(s => s.slug !== req.s.slug && s.domain && s.domain.verified && s.domain.name === d)) return res.status(409).json({ error: 'This domain is already connected to another site.' });
  req.s.domain = { name: d, verified: false }; save(); res.json(pub(req.s));
});
app.post('/api/sites/:slug/domain/verify', auth, owned, async (req, res) => {
  const d = req.s.domain;
  if (!d) return res.status(400).json({ error: 'Add a domain first.' });
  if (!SERVER_IP) return res.status(500).json({ error: 'SERVER_IP is not configured on the server.' });
  let found = [];
  try { found = await dns.resolve4(d.name); } catch {}
  if (!found.includes(SERVER_IP)) return res.json({ verified: false, found, expected: SERVER_IP });
  if (Object.values(db.sites).some(s => s.slug !== req.s.slug && s.domain && s.domain.verified && s.domain.name === d.name)) return res.status(409).json({ error: 'This domain is already connected to another site.' });
  d.verified = true; save(); res.json({ verified: true, site: pub(req.s) });
});
app.delete('/api/sites/:slug/domain', auth, owned, (req, res) => { req.s.domain = null; save(); res.json({ ok: true }); });

app.use(express.static(path.join(__dirname, 'public')));
app.use((err, req, res, next) => res.status(400).json({ error: err.code === 'LIMIT_FILE_SIZE' ? `File is larger than ${MAX_UPLOAD / 1048576} MB.` : err.message }));

app.listen(PORT, HOST, () => console.log(`HostX running on http://${HOST}:${PORT}  (base domain: ${BASE})`));
