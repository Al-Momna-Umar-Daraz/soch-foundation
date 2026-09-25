const http = require('http');
const fs = require('fs');
const path = require('path');

const root = path.join(__dirname, 'public');
const submissions = [];
const sessions = new Map();
const crypto = require('crypto');
const dataDir = path.join(__dirname, 'data');
const usersFile = path.join(dataDir, 'users.json');
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir);
let users = fs.existsSync(usersFile) ? JSON.parse(fs.readFileSync(usersFile, 'utf8')) : [];
const hashPassword = value => crypto.createHash('sha256').update(value).digest('hex');
const types = { '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8', '.js': 'text/javascript; charset=utf-8' };

const server = http.createServer((req, res) => {
  if (req.method === 'POST' && req.url === '/api/volunteers') {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', () => {
      try {
        const data = JSON.parse(body);
        if (!data.name || !data.email || !data.area) throw new Error('Missing required fields');
        submissions.push({ ...data, createdAt: new Date().toISOString() });
        res.writeHead(201, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: true, message: 'Thank you! Our team will contact you soon.' }));
      } catch (e) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: false, message: 'Please complete the required fields.' }));
      }
    });
    return;
  }
  if (req.method === 'POST' && req.url === '/api/auth/login') {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', () => {
      try {
        const { email, password } = JSON.parse(body);
        if (!email || !/^\S+@\S+\.\S+$/.test(email) || !password || password.length < 6) throw new Error('Invalid credentials');
        const user = users.find(item => item.email.toLowerCase() === email.toLowerCase());
        if (!user || user.passwordHash !== hashPassword(password)) throw new Error('Email or password is incorrect.');
        const token = require('crypto').randomBytes(24).toString('hex');
        sessions.set(token, { email, createdAt: Date.now() });
        res.writeHead(200, { 'Content-Type': 'application/json', 'Set-Cookie': `soch_session=${token}; HttpOnly; SameSite=Lax; Path=/` });
        res.end(JSON.stringify({ ok: true, user: { email }, message: req.url.endsWith('signup') ? 'Account created successfully.' : 'You are signed in.' }));
      } catch { res.writeHead(401, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ ok: false, message: 'Use a valid email and a password of at least 6 characters.' })); }
    });
    return;
  }
  if (req.method === 'POST' && req.url === '/api/auth/signup') {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', () => {
      try {
        const { fullName, phone, email, password } = JSON.parse(body);
        if (!fullName || !phone || !email || !/^\S+@\S+\.\S+$/.test(email) || !password || password.length < 6) throw new Error('Please complete all fields.');
        if (users.some(item => item.email.toLowerCase() === email.toLowerCase())) throw new Error('An account with this email already exists.');
        users.push({ fullName, phone, email, passwordHash: hashPassword(password), createdAt: new Date().toISOString() });
        fs.writeFileSync(usersFile, JSON.stringify(users, null, 2));
        const token = crypto.randomBytes(24).toString('hex'); sessions.set(token, { email, createdAt: Date.now() });
        res.writeHead(201, { 'Content-Type': 'application/json', 'Set-Cookie': `soch_session=${token}; HttpOnly; SameSite=Lax; Path=/` });
        res.end(JSON.stringify({ ok: true, user: { fullName, phone, email }, message: 'Account created successfully.' }));
      } catch (e) { res.writeHead(400, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ ok: false, message: e.message })); }
    });
    return;
  }
  const requested = req.url === '/' ? '/index.html' : req.url;
  const file = path.join(root, requested.split('?')[0]);
  if (!file.startsWith(root)) return res.writeHead(403).end();
  fs.readFile(file, (err, data) => {
    if (err) return res.writeHead(404).end('Not found');
    res.writeHead(200, { 'Content-Type': types[path.extname(file)] || 'application/octet-stream' });
    res.end(data);
  });
});
server.listen(process.env.PORT || 3000, () => console.log('SOCH volunteer site running on http://localhost:' + (process.env.PORT || 3000)));
