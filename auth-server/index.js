const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(bodyParser.json());

const USERS_FILE = path.join(__dirname, 'users.json');
function readUsers(){ try{ if(!fs.existsSync(USERS_FILE)) return []; return JSON.parse(fs.readFileSync(USERS_FILE,'utf8')||'[]'); }catch(e){console.error('readUsers error',e); return []; } }
function writeUsers(u){ try{ fs.writeFileSync(USERS_FILE, JSON.stringify(u,null,2)); }catch(e){console.error('writeUsers error',e);} }

const JWT_SECRET = process.env.JWT_SECRET || 'please-change-this';
const PORT = process.env.PORT || 3000;
const ADMIN_EMAIL = 'kai.horsfall@cmfalcons.org';

// Register
app.post('/auth/register', async (req, res) => {
  const { name, email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'email and password required' });
  const users = readUsers();
  const normalizedEmail = String(email).toLowerCase();
  if (users.find(u => u.email && u.email.toLowerCase() === normalizedEmail)) return res.status(400).json({ error: 'email already registered' });
  const passHash = await bcrypt.hash(password, 10);
  const isAdmin = normalizedEmail === ADMIN_EMAIL;
  const user = { id: Date.now(), name: name || normalizedEmail.split('@')[0], email: normalizedEmail, passHash, isAdmin: !!isAdmin, createdAt: Date.now() };
  users.push(user);
  writeUsers(users);
  const token = jwt.sign({ sub: user.email, name: user.name, isAdmin: !!isAdmin }, JWT_SECRET, { expiresIn: '30d' });
  return res.json({ ok: true, token, user: { email: user.email, name: user.name, isAdmin: !!isAdmin } });
});

// Login
app.post('/auth/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'email and password required' });
  const users = readUsers();
  const normalizedEmail = String(email).toLowerCase();
  const user = users.find(u => u.email && u.email.toLowerCase() === normalizedEmail);
  if (!user) return res.status(400).json({ error: 'invalid credentials' });
  const ok = await bcrypt.compare(password, user.passHash);
  if (!ok) return res.status(400).json({ error: 'invalid credentials' });
  const token = jwt.sign({ sub: user.email, name: user.name, isAdmin: !!user.isAdmin }, JWT_SECRET, { expiresIn: '30d' });
  return res.json({ ok: true, token, user: { email: user.email, name: user.name, isAdmin: !!user.isAdmin } });
});

// Me
app.get('/auth/me', (req, res) => {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ error: 'missing authorization' });
  const parts = auth.split(' ');
  if (parts[0] !== 'Bearer') return res.status(401).json({ error: 'invalid authorization' });
  const token = parts[1];
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    return res.json({ ok: true, user: { email: payload.sub, name: payload.name, isAdmin: !!payload.isAdmin } });
  } catch (e) {
    return res.status(401).json({ error: 'invalid token' });
  }
});

// Serve static files from repository root (useful when deployed with Render)
const publicRoot = path.join(__dirname, '..');
app.use(express.static(publicRoot));
app.get('*', (req, res) => {
  res.sendFile(path.join(publicRoot, 'nexus_all_in_one_site.html'));
});

app.listen(PORT, () => console.log(`kaichat auth & app server listening on ${PORT}`));
