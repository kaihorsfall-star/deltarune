const express = require('express');
const bodyParser = require('body-parser');
const sgMail = require('@sendgrid/mail');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const { customAlphabet } = require('nanoid');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(bodyParser.json());

const SENDGRID_API_KEY = process.env.SENDGRID_API_KEY;
const FROM_EMAIL = process.env.FROM_EMAIL;
const JWT_SECRET = process.env.JWT_SECRET || 'please-set-a-secret';
const CODE_TTL_SECONDS = Number(process.env.CODE_TTL_SECONDS || 600);

if(!SENDGRID_API_KEY) {
  console.error('SENDGRID_API_KEY not set in env');
  process.exit(1);
}
sgMail.setApiKey(SENDGRID_API_KEY);

// in-memory store for codes: { emailLower: {code, expiresAt, name(optional)} }
// Replace with a persistent store (Redis/DB) for production.
const codes = new Map();

const nanoid = customAlphabet('0123456789', 6); // 6-digit numeric codes

function generateCode() {
  return String(nanoid()).padStart(6, '0');
}

app.post('/auth/request-code', async (req, res) => {
  const { email, name } = req.body;
  if(!email) return res.status(400).json({error: 'email required'});
  const emailLC = String(email).toLowerCase().trim();

  const code = generateCode();
  const expiresAt = Date.now() + CODE_TTL_SECONDS * 1000;
  codes.set(emailLC, { code, expiresAt, name });

  // Send email with SendGrid
  const msg = {
    to: emailLC,
    from: FROM_EMAIL,
    subject: `${process.env.SITE_NAME || 'kaichat'} sign-in code`,
    text: `Your sign-in code is: ${code}\nIt expires in ${Math.round(CODE_TTL_SECONDS/60)} minutes.`,
    html: `<p>Your sign-in code is: <b style="font-size:18px">${code}</b></p><p>It expires in ${Math.round(CODE_TTL_SECONDS/60)} minutes.</p>`
  };

  try {
    await sgMail.send(msg);
    return res.json({ok:true, message: 'code sent'});
  } catch (err) {
    console.error('SendGrid error', err);
    return res.status(500).json({error:'failed to send email'});
  }
});

app.post('/auth/verify-code', (req, res) => {
  const { email, code } = req.body;
  if(!email || !code) return res.status(400).json({error:'email and code required'});
  const emailLC = String(email).toLowerCase().trim();
  const entry = codes.get(emailLC);
  if(!entry) return res.status(400).json({error:'no code requested for this email'});
  if(Date.now() > entry.expiresAt) { codes.delete(emailLC); return res.status(400).json({error:'code expired'}); }
  if(String(entry.code) !== String(code).trim()) return res.status(400).json({error:'invalid code'});

  // success: optionally create a user record in your DB.
  const user = {
    email: emailLC,
    name: entry.name || emailLC.split('@')[0],
    createdAt: Date.now()
  };

  // issue JWT
  const token = jwt.sign({ sub: user.email, name: user.name }, JWT_SECRET, { expiresIn: '30d' });

  // remove code so it cannot be reused
  codes.delete(emailLC);

  return res.json({ok:true, token, user});
});

// small cleanup loop to remove expired codes
setInterval(() => {
  const now = Date.now();
  for(const [email, entry] of codes) {
    if(entry.expiresAt < now) codes.delete(email);
  }
}, 60 * 1000);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Auth server listening on ${PORT}`));
