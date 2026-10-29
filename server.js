require('dotenv').config();
const express = require('express'), mongoose = require('mongoose'), jwt = require('jsonwebtoken');
const crypto = require('crypto'), path = require('path');
const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// One collection for everyone. role = 'student' or 'ambassador'.
const User = mongoose.model('User', new mongoose.Schema({
  role: { type: String, enum: ['student', 'ambassador'], required: true },
  name: String,
  phone: { type: String, unique: true },
  college: String,
  salt: String,
  pinHash: String,
  code: { type: String, unique: true, sparse: true }, // ambassadors only
  referredBy: String,                                  // ambassador code a student used
  approved: Boolean                                    // ambassadors: false until the admin approves
}, { timestamps: true }));

const hash = (pin, salt) => crypto.scryptSync(pin, salt, 32).toString('hex');
const sign = u => jwt.sign({ id: u._id }, process.env.JWT_SECRET, { expiresIn: '30d' });

async function makeCode(name) {
  const base = name.split(' ')[0].replace(/[^a-z]/gi, '').toUpperCase().slice(0, 6) || 'AMB';
  for (;;) {
    const code = base + Math.floor(1000 + Math.random() * 9000);
    if (!(await User.exists({ code }))) return code;
  }
}

async function profile(u) {
  const p = { role: u.role, name: u.name, phone: u.phone, college: u.college, code: u.code, referredBy: u.referredBy, approved: u.approved !== false };
  if (u.role === 'ambassador' && u.approved !== false) {
    const list = await User.find({ referredBy: u.code }).sort({ createdAt: -1 });
    p.referralCount = list.length;
    p.referrals = list.map(s => ({ name: s.name, college: s.college, joined: s.createdAt }));
  } else if (u.referredBy) {
    const a = await User.findOne({ code: u.referredBy });
    p.referredByName = a ? a.name : u.referredBy;
  }
  return p;
}

const auth = async (req, res, next) => {
  try {
    const { id } = jwt.verify((req.headers.authorization || '').replace('Bearer ', ''), process.env.JWT_SECRET);
    req.user = await User.findById(id);
    if (!req.user) throw new Error();
    next();
  } catch { res.status(401).json({ error: 'Please log in again.' }); }
};

app.post('/api/register', async (req, res) => {
  try {
    const { role, name = '', phone = '', college = '', pin = '', refCode = '' } = req.body;
    if (!['student', 'ambassador'].includes(role)) return res.status(400).json({ error: 'Choose student or ambassador.' });
    if (name.trim().length < 2) return res.status(400).json({ error: 'Enter your full name.' });
    if (!/^[6-9]\d{9}$/.test(phone)) return res.status(400).json({ error: 'Enter a valid 10-digit WhatsApp number.' });
    if (college.trim().length < 2) return res.status(400).json({ error: 'Enter your college name.' });
    if (!/^\d{4}$/.test(pin)) return res.status(400).json({ error: 'PIN must be 4 digits.' });
    if (await User.exists({ phone })) return res.status(409).json({ error: 'This number is already registered. Please log in.' });

    const salt = crypto.randomBytes(8).toString('hex');
    const doc = { role, name: name.trim(), phone, college: college.trim(), salt, pinHash: hash(pin, salt) };
    if (role === 'ambassador') doc.approved = false; // gets a code only after admin approval
    else if (refCode.trim()) {
      const amb = await User.findOne({ role: 'ambassador', code: refCode.trim().toUpperCase() });
      if (!amb) return res.status(400).json({ error: 'That referral code does not exist. Check it or leave it empty.' });
      doc.referredBy = amb.code;
    }
    const u = await User.create(doc);
    res.json({ token: sign(u), user: await profile(u) });
  } catch (e) { res.status(500).json({ error: 'Server error. Try again.' }); }
});

app.post('/api/login', async (req, res) => {
  const { phone = '', pin = '' } = req.body;
  const u = await User.findOne({ phone });
  const ok = u && crypto.timingSafeEqual(Buffer.from(hash(pin, u.salt)), Buffer.from(u.pinHash));
  if (!ok) return res.status(401).json({ error: 'Wrong number or PIN.' });
  res.json({ token: sign(u), user: await profile(u) });
});

app.get('/api/me', auth, async (req, res) => res.json(await profile(req.user)));

// ---- Admin (needs the ADMIN_KEY from .env) ----
const admin = (req, res, next) =>
  process.env.ADMIN_KEY && req.headers['x-admin-key'] === process.env.ADMIN_KEY ? next() : res.status(401).json({ error: 'Wrong admin key.' });

// Pending requests + approved ambassadors with verified referral counts (for payouts).
app.get('/api/admin/report', admin, async (req, res) => {
  const pending = await User.find({ role: 'ambassador', approved: false }).sort({ createdAt: 1 });
  const ambs = await User.find({ role: 'ambassador', approved: { $ne: false } });
  const approved = await Promise.all(ambs.map(async a => ({
    name: a.name, college: a.college, phone: a.phone, code: a.code,
    referrals: await User.countDocuments({ referredBy: a.code })
  })));
  res.json({
    pending: pending.map(a => ({ id: a._id, name: a.name, college: a.college, phone: a.phone })),
    approved: approved.sort((a, b) => b.referrals - a.referrals)
  });
});

app.post('/api/admin/approve', admin, async (req, res) => {
  const u = await User.findOne({ _id: req.body.id, role: 'ambassador', approved: false });
  if (!u) return res.status(404).json({ error: 'Request not found.' });
  u.code = await makeCode(u.name); u.approved = true; await u.save();
  res.json({ ok: true, code: u.code });
});

app.post('/api/admin/reject', admin, async (req, res) => {
  await User.deleteOne({ _id: req.body.id, role: 'ambassador', approved: false });
  res.json({ ok: true });
});

mongoose.connect(process.env.MONGODB_URI)
  .then(() => app.listen(process.env.PORT || 3000, () => console.log('Running on port ' + (process.env.PORT || 3000))))
  .catch(e => { console.error('Database connection failed:', e.message); process.exit(1); });