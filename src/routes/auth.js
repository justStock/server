import express from 'express';
import bcrypt from 'bcryptjs';
import rateLimit from 'express-rate-limit';
import jwt from 'jsonwebtoken';
import User from '../models/User.js';
import { sendOtpSms } from '../services/sms.js';
import { auth, admin } from '../middleware/auth.js';

const router = express.Router();

const requestLimiter = rateLimit({ windowMs: 60 * 1000, max: 5 });

function genOtp() {
  return String(Math.floor(100000 + Math.random() * 900000));
}

// Minimal, loose E.164 normalizer: keeps leading + and digits only
function normalizeE164Loose(input = '') {
  const s = String(input).trim();
  const kept = s.replace(/[^\d+]/g, '');
  // If it starts with 0 or doesn't include country code, you may add your own logic.
  return kept;
}

function isValidPhoneLoose(p) {
  // Accepts + and 8-15 digits overall (rough E.164 bounds)
  return /^\+?[1-9]\d{7,14}$/.test(p);
}

function isValidName(n) {
  return typeof n === 'string' && n.trim().length >= 2 && n.trim().length <= 100;
}

const adminOtpAllowedPhones = String(process.env.ADMIN_OTP_ALLOWED_PHONES || '')
  .split(',')
  .map((value) => normalizeE164Loose(value))
  .filter((value) => isValidPhoneLoose(value));

const adminOtpAllowedSet = new Set(adminOtpAllowedPhones);
const restrictAdminOtp = adminOtpAllowedSet.size > 0;

function isAdminPhoneAllowed(phone) {
  if (!restrictAdminOtp) return true;
  return adminOtpAllowedSet.has(phone);
}

function getAdminOtpExpiryMinutes() {
  const raw = process.env.ADMIN_OTP_EXP_MIN || process.env.OTP_EXP_MIN || '10';
  const parsed = parseInt(raw, 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : 10;
}

// Accept both /request-otp and /requestOtp
// CHANGE: now requires BOTH name and phone to send OTP.
// We persist name immediately (create-or-update) with the phone.
router.post(['/request-otp', '/requestOtp'], requestLimiter, async (req, res) => {
  try {
    const rawPhone = req.body?.phone ?? '';
    const rawName = req.body?.name ?? '';
    const phoneStr = normalizeE164Loose(rawPhone);
    const name = String(rawName).trim();

    if (!isValidName(name)) {
      return res.status(400).json({ error: 'valid name (2-100 chars) required' });
    }
    if (!isValidPhoneLoose(phoneStr)) {
      return res.status(400).json({ error: 'valid phone required (E.164, e.g., +9198xxxxxx)' });
    }

    // Create or update user with provided name+phone BEFORE sending OTP
    let user = await User.findOne({ phone: phoneStr });
    if (!user) {
      user = await User.create({ phone: phoneStr, name });
    } else {
      // If user exists, update name (you can restrict this if you don't want name changes here)
      user.name = name;
    }

    // Optional: throttle re-sends (uncomment to enforce 30s gap)
    // if (user.lastOtpAt && Date.now() - user.lastOtpAt.getTime() < 30_000) {
    //   return res.status(429).json({ error: 'please wait before requesting another OTP' });
    // }

    const otp = genOtp();
    const hash = await bcrypt.hash(otp, 10);
    const expMin = parseInt(process.env.OTP_EXP_MIN || '10', 10);

    user.otpHash = hash;
    user.otpExpiresAt = new Date(Date.now() + expMin * 60 * 1000);
    user.lastOtpAt = new Date();
    user.lastOtpIp = req.ip;
    await user.save();

    const sent = await sendOtpSms(phoneStr, otp);
    if (!sent) {
      // Dev fallback
      console.log(`[OTP][DEV] Phone=${phoneStr} Code=${otp}`);
    }

    return res.json({ ok: true, message: 'OTP sent' });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'server error' });
  }
});

// Admin: request OTP via phone + name
router.post(['/admin/request-otp', '/admin/requestOtp'], requestLimiter, async (req, res) => {
  try {
    const rawPhone = req.body?.phone ?? '';
    const rawName = req.body?.name ?? '';
    const phoneStr = normalizeE164Loose(rawPhone);
    const name = String(rawName).trim();

    if (!isValidName(name)) {
      return res.status(400).json({ error: 'valid name (2-100 chars) required' });
    }
    if (!isValidPhoneLoose(phoneStr)) {
      return res.status(400).json({ error: 'valid phone required (E.164, e.g., +9198xxxxxx)' });
    }
    if (!isAdminPhoneAllowed(phoneStr)) {
      return res.status(403).json({ error: 'phone not authorized for admin access' });
    }

    let user = await User.findOne({ phone: phoneStr });
    if (!user) {
      user = await User.create({ phone: phoneStr, name, role: 'admin' });
    } else {
      user.name = name;
      if (user.role !== 'admin') {
        user.role = 'admin';
      }
    }

    const otp = genOtp();
    const hash = await bcrypt.hash(otp, 10);
    const expMin = getAdminOtpExpiryMinutes();

    user.otpHash = hash;
    user.otpExpiresAt = new Date(Date.now() + expMin * 60 * 1000);
    user.lastOtpAt = new Date();
    user.lastOtpIp = req.ip;
    await user.save();

    const sent = await sendOtpSms(phoneStr, otp);
    if (!sent) {
      console.log(`[ADMIN OTP][DEV] Phone=${phoneStr} Code=${otp}`);
    }

    return res.json({ ok: true, message: 'OTP sent' });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'server error' });
  }
});

// Accept both /verify-otp and /verifyOtp
// CHANGE: verification expects ONLY phone + otp (name is NOT required here now).
router.post(['/verify-otp', '/verifyOtp'], async (req, res) => {
  try {
    const phoneStr = normalizeE164Loose(req.body?.phone ?? '');
    const otpStr = String(req.body?.otp ?? '').trim();

    if (!isValidPhoneLoose(phoneStr) || !otpStr) {
      return res.status(400).json({ error: 'phone and otp required' });
    }

    const user = await User.findOne({ phone: phoneStr });
    if (!user || !user.otpHash || !user.otpExpiresAt) {
      return res.status(400).json({ error: 'invalid request' });
    }
    if (user.otpExpiresAt.getTime() < Date.now()) {
      return res.status(400).json({ error: 'otp expired' });
    }

    const ok = await bcrypt.compare(otpStr, user.otpHash);
    if (!ok) return res.status(400).json({ error: 'invalid otp' });

    // Clear OTP state and finalize login
    user.otpHash = undefined;
    user.otpExpiresAt = undefined;
    user.lastLoginAt = new Date();
    user.lastLoginIp = req.ip;
    user.loginCount = (user.loginCount || 0) + 1;
    await user.save();

    const token = jwt.sign(
      { id: user._id.toString(), role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    return res.json({
      token,
      user: {
        id: user._id,
        phone: user.phone,
        name: user.name,
        email: user.email,
        role: user.role,
        walletBalance: user.walletBalance
      }
    });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'server error' });
  }
});

// Admin: verify OTP
router.post(['/admin/verify-otp', '/admin/verifyOtp'], async (req, res) => {
  try {
    const phoneStr = normalizeE164Loose(req.body?.phone ?? '');
    const otpStr = String(req.body?.otp ?? '').trim();

    if (!isValidPhoneLoose(phoneStr) || !otpStr) {
      return res.status(400).json({ error: 'phone and otp required' });
    }
    if (!isAdminPhoneAllowed(phoneStr)) {
      return res.status(403).json({ error: 'phone not authorized for admin access' });
    }

    const user = await User.findOne({ phone: phoneStr });
    if (!user || !user.otpHash || !user.otpExpiresAt) {
      return res.status(400).json({ error: 'invalid request' });
    }
    if (user.role !== 'admin') {
      return res.status(403).json({ error: 'not an admin account' });
    }
    if (user.otpExpiresAt.getTime() < Date.now()) {
      return res.status(400).json({ error: 'otp expired' });
    }

    const ok = await bcrypt.compare(otpStr, user.otpHash);
    if (!ok) return res.status(400).json({ error: 'invalid otp' });

    user.otpHash = undefined;
    user.otpExpiresAt = undefined;
    user.role = 'admin';
    user.lastLoginAt = new Date();
    user.lastLoginIp = req.ip;
    user.loginCount = (user.loginCount || 0) + 1;
    await user.save();

    const token = jwt.sign(
      { id: user._id.toString(), role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    return res.json({
      token,
      user: {
        id: user._id,
        phone: user.phone,
        name: user.name,
        email: user.email,
        role: user.role,
        walletBalance: user.walletBalance
      }
    });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'server error' });
  }
});

// Admin: register an admin account (company-only via protected token)
router.post('/admin/register', async (req, res) => {
  try {
    const provided = req.headers['x-admin-signup-token'] || req.body?.adminToken;
    const expected = process.env.ADMIN_SIGNUP_TOKEN;
    if (!expected || provided !== expected) {
      return res.status(403).json({ error: 'forbidden' });
    }

    const name = (req.body?.name || '').trim();
    const email = String(req.body?.email || '').trim().toLowerCase();
    const password = String(req.body?.password || '');

    if (!name || !email || !password) {
      return res.status(400).json({ error: 'name, email, password required' });
    }
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) {
      return res.status(400).json({ error: 'invalid email' });
    }

    const existing = await User.findOne({ email });
    if (existing) {
      return res.status(409).json({ error: 'email already exists' });
    }

    const passwordHash = await bcrypt.hash(password, 12);
    const user = await User.create({ name, email, passwordHash, role: 'admin' });

    return res.json({ ok: true, id: user._id });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'server error' });
  }
});

// Admin: email/password login
router.post('/admin/login', async (req, res) => {
  try {
    const email = String(req.body?.email || '').trim().toLowerCase();
    const password = String(req.body?.password || '');
    if (!email || !password) return res.status(400).json({ error: 'email and password required' });

    const user = await User.findOne({ email, role: 'admin' });
    if (!user || !user.passwordHash) return res.status(401).json({ error: 'invalid credentials' });

    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) return res.status(401).json({ error: 'invalid credentials' });

    user.lastLoginAt = new Date();
    user.lastLoginIp = req.ip;
    user.loginCount = (user.loginCount || 0) + 1;
    await user.save();

    const token = jwt.sign(
      { id: user._id.toString(), role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    return res.json({
      token,
      user: { id: user._id, name: user.name, email: user.email, role: user.role, walletBalance: user.walletBalance }
    });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'server error' });
  }
});

// Admin self info
router.get('/admin/me', auth, admin, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ error: 'not found' });
    return res.json({
      user: { id: user._id, name: user.name, email: user.email, role: user.role, walletBalance: user.walletBalance }
    });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'server error' });
  }
});

// Update profile after login (optional)
router.put(['/me', '/profile'], auth, async (req, res) => {
  try {
    const { name, email } = req.body || {};
    const update = {};
    if (typeof name === 'string') update.name = name.trim();
    if (typeof email === 'string') update.email = email.trim().toLowerCase();
    if (Object.keys(update).length === 0) {
      return res.status(400).json({ error: 'no updatable fields' });
    }

    const user = await User.findByIdAndUpdate(req.user.id, { $set: update }, { new: true });
    if (!user) return res.status(404).json({ error: 'user not found' });

    return res.json({
      user: { id: user._id, phone: user.phone, name: user.name, email: user.email, role: user.role, walletBalance: user.walletBalance }
    });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'server error' });
  }
});

export default router;
