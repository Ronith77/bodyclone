// server.js
require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const nodemailer = require('nodemailer');

const app = express();

// Simple request logger
app.use((req, res, next) => {
  console.log(new Date().toISOString(), req.method, req.url);
  next();
});

// Middleware
app.use(helmet());
app.use(express.json());

// 🔴 CHANGED: allow all origins during development
// (this fixes "Error connecting to server" from your React app)
app.use(cors());

const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 200 });
app.use(limiter);

// DB pool
const pool = new Pool({ connectionString: process.env.DATABASE_URL });

// Config
const SALT_ROUNDS = 10;
const ACCESS_TOKEN_SECRET = process.env.ACCESS_TOKEN_SECRET || 'access_secret';
const ACCESS_TOKEN_EXPIRES_IN = '15m';
const REFRESH_TOKEN_SECRET = process.env.REFRESH_TOKEN_SECRET || 'refresh_secret';
const REFRESH_TOKEN_EXPIRES_DAYS = process.env.REFRESH_TOKEN_EXPIRES_DAYS
  ? parseInt(process.env.REFRESH_TOKEN_EXPIRES_DAYS)
  : 30;

// Mailer
const mailTransport = nodemailer.createTransport({
  host: process.env.SMTP_HOST || 'smtp.gmail.com',
  port: process.env.SMTP_PORT ? parseInt(process.env.SMTP_PORT) : 587,
  secure: false,
  auth: process.env.SMTP_USER
    ? { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
    : undefined,
});

async function sendMail(to, subject, html) {
  if (!process.env.SMTP_USER) {
    console.warn('SMTP not configured — skipping email send');
    return null;
  }
  const info = await mailTransport.sendMail({
    from: process.env.SMTP_FROM || process.env.SMTP_USER,
    to,
    subject,
    html,
  });
  console.log('Mail sent:', info.messageId);
  return info;
}

// Helpers
function createAccessToken(payload) {
  return jwt.sign(payload, ACCESS_TOKEN_SECRET, { expiresIn: ACCESS_TOKEN_EXPIRES_IN });
}
function createRefreshToken(payload) {
  return jwt.sign(payload, REFRESH_TOKEN_SECRET, {
    expiresIn: `${REFRESH_TOKEN_EXPIRES_DAYS}d`,
  });
}

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ error: 'Missing Authorization header' });
  const token = authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Malformed Authorization header' });
  jwt.verify(token, ACCESS_TOKEN_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid or expired token' });
    req.user = user; // { userId, email, iat, exp }
    next();
  });
}

// Admin middleware
async function requireAdmin(req, res, next) {
  try {
    if (!req.user || !req.user.userId)
      return res.status(401).json({ error: 'Unauthorized' });
    const { rows } = await pool.query('SELECT role FROM users WHERE id=$1', [
      req.user.userId,
    ]);
    if (!rows.length) return res.status(404).json({ error: 'User not found' });
    if (rows[0].role !== 'admin') return res.status(403).json({ error: 'Admin only' });
    next();
  } catch (err) {
    console.error('Admin middleware error', err);
    res.status(500).json({ error: 'Server error' });
  }
}

// Routes

// Register
app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password, full_name } = req.body;
    if (!email || !password)
      return res.status(400).json({ error: 'email and password required' });

    const { rows: existing } = await pool.query(
      'SELECT id FROM users WHERE email=$1',
      [email.toLowerCase()]
    );
    if (existing.length)
      return res.status(400).json({ error: 'User with that email already exists' });

    const password_hash = await bcrypt.hash(password, SALT_ROUNDS);
    const verification_token = uuidv4();

    const insertQuery = `
      INSERT INTO users (email, password_hash, full_name, verification_token)
      VALUES ($1,$2,$3,$4)
      RETURNING id, email, full_name, is_verified, created_at
    `;
    const { rows } = await pool.query(insertQuery, [
      email.toLowerCase(),
      password_hash,
      full_name || null,
      verification_token,
    ]);
    const user = rows[0];

    const verificationLink = `${
      process.env.CLIENT_URL || 'http://localhost:3000'
    }/verify-email?token=${verification_token}`;

    try {
      const html = `<p>Click to verify: <a href="${verificationLink}">${verificationLink}</a></p>`;
      await sendMail(email, 'Verify your HealthMate account', html);
    } catch (err) {
      console.warn(
        'Failed to send verification email; returning link in response for dev'
      );
    }

    res.status(201).json({
      message: 'Registered. Verify your email (link sent if SMTP configured).',
      user: { id: user.id, email: user.email, full_name: user.full_name },
      verificationLink,
    });
  } catch (err) {
    console.error('Register error', err);
    res.status(500).json({ error: 'Server error during register' });
  }
});

// Verify email
app.get('/api/auth/verify', async (req, res) => {
  try {
    const token = req.query.token;
    if (!token) return res.status(400).json({ error: 'token query param required' });

    const { rows } = await pool.query(
      'SELECT id, is_verified FROM users WHERE verification_token=$1',
      [token]
    );
    if (!rows.length) return res.status(400).json({ error: 'Invalid verification token' });

    const user = rows[0];
    if (user.is_verified) return res.json({ message: 'Email already verified' });

    await pool.query(
      'UPDATE users SET is_verified=true, verification_token=null WHERE id=$1',
      [user.id]
    );
    res.json({ message: 'Email verified successfully' });
  } catch (err) {
    console.error('Verify error', err);
    res.status(500).json({ error: 'Server error during verification' });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password)
      return res.status(400).json({ error: 'email and password required' });

    const { rows } = await pool.query(
      'SELECT id, email, password_hash, full_name, is_verified FROM users WHERE email=$1',
      [email.toLowerCase()]
    );
    if (!rows.length) return res.status(400).json({ error: 'Invalid credentials' });

    const user = rows[0];
    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) return res.status(400).json({ error: 'Invalid credentials' });

    if (!user.is_verified)
      return res.status(403).json({
        error: 'Email not verified. Please verify before logging in.',
      });

    const accessToken = createAccessToken({ userId: user.id, email: user.email });
    const refreshToken = createRefreshToken({
      userId: user.id,
      email: user.email,
    });
    const expiresAt = new Date(
      Date.now() + REFRESH_TOKEN_EXPIRES_DAYS * 24 * 60 * 60 * 1000
    );

    await pool.query(
      'INSERT INTO refresh_tokens (user_id, token, expires_at) VALUES ($1,$2,$3)',
      [user.id, refreshToken, expiresAt]
    );

    res.json({
      accessToken,
      refreshToken,
      user: { id: user.id, email: user.email, full_name: user.full_name },
    });
  } catch (err) {
    console.error('Login error', err);
    res.status(500).json({ error: 'Server error during login' });
  }
});

// Refresh token
app.post('/api/auth/refresh', async (req, res) => {
  try {
    const { refreshToken } = req.body;
    if (!refreshToken)
      return res.status(400).json({ error: 'refreshToken required' });

    const { rows } = await pool.query(
      'SELECT user_id, expires_at FROM refresh_tokens WHERE token=$1',
      [refreshToken]
    );
    if (!rows.length) return res.status(403).json({ error: 'Invalid refresh token' });

    const item = rows[0];
    if (new Date() > new Date(item.expires_at)) {
      await pool.query('DELETE FROM refresh_tokens WHERE token=$1', [refreshToken]);
      return res.status(403).json({ error: 'Refresh token expired' });
    }

    jwt.verify(refreshToken, REFRESH_TOKEN_SECRET, (err, payload) => {
      if (err) return res.status(403).json({ error: 'Invalid refresh token' });
      const newAccess = createAccessToken({
        userId: payload.userId,
        email: payload.email,
      });
      res.json({ accessToken: newAccess });
    });
  } catch (err) {
    console.error('Refresh token error', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Logout
app.post('/api/auth/logout', async (req, res) => {
  try {
    const { refreshToken } = req.body;
    if (!refreshToken)
      return res.status(400).json({ error: 'refreshToken required' });

    await pool.query('DELETE FROM refresh_tokens WHERE token=$1', [refreshToken]);
    res.json({ message: 'Logged out' });
  } catch (err) {
    console.error('Logout error', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Forgot password
app.post('/api/auth/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'email required' });

    const { rows } = await pool.query('SELECT id FROM users WHERE email=$1', [
      email.toLowerCase(),
    ]);
    if (!rows.length) {
      return res.json({
        message:
          'If that email exists, a password reset link was created (dev: returned in response).',
      });
    }

    const user = rows[0];
    const resetToken = uuidv4();
    const expires = new Date(Date.now() + 60 * 60 * 1000); // 1 hour

    await pool.query(
      'UPDATE users SET reset_password_token=$1, reset_password_expires=$2 WHERE id=$3',
      [resetToken, expires, user.id]
    );

    const resetLink = `${
      process.env.CLIENT_URL || 'http://localhost:3000'
    }/reset-password?token=${resetToken}`;

    try {
      const html = `<p>Click to reset your password: <a href="${resetLink}">${resetLink}</a></p>`;
      await sendMail(email, 'Reset your HealthMate password', html);
    } catch (err) {
      console.warn(
        'Failed to send reset email; returning link in response for dev'
      );
    }

    res.json({
      message:
        'Password reset link created (if SMTP configured it was sent).',
      resetLink,
    });
  } catch (err) {
    console.error('Forgot password error', err);
    res.status(500).json({ error: 'Server error during forgot-password' });
  }
});

// Reset password
app.post('/api/auth/reset-password', async (req, res) => {
  try {
    const { token, newPassword } = req.body;
    if (!token || !newPassword)
      return res.status(400).json({ error: 'token and newPassword required' });

    const { rows } = await pool.query(
      'SELECT id, reset_password_expires FROM users WHERE reset_password_token=$1',
      [token]
    );
    if (!rows.length)
      return res.status(400).json({ error: 'Invalid or expired reset token' });

    const user = rows[0];
    const expires = user.reset_password_expires;
    if (!expires || new Date() > new Date(expires))
      return res.status(400).json({ error: 'Reset token expired' });

    const password_hash = await bcrypt.hash(newPassword, SALT_ROUNDS);
    await pool.query(
      'UPDATE users SET password_hash=$1, reset_password_token=null, reset_password_expires=null WHERE id=$2',
      [password_hash, user.id]
    );

    res.json({ message: 'Password reset successful' });
  } catch (err) {
    console.error('Reset password error', err);
    res.status(500).json({ error: 'Server error during reset-password' });
  }
});

// Profile (protected)
app.get('/api/auth/profile', authenticateToken, async (req, res) => {
  try {
    const { userId } = req.user;
    const { rows } = await pool.query(
      'SELECT id, email, full_name, is_verified, role, created_at FROM users WHERE id=$1',
      [userId]
    );
    if (!rows.length) return res.status(404).json({ error: 'User not found' });
    res.json({ user: rows[0] });
  } catch (err) {
    console.error('Profile error', err);
    res.status(500).json({ error: 'Server error fetching profile' });
  }
});

// Admin endpoints

// List users
app.get('/api/admin/users', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit) || 20, 100);
    const page = Math.max(parseInt(req.query.page) || 1, 1);
    const q = (req.query.search || '').toLowerCase();
    const offset = (page - 1) * limit;

    if (q) {
      const { rows } = await pool.query(
        `
        SELECT id, email, full_name, is_verified, role, created_at
        FROM users
        WHERE LOWER(email) LIKE $1 OR LOWER(full_name) LIKE $1
        ORDER BY created_at DESC
        LIMIT $2 OFFSET $3
        `,
        [`%${q}%`, limit, offset]
      );
      return res.json({ users: rows });
    } else {
      const { rows } = await pool.query(
        `
        SELECT id, email, full_name, is_verified, role, created_at
        FROM users
        ORDER BY created_at DESC
        LIMIT $1 OFFSET $2
        `,
        [limit, offset]
      );
      return res.json({ users: rows });
    }
  } catch (err) {
    console.error('Admin list error', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get single user
app.get('/api/admin/users/:id', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { rows } = await pool.query(
      'SELECT id, email, full_name, is_verified, role, created_at FROM users WHERE id=$1',
      [id]
    );
    if (!rows.length) return res.status(404).json({ error: 'User not found' });
    res.json({ user: rows[0] });
  } catch (err) {
    console.error('Admin get user error', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Create user
app.post('/api/admin/users', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { email, full_name, password, role } = req.body;
    if (!email) return res.status(400).json({ error: 'email required' });

    const { rows: existing } = await pool.query(
      'SELECT id FROM users WHERE email=$1',
      [email.toLowerCase()]
    );
    if (existing.length)
      return res.status(400).json({ error: 'User with that email already exists' });

    const password_hash = password
      ? await bcrypt.hash(password, SALT_ROUNDS)
      : await bcrypt.hash(uuidv4().slice(0, 12), SALT_ROUNDS);

    const insertQ = `
      INSERT INTO users (email, password_hash, full_name, role)
      VALUES ($1,$2,$3,$4)
      RETURNING id, email, full_name, role, is_verified
    `;
    const { rows } = await pool.query(insertQ, [
      email.toLowerCase(),
      password_hash,
      full_name || null,
      role || 'user',
    ]);
    res.status(201).json({ user: rows[0] });
  } catch (err) {
    console.error('Admin create user error', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Update user
app.put('/api/admin/users/:id', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { full_name, role, is_verified } = req.body;
    await pool.query(
      `
      UPDATE users
      SET full_name=COALESCE($1,full_name),
          role=COALESCE($2,role),
          is_verified=COALESCE($3,is_verified)
      WHERE id=$4
      `,
      [full_name, role, is_verified, id]
    );
    res.json({ message: 'User updated' });
  } catch (err) {
    console.error('Admin update error', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Delete user
app.delete(
  '/api/admin/users/:id',
  authenticateToken,
  requireAdmin,
  async (req, res) => {
    try {
      const { id } = req.params;
      await pool.query('DELETE FROM users WHERE id=$1', [id]);
      res.json({ message: 'User deleted' });
    } catch (err) {
      console.error('Admin delete error', err);
      res.status(500).json({ error: 'Server error' });
    }
  }
);

// Verify toggle
app.post(
  '/api/admin/users/:id/verify',
  authenticateToken,
  requireAdmin,
  async (req, res) => {
    try {
      const { id } = req.params;
      const { is_verified } = req.body;
      await pool.query('UPDATE users SET is_verified=$1 WHERE id=$2', [
        !!is_verified,
        id,
      ]);
      res.json({ message: 'User verification toggled' });
    } catch (err) {
      console.error('Admin verify toggle error', err);
      res.status(500).json({ error: 'Server error' });
    }
  }
);

// DEBUG: list users without auth (for development only)
console.log('Registering /debug/users route');
app.get('/debug/users', async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, full_name, email, role, is_active, created_at
       FROM users
       ORDER BY id`
    );
    res.json(result.rows);
  } catch (err) {
    console.error('Error fetching users (debug):', err);
    res
      .status(500)
      .json({ message: 'Failed to fetch users' });
  }
});

// Health check
app.get('/', (req, res) =>
  res.json({ ok: true, now: new Date().toISOString() })
);

// Start server
const PORT = process.env.PORT || 4000;

app.listen(PORT, async () => {
  console.log(`Server running on port ${PORT}`);
  try {
    await pool.query('SELECT 1');
    console.log('Connected to DB');
  } catch (err) {
    console.error('DB connection failed', err);
  }
});
