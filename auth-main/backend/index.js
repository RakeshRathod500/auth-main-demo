const express = require('express');
const { Pool } = require('pg');
const speakeasy = require('speakeasy');
const qrcode = require('qrcode');
const cors = require('cors');
require('dotenv').config();

const app = express();

// Optional: Restrict CORS to your frontend server
const corsOptions = {
  origin: '44.223.30.17', // replace with actual IP/domain
  credentials: true,
};
app.use(cors(corsOptions));

app.use(express.json());

const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
});

pool.connect((err, client, release) => {
  if (err) {
    return console.error('Error acquiring client', err.stack);
  }
  console.log('Database connected successfully');
  release();
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const result = await pool.query('SELECT * FROM users WHERE username = $1 AND password = $2', [username, password]);
    const user = result.rows[0];
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });

    if (user.role && user.role.trim().toLowerCase() === 'admin') {
      return res.json({ success: true, role: user.role });
    }

    if (!user.is_2fa_setup) {
      const secret = speakeasy.generateSecret({ name: `Craftysogo:${username}` });
      await pool.query('UPDATE users SET secret_2fa = $1 WHERE id = $2', [secret.base32, user.id]);
      qrcode.toDataURL(secret.otpauth_url, (err, data_url) => {
        if (err) return res.status(500).json({ error: 'QR code generation failed' });
        res.json({ qrCode: data_url, userId: user.id, is2FASetup: false });
      });
    } else {
      res.json({ userId: user.id, is2FASetup: true });
    }
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/verify-2fa', async (req, res) => {
  const { userId, token } = req.body;
  try {
    const user = (await pool.query('SELECT * FROM users WHERE id = $1', [userId])).rows[0];
    const verified = speakeasy.totp.verify({
      secret: user.secret_2fa,
      encoding: 'base32',
      token,
    });

    if (verified) {
      await pool.query('UPDATE users SET is_2fa_setup = TRUE WHERE id = $1', [userId]);
      res.json({ success: true, role: user.role });
    } else {
      res.status(401).json({ error: 'Invalid 2FA code' });
    }
  } catch (err) {
    console.error('2FA verification error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/users', async (req, res) => {
  try {
    const result = await pool.query('SELECT id, username, role FROM users');
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

app.post('/users', async (req, res) => {
  const { username, password, role } = req.body;
  try {
    const result = await pool.query(
      'INSERT INTO users (username, password, role) VALUES ($1, $2, $3) RETURNING *',
      [username, password, role || 'user']
    );
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Failed to create user' });
  }
});

app.delete('/users/:id', async (req, res) => {
  const { id } = req.params;
  try {
    await pool.query('DELETE FROM users WHERE id = $1', [id]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed to delete user' });
  }
});

app.listen(3000, () => console.log('Server running on port 3000'));
