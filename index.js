// ===== Import library =====
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');
const mysql = require('mysql2/promise');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 80;
const SECRET_KEY = process.env.JWT_SECRET || "secret123";

// ===== Middleware global =====
app.use(express.json());
app.use(helmet());
app.use(cors());

// ===== Database Pool =====
const db = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASS || '',
  database: process.env.DB_NAME || 'testdb',
});

// ===== JWT Auth Middleware =====
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'] || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.split(' ')[1] : null;
  if (!token) return res.status(401).json({ message: 'Token required' });

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) return res.status(403).json({ message: 'Invalid or expired token' });
    req.user = user;
    next();
  });
}

// ===== Routes =====

// Root
app.get('/', (req, res) => res.send(`Server running on port ${port}`));

// Dummy GET
app.get('/dummy-get', (req, res) => res.json({ message: 'This is a dummy GET API' }));

// Login (generate JWT)
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const [rows] = await db.query(
      "SELECT * FROM users WHERE username=? AND password=?",
      [username, password]
    );
    if (!rows.length) return res.status(401).json({ message: 'Username/password salah' });
    const token = jwt.sign({ username }, SECRET_KEY, { expiresIn: '1h' });
    res.json({ token });
  } catch (err) {
    res.status(500).json({ message: 'Database error' });
  }
});

// GET all users (protected)
app.get('/users', authenticateToken, async (req, res) => {
  try {
    const [rows] = await db.query("SELECT id, username, email FROM users");
    res.json(rows);
  } catch (err) {
    res.status(500).json({ message: 'Database error' });
  }
});

// GET user by ID (protected)
app.get('/users/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const [rows] = await db.query(
      "SELECT id, username, email FROM users WHERE id=?",
      [id]
    );
    res.json(rows);
  } catch (err) {
    res.status(500).json({ message: 'Database error' });
  }
});

// POST add user (protected + validation)
app.post('/users', authenticateToken,
  body('username').isLength({ min: 3 }),
  body('email').isEmail(),
  body('password').isLength({ min: 4 }),
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const { username, email, password } = req.body;
    try {
      await db.query(
        "INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
        [username, email, password]
      );
      res.json({ message: "User berhasil ditambahkan" });
    } catch (err) {
      res.status(500).json({ message: 'Database error' });
    }
  }
);

// DELETE user by ID (protected)
app.delete('/users/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  try {
    const [result] = await db.query("DELETE FROM users WHERE id=?", [id]);
    if (result.affectedRows > 0) res.json({ message: `User ${id} dihapus` });
    else res.status(404).json({ message: 'User tidak ditemukan' });
  } catch (err) {
    res.status(500).json({ message: 'Database error' });
  }
});

// ===== Start server =====
app.listen(port, () => console.log(`Server running on http://localhost:${port}`));
