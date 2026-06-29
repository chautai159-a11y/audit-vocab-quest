const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');

const app = express();
const SECRET = process.env.JWT_SECRET || 'avq_change_this_secret_in_production';
const PORT = process.env.PORT || 3000;

// ── Database (PostgreSQL) ─────────────────────────────────────────────────────
const dbUrl = process.env.DATABASE_URL || '';
const pool = new Pool({
  connectionString: dbUrl,
  connectionTimeoutMillis: 5000,
  ssl: dbUrl && !dbUrl.includes('localhost') && !dbUrl.includes('.railway.internal')
    ? { rejectUnauthorized: false }
    : false
});

async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id            SERIAL PRIMARY KEY,
      username      TEXT NOT NULL UNIQUE,
      display_name  TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      created_at    DATE DEFAULT CURRENT_DATE
    );

    CREATE TABLE IF NOT EXISTS progress (
      user_id   INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
      xp        INTEGER DEFAULT 0,
      streak    INTEGER DEFAULT 0,
      last_date TEXT    DEFAULT NULL
    );

    CREATE TABLE IF NOT EXISTS completions (
      id         SERIAL PRIMARY KEY,
      user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      word_index INTEGER NOT NULL,
      play_date  TEXT    NOT NULL,
      correct    INTEGER NOT NULL,
      xp_earned  INTEGER NOT NULL,
      created_at TIMESTAMP DEFAULT NOW(),
      UNIQUE(user_id, play_date)
    );
  `);
  console.log('✅  Database tables ready.');
}

// ── Middleware ────────────────────────────────────────────────────────────────
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

function auth(req, res, next) {
  try {
    const token = (req.headers.authorization || '').replace('Bearer ', '');
    req.user = jwt.verify(token, SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Phiên đăng nhập hết hạn. Vui lòng đăng nhập lại.' });
  }
}

// ── Auth ──────────────────────────────────────────────────────────────────────
app.post('/api/register', async (req, res) => {
  const { username, display_name, password } = req.body || {};
  if (!username?.trim() || !display_name?.trim() || !password)
    return res.status(400).json({ error: 'Vui lòng điền đầy đủ thông tin.' });
  if (password.length < 6)
    return res.status(400).json({ error: 'Mật khẩu phải có ít nhất 6 ký tự.' });
  if (username.trim().length < 3)
    return res.status(400).json({ error: 'Tên đăng nhập phải có ít nhất 3 ký tự.' });

  try {
    const hash = bcrypt.hashSync(password, 10);
    const { rows } = await pool.query(
      'INSERT INTO users (username, display_name, password_hash) VALUES ($1, $2, $3) RETURNING id',
      [username.trim().toLowerCase(), display_name.trim(), hash]
    );
    const uid = rows[0].id;
    await pool.query('INSERT INTO progress (user_id) VALUES ($1)', [uid]);

    const token = jwt.sign({ id: uid }, SECRET, { expiresIn: '90d' });
    res.json({ token, display_name: display_name.trim() });
  } catch (e) {
    if (e.code === '23505')
      return res.status(400).json({ error: 'Tên đăng nhập đã được sử dụng.' });
    console.error(e);
    res.status(500).json({ error: 'Lỗi server.' });
  }
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body || {};
  const { rows } = await pool.query(
    'SELECT * FROM users WHERE username = $1',
    [username?.trim()?.toLowerCase()]
  );
  const user = rows[0];
  if (!user || !bcrypt.compareSync(password || '', user.password_hash))
    return res.status(401).json({ error: 'Sai tên đăng nhập hoặc mật khẩu.' });

  const token = jwt.sign({ id: user.id }, SECRET, { expiresIn: '90d' });
  res.json({ token, display_name: user.display_name });
});

// ── Profile ───────────────────────────────────────────────────────────────────
app.get('/api/profile', auth, async (req, res) => {
  const { rows } = await pool.query(`
    SELECT u.display_name, p.xp, p.streak, p.last_date
    FROM users u JOIN progress p ON u.id = p.user_id
    WHERE u.id = $1
  `, [req.user.id]);

  const { rows: completionRows } = await pool.query(
    'SELECT play_date FROM completions WHERE user_id = $1',
    [req.user.id]
  );

  res.json({
    ...rows[0],
    completed_dates: completionRows.map(r => r.play_date)
  });
});

// ── Submit daily result ───────────────────────────────────────────────────────
app.post('/api/complete', auth, async (req, res) => {
  const { word_index, play_date, correct, xp_earned } = req.body || {};

  try {
    await pool.query(
      'INSERT INTO completions (user_id, word_index, play_date, correct, xp_earned) VALUES ($1,$2,$3,$4,$5)',
      [req.user.id, word_index, play_date, correct, xp_earned]
    );
  } catch (e) {
    if (e.code === '23505')
      return res.status(409).json({ error: 'Đã hoàn thành từ hôm nay rồi.' });
    return res.status(500).json({ error: 'Lỗi server.' });
  }

  const { rows } = await pool.query(
    'SELECT xp, streak, last_date FROM progress WHERE user_id = $1',
    [req.user.id]
  );
  const prog = rows[0];
  const yesterday = new Date(Date.now() - 864e5).toISOString().slice(0, 10);
  const newStreak = prog.last_date === yesterday ? Number(prog.streak) + 1 : 1;
  const newXp = Number(prog.xp) + xp_earned;

  await pool.query(
    'UPDATE progress SET xp=$1, streak=$2, last_date=$3 WHERE user_id=$4',
    [newXp, newStreak, play_date, req.user.id]
  );

  res.json({ xp: newXp, streak: newStreak });
});

// ── Leaderboard ───────────────────────────────────────────────────────────────
app.get('/api/leaderboard', auth, async (req, res) => {
  const { rows } = await pool.query(`
    SELECT u.id, u.display_name, p.xp, p.streak,
           COUNT(c.id)::int AS words_done
    FROM users u
    JOIN progress p ON u.id = p.user_id
    LEFT JOIN completions c ON u.id = c.user_id
    GROUP BY u.id, u.display_name, p.xp, p.streak
    ORDER BY p.xp DESC
    LIMIT 20
  `);
  res.json(rows.map((r, i) => ({ ...r, rank: i + 1, is_me: r.id === req.user.id })));
});

// ── Fallback ──────────────────────────────────────────────────────────────────
app.get('*', (_, res) =>
  res.sendFile(path.join(__dirname, 'public', 'index.html'))
);

// ── Start ─────────────────────────────────────────────────────────────────────
async function startWithRetry(retries = 30, delay = 5000) {
  for (let i = 1; i <= retries; i++) {
    try {
      await initDB();
      app.listen(PORT, () => {
        console.log(`\n✅  Audit Vocab Quest → http://localhost:${PORT}\n`);
      });
      return;
    } catch (err) {
      console.error(`⏳  DB attempt ${i}/${retries} failed:`, err.message || err.code || String(err));
      if (i === retries) { console.error('❌  Giving up.'); process.exit(1); }
      await new Promise(r => setTimeout(r, delay));
    }
  }
}
startWithRetry();
