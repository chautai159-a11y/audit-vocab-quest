const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');

const app = express();
const SECRET       = process.env.JWT_SECRET       || 'avq_change_this_secret_in_production';
const ADMIN_SECRET = process.env.ADMIN_JWT_SECRET || 'avq_admin_secret_change_in_production';
const ADMIN_USER   = process.env.ADMIN_USERNAME   || 'admin';
const ADMIN_PASS   = process.env.ADMIN_PASSWORD   || '';
const PORT = process.env.PORT || 3000;

// ── Database (PostgreSQL) ─────────────────────────────────────────────────────
const dbUrl = process.env.DATABASE_URL || '';
const needsSsl = dbUrl && !dbUrl.includes('localhost') && !dbUrl.includes('127.0.0.1');
const pool = new Pool({
  connectionString: dbUrl,
  connectionTimeoutMillis: 5000,
  ssl: needsSsl ? { rejectUnauthorized: false } : false
});

async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id            SERIAL PRIMARY KEY,
      username      TEXT NOT NULL UNIQUE,
      display_name  TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      is_active     BOOLEAN DEFAULT TRUE,
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
  // migrate: add is_active to existing tables that predate this column
  await pool.query(`
    ALTER TABLE users ADD COLUMN IF NOT EXISTS is_active BOOLEAN DEFAULT TRUE;
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

function adminAuth(req, res, next) {
  try {
    const token = (req.headers.authorization || '').replace('Bearer ', '');
    const payload = jwt.verify(token, ADMIN_SECRET);
    if (payload.role !== 'admin') throw new Error('not admin');
    next();
  } catch {
    res.status(401).json({ error: 'Không có quyền truy cập.' });
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
  if (user.is_active === false)
    return res.status(403).json({ error: 'Tài khoản đã bị khóa. Vui lòng liên hệ quản trị viên.' });

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

// ── Admin ─────────────────────────────────────────────────────────────────────
app.post('/api/admin/login', (req, res) => {
  const { username, password } = req.body || {};
  if (!ADMIN_PASS) return res.status(503).json({ error: 'Admin chưa được cấu hình.' });
  if (username !== ADMIN_USER || password !== ADMIN_PASS)
    return res.status(401).json({ error: 'Sai tên đăng nhập hoặc mật khẩu admin.' });

  const token = jwt.sign({ role: 'admin' }, ADMIN_SECRET, { expiresIn: '8h' });
  res.json({ token });
});

app.get('/api/admin/stats', adminAuth, async (req, res) => {
  const today = new Date().toISOString().slice(0, 10);
  const [totals, active, completions] = await Promise.all([
    pool.query('SELECT COUNT(*)::int AS total_users, COUNT(*) FILTER (WHERE is_active) ::int AS active_users FROM users'),
    pool.query('SELECT COUNT(DISTINCT user_id)::int AS active_today FROM completions WHERE play_date = $1', [today]),
    pool.query('SELECT COUNT(*)::int AS total_completions, COALESCE(SUM(xp_earned),0)::int AS total_xp FROM completions'),
  ]);
  res.json({ ...totals.rows[0], ...active.rows[0], ...completions.rows[0] });
});

app.get('/api/admin/users', adminAuth, async (req, res) => {
  const { rows } = await pool.query(`
    SELECT u.id, u.username, u.display_name, u.is_active, u.created_at,
           p.xp, p.streak, p.last_date,
           COUNT(c.id)::int AS words_done
    FROM users u
    JOIN progress p ON u.id = p.user_id
    LEFT JOIN completions c ON u.id = c.user_id
    GROUP BY u.id, u.username, u.display_name, u.is_active, u.created_at,
             p.xp, p.streak, p.last_date
    ORDER BY u.created_at DESC, u.id DESC
  `);
  res.json(rows);
});

app.patch('/api/admin/users/:id', adminAuth, async (req, res) => {
  const { id } = req.params;
  const { display_name, is_active } = req.body || {};
  if (display_name !== undefined) {
    await pool.query('UPDATE users SET display_name=$1 WHERE id=$2', [display_name.trim(), id]);
  }
  if (is_active !== undefined) {
    await pool.query('UPDATE users SET is_active=$1 WHERE id=$2', [is_active, id]);
  }
  res.json({ ok: true });
});

app.post('/api/admin/users/:id/reset-password', adminAuth, async (req, res) => {
  const { id } = req.params;
  const { new_password } = req.body || {};
  if (!new_password || new_password.length < 6)
    return res.status(400).json({ error: 'Mật khẩu mới phải có ít nhất 6 ký tự.' });
  const hash = bcrypt.hashSync(new_password, 10);
  await pool.query('UPDATE users SET password_hash=$1 WHERE id=$2', [hash, id]);
  res.json({ ok: true });
});

app.delete('/api/admin/users/:id', adminAuth, async (req, res) => {
  await pool.query('DELETE FROM users WHERE id=$1', [req.params.id]);
  res.json({ ok: true });
});

// ── Fallback ──────────────────────────────────────────────────────────────────
app.get('/admin', (_, res) =>
  res.sendFile(path.join(__dirname, 'public', 'admin.html'))
);

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
