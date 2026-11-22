const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const multer = require('multer');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Database = require('better-sqlite3');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 3000;
const ROOT = __dirname;
const DATA_DIR = process.env.DATA_DIR || path.join(ROOT, 'data');
const UPLOAD_DIR = process.env.UPLOAD_DIR || path.join(DATA_DIR, 'uploads');

fs.mkdirSync(UPLOAD_DIR, { recursive: true });
fs.mkdirSync(DATA_DIR, { recursive: true });

const JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET || JWT_SECRET.length < 32) {
  console.error('Set JWT_SECRET to a random secret of at least 32 characters.');
  process.exit(1);
}

const db = new Database(path.join(DATA_DIR, 'vybora.sqlite'));

db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  display_name TEXT NOT NULL,
  username TEXT NOT NULL UNIQUE COLLATE NOCASE,
  email TEXT NOT NULL UNIQUE COLLATE NOCASE,
  password_hash TEXT NOT NULL,
  bio TEXT DEFAULT '',
  avatar TEXT DEFAULT '',
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS posts(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id),
  video_path TEXT NOT NULL,
  caption TEXT DEFAULT '',
  hashtags TEXT DEFAULT '',
  views INTEGER DEFAULT 0,
  ai_label TEXT DEFAULT 'approved',
  ai_reason TEXT DEFAULT '',
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS likes(
  user_id INTEGER NOT NULL REFERENCES users(id),
  post_id INTEGER NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY(user_id, post_id)
);

CREATE TABLE IF NOT EXISTS comments(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id),
  post_id INTEGER NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
  text TEXT NOT NULL,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS follows(
  follower_id INTEGER NOT NULL REFERENCES users(id),
  following_id INTEGER NOT NULL REFERENCES users(id),
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY(follower_id, following_id),
  CHECK(follower_id != following_id)
);

CREATE TABLE IF NOT EXISTS stories(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id),
  media_path TEXT NOT NULL,
  media_type TEXT NOT NULL,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS messages(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  sender_id INTEGER NOT NULL REFERENCES users(id),
  receiver_id INTEGER NOT NULL REFERENCES users(id),
  text TEXT NOT NULL,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS feedback(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id),
  type TEXT NOT NULL,
  text TEXT NOT NULL,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS reports(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  reporter_id INTEGER NOT NULL REFERENCES users(id),
  post_id INTEGER REFERENCES posts(id),
  reason TEXT NOT NULL,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS posts_created
ON posts(created_at DESC);

CREATE INDEX IF NOT EXISTS messages_pair
ON messages(sender_id, receiver_id, created_at);
`);

app.use(helmet({
  crossOriginResourcePolicy: { policy: 'cross-origin' },
  contentSecurityPolicy: false
}));

app.use(express.json({ limit: '1mb' }));

app.use('/uploads', express.static(UPLOAD_DIR, {
  maxAge: '1d'
}));

app.use(express.static(ROOT));

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 300,
  standardHeaders: true,
  legacyHeaders: false
});

app.use('/api', limiter);

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => {
    cb(
      null,
      crypto.randomUUID() +
      path.extname(file.originalname).toLowerCase()
    );
  }
});

const upload = multer({
  storage,
  limits: {
    fileSize: 100 * 1024 * 1024
  },
  fileFilter: (req, file, cb) => {
    const ok =
      file.mimetype.startsWith('video/') ||
      file.mimetype.startsWith('image/');

    cb(
      ok ? null : new Error('Only image or video files are accepted.'),
      ok
    );
  }
});

const publicUser = u => ({
  id: u.id,
  username: u.username,
  display_name: u.display_name,
  bio: u.bio,
  avatar: u.avatar,
  created_at: u.created_at
});

function auth(req, res, next) {
  const h = req.headers.authorization || '';
  const t = h.startsWith('Bearer ') ? h.slice(7) : '';

  try {
    req.user = jwt.verify(t, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({
      error: 'Please log in to continue.'
    });
  }
}

function tokenFor(u) {
  return jwt.sign(
    { id: u.id, username: u.username },
    JWT_SECRET,
    { expiresIn: '14d' }
  );
}

function counts(userId) {
  return {
    followers_count: db.prepare(
      'SELECT count(*) n FROM follows WHERE following_id=?'
    ).get(userId).n,

    following_count: db.prepare(
      'SELECT count(*) n FROM follows WHERE follower_id=?'
    ).get(userId).n
  };
}

function postObject(p, viewer) {
  const user = db.prepare(
    'SELECT * FROM users WHERE id=?'
  ).get(p.user_id);

  return {
    ...p,
    video_url: '/uploads/' + p.video_path,
    user: publicUser(user),

    likes_count: db.prepare(
      'SELECT count(*) n FROM likes WHERE post_id=?'
    ).get(p.id).n,

    comments_count: db.prepare(
      'SELECT count(*) n FROM comments WHERE post_id=?'
    ).get(p.id).n,

    liked: !!db.prepare(
      'SELECT 1 FROM likes WHERE post_id=? AND user_id=?'
    ).get(p.id, viewer)
  };
}

function analyseVideo(file, caption, hashtags) {
  const text = (caption + ' ' + hashtags).toLowerCase();

  const blocked = [
    'kill yourself',
    'terrorist recruitment',
    'child sexual',
    'rape threats',
    'how to make a bomb'
  ];

  if (blocked.some(x => text.includes(x))) {
    return {
      label: 'review',
      reason: 'Potentially harmful text detected; sent for human review.'
    };
  }

  if (!file.mimetype.startsWith('video/')) {
    return {
      label: 'review',
      reason: 'This upload is not a video; sent for review.'
    };
  }

  if (!caption.trim() && !hashtags.trim()) {
    return {
      label: 'limited',
      reason: 'Add context or hashtags to help people discover your video.'
    };
  }

  return {
    label: 'approved',
    reason: 'No obvious feed-suitability issue detected. Engagement and viewer feedback will guide distribution.'
  };
}

// REGISTER
app.post(
  '/api/auth/register',
  rateLimit({ windowMs: 60 * 60 * 1000, limit: 15 }),
  async (req, res) => {
    try {
      const {
        display_name,
        username,
        email,
        password
      } = req.body || {};

      if (!display_name || !username || !email || !password) {
        return res.status(400).json({
          error: 'Complete all fields.'
        });
      }

      if (!/^[a-zA-Z0-9_]{3,20}$/.test(username)) {
        return res.status(400).json({
          error: 'Username must be 3–20 characters (letters, numbers, underscores).'
        });
      }

      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        return res.status(400).json({
          error: 'Enter a valid email.'
        });
      }

      if (password.length < 8) {
        return res.status(400).json({
          error: 'Password must be at least 8 characters.'
        });
      }

      const hash = await bcrypt.hash(password, 12);

      const info = db.prepare(`
        INSERT INTO users(
          display_name,
          username,
          email,
          password_hash
        )
        VALUES(?,?,?,?)
      `).run(
        display_name.trim().slice(0, 60),
        username,
        email.toLowerCase(),
        hash
      );

      const u = db.prepare(
        'SELECT * FROM users WHERE id=?'
      ).get(info.lastInsertRowid);

      res.json({
        token: tokenFor(u),
        user: publicUser(u)
      });

    } catch (e) {
      res.status(400).json({
        error:
          e.code === 'SQLITE_CONSTRAINT_UNIQUE'
            ? 'That username or email is already registered.'
            : 'Could not create account.'
      });
    }
  }
);

// LOGIN
app.post(
  '/api/auth/login',
  rateLimit({ windowMs: 15 * 60 * 1000, limit: 20 }),
  async (req, res) => {
    const { identity, password } = req.body || {};

    const u = db.prepare(`
      SELECT * FROM users
      WHERE username=? COLLATE NOCASE
      OR email=? COLLATE NOCASE
    `).get(identity || '', identity || '');

    if (!u || !await bcrypt.compare(password || '', u.password_hash)) {
      return res.status(401).json({
        error: 'Incorrect username/email or password.'
      });
    }

    res.json({
      token: tokenFor(u),
      user: publicUser(u)
    });
  }
);

// CURRENT USER
app.get('/api/me', auth, (req, res) => {
  const u = db.prepare(
    'SELECT * FROM users WHERE id=?'
  ).get(req.user.id);

  if (!u) {
    return res.status(404).json({
      error: 'Account not found.'
    });
  }

  res.json({
    user: {
      ...publicUser(u),
      ...counts(u.id)
    }
  });
});

// UPDATE PROFILE
app.patch('/api/me', auth, (req, res) => {
  const bio = String(req.body.bio || '').slice(0, 240);

  db.prepare(
    'UPDATE users SET bio=? WHERE id=?'
  ).run(bio, req.user.id);

  const u = db.prepare(
    'SELECT * FROM users WHERE id=?'
  ).get(req.user.id);

  res.json({
    user: {
      ...publicUser(u),
      ...counts(u.id)
    }
  });
});

// VIDEO FEED
app.get('/api/posts', auth, (req, res) => {
  let rows;

  if (req.query.following === '1') {
    rows = db.prepare(`
      SELECT p.*
      FROM posts p
      JOIN follows f ON f.following_id=p.user_id
      WHERE f.follower_id=?
      AND p.ai_label != ?
      ORDER BY p.created_at DESC
      LIMIT 60
    `).all(req.user.id, 'review');

  } else {
    rows = db.prepare(`
      SELECT p.*
      FROM posts p
      WHERE p.ai_label != 'review'
      ORDER BY
        (SELECT count(*) FROM likes l WHERE l.post_id=p.id)*1.0
        +
        (SELECT count(*) FROM comments c WHERE c.post_id=p.id)*2.0
        DESC,
        p.created_at DESC
      LIMIT 60
    `).all();
  }

  res.json({
    posts: rows.map(p => postObject(p, req.user.id))
  });
});

// UPLOAD VIDEO
app.post('/api/posts', auth, upload.single('video'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({
      error: 'Select a video file.'
    });
  }

  if (!req.file.mimetype.startsWith('video/')) {
    fs.unlinkSync(req.file.path);

    return res.status(400).json({
      error: 'Please upload a video, not an image.'
    });
  }

  const caption = String(req.body.caption || '').slice(0, 500);
  const hashtags = String(req.body.hashtags || '').slice(0, 300);

  const analysis = analyseVideo(req.file, caption, hashtags);

  const info = db.prepare(`
    INSERT INTO posts(
      user_id,
      video_path,
      caption,
      hashtags,
      ai_label,
      ai_reason
    )
    VALUES(?,?,?,?,?,?)
  `).run(
    req.user.id,
    path.basename(req.file.filename),
    caption,
    hashtags,
    analysis.label,
    analysis.reason
  );

  res.json({
    post: postObject(
      db.prepare('SELECT * FROM posts WHERE id=?')
        .get(info.lastInsertRowid),
      req.user.id
    ),
    analysis
  });
});

// VIDEO VIEWS
app.post('/api/posts/:id/view', auth, (req, res) => {
  const id = Number(req.params.id);

  const info = db.prepare(
    'UPDATE posts SET views=views+1 WHERE id=?'
  ).run(id);

  if (!info.changes) {
    return res.status(404).json({
      error: 'Video not found.'
    });
  }

  res.json({
    views: db.prepare(
      'SELECT views FROM posts WHERE id=?'
    ).get(id).views
  });
});

// LIKE / UNLIKE
app.post('/api/posts/:id/like', auth, (req, res) => {
  const id = Number(req.params.id);

  if (!db.prepare('SELECT id FROM posts WHERE id=?').get(id)) {
    return res.status(404).json({
      error: 'Video not found.'
    });
  }

  const old = db.prepare(
    'SELECT 1 FROM likes WHERE user_id=? AND post_id=?'
  ).get(req.user.id, id);

  if (old) {
    db.prepare(
      'DELETE FROM likes WHERE user_id=? AND post_id=?'
    ).run(req.user.id, id);
  } else {
    db.prepare(
      'INSERT INTO likes(user_id,post_id) VALUES(?,?)'
    ).run(req.user.id, id);
  }

  res.json({
    liked: !old,
    likes_count: db.prepare(
      'SELECT count(*) n FROM likes WHERE post_id=?'
    ).get(id).n
  });
});

// GET COMMENTS
app.get('/api/posts/:id/comments', auth, (req, res) => {
  const comments = db.prepare(`
    SELECT c.*,u.username,u.display_name,u.avatar
    FROM comments c
    JOIN users u ON u.id=c.user_id
    WHERE c.post_id=?
    ORDER BY c.created_at ASC
    LIMIT 100
  `).all(req.params.id);

  res.json({
    comments: comments.map(c => ({
      id: c.id,
      text: c.text,
      created_at: c.created_at,
      user: {
        username: c.username,
        display_name: c.display_name,
        avatar: c.avatar
      }
    }))
  });
});

// ADD COMMENT
app.post('/api/posts/:id/comments', auth, (req, res) => {
  const text = String(req.body.text || '').trim().slice(0, 500);

  if (!text) {
    return res.status(400).json({
      error: 'Write a comment first.'
    });
  }

  if (!db.prepare('SELECT id FROM posts WHERE id=?').get(req.params.id)) {
    return res.status(404).json({
      error: 'Video not found.'
    });
  }

  db.prepare(`
    INSERT INTO comments(user_id,post_id,text)
    VALUES(?,?,?)
  `).run(req.user.id, req.params.id, text);

  res.json({ ok: true });
});

// USER PROFILE
app.get('/api/users/:username', auth, (req, res) => {
  const u = db.prepare(
    'SELECT * FROM users WHERE username=? COLLATE NOCASE'
  ).get(req.params.username);

  if (!u) {
    return res.status(404).json({
      error: 'User not found.'
    });
  }

  const posts = db.prepare(`
    SELECT * FROM posts
    WHERE user_id=? AND ai_label != ?
    ORDER BY created_at DESC
  `).all(u.id, 'review');

  res.json({
    user: {
      ...publicUser(u),
      ...counts(u.id)
    },
    posts: posts.map(p => postObject(p, req.user.id))
  });
});

// FOLLOW / UNFOLLOW
app.post('/api/users/:username/follow', auth, (req, res) => {
  const u = db.prepare(
    'SELECT id FROM users WHERE username=? COLLATE NOCASE'
  ).get(req.params.username);

  if (!u) {
    return res.status(404).json({
      error: 'User not found.'
    });
  }

  if (u.id === req.user.id) {
    return res.status(400).json({
      error: 'You cannot follow yourself.'
    });
  }

  const old = db.prepare(`
    SELECT 1 FROM follows
    WHERE follower_id=? AND following_id=?
  `).get(req.user.id, u.id);

  if (old) {
    db.prepare(`
      DELETE FROM follows
      WHERE follower_id=? AND following_id=?
    `).run(req.user.id, u.id);
  } else {
    db.prepare(`
      INSERT INTO follows(follower_id,following_id)
      VALUES(?,?)
    `).run(req.user.id, u.id);
  }

  res.json({
    following: !old
  });
});

// STORIES FEED
app.get('/api/stories', auth, (req, res) => {
  const stories = db.prepare(`
    SELECT s.*,u.username
    FROM stories s
    JOIN users u ON u.id=s.user_id
    WHERE s.created_at >= datetime('now','-1 day')
    ORDER BY s.created_at DESC
  `).all();

  res.json({
    stories: stories.map(s => ({
      id: s.id,
      media_url: '/uploads/' + s.media_path,
      media_type: s.media_type,
      user: {
        username: s.username
      }
    }))
  });
});

// UPLOAD STORY
app.post('/api/stories', auth, upload.single('media'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({
      error: 'Choose an image or video.'
    });
  }

  if (
    !req.file.mimetype.startsWith('image/') &&
    !req.file.mimetype.startsWith('video/')
  ) {
    return res.status(400).json({
      error: 'Unsupported story format.'
    });
  }

  db.prepare(`
    INSERT INTO stories(user_id,media_path,media_type)
    VALUES(?,?,?)
  `).run(
    req.user.id,
    path.basename(req.file.filename),
    req.file.mimetype
  );

  res.json({ ok: true });
});

// VIEW STORY
app.get('/api/stories/:id', auth, (req, res) => {
  const s = db.prepare(`
    SELECT s.*,u.username
    FROM stories s
    JOIN users u ON u.id=s.user_id
    WHERE s.id=?
    AND s.created_at >= datetime('now','-1 day')
  `).get(req.params.id);

  if (!s) {
    return res.status(404).json({
      error: 'Story expired or not found.'
    });
  }

  res.json({
    story: {
      media_url: '/uploads/' + s.media_path,
      media_type: s.media_type,
      user: {
        username: s.username
      }
    }
  });
});

// SEARCH
app.get('/api/search', auth, (req, res) => {
  const q = String(req.query.q || '')
    .replace(/^@/, '')
    .slice(0, 50);

  const users = db.prepare(`
    SELECT * FROM users
    WHERE username LIKE ? OR display_name LIKE ?
    LIMIT 15
  `).all('%' + q + '%', '%' + q + '%');

  const tag = q.replace(/^#/, '');

  const hashtags = db.prepare(`
    SELECT hashtags,count(*) count
    FROM posts
    WHERE hashtags LIKE ?
    GROUP BY hashtags
    LIMIT 10
  `).all('%' + tag + '%').map(x => ({
    tag: x.hashtags.replace(/#/g, '').split(/\s+/)[0],
    count: x.count
  }));

  res.json({
    users: users
      .filter(u => u.id !== req.user.id)
      .map(publicUser),
    hashtags
  });
});

// TRENDING HASHTAGS
app.get('/api/trending', auth, (req, res) => {
  const rows = db.prepare(`
    SELECT hashtags,count(*) count
    FROM posts
    WHERE created_at >= datetime('now','-7 days')
    AND hashtags != ''
    GROUP BY hashtags
    ORDER BY count DESC
    LIMIT 8
  `).all();

  res.json({
    hashtags: rows.map(r => ({
      tag: r.hashtags.replace(/#/g, '').split(/\s+/)[0],
      count: r.count
    }))
  });
});

// SUGGESTED USERS
app.get('/api/suggestions', auth, (req, res) => {
  const users = db.prepare(`
    SELECT * FROM users
    WHERE id != ?
    AND id NOT IN (
      SELECT following_id FROM follows
      WHERE follower_id=?
    )
    ORDER BY created_at DESC
    LIMIT 5
  `).all(req.user.id, req.user.id);

  res.json({
    users: users.map(publicUser)
  });
});

// GET MESSAGES
app.get('/api/messages/:username', auth, (req, res) => {
  const u = db.prepare(
    'SELECT * FROM users WHERE username=? COLLATE NOCASE'
  ).get(req.params.username);

  if (!u) {
    return res.status(404).json({
      error: 'User not found.'
    });
  }

  const messages = db.prepare(`
    SELECT * FROM messages
    WHERE (sender_id=? AND receiver_id=?)
    OR (sender_id=? AND receiver_id=?)
    ORDER BY created_at ASC
    LIMIT 200
  `).all(req.user.id, u.id, u.id, req.user.id);

  res.json({
    user: publicUser(u),
    messages
  });
});

// SEND MESSAGE
app.post('/api/messages/:username', auth, (req, res) => {
  const u = db.prepare(
    'SELECT * FROM users WHERE username=? COLLATE NOCASE'
  ).get(req.params.username);

  const text = String(req.body.text || '')
    .trim()
    .slice(0, 2000);

  if (!u) {
    return res.status(404).json({
      error: 'User not found.'
    });
  }

  if (u.id === req.user.id) {
    return res.status(400).json({
      error: 'You cannot message yourself.'
    });
  }

  if (!text) {
    return res.status(400).json({
      error: 'Message cannot be empty.'
    });
  }

  db.prepare(`
    INSERT INTO messages(sender_id,receiver_id,text)
    VALUES(?,?,?)
  `).run(req.user.id, u.id, text);

  const messages = db.prepare(`
    SELECT * FROM messages
    WHERE (sender_id=? AND receiver_id=?)
    OR (sender_id=? AND receiver_id=?)
    ORDER BY created_at ASC
    LIMIT 200
  `).all(req.user.id, u.id, u.id, req.user.id);

  res.json({ messages });
});

// FEEDBACK
app.post('/api/feedback', auth, (req, res) => {
  const type = String(req.body.type || 'Feedback').slice(0, 60);
  const text = String(req.body.text || '').trim().slice(0, 3000);

  if (!text) {
    return res.status(400).json({
      error: 'Please add feedback.'
    });
  }

  db.prepare(`
    INSERT INTO feedback(user_id,type,text)
    VALUES(?,?,?)
  `).run(req.user.id, type, text);

  res.json({ ok: true });
});

// REPORT CONTENT
app.post('/api/reports', auth, (req, res) => {
  const reason = String(req.body.reason || '')
    .trim()
    .slice(0, 500);

  if (!reason) {
    return res.status(400).json({
      error: 'Please include a reason.'
    });
  }

  db.prepare(`
    INSERT INTO reports(reporter_id,post_id,reason)
    VALUES(?,?,?)
  `).run(
    req.user.id,
    req.body.post_id || null,
    reason
  );

  res.json({ ok: true });
});

// SERVE WEBSITE
app.get('*', (req, res) => {
  res.sendFile(path.join(ROOT, 'index.html'));
});

// ERROR HANDLING
app.use((err, req, res, next) => {
  console.error(err);

  res.status(
    err instanceof multer.MulterError ? 400 : 500
  ).json({
    error:
      err instanceof multer.MulterError
        ? (
            err.code === 'LIMIT_FILE_SIZE'
              ? 'File exceeds 100 MB.'
              : 'Upload failed.'
          )
        : err.message || 'Server error.'
  });
});

// START SERVER
app.listen(PORT, () => {
  console.log(`VYBORA running on port ${PORT}`);
});
