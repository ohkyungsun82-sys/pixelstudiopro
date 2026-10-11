const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
const DATA_FILE = path.join(__dirname, 'data.json');
const ADMIN_USERNAME = 'sunnywp82';
const TOKEN_SECRET = process.env.TOKEN_SECRET || 'psp-ultra-secret-hmac-key-2026-secure';

app.set('trust proxy', true);
app.use(express.json({ limit: '50mb' }));

let db = {
  users: {},
  gallery: [],
  bannedIPs: []
};

if (fs.existsSync(DATA_FILE)) {
  try {
    const loaded = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
    db.users = loaded.users || {};
    db.gallery = loaded.gallery || [];
    db.bannedIPs = loaded.bannedIPs || [];
  } catch (e) {}
}

function hashPassword(pw) {
  return crypto.createHash('sha256').update(pw + '_psp_salt').digest('hex');
}

function createToken(username) {
  const payload = Buffer.from(JSON.stringify({ u: username, t: Date.now() })).toString('base64url');
  const sig = crypto.createHmac('sha256', TOKEN_SECRET).update(payload).digest('base64url');
  return `${payload}.${sig}`;
}

function verifyToken(token) {
  if (!token || typeof token !== 'string' || !token.includes('.')) return null;
  const [payload, sig] = token.split('.');
  const expectedSig = crypto.createHmac('sha256', TOKEN_SECRET).update(payload).digest('base64url');
  if (sig !== expectedSig) return null;
  try {
    const data = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
    return data.u;
  } catch (e) {
    return null;
  }
}

function saveDB() {
  try {
    fs.writeFileSync(DATA_FILE, JSON.stringify(db));
  } catch (e) {}
}

function getClientIP(req) {
  const xff = req.headers['x-forwarded-for'];
  if (xff) return xff.split(',')[0].trim();
  return req.ip || req.connection?.remoteAddress || '0.0.0.0';
}

function getAuthUser(req) {
  const authHeader = req.headers['authorization'] || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
  const username = verifyToken(token);
  if (!username || !db.users[username]) return null;
  return db.users[username];
}

app.use((req, res, next) => {
  const clientIP = getClientIP(req);
  const user = getAuthUser(req);
  const isRealAdmin = user && user.username === ADMIN_USERNAME;

  if (db.bannedIPs.includes(clientIP) && !isRealAdmin) {
    if (req.path.startsWith('/api/')) {
      return res.status(403).json({ error: `접속하신 IP(${clientIP})는 영구 차단되었습니다.` });
    }
    return res.status(403).send(`
      <!DOCTYPE html><html lang="ko"><head><meta charset="UTF-8"><title>접속 차단됨</title></head>
      <body style="background:#090a0f;color:#ef4444;font-family:sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;text-align:center;">
        <div>
          <h1 style="font-size:32px;">🚫 IP 접속이 차단되었습니다</h1>
          <p style="color:#9ca3af;margin-top:10px;">해당 IP(${clientIP})의 접근이 제한되었습니다.</p>
        </div>
      </body></html>
    `);
  }
  next();
});

app.use(express.static(__dirname));

function sanitizeUser(u) {
  return {
    username: u.username,
    email: u.email || '',
    bio: u.bio || '도트 크리에이터',
    avatarColor: u.avatarColor || '#6366f1',
    role: u.username === ADMIN_USERNAME ? 'admin' : 'user',
    banned: !!u.banned,
    ip: u.ip || ''
  };
}

app.get('/api/me', (req, res) => {
  const user = getAuthUser(req);
  if (!user) return res.status(401).json({ error: '유효하지 않은 세션입니다.' });
  if (user.banned && user.username !== ADMIN_USERNAME) {
    return res.status(403).json({ error: '정지된 계정입니다.' });
  }
  res.json({ user: sanitizeUser(user) });
});

app.post('/api/signup', (req, res) => {
  const { username, password, email, bio } = req.body;
  const ip = getClientIP(req);
  if (!username || !password) {
    return res.status(400).json({ error: '아이디와 비밀번호를 모두 입력해주세요.' });
  }
  const cleanName = username.trim();
  if (db.users[cleanName]) {
    return res.status(400).json({ error: '이미 존재하는 아이디입니다.' });
  }
  const role = cleanName === ADMIN_USERNAME ? 'admin' : 'user';
  db.users[cleanName] = {
    username: cleanName,
    passwordHash: hashPassword(password),
    email: email || '',
    bio: bio || '도트 크리에이터',
    avatarColor: role === 'admin' ? '#f59e0b' : '#6366f1',
    role,
    banned: false,
    ip
  };
  saveDB();
  const token = createToken(cleanName);
  res.json({ token, user: sanitizeUser(db.users[cleanName]) });
});

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  const ip = getClientIP(req);
  if (!username || !password) {
    return res.status(400).json({ error: '아이디와 비밀번호를 입력해주세요.' });
  }
  const cleanName = username.trim();
  let user = db.users[cleanName];

  if (!user && cleanName === ADMIN_USERNAME) {
    user = {
      username: ADMIN_USERNAME,
      passwordHash: hashPassword(password),
      email: '',
      bio: 'Pixel Studio Pro Admin',
      avatarColor: '#f59e0b',
      role: 'admin',
      banned: false,
      ip
    };
    db.users[ADMIN_USERNAME] = user;
  }

  if (!user) {
    return res.status(401).json({ error: '존재하지 않는 아이디거나 비밀번호가 틀렸습니다.' });
  }

  const incomingHash = hashPassword(password);
  const validPass = user.passwordHash ? (user.passwordHash === incomingHash) : (user.password === password);
  if (!validPass) {
    return res.status(401).json({ error: '존재하지 않는 아이디거나 비밀번호가 틀렸습니다.' });
  }

  if (user.banned && cleanName !== ADMIN_USERNAME) {
    return res.status(403).json({ error: '정지(Ban)된 계정입니다.' });
  }

  user.passwordHash = incomingHash;
  delete user.password;
  user.ip = ip;
  if (cleanName === ADMIN_USERNAME) user.role = 'admin';
  saveDB();

  const token = createToken(cleanName);
  res.json({ token, user: sanitizeUser(user) });
});

app.post('/api/google-auth', (req, res) => {
  const { email, username, password } = req.body;
  const ip = getClientIP(req);
  if (!email || !email.includes('@')) {
    return res.status(400).json({ error: '올바른 Google 이메일을 입력해주세요.' });
  }
  const targetName = (username || email.split('@')[0]).trim();
  let user = db.users[targetName];

  if (user) {
    if (user.email && user.email !== email) {
      return res.status(403).json({ error: '이미 다른 이메일과 연동된 닉네임입니다.' });
    }
    if (user.passwordHash && password && user.passwordHash !== hashPassword(password)) {
      return res.status(401).json({ error: '기존 계정의 비밀번호가 일치하지 않습니다.' });
    }
    if (user.banned && user.username !== ADMIN_USERNAME) {
      return res.status(403).json({ error: '정지된 계정입니다.' });
    }
    user.email = email;
    user.ip = ip;
  } else {
    const role = targetName === ADMIN_USERNAME ? 'admin' : 'user';
    user = {
      username: targetName,
      passwordHash: password ? hashPassword(password) : hashPassword(email),
      email,
      bio: 'Google 연동 크리에이터',
      avatarColor: role === 'admin' ? '#f59e0b' : '#3b82f6',
      role,
      banned: false,
      ip
    };
    db.users[targetName] = user;
  }
  saveDB();
  const token = createToken(user.username);
  res.json({ token, user: sanitizeUser(user) });
});

app.put('/api/profile', (req, res) => {
  const user = getAuthUser(req);
  if (!user) return res.status(401).json({ error: '로그인이 필요합니다.' });

  const { email, bio, avatarColor, newPassword } = req.body;
  if (email !== undefined) user.email = email.trim();
  if (bio !== undefined) user.bio = bio.trim();
  if (avatarColor !== undefined) user.avatarColor = avatarColor;
  if (newPassword && newPassword.trim() !== '') {
    user.passwordHash = hashPassword(newPassword.trim());
  }

  saveDB();
  res.json({ user: sanitizeUser(user) });
});

app.get('/api/gallery', (req, res) => {
  const user = getAuthUser(req);
  const isRealAdmin = user && user.username === ADMIN_USERNAME;

  const list = db.gallery.map(art => {
    const likedBy = Array.isArray(art.likedBy) ? art.likedBy : [];
    const likedByMe = user ? likedBy.includes(user.username) : false;
    const canEdit = isRealAdmin || (user && user.username === art.author) || !!art.allowEdit;

    return {
      id: art.id,
      title: art.title,
      description: art.description || '',
      author: art.author,
      authorAvatarColor: art.authorAvatarColor || '#6366f1',
      authorRole: art.authorRole || 'user',
      likes: likedBy.length,
      likedByMe,
      allowEdit: !!art.allowEdit,
      censored: !!art.censored,
      size: art.size || 32,
      fps: art.fps || 6,
      frames: (art.censored && !isRealAdmin) ? [] : art.frames,
      ip: isRealAdmin ? art.ip : undefined
    };
  });
  res.json({ gallery: list });
});

app.post('/api/gallery', (req, res) => {
  const user = getAuthUser(req);
  if (!user) return res.status(401).json({ error: '로그인이 필요합니다.' });
  if (user.banned && user.username !== ADMIN_USERNAME) {
    return res.status(403).json({ error: '정지된 계정은 작품을 공유할 수 없습니다.' });
  }

  const { title, description, allowEdit, size, fps, frames } = req.body;
  if (!title || !frames || !Array.isArray(frames)) {
    return res.status(400).json({ error: '작품 이름과 그림 데이터가 필요합니다.' });
  }

  const newArt = {
    id: 'art-' + Date.now(),
    title: title.trim(),
    description: (description || '').trim(),
    author: user.username,
    authorAvatarColor: user.avatarColor || '#6366f1',
    authorRole: user.username === ADMIN_USERNAME ? 'admin' : 'user',
    ip: getClientIP(req),
    likedBy: [],
    allowEdit: !!allowEdit,
    censored: false,
    size: size || 32,
    fps: fps || 6,
    frames
  };
  db.gallery.unshift(newArt);
  if (db.gallery.length > 60) db.gallery.pop();
  saveDB();
  res.json({ success: true });
});

app.post('/api/gallery/:id/like', (req, res) => {
  const user = getAuthUser(req);
  if (!user) return res.status(401).json({ error: '좋아요를 누르려면 로그인해주세요.' });

  const art = db.gallery.find(a => a.id === req.params.id);
  if (!art) return res.status(404).json({ error: '작품을 찾을 수 없습니다.' });

  if (!Array.isArray(art.likedBy)) art.likedBy = [];
  const idx = art.likedBy.indexOf(user.username);
  let liked = false;
  if (idx === -1) {
    art.likedBy.push(user.username);
    liked = true;
  } else {
    art.likedBy.splice(idx, 1);
    liked = false;
  }
  saveDB();
  res.json({ likes: art.likedBy.length, liked });
});

function verifyAdmin(req, res, next) {
  const user = getAuthUser(req);
  if (!user || user.username !== ADMIN_USERNAME) {
    return res.status(403).json({ error: '접근 권한이 없습니다.' });
  }
  next();
}

app.get('/api/admin/overview', verifyAdmin, (req, res) => {
  res.json({
    users: Object.values(db.users).map(sanitizeUser),
    bannedIPs: db.bannedIPs
  });
});

app.delete('/api/admin/gallery/:id', verifyAdmin, (req, res) => {
  db.gallery = db.gallery.filter(a => a.id !== req.params.id);
  saveDB();
  res.json({ success: true });
});

app.post('/api/admin/gallery/:id/censor', verifyAdmin, (req, res) => {
  const art = db.gallery.find(a => a.id === req.params.id);
  if (!art) return res.status(404).json({ error: '작품을 찾을 수 없습니다.' });
  art.censored = !art.censored;
  saveDB();
  res.json({ censored: art.censored });
});

app.post('/api/admin/ban-user', verifyAdmin, (req, res) => {
  const { targetUsername, ban } = req.body;
  if (targetUsername === ADMIN_USERNAME) {
    return res.status(400).json({ error: '관리자 계정은 정지할 수 없습니다.' });
  }
  const target = db.users[targetUsername];
  if (!target) return res.status(404).json({ error: '해당 유저를 찾을 수 없습니다.' });
  target.banned = !!ban;
  saveDB();
  res.json({ user: sanitizeUser(target) });
});

app.post('/api/admin/ban-ip', verifyAdmin, (req, res) => {
  const { ip, action } = req.body;
  if (!ip) return res.status(400).json({ error: 'IP 주소를 입력해주세요.' });
  if (action === 'unban') {
    db.bannedIPs = db.bannedIPs.filter(item => item !== ip);
  } else {
    if (!db.bannedIPs.includes(ip)) db.bannedIPs.push(ip);
  }
  saveDB();
  res.json({ bannedIPs: db.bannedIPs });
});

app.get(['/', '/draw', '/login', '/gallery', '/profile', '/admin'], (req, res) => {
  if (req.path === '/') return res.redirect('/draw');
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, () => {
  console.log(`Pixel Studio Pro Server running on port ${PORT}`);
});
