const express = require('express');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;
const DATA_FILE = path.join(__dirname, 'data.json');
const ADMIN_USERNAME = 'sunnywp82';

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

function ensureAdminAccount() {
  if (!db.users[ADMIN_USERNAME]) {
    db.users[ADMIN_USERNAME] = {
      username: ADMIN_USERNAME,
      password: 'admin',
      email: 'sunnywp82@google.com',
      bio: 'Pixel Studio Pro 총괄 관리자 (Admin)',
      avatarColor: '#f59e0b',
      role: 'admin',
      banned: false,
      ip: '127.0.0.1'
    };
  } else {
    db.users[ADMIN_USERNAME].role = 'admin';
    db.users[ADMIN_USERNAME].banned = false;
  }
}
ensureAdminAccount();

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

app.use((req, res, next) => {
  const clientIP = getClientIP(req);
  const reqAdmin = req.headers['x-admin-user'];
  if (db.bannedIPs.includes(clientIP) && reqAdmin !== ADMIN_USERNAME) {
    if (req.path.startsWith('/api/')) {
      return res.status(403).json({ error: `접속하신 IP(${clientIP})는 관리자에 의해 영구 차단되었습니다.` });
    }
    return res.status(403).send(`
      <!DOCTYPE html><html lang="ko"><head><meta charset="UTF-8"><title>접속 차단됨</title></head>
      <body style="background:#090a0f;color:#ef4444;font-family:sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;text-align:center;">
        <div>
          <h1 style="font-size:32px;">🚫 IP 접속이 차단되었습니다</h1>
          <p style="color:#9ca3af;margin-top:10px;">관리자(sunnywp82)에 의해 해당 IP(${clientIP})의 접근이 제한되었습니다.</p>
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
    role: u.username === ADMIN_USERNAME ? 'admin' : (u.role || 'user'),
    banned: !!u.banned,
    ip: u.ip || ''
  };
}

app.post('/api/signup', (req, res) => {
  const { username, password, email, bio, avatarColor } = req.body;
  const ip = getClientIP(req);
  if (!username || !password) {
    return res.status(400).json({ error: '아이디와 비밀번호를 모두 입력해주세요.' });
  }
  if (db.users[username]) {
    return res.status(400).json({ error: '이미 존재하는 아이디입니다.' });
  }
  const role = username === ADMIN_USERNAME ? 'admin' : 'user';
  db.users[username] = {
    username,
    password,
    email: email || '',
    bio: bio || (role === 'admin' ? '총괄 관리자' : '도트 크리에이터'),
    avatarColor: avatarColor || (role === 'admin' ? '#f59e0b' : '#6366f1'),
    role,
    banned: false,
    ip
  };
  saveDB();
  res.json({ user: sanitizeUser(db.users[username]) });
});

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  const ip = getClientIP(req);
  let user = db.users[username];

  if (username === ADMIN_USERNAME && user && user.password === 'admin') {
    user.password = password;
  }

  if (!user || user.password !== password) {
    return res.status(401).json({ error: '아이디가 없거나 비밀번호가 틀렸습니다.' });
  }
  if (user.banned && username !== ADMIN_USERNAME) {
    return res.status(403).json({ error: '관리자에 의해 정지(Ban)된 계정입니다.' });
  }
  user.ip = ip;
  if (username === ADMIN_USERNAME) user.role = 'admin';
  saveDB();
  res.json({ user: sanitizeUser(user) });
});

app.post('/api/google-auth', (req, res) => {
  const { email, username, avatarColor } = req.body;
  const ip = getClientIP(req);
  if (!email) {
    return res.status(400).json({ error: '이메일 주소를 입력해주세요.' });
  }
  const targetName = (username || email.split('@')[0]).trim();
  let user = Object.values(db.users).find(u => u.email === email) || db.users[targetName];

  if (!user) {
    const role = targetName === ADMIN_USERNAME ? 'admin' : 'user';
    user = {
      username: targetName,
      password: 'google-oauth-user',
      email,
      bio: 'Google 연동 크리에이터',
      avatarColor: avatarColor || (role === 'admin' ? '#f59e0b' : '#3b82f6'),
      role,
      banned: false,
      ip
    };
    db.users[targetName] = user;
  } else {
    if (user.banned && user.username !== ADMIN_USERNAME) {
      return res.status(403).json({ error: '관리자에 의해 정지(Ban)된 계정입니다.' });
    }
    user.email = email;
    user.ip = ip;
    if (user.username === ADMIN_USERNAME) user.role = 'admin';
  }
  saveDB();
  res.json({ user: sanitizeUser(user) });
});

app.put('/api/profile', (req, res) => {
  const { username, email, bio, avatarColor, newPassword } = req.body;
  const user = db.users[username];
  if (!user) return res.status(404).json({ error: '유저를 찾을 수 없습니다.' });

  if (email !== undefined) user.email = email;
  if (bio !== undefined) user.bio = bio;
  if (avatarColor !== undefined) user.avatarColor = avatarColor;
  if (newPassword && newPassword.trim() !== '') user.password = newPassword.trim();

  saveDB();
  res.json({ user: sanitizeUser(user) });
});

app.get('/api/gallery', (req, res) => {
  res.json({ gallery: db.gallery });
});

app.post('/api/gallery', (req, res) => {
  const { title, author, size, fps, frames } = req.body;
  const ip = getClientIP(req);
  const user = db.users[author];
  if (!user) return res.status(401).json({ error: '로그인이 필요합니다.' });
  if (user.banned && author !== ADMIN_USERNAME) {
    return res.status(403).json({ error: '정지된 계정은 게시물을 올릴 수 없습니다.' });
  }
  const newArt = {
    id: 'art-' + Date.now(),
    title: title || '제목 없음',
    author,
    authorAvatarColor: user.avatarColor || '#6366f1',
    authorRole: user.role || 'user',
    ip,
    likes: 1,
    censored: false,
    size: size || 32,
    fps: fps || 6,
    frames
  };
  db.gallery.unshift(newArt);
  if (db.gallery.length > 50) db.gallery.pop();
  saveDB();
  res.json({ art: newArt });
});

app.post('/api/gallery/:id/like', (req, res) => {
  const art = db.gallery.find(a => a.id === req.params.id);
  if (!art) return res.status(404).json({ error: '작품을 찾을 수 없습니다.' });
  art.likes += 1;
  saveDB();
  res.json({ likes: art.likes });
});

function verifyAdmin(req, res, next) {
  const adminUser = req.headers['x-admin-user'] || req.body?.adminUser;
  if (adminUser !== ADMIN_USERNAME) {
    return res.status(403).json({ error: '관리자(sunnywp82) 권한이 필요합니다.' });
  }
  next();
}

app.get('/api/admin/overview', verifyAdmin, (req, res) => {
  res.json({
    users: Object.values(db.users).map(sanitizeUser),
    bannedIPs: db.bannedIPs,
    galleryCount: db.gallery.length
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
    return res.status(400).json({ error: '관리자 본인은 정지할 수 없습니다.' });
  }
  const target = db.users[targetUsername];
  if (!target) return res.status(404).json({ error: '해당 유저가 없습니다.' });
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
