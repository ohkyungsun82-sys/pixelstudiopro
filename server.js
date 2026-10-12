const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const mongoose = require('mongoose');

const app = express();
const PORT = process.env.PORT || 3000;
const DATA_FILE = path.join(__dirname, 'data.json');
const ADMIN_USERNAME = 'sunnywp82';
const TOKEN_SECRET = process.env.TOKEN_SECRET || 'psp-ultra-secret-hmac-key-2026-secure';
const MONGODB_URI = process.env.MONGODB_URI || '';

app.set('trust proxy', true);
app.use(express.json({ limit: '50mb' }));

let db = {
  users: {},
  gallery: [],
  bannedIPs: []
};

let StateModel = null;

async function initDatabase() {
  if (MONGODB_URI) {
    try {
      await mongoose.connect(MONGODB_URI);
      const schema = new mongoose.Schema({
        key: { type: String, unique: true },
        users: { type: Object, default: {} },
        gallery: { type: Array, default: [] },
        bannedIPs: { type: Array, default: [] }
      }, { minimize: false });

      StateModel = mongoose.model('AppState', schema);
      const doc = await StateModel.findOne({ key: 'main' });
      if (doc) {
        db.users = doc.users || {};
        db.gallery = doc.gallery || [];
        db.bannedIPs = doc.bannedIPs || [];
      } else {
        await StateModel.create({ key: 'main', users: db.users, gallery: db.gallery, bannedIPs: db.bannedIPs });
      }
      console.log('MongoDB 영구 저장소 연결 완료');
      return;
    } catch (e) {
      console.error('MongoDB 연결 실패, 로컬 파일 모드로 작동합니다:', e.message);
    }
  }

  if (fs.existsSync(DATA_FILE)) {
    try {
      const loaded = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
      db.users = loaded.users || {};
      db.gallery = loaded.gallery || [];
      db.bannedIPs = loaded.bannedIPs || [];
    } catch (e) {}
  }
}

let saveTimer = null;
function saveDB() {
  try {
    fs.writeFileSync(DATA_FILE, JSON.stringify(db));
  } catch (e) {}

  if (StateModel) {
    clearTimeout(saveTimer);
    saveTimer = setTimeout(async () => {
      try {
        await StateModel.updateOne(
          { key: 'main' },
          { $set: { users: db.users, gallery: db.gallery, bannedIPs: db.bannedIPs } },
          { upsert: true }
        );
      } catch (e) {}
    }, 300);
  }
}

function hashPassword(pw) {
  return crypto.createHash('sha256').update(pw + '_psp_salt').digest('hex');
}

function createToken(userObj) {
  const payloadData = {
    u: userObj.username,
    e: userObj.email || '',
    b: userObj.bio || '도트 크리에이터',
    c: userObj.avatarColor || '#6366f1',
    r: userObj.username === ADMIN_USERNAME ? 'admin' : 'user',
    p: userObj.passwordHash || ''
  };
  const payload = Buffer.from(JSON.stringify(payloadData)).toString('base64url');
  const sig = crypto.createHmac('sha256', TOKEN_SECRET).update(payload).digest('base64url');
  return `${payload}.${sig}`;
}

function verifyTokenData(token) {
  if (!token || typeof token !== 'string' || !token.includes('.')) return null;
  const [payload, sig] = token.split('.');
  const expectedSig = crypto.createHmac('sha256', TOKEN_SECRET).update(payload).digest('base64url');
  if (sig !== expectedSig) return null;
  try {
    return JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
  } catch (e) {
    return null;
  }
}

function getClientIP(req) {
  const xff = req.headers['x-forwarded-for'];
  if (xff) return xff.split(',')[0].trim();
  return req.ip || req.connection?.remoteAddress || '0.0.0.0';
}

function getAuthUser(req) {
  const authHeader = req.headers['authorization'] || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
  const data = verifyTokenData(token);
  if (!data || !data.u) return null;

  if (!db.users[data.u]) {
    db.users[data.u] = {
      username: data.u,
      passwordHash: data.p || '',
      email: data.e || '',
      bio: data.b || '도트 크리에이터',
      avatarColor: data.c || (data.u === ADMIN_USERNAME ? '#f59e0b' : '#6366f1'),
      role: data.u === ADMIN_USERNAME ? 'admin' : 'user',
      banned: false,
      ip: getClientIP(req)
    };
    saveDB();
  }
  return db.users[data.u];
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
    bio: u.bio || '도트 크리에이터
