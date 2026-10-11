const express = require('express');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;
const DATA_FILE = path.join(__dirname, 'data.json');

app.use(express.json({ limit: '50mb' }));
app.use(express.static(__dirname));

let db = {
  users: {},
  gallery: []
};

if (fs.existsSync(DATA_FILE)) {
  try {
    db = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
  } catch (e) {}
}

function saveDB() {
  try {
    fs.writeFileSync(DATA_FILE, JSON.stringify(db));
  } catch (e) {}
}

app.post('/api/signup', (req, res) => {
  const { username, password, bio } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: '아이디와 비밀번호를 모두 입력해주세요.' });
  }
  if (db.users[username]) {
    return res.status(400).json({ error: '이미 존재하는 닉네임입니다.' });
  }
  db.users[username] = { username, password, bio: bio || '도트 크리에이터' };
  saveDB();
  res.json({ user: { username, bio: db.users[username].bio } });
});

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  const user = db.users[username];
  if (!user || user.password !== password) {
    return res.status(401).json({ error: '아이디가 없거나 비밀번호가 틀렸습니다.' });
  }
  res.json({ user: { username: user.username, bio: user.bio } });
});

app.get('/api/gallery', (req, res) => {
  res.json({ gallery: db.gallery });
});

app.post('/api/gallery', (req, res) => {
  const { title, author, size, fps, frames } = req.body;
  if (!title || !author || !frames) {
    return res.status(400).json({ error: '필수 작품 데이터가 누락되었습니다.' });
  }
  const newArt = {
    id: 'art-' + Date.now(),
    title,
    author,
    likes: 1,
    size: size || 32,
    fps: fps || 6,
    frames
  };
  db.gallery.unshift(newArt);
  if (db.gallery.length > 40) db.gallery.pop();
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

app.get(['/', '/draw', '/login', '/gallery'], (req, res) => {
  if (req.path === '/') return res.redirect('/draw');
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});