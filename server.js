"use strict";

const path = require("path");
const fs = require("fs");
const express = require("express");
const session = require("express-session");
const SQLiteStore = require("connect-sqlite3")(session);
const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");
const helmet = require("helmet");
const http = require("http");
const { Server } = require("socket.io");

const PORT = Number(process.env.PORT || 3000);
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, "data");
const SESSION_SECRET = process.env.SESSION_SECRET;
const ADMIN_USERNAME = String(process.env.ADMIN_USERNAME || "").trim().toLowerCase();

if (!SESSION_SECRET || SESSION_SECRET.length < 32) {
  console.error("Set SESSION_SECRET to a random string of at least 32 characters.");
  process.exit(1);
}
fs.mkdirSync(DATA_DIR, { recursive: true });

const db = new Database(path.join(DATA_DIR, "vayu.sqlite"));
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE COLLATE NOCASE,
  password_hash TEXT NOT NULL,
  is_admin INTEGER NOT NULL DEFAULT 0,
  is_banned INTEGER NOT NULL DEFAULT 0,
  timeout_until INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  sender_id INTEGER NOT NULL REFERENCES users(id),
  recipient_id INTEGER REFERENCES users(id),
  body TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS messages_group_idx ON messages(recipient_id, id);
CREATE INDEX IF NOT EXISTS messages_private_idx ON messages(sender_id, recipient_id, id);
`);

const app = express();
app.disable("x-powered-by");
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "12kb" }));

const sessionMiddleware = session({
  store: new SQLiteStore({ db: "sessions.sqlite", dir: DATA_DIR }),
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  name: "vayu.sid",
  cookie: {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    maxAge: 7 * 24 * 60 * 60 * 1000
  }
});
app.use(sessionMiddleware);

const server = http.createServer(app);
const io = new Server(server);
io.engine.use(sessionMiddleware);

app.use(express.static(path.join(__dirname, "public")));

function safeUser(row) {
  return {
    id: row.id,
    username: row.username,
    admin: Boolean(row.is_admin),
    online: onlineUserIds.has(row.id)
  };
}

const onlineUserIds = new Set();
const socketsByUser = new Map();

function getCurrentUser(req) {
  if (!req.session.userId) return null;
  return db.prepare("SELECT * FROM users WHERE id = ?").get(req.session.userId) || null;
}

function accountAllowed(user) {
  return user && !user.is_banned && Number(user.timeout_until) <= Date.now();
}

function requireLogin(req, res, next) {
  const user = getCurrentUser(req);
  if (!accountAllowed(user)) {
    if (req.session) req.session.destroy(() => {});
    return res.status(401).json({ error: "Please log in again. Your account may be restricted." });
  }
  req.user = user;
  next();
}

function requireAdmin(req, res, next) {
  if (!req.user.is_admin) return res.status(403).json({ error: "Admin permission required." });
  next();
}

function cleanUsername(value) {
  return String(value || "").trim();
}

function cleanMessage(value) {
  return String(value || "").trim().slice(0, 1000);
}

app.post("/api/register", async (req, res) => {
  const username = cleanUsername(req.body.username);
  const password = String(req.body.password || "");

  if (!/^[A-Za-z0-9_]{3,20}$/.test(username)) {
    return res.status(400).json({ error: "Username must be 3–20 letters, numbers, or underscores." });
  }
  if (password.length < 8 || password.length > 72) {
    return res.status(400).json({ error: "Password must be 8–72 characters." });
  }

  try {
    const count = db.prepare("SELECT COUNT(*) AS n FROM users").get().n;
    const isFirstAdmin = count === 0 && ADMIN_USERNAME && username.toLowerCase() === ADMIN_USERNAME;
    const passwordHash = await bcrypt.hash(password, 12);
    const result = db.prepare(`
      INSERT INTO users (username, password_hash, is_admin, created_at)
      VALUES (?, ?, ?, ?)
    `).run(username, passwordHash, isFirstAdmin ? 1 : 0, Date.now());

    req.session.userId = Number(result.lastInsertRowid);
    req.session.save(err => {
      if (err) return res.status(500).json({ error: "Could not create session." });
      const user = db.prepare("SELECT * FROM users WHERE id = ?").get(req.session.userId);
      res.json({ user: safeUser(user) });
    });
  } catch (err) {
    if (String(err.code).includes("SQLITE_CONSTRAINT")) {
      return res.status(409).json({ error: "That username is already taken." });
    }
    console.error(err);
    res.status(500).json({ error: "Registration failed." });
  }
});

app.post("/api/login", async (req, res) => {
  const username = cleanUsername(req.body.username);
  const password = String(req.body.password || "");
  const user = db.prepare("SELECT * FROM users WHERE username = ? COLLATE NOCASE").get(username);

  if (!user || !(await bcrypt.compare(password, user.password_hash))) {
    return res.status(401).json({ error: "Incorrect username or password." });
  }
  if (!accountAllowed(user)) {
    return res.status(403).json({ error: user.is_banned ? "This account is banned." : "This account is timed out." });
  }

  req.session.regenerate(err => {
    if (err) return res.status(500).json({ error: "Could not start session." });
    req.session.userId = user.id;
    req.session.save(saveErr => {
      if (saveErr) return res.status(500).json({ error: "Could not save session." });
      res.json({ user: safeUser(user) });
    });
  });
});

app.post("/api/logout", requireLogin, (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

app.get("/api/me", requireLogin, (req, res) => {
  res.json({ user: safeUser(req.user) });
});

app.get("/api/users", requireLogin, (req, res) => {
  const users = db.prepare("SELECT id, username, is_admin, is_banned, timeout_until, created_at FROM users WHERE is_banned = 0 ORDER BY username").all();
  res.json({ users: users.map(safeUser) });
});

app.get("/api/messages", requireLogin, (req, res) => {
  const withName = String(req.query.with || "").trim();
  let rows;
  if (!withName) {
    rows = db.prepare(`
      SELECT m.id, u.username AS sender, m.body, m.created_at
      FROM messages m JOIN users u ON u.id = m.sender_id
      WHERE m.recipient_id IS NULL ORDER BY m.id DESC LIMIT 100
    `).all().reverse();
  } else {
    const other = db.prepare("SELECT id FROM users WHERE username = ? COLLATE NOCASE AND is_banned = 0").get(withName);
    if (!other) return res.status(404).json({ error: "User not found." });
    rows = db.prepare(`
      SELECT m.id, u.username AS sender, m.body, m.created_at
      FROM messages m JOIN users u ON u.id = m.sender_id
      WHERE (m.sender_id = ? AND m.recipient_id = ?)
         OR (m.sender_id = ? AND m.recipient_id = ?)
      ORDER BY m.id DESC LIMIT 100
    `).all(req.user.id, other.id, other.id, req.user.id).reverse();
  }
  res.json({ messages: rows });
});

app.post("/api/messages", requireLogin, (req, res) => {
  const body = cleanMessage(req.body.message);
  const recipientName = String(req.body.to || "").trim();
  if (!body) return res.status(400).json({ error: "Message cannot be empty." });

  let recipientId = null;
  if (recipientName) {
    const recipient = db.prepare("SELECT id FROM users WHERE username = ? COLLATE NOCASE AND is_banned = 0").get(recipientName);
    if (!recipient) return res.status(404).json({ error: "Recipient not found." });
    if (recipient.id === req.user.id) return res.status(400).json({ error: "You cannot message yourself." });
    recipientId = recipient.id;
  }

  const result = db.prepare(`
    INSERT INTO messages (sender_id, recipient_id, body, created_at)
    VALUES (?, ?, ?, ?)
  `).run(req.user.id, recipientId, body, Date.now());

  const message = {
    id: Number(result.lastInsertRowid),
    sender: req.user.username,
    body,
    created_at: Date.now()
  };

  if (recipientId === null) {
    io.emit("group-message", message);
  } else {
    const privateMessage = { ...message, recipient: recipientName };
    for (const targetId of [req.user.id, recipientId]) {
      const ids = socketsByUser.get(targetId);
      if (ids) for (const socketId of ids) io.to(socketId).emit("private-message", privateMessage);
    }
  }
  res.json({ message });
});

app.post("/api/admin/:action", requireLogin, requireAdmin, async (req, res) => {
  const action = req.params.action;
  const username = String(req.body.username || "").trim();
  const target = db.prepare("SELECT * FROM users WHERE username = ? COLLATE NOCASE").get(username);

  if (!target) return res.status(404).json({ error: "User not found." });
  if (target.is_admin) return res.status(403).json({ error: "Admin accounts cannot be modified here." });

  if (action === "rename") {
    const newName = String(req.body.newUsername || "").trim();
    if (!/^[A-Za-z0-9_]{3,20}$/.test(newName)) return res.status(400).json({ error: "Invalid new username." });
    try {
      db.prepare("UPDATE users SET username = ? WHERE id = ?").run(newName, target.id);
    } catch {
      return res.status(409).json({ error: "That username is already taken." });
    }
  } else if (action === "ban") {
    db.prepare("UPDATE users SET is_banned = 1 WHERE id = ?").run(target.id);
    disconnectUser(target.id);
  } else if (action === "timeout") {
    const minutes = Math.max(1, Math.min(1440, Number(req.body.minutes) || 5));
    db.prepare("UPDATE users SET timeout_until = ? WHERE id = ?").run(Date.now() + minutes * 60000, target.id);
    disconnectUser(target.id);
  } else if (action === "password") {
    const newPassword = String(req.body.newPassword || "");
    if (newPassword.length < 8 || newPassword.length > 72) return res.status(400).json({ error: "New password must be 8–72 characters." });
    const passwordHash = await bcrypt.hash(newPassword, 12);
    db.prepare("UPDATE users SET password_hash = ? WHERE id = ?").run(passwordHash, target.id);
    disconnectUser(target.id);
  } else {
    return res.status(404).json({ error: "Unknown admin action." });
  }
  res.json({ ok: true });
});

function disconnectUser(userId) {
  const ids = socketsByUser.get(userId);
  if (ids) for (const socketId of ids) io.to(socketId).emit("account-restricted");
  socketsByUser.delete(userId);
  onlineUserIds.delete(userId);
  io.emit("presence", [...onlineUserIds]);
}

io.on("connection", socket => {
  const session = socket.request.session;
  const userId = session && session.userId;
  const user = userId && db.prepare("SELECT * FROM users WHERE id = ?").get(userId);
  if (!accountAllowed(user)) {
    socket.disconnect(true);
    return;
  }

  if (!socketsByUser.has(user.id)) socketsByUser.set(user.id, new Set());
  socketsByUser.get(user.id).add(socket.id);
  onlineUserIds.add(user.id);
  io.emit("presence", [...onlineUserIds]);
  socket.broadcast.emit("system-notice", user.username + " joined.");

  socket.on("disconnect", () => {
    const ids = socketsByUser.get(user.id);
    if (ids) {
      ids.delete(socket.id);
      if (ids.size === 0) {
        socketsByUser.delete(user.id);
        onlineUserIds.delete(user.id);
        io.emit("presence", [...onlineUserIds]);
        socket.broadcast.emit("system-notice", user.username + " left.");
      }
    }
  });
});

server.listen(PORT, () => console.log(`VAYU chat running on port ${PORT}`));
