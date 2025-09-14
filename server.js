// server.js (ESM) — portable, listen on 0.0.0.0
// Requirements: package.json -> "type": "module" (or use server.mjs)

import express from "express";
import pkg from "pg";
import path from "path";
import fs from "fs";
import { fileURLToPath } from "url";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";

dotenv.config();

const { Pool } = pkg;
const app = express();

// __dirname in ESM
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Public dir (can override by PUBLIC_DIR env)
const publicDir = path.resolve(process.env.PUBLIC_DIR || path.join(__dirname, "public"));

// Body parsers
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve static if exists
if (fs.existsSync(publicDir)) {
  app.use(express.static(publicDir));
  console.log(`✅ Serving static files from: ${publicDir}`);
} else {
  console.warn(`⚠️ Static folder not found: ${publicDir} — static files WILL NOT be served`);
}

// Build pool config: prefer DATABASE_URL, otherwise use per-field env vars
let poolConfig = {};
if (process.env.DATABASE_URL) {
  poolConfig.connectionString = process.env.DATABASE_URL;
  if (process.env.PGSSLMODE === "require") {
    poolConfig.ssl = { rejectUnauthorized: false };
  }
} else {
  poolConfig = {
    user: process.env.DB_USER || process.env.PGUSER || "postgres",
    host: process.env.DB_HOST || process.env.PGHOST || "localhost",
    database: process.env.DB_NAME || process.env.PGDATABASE || "myapp",
    password: process.env.DB_PASSWORD || process.env.PGPASSWORD || "",
    port: parseInt(process.env.DB_PORT || process.env.PGPORT || "5432", 10),
  };
}

const pool = new Pool(poolConfig);

// Test connection (don't crash the app, just log); try to set client_encoding to UTF8 (if possible)
(async function testDB() {
  try {
    const client = await pool.connect();
    try {
      await client.query("SET client_encoding = 'UTF8'");
    } catch (e) {
      console.warn("⚠️ Could not set client_encoding to UTF8 (server/template encoding may differ):", e.message);
    }
    client.release();
    console.log(`✅ PostgreSQL connected (${poolConfig.database || "via connectionString"})`);
  } catch (err) {
    console.error("❌ PostgreSQL connection failed:", err.message || err);
  }
})();

// Initialize users table (idempotent)
async function initDB() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        name TEXT NOT NULL,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);
    console.log("✅ Bảng users đã sẵn sàng");
  } catch (err) {
    console.error("❌ DB init error:", err.message || err);
  }
}
initDB();

// Helper: token
function makeToken(userId) {
  return jwt.sign({ userId }, process.env.JWT_SECRET || "dev_local_secret", { expiresIn: "2h" });
}

// --- API: Register ---
app.post("/api/register", async (req, res) => {
  const { name, username, email, password } = req.body;
  if (!name || !username || !email || !password) return res.status(400).json({ message: "Thiếu dữ liệu!" });

  try {
    // Check trước nếu username hoặc email đã tồn tại
    const existing = await pool.query(
      "SELECT id FROM users WHERE username = $1 OR email = $2",
      [username, email]
    );
    if (existing.rows.length > 0) {
      return res.status(409).json({ message: "Tên đăng nhập hoặc email đã tồn tại!" });
    }

    const hashed = await bcrypt.hash(password, 10);
    const result = await pool.query(
      "INSERT INTO users (name, username, email, password) VALUES ($1, $2, $3, $4) RETURNING id, name, username, email",
      [name, username, email, hashed]
    );
    const user = result.rows[0];
    const token = makeToken(user.id);
    res.json({ message: "Đăng ký thành công!", token, user });
  } catch (err) {
    console.error("❌ SQL Error (register):", err.message || err);
    res.status(500).json({ message: "Lỗi server khi đăng ký!" });
  }
});

// --- API: Login ---
app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ message: "Thiếu tên đăng nhập hoặc mật khẩu!" });

  try {
    const result = await pool.query("SELECT id, name, username, email, password FROM users WHERE username = $1", [username]);
    if (result.rows.length === 0) return res.status(401).json({ message: "Sai tên đăng nhập hoặc mật khẩu!" });

    const user = result.rows[0];
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ message: "Sai tên đăng nhập hoặc mật khẩu!" });

    const token = makeToken(user.id);
    res.json({
      message: "Đăng nhập thành công!",
      token,
      user: { id: user.id, name: user.name, username: user.username, email: user.email },
    });
  } catch (err) {
    console.error("❌ SQL Error (login):", err.message || err);
    res.status(500).json({ message: "Lỗi server khi đăng nhập!" });
  }
});

// --- API: me (from token) ---
app.get("/api/me", async (req, res) => {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith("Bearer ")) return res.status(401).json({ message: "Không có token" });
  const token = auth.split(" ")[1];
  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET || "dev_local_secret");
    const result = await pool.query("SELECT id, name, username, email, created_at FROM users WHERE id = $1", [payload.userId]);
    if (result.rows.length === 0) return res.status(404).json({ message: "Người dùng không tồn tại" });
    res.json({ user: result.rows[0] });
  } catch (err) {
    if (err.name === "TokenExpiredError") {
      return res.status(401).json({ message: "Token đã hết hạn, vui lòng đăng nhập lại" });
    }
    console.error("Auth error:", err.message || err);
    return res.status(401).json({ message: "Token không hợp lệ" });
  }
});

// Root route: prefer main.html, fallback to other pages
app.get("/", (req, res) => {
  const tryFiles = ["main.html", "login.html", "index.html", "app.html", "register.html"];
  for (const f of tryFiles) {
    const p = path.join(publicDir, f);
    if (fs.existsSync(p)) return res.sendFile(p);
  }
  return res.status(200).send("Welcome. No frontend found in " + publicDir);
});

// Fallback for SPA / static (do not use app.get('*',...) to avoid path-to-regexp issues)
app.use((req, res, next) => {
  if (req.path.startsWith("/api/")) return next();
  const indexPath = path.join(publicDir, "index.html");
  if (fs.existsSync(indexPath)) return res.sendFile(indexPath);
  if (fs.existsSync(publicDir)) return res.status(404).send("Not found");
  return res.status(404).send("No frontend found in " + publicDir);
});

// Start server on all interfaces
const PORT = parseInt(process.env.PORT || "5000", 10);
app.listen(PORT, "0.0.0.0", () => {
  console.log(`🚀 Server chạy trên cổng ${PORT} (listening on 0.0.0.0).`);
  console.log(`ℹ️  Truy cập local: http://localhost:${PORT}/`);
  console.log(`ℹ️  Nếu muốn truy cập từ LAN: http://<your-machine-ip>:${PORT}/`);
});
