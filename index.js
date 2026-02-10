import express from "express";
import cors from "cors";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { randomBytes, scryptSync, timingSafeEqual } from "crypto";
import pkg from "pg";

const { Pool } = pkg;

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const WORDS_PATH = path.join(__dirname, "words.json");
const USERS_PATH = path.join(__dirname, "users.json");
const SESSIONS_PATH = path.join(__dirname, "sessions.json");
const TOKEN_COOKIE_NAME = "auth_token";

const app = express();

// Явно указываем, с каких доменов можно ходить с куками
const allowedOrigins = [
  "http://localhost:3000",
  "https://ege-vocabulary.vercel.app",
];

app.use(
  cors({
    credentials: true,
    origin(origin, callback) {
      // Для server-to-server или curl без Origin — просто разрешаем
      if (!origin) return callback(null, true);

      if (allowedOrigins.includes(origin)) {
        return callback(null, true);
      }

      return callback(new Error("Not allowed by CORS"));
    },
  })
);

app.use(express.json());

// -------- Postgres pool --------
// Используем Neon URL из переменной окружения, созданной интеграцией.
// Если когда-нибудь переименуешь переменную, просто поправь здесь.

const connectionString =
  process.env.EGE_STORGAE_DATABASE_URL ||
  process.env.EGE_STORGAE_POSTGRES_URL_NON_POOLING ||
  process.env.EGE_STORGAE_DATABASE_URL_UNPOOLED;

if (!connectionString) {
  console.warn(
    "Postgres connection string is not set. Please configure EGE_STORGAE_DATABASE_URL in Vercel."
  );
}

const pool = new Pool({
  connectionString,
  max: 5,
  idleTimeoutMillis: 30_000,
});

async function ensureTables() {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS words (
        id SERIAL PRIMARY KEY,
        accent TEXT NOT NULL,
        stress_index INTEGER NOT NULL
      );
    `);

    // Если таблица пустая, один раз заливаем данные из локального words.json
    const countRes = await client.query("SELECT COUNT(*)::int AS count FROM words");
    if (countRes.rows[0]?.count === 0) {
      try {
        const raw = fs.readFileSync(WORDS_PATH, "utf8");
        const data = JSON.parse(raw);
        const initialWords = Array.isArray(data.words) ? data.words : [];
        for (const w of initialWords) {
          if (
            !w ||
            typeof w.accent !== "string" ||
            typeof w.stress_index !== "number"
          ) {
            continue;
          }
          await client.query(
            "INSERT INTO words (accent, stress_index) VALUES ($1, $2)",
            [w.accent.trim().toLowerCase(), w.stress_index]
          );
        }
        console.log(`Seeded ${initialWords.length} words into Postgres`);
      } catch (seedErr) {
        console.error("Failed to seed initial words from words.json", seedErr);
      }
    }

    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL UNIQUE,
        email TEXT UNIQUE,
        phone TEXT UNIQUE,
        password_hash TEXT NOT NULL,
        best_streak INTEGER NOT NULL DEFAULT 0,
        current_streak INTEGER NOT NULL DEFAULT 0,
        wrong_words TEXT[] NOT NULL DEFAULT '{}',
        reset_code TEXT,
        reset_code_expires_at TIMESTAMPTZ
      );
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS sessions (
        token TEXT PRIMARY KEY,
        user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        expires_at TIMESTAMPTZ
      );
    `);
  } finally {
    client.release();
  }
}

// Запускаем миграцию при старте (на Vercel — на каждом холодном старте, что ок).
ensureTables().catch((err) => {
  console.error("Failed to ensure tables", err);
});

// -------- Words helpers (Postgres) --------

async function readWords() {
  const result = await pool.query("SELECT accent, stress_index FROM words ORDER BY id ASC");
  return result.rows;
}

async function writeWords(words) {
  // Простой вариант: очищаем и вставляем заново.
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query("TRUNCATE TABLE words");
    for (const w of words) {
      await client.query(
        "INSERT INTO words (accent, stress_index) VALUES ($1, $2)",
        [w.accent, w.stress_index]
      );
    }
    await client.query("COMMIT");
  } catch (err) {
    await client.query("ROLLBACK");
    throw err;
  } finally {
    client.release();
  }
}

// -------- User & session storage (Postgres) --------

async function readUsers() {
  const result = await pool.query("SELECT * FROM users");
  return result.rows;
}

// writeUsers больше не нужен для полноты, но оставим на случай,
// если где-то останется вызов. Просто ничего не делает.
async function writeUsers() {
  return;
}

async function readSessions() {
  const result = await pool.query("SELECT * FROM sessions");
  return result.rows;
}

async function writeSessions() {
  return;
}

// -------- Password hashing --------

function hashPassword(password) {
  const salt = randomBytes(16).toString("hex");
  const hash = scryptSync(password, salt, 64).toString("hex");
  return `${salt}:${hash}`;
}

function verifyPassword(password, stored) {
  if (!stored || typeof stored !== "string" || !stored.includes(":")) return false;
  const [salt, hash] = stored.split(":");
  const storedHashBuffer = Buffer.from(hash, "hex");
  const testHash = scryptSync(password, salt, 64);
  if (storedHashBuffer.length !== testHash.length) return false;
  return timingSafeEqual(storedHashBuffer, testHash);
}

// -------- Basic validators --------

function isValidEmail(value) {
  if (!value) return false;
  const email = String(value).trim().toLowerCase();
  // Simple email pattern: something@something.domain
  const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return re.test(email);
}

function isValidPhone(value) {
  if (!value) return false;
  const phone = String(value).trim();
  // Digits with optional leading +, length 10-15
  const re = /^\+?\d{10,15}$/;
  return re.test(phone);
}

// -------- Token & cookie helpers --------

function createSessionToken() {
  return randomBytes(32).toString("hex");
}

function parseCookies(req) {
  const header = req.headers.cookie;
  if (!header) return {};
  return header.split(";").reduce((acc, part) => {
    const [key, ...rest] = part.split("=");
    if (!key) return acc;
    acc[key.trim()] = decodeURIComponent(rest.join("=").trim());
    return acc;
  }, {});
}

function getAuthTokenFromRequest(req) {
  const cookies = parseCookies(req);
  return cookies[TOKEN_COOKIE_NAME] || null;
}

async function getUserFromToken(req) {
  const token = getAuthTokenFromRequest(req);
  if (!token) return null;

  const now = new Date();
  const sessionResult = await pool.query(
    `SELECT * FROM sessions WHERE token = $1 AND (expires_at IS NULL OR expires_at > $2)`,
    [token, now]
  );
  if (sessionResult.rowCount === 0) return null;
  const session = sessionResult.rows[0];

  const userResult = await pool.query(`SELECT * FROM users WHERE id = $1`, [session.user_id]);
  if (userResult.rowCount === 0) return null;

  return userResult.rows[0];
}

async function authMiddleware(req, res, next) {
  try {
    const user = await getUserFromToken(req);
    if (!user) {
      return res.status(401).json({ error: "Not authenticated" });
    }
    req.user = user;
    next();
  } catch (err) {
    console.error("authMiddleware error", err);
    return res.status(500).json({ error: "Auth check failed" });
  }
}

// -------- Words routes --------

app.get("/words", async (req, res) => {
  try {
    const words = await readWords();
    res.json({ words });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to read words" });
  }
});

app.post("/words", async (req, res) => {
  try {
    const { accent, stress_index } = req.body;
    if (typeof accent !== "string" || typeof stress_index !== "number") {
      return res.status(400).json({ error: "Need accent (string) and stress_index (number)" });
    }
    const normalizedAccent = accent.trim().toLowerCase();
    await pool.query("INSERT INTO words (accent, stress_index) VALUES ($1, $2)", [
      normalizedAccent,
      stress_index,
    ]);
    const words = await readWords();
    res.status(201).json({ words });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to add word" });
  }
});

// -------- Auth routes (Postgres) --------

// Registration via email or phone
app.post("/auth/register", async (req, res) => {
  try {
    const { name, password, email, phone } = req.body || {};

    if (typeof name !== "string" || !name.trim()) {
      return res.status(400).json({ error: "Name is required" });
    }
    if (typeof password !== "string" || password.length < 6) {
      return res.status(400).json({ error: "Password must be at least 6 characters" });
    }
    if (!email && !phone) {
      return res.status(400).json({ error: "Either email or phone is required" });
    }

    // Validate email / phone formats if provided
    if (email && !isValidEmail(email)) {
      return res.status(400).json({ error: "Invalid email format" });
    }
    if (phone && !isValidPhone(phone)) {
      return res.status(400).json({ error: "Invalid phone format" });
    }

    const normalizedName = name.trim();
    const normalizedEmail = email ? String(email).trim().toLowerCase() : null;
    const normalizedPhone = phone ? String(phone).trim() : null;

    const existingByName = await pool.query(
      "SELECT 1 FROM users WHERE name = $1 LIMIT 1",
      [normalizedName]
    );
    if (existingByName.rowCount > 0) {
      return res.status(409).json({ error: "User with this name already exists" });
    }

    if (normalizedEmail) {
      const existingByEmail = await pool.query(
        "SELECT 1 FROM users WHERE email = $1 LIMIT 1",
        [normalizedEmail]
      );
      if (existingByEmail.rowCount > 0) {
        return res.status(409).json({ error: "User with this email already exists" });
      }
    }

    if (normalizedPhone) {
      const existingByPhone = await pool.query(
        "SELECT 1 FROM users WHERE phone = $1 LIMIT 1",
        [normalizedPhone]
      );
      if (existingByPhone.rowCount > 0) {
        return res.status(409).json({ error: "User with this phone already exists" });
      }
    }

    const id = randomBytes(12).toString("hex");
    const passwordHash = hashPassword(password);

    await pool.query(
      `INSERT INTO users
        (id, name, email, phone, password_hash, best_streak, current_streak, wrong_words)
       VALUES ($1,$2,$3,$4,$5,0,0,'{}')`,
      [id, normalizedName, normalizedEmail, normalizedPhone, passwordHash]
    );

    return res.status(201).json({
      id,
      name: normalizedName,
      email: normalizedEmail,
      phone: normalizedPhone,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to register user" });
  }
});

// Login: check identifier (name/email/phone) + password, return token in httpOnly cookie
app.post("/auth/login", async (req, res) => {
  try {
    const { name, email, phone, password } = req.body || {};

    if (typeof password !== "string") {
      return res.status(400).json({ error: "Password is required" });
    }
    if (!name && !email && !phone) {
      return res.status(400).json({ error: "Name, email or phone is required" });
    }

    let userResult;
    if (email) {
      const normalizedEmail = String(email).trim().toLowerCase();
      userResult = await pool.query("SELECT * FROM users WHERE email = $1", [normalizedEmail]);
    } else if (phone) {
      const normalizedPhone = String(phone).trim();
      userResult = await pool.query("SELECT * FROM users WHERE phone = $1", [normalizedPhone]);
    } else if (name) {
      const normalizedName = String(name).trim();
      userResult = await pool.query("SELECT * FROM users WHERE name = $1", [normalizedName]);
    }

    if (!userResult || userResult.rowCount === 0) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const user = userResult.rows[0];

    const validPassword = verifyPassword(password, user.password_hash);
    if (!validPassword) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const token = createSessionToken();
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days

    await pool.query(
      `INSERT INTO sessions (token, user_id, created_at, expires_at)
       VALUES ($1,$2,$3,$4)`,
      [token, user.id, new Date().toISOString(), expiresAt.toISOString()]
    );

    res.cookie(TOKEN_COOKIE_NAME, token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      expires: expiresAt,
    });

    return res.json({
      id: user.id,
      name: user.name,
      email: user.email,
      phone: user.phone,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to login" });
  }
});

// Logout: clear cookie and remove session
app.post("/auth/logout", async (req, res) => {
  try {
    const token = getAuthTokenFromRequest(req);
    if (token) {
      await pool.query("DELETE FROM sessions WHERE token = $1", [token]);
    }
    res.clearCookie(TOKEN_COOKIE_NAME);
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to logout" });
  }
});

// Forgot password: send code via email or phone (simulated)
app.post("/auth/forgot-password", async (req, res) => {
  try {
    const { email, phone } = req.body || {};
    if (!email && !phone) {
      return res.status(400).json({ error: "Email or phone is required" });
    }

    let userResult;
    let method = null;

    if (email) {
      if (!isValidEmail(email)) {
        return res.status(400).json({ error: "Invalid email format" });
      }
      const normalizedEmail = String(email).trim().toLowerCase();
      userResult = await pool.query("SELECT * FROM users WHERE email = $1", [normalizedEmail]);
      method = "email";
    } else if (phone) {
      if (!isValidPhone(phone)) {
        return res.status(400).json({ error: "Invalid phone format" });
      }
      const normalizedPhone = String(phone).trim();
      userResult = await pool.query("SELECT * FROM users WHERE phone = $1", [normalizedPhone]);
      method = "sms";
    }

    if (!userResult || userResult.rowCount === 0) {
      // To avoid leaking which accounts exist, respond with generic message
      return res.json({ message: "Если учетная запись существует, то код был отправлен" });
    }

    const user = userResult.rows[0];

    const code = String(Math.floor(100000 + Math.random() * 900000)); // 6 digits
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes

    await pool.query(
      `UPDATE users
       SET reset_code = $1, reset_code_expires_at = $2
       WHERE id = $3`,
      [code, expiresAt.toISOString(), user.id]
    );

    // Here you would actually send email or SMS. For now we log it.
    console.log(`Password reset code for user ${user.name} via ${method}: ${code}`);

    return res.json({ message: "Если учетная запись существует, то код был отправлен" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Не удалось запустить сброс пароля" });
  }
});

// Reset password using code
app.post("/auth/reset-password", async (req, res) => {
  try {
    const { name, code, newPassword } = req.body || {};

    if (!name || !code || !newPassword) {
      return res.status(400).json({ error: "Name, code and newPassword are required" });
    }
    if (typeof newPassword !== "string" || newPassword.length < 6) {
      return res.status(400).json({ error: "newPassword must be at least 6 characters" });
    }

    const normalizedName = String(name).trim();
    const userResult = await pool.query("SELECT * FROM users WHERE name = $1", [normalizedName]);
    if (userResult.rowCount === 0) {
      return res.status(400).json({ error: "Invalid code or user" });
    }

    const user = userResult.rows[0];

    if (!user.reset_code || !user.reset_code_expires_at) {
      return res.status(400).json({ error: "Invalid code or user" });
    }

    const now = Date.now();
    const expiresAt = new Date(user.reset_code_expires_at).getTime();
    if (now > expiresAt) {
      return res.status(400).json({ error: "Code has expired" });
    }

    if (String(code).trim() !== String(user.reset_code).trim()) {
      return res.status(400).json({ error: "Invalid code" });
    }

    const newHash = hashPassword(newPassword);

    await pool.query(
      `UPDATE users
       SET password_hash = $1, reset_code = NULL, reset_code_expires_at = NULL
       WHERE id = $2`,
      [newHash, user.id]
    );

    return res.json({ message: "Password has been reset" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to reset password" });
  }
});

// -------- Profile routes --------

// Get current user's profile (best streak, current streak, wrong words)
app.get("/profile", authMiddleware, (req, res) => {
  const user = req.user;
  res.json({
    id: user.id,
    name: user.name,
    email: user.email,
    phone: user.phone,
    bestStreak: user.best_streak ?? 0,
    currentStreak: user.current_streak ?? 0,
    wrongWords: Array.isArray(user.wrong_words) ? user.wrong_words : [],
  });
});

// Update stats after answer: correct or not, and which word
app.post("/profile/answer", authMiddleware, async (req, res) => {
  try {
    const { accent, correct } = req.body || {};
    if (typeof accent !== "string") {
      return res.status(400).json({ error: "accent is required" });
    }
    if (typeof correct !== "boolean") {
      return res.status(400).json({ error: "correct must be boolean" });
    }

    const userId = req.user.id;
    const userResult = await pool.query("SELECT * FROM users WHERE id = $1", [userId]);
    if (userResult.rowCount === 0) {
      return res.status(404).json({ error: "User not found" });
    }

    const user = userResult.rows[0];

    let currentStreak = user.current_streak || 0;
    let bestStreak = user.best_streak || 0;
    let wrongWords = Array.isArray(user.wrong_words) ? user.wrong_words.slice() : [];

    if (correct) {
      currentStreak += 1;
      if (!bestStreak || currentStreak > bestStreak) {
        bestStreak = currentStreak;
      }
    } else {
      currentStreak = 0;
      const word = accent.trim().toLowerCase();
      if (!wrongWords.includes(word)) {
        wrongWords.push(word);
      }
    }

    await pool.query(
      `UPDATE users
       SET best_streak = $1, current_streak = $2, wrong_words = $3
       WHERE id = $4`,
      [bestStreak, currentStreak, wrongWords, userId]
    );

    res.json({
      bestStreak,
      currentStreak,
      wrongWords,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to update profile stats" });
  }
});

// Vercel (@vercel/node) expects the module to export a handler/app.
// For local development we still start the server with app.listen().
export default app;

if (!process.env.VERCEL) {
  const PORT = process.env.PORT || 3001;
  app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
  });
}
