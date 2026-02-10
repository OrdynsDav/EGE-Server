import express from "express";
import cors from "cors";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { randomBytes, scryptSync, timingSafeEqual } from "crypto";

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

// -------- Words helpers --------

function readWords() {
  const raw = fs.readFileSync(WORDS_PATH, "utf8");
  const data = JSON.parse(raw);
  return data.words || [];
}

function writeWords(words) {
  fs.writeFileSync(WORDS_PATH, JSON.stringify({ words }, null, 2), "utf8");
}

// -------- User & session storage (file-based) --------

function readUsers() {
  try {
    const raw = fs.readFileSync(USERS_PATH, "utf8");
    const data = JSON.parse(raw);
    return data.users || [];
  } catch (err) {
    if (err.code === "ENOENT") {
      return [];
    }
    throw err;
  }
}

function writeUsers(users) {
  fs.writeFileSync(USERS_PATH, JSON.stringify({ users }, null, 2), "utf8");
}

function readSessions() {
  try {
    const raw = fs.readFileSync(SESSIONS_PATH, "utf8");
    const data = JSON.parse(raw);
    return data.sessions || [];
  } catch (err) {
    if (err.code === "ENOENT") {
      return [];
    }
    throw err;
  }
}

function writeSessions(sessions) {
  fs.writeFileSync(SESSIONS_PATH, JSON.stringify({ sessions }, null, 2), "utf8");
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

function getUserFromToken(req) {
  const token = getAuthTokenFromRequest(req);
  if (!token) return null;

  const sessions = readSessions();
  const now = Date.now();
  const session = sessions.find(
    (s) => s.token === token && (!s.expiresAt || new Date(s.expiresAt).getTime() > now)
  );
  if (!session) return null;

  const users = readUsers();
  const user = users.find((u) => u.id === session.userId);
  return user || null;
}

function authMiddleware(req, res, next) {
  const user = getUserFromToken(req);
  if (!user) {
    return res.status(401).json({ error: "Not authenticated" });
  }
  req.user = user;
  next();
}

// -------- Words routes --------

app.get("/words", (req, res) => {
  try {
    const words = readWords();
    res.json({ words });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to read words" });
  }
});

app.post("/words", (req, res) => {
  try {
    const { accent, stress_index } = req.body;
    if (typeof accent !== "string" || typeof stress_index !== "number") {
      return res.status(400).json({ error: "Need accent (string) and stress_index (number)" });
    }
    const words = readWords();
    words.push({ accent: accent.trim().toLowerCase(), stress_index });
    writeWords(words);
    res.status(201).json({ words });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to add word" });
  }
});

// -------- Auth routes --------

// Registration via email or phone
app.post("/auth/register", (req, res) => {
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

    const users = readUsers();
    const normalizedName = name.trim();
    const normalizedEmail = email ? String(email).trim().toLowerCase() : null;
    const normalizedPhone = phone ? String(phone).trim() : null;

    if (users.some((u) => u.name === normalizedName)) {
      return res.status(409).json({ error: "User with this name already exists" });
    }
    if (normalizedEmail && users.some((u) => u.email === normalizedEmail)) {
      return res.status(409).json({ error: "User with this email already exists" });
    }
    if (normalizedPhone && users.some((u) => u.phone === normalizedPhone)) {
      return res.status(409).json({ error: "User with this phone already exists" });
    }

    const newUser = {
      id: randomBytes(12).toString("hex"),
      name: normalizedName,
      email: normalizedEmail,
      phone: normalizedPhone,
      passwordHash: hashPassword(password),
      bestStreak: 0,
      currentStreak: 0,
      wrongWords: [],
      resetCode: null,
      resetCodeExpiresAt: null,
    };

    users.push(newUser);
    writeUsers(users);

    return res.status(201).json({
      id: newUser.id,
      name: newUser.name,
      email: newUser.email,
      phone: newUser.phone,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to register user" });
  }
});

// Login: check identifier (name/email/phone) + password, return token in httpOnly cookie
app.post("/auth/login", (req, res) => {
  try {
    const { name, email, phone, password } = req.body || {};

    if (typeof password !== "string") {
      return res.status(400).json({ error: "Password is required" });
    }
    if (!name && !email && !phone) {
      return res.status(400).json({ error: "Name, email or phone is required" });
    }

    const users = readUsers();
    let user = null;

    if (email) {
      const normalizedEmail = String(email).trim().toLowerCase();
      user = users.find((u) => u.email === normalizedEmail);
    } else if (phone) {
      const normalizedPhone = String(phone).trim();
      user = users.find((u) => u.phone === normalizedPhone);
    } else if (name) {
      const normalizedName = String(name).trim();
      user = users.find((u) => u.name === normalizedName);
    }

    if (!user) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const validPassword = verifyPassword(password, user.passwordHash);
    if (!validPassword) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const token = createSessionToken();
    const sessions = readSessions();

    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days
    sessions.push({
      token,
      userId: user.id,
      createdAt: new Date().toISOString(),
      expiresAt: expiresAt.toISOString(),
    });
    writeSessions(sessions);

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
app.post("/auth/logout", (req, res) => {
  try {
    const token = getAuthTokenFromRequest(req);
    if (token) {
      const sessions = readSessions();
      const filtered = sessions.filter((s) => s.token !== token);
      writeSessions(filtered);
    }
    res.clearCookie(TOKEN_COOKIE_NAME);
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to logout" });
  }
});

// Forgot password: send code via email or phone (simulated)
app.post("/auth/forgot-password", (req, res) => {
  try {
    const { email, phone } = req.body || {};
    if (!email && !phone) {
      return res.status(400).json({ error: "Email or phone is required" });
    }

    const users = readUsers();
    let user = null;
    let method = null;

    if (email) {
      if (!isValidEmail(email)) {
        return res.status(400).json({ error: "Invalid email format" });
      }
      const normalizedEmail = String(email).trim().toLowerCase();
      user = users.find((u) => u.email === normalizedEmail);
      method = "email";
    } else if (phone) {
      if (!isValidPhone(phone)) {
        return res.status(400).json({ error: "Invalid phone format" });
      }
      const normalizedPhone = String(phone).trim();
      user = users.find((u) => u.phone === normalizedPhone);
      method = "sms";
    }

    if (!user) {
      // To avoid leaking which accounts exist, respond with generic message
      return res.json({ message: "If the account exists, a code has been sent" });
    }

    const code = String(Math.floor(100000 + Math.random() * 900000)); // 6 digits
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes

    user.resetCode = code;
    user.resetCodeExpiresAt = expiresAt.toISOString();

    writeUsers(users);

    // Here you would actually send email or SMS. For now we log it.
    console.log(`Password reset code for user ${user.name} via ${method}: ${code}`);

    return res.json({ message: "If the account exists, a code has been sent" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to start password reset" });
  }
});

// Reset password using code
app.post("/auth/reset-password", (req, res) => {
  try {
    const { name, code, newPassword } = req.body || {};

    if (!name || !code || !newPassword) {
      return res.status(400).json({ error: "Name, code and newPassword are required" });
    }
    if (typeof newPassword !== "string" || newPassword.length < 6) {
      return res.status(400).json({ error: "newPassword must be at least 6 characters" });
    }

    const users = readUsers();
    const user = users.find((u) => u.name === String(name).trim());
    if (!user || !user.resetCode || !user.resetCodeExpiresAt) {
      return res.status(400).json({ error: "Invalid code or user" });
    }

    const now = Date.now();
    const expiresAt = new Date(user.resetCodeExpiresAt).getTime();
    if (now > expiresAt) {
      return res.status(400).json({ error: "Code has expired" });
    }

    if (String(code).trim() !== String(user.resetCode).trim()) {
      return res.status(400).json({ error: "Invalid code" });
    }

    user.passwordHash = hashPassword(newPassword);
    user.resetCode = null;
    user.resetCodeExpiresAt = null;

    writeUsers(users);

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
    bestStreak: user.bestStreak,
    currentStreak: user.currentStreak,
    wrongWords: user.wrongWords || [],
  });
});

// Update stats after answer: correct or not, and which word
app.post("/profile/answer", authMiddleware, (req, res) => {
  try {
    const { accent, correct } = req.body || {};
    if (typeof accent !== "string") {
      return res.status(400).json({ error: "accent is required" });
    }
    if (typeof correct !== "boolean") {
      return res.status(400).json({ error: "correct must be boolean" });
    }

    const users = readUsers();
    const userIndex = users.findIndex((u) => u.id === req.user.id);
    if (userIndex === -1) {
      return res.status(404).json({ error: "User not found" });
    }

    const user = users[userIndex];

    if (correct) {
      user.currentStreak = (user.currentStreak || 0) + 1;
      if (!user.bestStreak || user.currentStreak > user.bestStreak) {
        user.bestStreak = user.currentStreak;
      }
    } else {
      user.currentStreak = 0;
      const word = accent.trim().toLowerCase();
      user.wrongWords = Array.isArray(user.wrongWords) ? user.wrongWords : [];
      if (!user.wrongWords.includes(word)) {
        user.wrongWords.push(word);
      }
    }

    users[userIndex] = user;
    writeUsers(users);

    res.json({
      bestStreak: user.bestStreak,
      currentStreak: user.currentStreak,
      wrongWords: user.wrongWords,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to update profile stats" });
  }
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
