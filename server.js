const express = require("express");
const session = require("express-session");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const db = require("./db");

const app = express();
const PORT = 3000;
const PRIVATE_UPLOAD_DIR = path.join(__dirname, "private_uploads");

if (!fs.existsSync(PRIVATE_UPLOAD_DIR)) {
  fs.mkdirSync(PRIVATE_UPLOAD_DIR, { recursive: true });
}

app.use(helmet());
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(session({
  secret: process.env.SESSION_SECRET || "replace-this-secret-before-deployment",
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: "strict", secure: false, maxAge: 30 * 60 * 1000 }
}));
app.use(express.static(path.join(__dirname, "public")));

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: { error: "Too many login attempts. Try again later." }
});

function requireLogin(req, res, next) {
  if (!req.session.studentId) {
    return res.status(401).json({ error: "Please log in first." });
  }
  next();
}

// Secure login: password is checked with bcrypt and SQL values are parameterized.
app.post("/login", loginLimiter, (req, res) => {
  const { username, password } = req.body;

  if (typeof username !== "string" || typeof password !== "string" ||
      !username.trim() || !password) {
    return res.status(400).json({ error: "Enter username and password." });
  }

  db.get(
    "SELECT id, username, password_hash FROM students WHERE username = ?",
    [username.trim()],
    (err, student) => {
      if (err) return res.status(500).json({ error: "Database error." });

      const valid = student && bcrypt.compareSync(password, student.password_hash);
      if (!valid) return res.status(401).json({ error: "Invalid username or password." });

      req.session.regenerate((sessionErr) => {
        if (sessionErr) return res.status(500).json({ error: "Could not create session." });
        req.session.studentId = student.id;
        req.session.username = student.username;
        res.json({ message: "Login successful.", username: student.username });
      });
    }
  );
});

app.post("/logout", (req, res) => {
  req.session.destroy(() => res.json({ message: "Logged out." }));
});

app.get("/me", requireLogin, (req, res) => {
  res.json({ username: req.session.username });
});

// Deliberately vulnerable route for LOCAL classroom demonstration only.
// Never deploy this route. It concatenates untrusted input into SQL.
app.post("/demo/insecure-login", (req, res) => {
  const username = String(req.body.username || "");
  const password = String(req.body.password || "");
  const sql = `SELECT id, username FROM students WHERE username = '${username}' AND password_hash = '${password}'`;
  db.get(sql, (err, row) => {
    if (err) return res.status(400).json({ error: "SQL query failed.", detail: err.message });
    if (row) return res.json({ message: "Insecure demo: query returned a row." });
    res.status(401).json({ error: "Login failed." });
  });
});

// Upload to memory first. Validate size, declared type, extension AND file signature.
// Files are saved outside public/ using a server-generated random name.
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 2 * 1024 * 1024, files: 1 },
  fileFilter: (req, file, cb) => {
    const allowedMime = ["image/jpeg", "image/png"];
    const ext = path.extname(file.originalname).toLowerCase();
    const allowedExt = [".jpg", ".jpeg", ".png"];
    if (!allowedMime.includes(file.mimetype) || !allowedExt.includes(ext)) {
      return cb(new Error("Only JPG and PNG images are allowed."));
    }
    cb(null, true);
  }
});

function hasValidImageSignature(buffer, mime) {
  if (mime === "image/jpeg") {
    return buffer.length >= 3 &&
      buffer[0] === 0xff && buffer[1] === 0xd8 && buffer[2] === 0xff;
  }
  if (mime === "image/png") {
    return buffer.length >= 8 &&
      buffer.subarray(0, 8).equals(Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]));
  }
  return false;
}

app.post("/upload", requireLogin, (req, res) => {
  upload.single("profilePicture")(req, res, (err) => {
    if (err) {
      const message = err.code === "LIMIT_FILE_SIZE"
        ? "File is too large. Maximum size is 2 MB."
        : err.message;
      return res.status(400).json({ error: message });
    }

    if (!req.file) return res.status(400).json({ error: "Choose an image file." });

    if (!hasValidImageSignature(req.file.buffer, req.file.mimetype)) {
      return res.status(400).json({ error: "File content is not a valid JPG/PNG image." });
    }

    const extension = req.file.mimetype === "image/png" ? ".png" : ".jpg";
    const safeName = crypto.randomUUID() + extension;
    fs.writeFile(path.join(PRIVATE_UPLOAD_DIR, safeName), req.file.buffer, (writeErr) => {
      if (writeErr) return res.status(500).json({ error: "Could not save file." });
      res.json({ message: "Profile picture uploaded securely.", fileId: safeName });
    });
  });
});

// Private download: requires an authenticated session.
app.get("/profile-picture/:fileId", requireLogin, (req, res) => {
  const fileId = req.params.fileId;
  if (!/^[a-f0-9-]+\.(jpg|png)$/.test(fileId)) {
    return res.status(400).json({ error: "Invalid file identifier." });
  }
  const filePath = path.join(PRIVATE_UPLOAD_DIR, fileId);
  if (!fs.existsSync(filePath)) return res.status(404).json({ error: "Image not found." });
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.sendFile(filePath);
});

app.use((err, req, res, next) => {
  res.status(400).json({ error: err.message || "Request failed." });
});

app.listen(PORT, () => {
  console.log(`CampusConnect running at http://localhost:${PORT}`);
  console.log("Demo account: student / Campus@123");
});
