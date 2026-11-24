const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcryptjs");

const db = new sqlite3.Database("./campusconnect.db");

db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS students (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL
    )
  `);

  // Local demonstration account: student / Campus@123
  const hash = bcrypt.hashSync("Campus@123", 10);
  db.run(
    "INSERT OR IGNORE INTO students (username, password_hash) VALUES (?, ?)",
    ["student", hash]
  );
});

module.exports = db;
