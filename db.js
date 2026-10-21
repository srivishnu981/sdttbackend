const Database = require('better-sqlite3');
const path = require('path');

const db = new Database(path.join(__dirname, 'attendance.db'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
CREATE TABLE IF NOT EXISTS students (
  id        INTEGER PRIMARY KEY AUTOINCREMENT,
  roll_no   TEXT NOT NULL UNIQUE,
  name      TEXT NOT NULL,
  device_id TEXT
);

CREATE TABLE IF NOT EXISTS teachers (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  teacher_code TEXT NOT NULL UNIQUE,
  name         TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS classes (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  code       TEXT NOT NULL UNIQUE,
  subject    TEXT NOT NULL,
  teacher_id INTEGER REFERENCES teachers(id)
);

CREATE TABLE IF NOT EXISTS sessions (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  class_id   INTEGER REFERENCES classes(id),
  started_at TEXT NOT NULL DEFAULT (datetime('now')),
  ended_at   TEXT,
  status     TEXT NOT NULL DEFAULT 'active'
);

CREATE TABLE IF NOT EXISTS attendance (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  session_id INTEGER NOT NULL REFERENCES sessions(id),
  student_id INTEGER NOT NULL REFERENCES students(id),
  marked_at  TEXT NOT NULL DEFAULT (datetime('now')),
  method     TEXT NOT NULL DEFAULT 'qr+biometric',
  UNIQUE (session_id, student_id)
);
`);

db.exec(`CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT UNIQUE NOT NULL,
  roll_no TEXT NOT NULL,
  password_hash TEXT NOT NULL
)`);


module.exports = db;