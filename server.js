// server.js
// Express backend for the attendance app's rotating-QR flow.
// Sessions and attendance are stored in SQLite (attendance.db).
// Only the short-lived rotating QR token and OTP codes are kept in memory.
//
// Accounts:
//  - signup needs an email OTP (proves the student owns the college email)
//  - every login needs an email OTP (after password check)
//  - forgot password = email OTP + new password
//  - each account is locked to one phone (device binding)
//  - the app stays logged in via a JWT saved on the phone

require("dotenv").config();

const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const QRCode = require("qrcode");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");
const db = require("./db");

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 4000;

// ---- Auth config -----------------------------------------------------------
const JWT_SECRET = process.env.JWT_SECRET || "change-this-secret";
// Set COLLEGE_EMAIL_DOMAIN in .env (e.g. iiitdwd.ac.in). Email looks like 25bcs174@domain
const EMAIL_DOMAIN = (process.env.COLLEGE_EMAIL_DOMAIN || "college.edu").replace(/\./g, "\\.");
const EMAIL_RE = new RegExp(`^([a-z0-9]+)@${EMAIL_DOMAIN}$`, "i"); // group 1 = roll no

// How often the QR code rotates (ms).
const QR_ROTATE_INTERVAL_MS = 10_000;

// ---- Email OTP -------------------------------------------------------------
const OTP_EXPIRY_MS = 5 * 60 * 1000; // OTP valid for 5 minutes
const OTP_RESEND_MS = 30 * 1000; // wait 30s between OTP requests
const OTP_MAX_ATTEMPTS = 5; // wrong guesses before the OTP is burned

// "purpose:email" -> { code, expiresAt, attempts, sentAt }
const otpStore = new Map();

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_APP_PASSWORD,
  },
});

const OTP_SUBJECTS = {
  signup: "Verify your email - Attendance App",
  login: "Your login code - Attendance App",
  reset: "Reset your password - Attendance App",
};

async function sendOtpEmail(email, code, purpose) {
  // Dev mode: no email credentials set -> print the OTP in this terminal.
  if (!process.env.EMAIL_USER || !process.env.EMAIL_APP_PASSWORD) {
    console.log(`[DEV OTP] ${purpose} code for ${email}: ${code}`);
    return;
  }
  await transporter.sendMail({
    from: `"Attendance App" <${process.env.EMAIL_USER}>`,
    to: email,
    subject: OTP_SUBJECTS[purpose] || "Your code",
    text: `Your verification code is ${code}. It expires in 5 minutes. If you did not request this, ignore this email.`,
  });
}

// Creates + emails an OTP. Returns { ok: true } or { error }.
async function issueOtp(purpose, email) {
  const key = `${purpose}:${email}`;
  const old = otpStore.get(key);
  if (old && Date.now() - old.sentAt < OTP_RESEND_MS) {
    const wait = Math.ceil((OTP_RESEND_MS - (Date.now() - old.sentAt)) / 1000);
    return { error: `Please wait ${wait}s before requesting another OTP` };
  }
  const code = String(crypto.randomInt(100000, 1000000));
  otpStore.set(key, { code, expiresAt: Date.now() + OTP_EXPIRY_MS, attempts: 0, sentAt: Date.now() });
  try {
    await sendOtpEmail(email, code, purpose);
  } catch (err) {
    otpStore.delete(key);
    console.error("Failed to send OTP email:", err.message);
    return { error: "Could not send the email. Try again in a moment." };
  }
  return { ok: true };
}

// Returns null if the OTP is right, otherwise an error message.
function checkOtp(purpose, email, code) {
  const key = `${purpose}:${email}`;
  const rec = otpStore.get(key);
  if (!rec || Date.now() > rec.expiresAt) {
    otpStore.delete(key);
    return "OTP expired. Please request a new one.";
  }
  rec.attempts += 1;
  if (rec.attempts > OTP_MAX_ATTEMPTS) {
    otpStore.delete(key);
    return "Too many wrong attempts. Please request a new OTP.";
  }
  if (String(code || "").trim() !== rec.code) return "Wrong OTP";
  otpStore.delete(key); // one-time use
  return null;
}

// ---- Database --------------------------------------------------------------
// Users table for student accounts (created on first run).
db.exec(`CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT UNIQUE NOT NULL,
  roll_no TEXT NOT NULL,
  password_hash TEXT NOT NULL
)`);

// Device binding column (errors if it already exists, which is fine).
try {
  db.exec("ALTER TABLE users ADD COLUMN device_id TEXT");
} catch {}

const q = {
  teacherByCode: db.prepare("SELECT id FROM teachers WHERE teacher_code = ?"),
  insertTeacher: db.prepare("INSERT INTO teachers (teacher_code, name) VALUES (?, ?)"),
  classByCode: db.prepare("SELECT id FROM classes WHERE code = ?"),
  insertClass: db.prepare("INSERT INTO classes (code, subject, teacher_id) VALUES (?, ?, ?)"),
  insertSession: db.prepare("INSERT INTO sessions (class_id) VALUES (?)"),
  sessionById: db.prepare(`
    SELECT s.id, s.status, s.started_at, s.ended_at, c.code AS class_code, t.teacher_code
    FROM sessions s
    LEFT JOIN classes c ON c.id = s.class_id
    LEFT JOIN teachers t ON t.id = c.teacher_id
    WHERE s.id = ?`),
  endSession: db.prepare(
    "UPDATE sessions SET status = 'ended', ended_at = datetime('now') WHERE id = ?"
  ),
  endStaleSessions: db.prepare(
    "UPDATE sessions SET status = 'ended', ended_at = datetime('now') WHERE status = 'active'"
  ),
  studentByRoll: db.prepare("SELECT id, roll_no, name FROM students WHERE roll_no = ?"),
  insertAttendance: db.prepare(
    "INSERT OR IGNORE INTO attendance (session_id, student_id) VALUES (?, ?)"
  ),
  attendanceForSession: db.prepare(`
    SELECT st.roll_no AS rollNo, st.name, a.marked_at AS markedAt
    FROM attendance a
    JOIN students st ON st.id = a.student_id
    WHERE a.session_id = ?
    ORDER BY st.roll_no`),
  // auth
  userByEmail: db.prepare("SELECT * FROM users WHERE email = ?"),
  insertUser: db.prepare(
    "INSERT INTO users (email, roll_no, password_hash, device_id) VALUES (?, ?, ?, ?)"
  ),
  userByDevice: db.prepare("SELECT id FROM users WHERE device_id = ?"),
  bindDevice: db.prepare("UPDATE users SET device_id = ? WHERE id = ?"),
  updatePassword: db.prepare("UPDATE users SET password_hash = ? WHERE id = ?"),
};

// A server restart kills the QR rotation timers, so any session still
// marked 'active' in the DB is dead. Close them on boot.
q.endStaleSessions.run();

// Teacher/class data isn't fully in the DB yet (we're doing that later),
// so create the rows on first use from the codes the app sends (T101, C003...).
function getOrCreateTeacher(code) {
  const row = q.teacherByCode.get(code);
  if (row) return row.id;
  return q.insertTeacher.run(code, code).lastInsertRowid;
}

function getOrCreateClass(code, teacherDbId) {
  const row = q.classByCode.get(code);
  if (row) return row.id;
  return q.insertClass.run(code, code, teacherDbId).lastInsertRowid;
}

// ---- In-memory state (QR only) ---------------------------------------------
// activeQr.get(sessionId) -> { qrToken, qrDataUrl, qrIssuedAt, rotateHandle }
const activeQr = new Map();

function generateToken() {
  return crypto.randomBytes(16).toString("hex");
}

async function rotateQr(sessionId, state) {
  state.qrToken = generateToken();
  state.qrIssuedAt = Date.now();

  // Payload the mobile app scans and sends back to /attendance/mark.
  const payload = JSON.stringify({ sessionId, token: state.qrToken });

  state.qrDataUrl = await QRCode.toDataURL(payload, {
    errorCorrectionLevel: "M",
    margin: 1,
    width: 320,
  });
}

// ---- Auth middleware -------------------------------------------------------
// The login token carries the phone's device id, so a copied token (or a
// shared password) is useless on any other phone.
const makeToken = (u) =>
  jwt.sign({ email: u.email, roll: u.roll_no, dev: u.device_id }, JWT_SECRET, {
    expiresIn: "180d",
  });

function requireAuth(req, res, next) {
  try {
    const t = (req.headers.authorization || "").replace("Bearer ", "");
    req.user = jwt.verify(t, JWT_SECRET); // { email, roll, dev }
    if (!req.user.dev || req.user.dev !== req.headers["x-device-id"]) {
      throw new Error("device mismatch");
    }
    next();
  } catch {
    res.status(401).json({ error: "Unauthorized" });
  }
}

// Shared helpers for the auth routes.
const cleanEmail = (v) => String(v || "").trim().toLowerCase();

// Returns an error message if this user may not log in from this phone.
function deviceProblem(user, deviceId) {
  if (!deviceId) return "Device not recognised";
  if (user.device_id && user.device_id !== deviceId) {
    return "This account is linked to another phone. Ask admin to reset.";
  }
  if (!user.device_id && q.userByDevice.get(deviceId)) {
    return "This phone is already registered to another account";
  }
  return null;
}

// ---- Auth routes -----------------------------------------------------------

// SIGNUP step 1: check email/roll/phone, then email an OTP.
app.post("/auth/signup/request-otp", async (req, res) => {
  const email = cleanEmail(req.body?.email);
  const deviceId = String(req.body?.deviceId || "");

  const m = EMAIL_RE.exec(email);
  if (!m) return res.status(400).json({ error: "Use your college email (with roll no)" });
  if (!deviceId) return res.status(400).json({ error: "Device not recognised" });
  if (q.userByDevice.get(deviceId)) {
    return res.status(403).json({ error: "This phone is already registered to another account" });
  }
  if (!q.studentByRoll.get(m[1].toUpperCase())) {
    return res.status(403).json({ error: "Roll no not in student list" });
  }
  if (q.userByEmail.get(email)) {
    return res.status(409).json({ error: "Account already exists. Please log in." });
  }

  const r = await issueOtp("signup", email);
  if (r.error) return res.status(429).json({ error: r.error });
  res.json({ ok: true });
});

// SIGNUP step 2: verify OTP, create the account, log the student in.
app.post("/auth/signup", async (req, res) => {
  const email = cleanEmail(req.body?.email);
  const password = String(req.body?.password || "");
  const deviceId = String(req.body?.deviceId || "");
  const otp = req.body?.otp;

  const m = EMAIL_RE.exec(email);
  if (!m) return res.status(400).json({ error: "Use your college email (with roll no)" });
  if (password.length < 6) return res.status(400).json({ error: "Password must be 6+ characters" });
  if (!deviceId) return res.status(400).json({ error: "Device not recognised" });
  if (q.userByDevice.get(deviceId)) {
    return res.status(403).json({ error: "This phone is already registered to another account" });
  }

  const roll = m[1].toUpperCase();
  const student = q.studentByRoll.get(roll);
  if (!student) return res.status(403).json({ error: "Roll no not in student list" });
  if (q.userByEmail.get(email)) return res.status(409).json({ error: "Account already exists" });

  const otpError = checkOtp("signup", email, otp);
  if (otpError) return res.status(400).json({ error: otpError });

  const hash = await bcrypt.hash(password, 10);
  q.insertUser.run(email, roll, hash, deviceId);

  res.json({
    token: makeToken({ email, roll_no: roll, device_id: deviceId }),
    user: { name: student.name, rollNo: roll },
  });
});

// LOGIN step 1: check password + phone, then email an OTP.
app.post("/auth/login", async (req, res) => {
  const email = cleanEmail(req.body?.email);
  const password = String(req.body?.password || "");
  const deviceId = String(req.body?.deviceId || "");

  const u = q.userByEmail.get(email);
  if (!u || !(await bcrypt.compare(password, u.password_hash))) {
    return res.status(401).json({ error: "Wrong email or password" });
  }
  const problem = deviceProblem(u, deviceId);
  if (problem) return res.status(403).json({ error: problem });

  const r = await issueOtp("login", email);
  if (r.error) return res.status(429).json({ error: r.error });
  res.json({ otpRequired: true });
});

// LOGIN step 2: verify OTP, return the login token.
app.post("/auth/login/verify", (req, res) => {
  const email = cleanEmail(req.body?.email);
  const deviceId = String(req.body?.deviceId || "");

  const u = q.userByEmail.get(email);
  if (!u) return res.status(401).json({ error: "Wrong email or password" });
  const problem = deviceProblem(u, deviceId);
  if (problem) return res.status(403).json({ error: problem });

  const otpError = checkOtp("login", email, req.body?.otp);
  if (otpError) return res.status(400).json({ error: otpError });

  if (!u.device_id) {
    // Older account with no phone linked yet: link this phone now.
    q.bindDevice.run(deviceId, u.id);
    u.device_id = deviceId;
  }

  const student = q.studentByRoll.get(u.roll_no);
  res.json({
    token: makeToken(u),
    user: { name: student?.name, rollNo: u.roll_no },
  });
});

// FORGOT PASSWORD step 1: email an OTP (same reply whether or not the account exists).
app.post("/auth/forgot/request-otp", async (req, res) => {
  const email = cleanEmail(req.body?.email);
  const u = EMAIL_RE.test(email) ? q.userByEmail.get(email) : null;

  if (u) {
    const r = await issueOtp("reset", email);
    if (r.error) return res.status(429).json({ error: r.error });
  }
  res.json({ ok: true });
});

// FORGOT PASSWORD step 2: verify OTP and set the new password.
app.post("/auth/forgot/reset", async (req, res) => {
  const email = cleanEmail(req.body?.email);
  const newPassword = String(req.body?.newPassword || "");

  if (newPassword.length < 6) {
    return res.status(400).json({ error: "Password must be 6+ characters" });
  }
  const u = q.userByEmail.get(email);
  if (!u) return res.status(400).json({ error: "Wrong OTP" });

  const otpError = checkOtp("reset", email, req.body?.otp);
  if (otpError) return res.status(400).json({ error: otpError });

  q.updatePassword.run(await bcrypt.hash(newPassword, 10), u.id);
  res.json({ ok: true });
});

// App calls this on startup to check the saved token is still valid.
app.get("/auth/me", requireAuth, (req, res) => {
  const student = q.studentByRoll.get(req.user.roll);
  res.json({ name: student?.name, rollNo: req.user.roll });
});

// ---- Session / attendance routes -------------------------------------------

app.get("/ping", (req, res) => {
  res.json({ ok: true, time: Date.now() });
});

// Professor taps "Start Session" -> opens a session and starts rotating QR.
app.post("/session/start", async (req, res) => {
  const { teacherId, classId } = req.body || {};

  if (!teacherId || !classId) {
    return res.status(400).json({ error: "teacherId and classId are required" });
  }

  const teacherDbId = getOrCreateTeacher(String(teacherId));
  const classDbId = getOrCreateClass(String(classId), teacherDbId);
  const sessionId = Number(q.insertSession.run(classDbId).lastInsertRowid);

  const state = {
    qrToken: null,
    qrDataUrl: null,
    qrIssuedAt: null,
    rotateHandle: null,
  };
  activeQr.set(sessionId, state);

  await rotateQr(sessionId, state);

  state.rotateHandle = setInterval(() => {
    rotateQr(sessionId, state).catch((err) => {
      console.error(`QR rotation failed for session ${sessionId}:`, err);
    });
  }, QR_ROTATE_INTERVAL_MS);

  res.json({
    sessionId,
    qrDataUrl: state.qrDataUrl,
    rotateIntervalMs: QR_ROTATE_INTERVAL_MS,
    qrIssuedAt: state.qrIssuedAt,
  });
});

// Teacher screen polls this every 5s to pick up the current QR image.
app.get("/session/qr", (req, res) => {
  const sessionId = Number(req.query.sessionId);
  const row = q.sessionById.get(sessionId);

  if (!row) {
    return res.status(404).json({ error: "session not found" });
  }
  const state = activeQr.get(sessionId);
  if (row.status !== "active" || !state) {
    return res.status(410).json({ error: "session has ended" });
  }

  const msRemaining = QR_ROTATE_INTERVAL_MS - (Date.now() - state.qrIssuedAt);

  res.json({
    qrDataUrl: state.qrDataUrl,
    qrIssuedAt: state.qrIssuedAt,
    msUntilNextRotation: Math.max(0, msRemaining),
  });
});

// Student app scans the QR and posts back the token it decoded.
// The student is identified by their login token (req.user.roll), not the request body.
app.post("/attendance/mark", requireAuth, (req, res) => {
  const { sessionId: rawSessionId, token } = req.body || {};

  if (!rawSessionId || !token) {
    return res.status(400).json({ error: "sessionId and token are required" });
  }

  const sessionId = Number(rawSessionId);
  const row = q.sessionById.get(sessionId);
  const state = activeQr.get(sessionId);
  if (!row || row.status !== "active" || !state) {
    return res.status(404).json({ error: "session not found or ended" });
  }

  if (token !== state.qrToken) {
    // Stale (already rotated) or spoofed/screenshotted QR.
    return res.status(409).json({ error: "QR token expired or invalid" });
  }

  const student = q.studentByRoll.get(req.user.roll);
  if (!student) {
    return res.status(404).json({ error: "student not found" });
  }

  // UNIQUE(session_id, student_id) makes a repeat insert a no-op.
  const result = q.insertAttendance.run(sessionId, student.id);
  res.json({
    ok: true,
    alreadyMarked: result.changes === 0,
    student: { rollNo: student.roll_no, name: student.name },
  });
});

// Status the teacher dashboard can poll for a live headcount.
app.get("/session/status", (req, res) => {
  const sessionId = Number(req.query.sessionId);
  const row = q.sessionById.get(sessionId);

  if (!row) {
    return res.status(404).json({ error: "session not found" });
  }

  const present = q.attendanceForSession.all(sessionId);

  res.json({
    sessionId,
    active: row.status === "active",
    classId: row.class_code,
    teacherId: row.teacher_code,
    presentCount: present.length,
    presentStudentIds: present.map((p) => p.rollNo),
    presentStudents: present,
  });
});

// Professor taps "End Session" -> stop rotating, freeze final headcount.
app.post("/session/end", (req, res) => {
  const sessionId = Number((req.body || {}).sessionId);
  const row = q.sessionById.get(sessionId);

  if (!row) {
    return res.status(404).json({ error: "session not found" });
  }

  const state = activeQr.get(sessionId);
  if (state) {
    clearInterval(state.rotateHandle);
    activeQr.delete(sessionId);
  }
  q.endSession.run(sessionId);

  const present = q.attendanceForSession.all(sessionId);

  res.json({
    ok: true,
    sessionId,
    presentCount: present.length,
    presentStudentIds: present.map((p) => p.rollNo),
    presentStudents: present,
  });
});

// TEST ONLY: mark a student present without scanning. Off unless ALLOW_TEST_MARK=1.
if (process.env.ALLOW_TEST_MARK === "1") {
  const latestActive = db.prepare(
    "SELECT id FROM sessions WHERE status = 'active' ORDER BY id DESC LIMIT 1"
  );
  app.get("/dev/mark", (req, res) => {
    const active = latestActive.get();
    if (!active) return res.status(404).json({ error: "no active session" });
    const student = q.studentByRoll.get(String(req.query.roll || "").trim().toUpperCase());
    if (!student) return res.status(404).json({ error: "student not found" });
    const r = q.insertAttendance.run(active.id, student.id);
    res.json({ ok: true, alreadyMarked: r.changes === 0, student: student.roll_no });
  });
}

app.listen(PORT, () => {
  console.log(`Attendance backend listening on http://localhost:${PORT}`);
});