// server.js
// Express backend for the attendance app's rotating-QR flow.
// Sessions and attendance are now stored in SQLite (attendance.db).
// Only the short-lived rotating QR token is kept in memory.
 
const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const QRCode = require("qrcode");
const db = require("./db");
 
const app = express();
app.use(cors());
app.use(express.json());
 
const PORT = process.env.PORT || 4000;
require("dotenv").config();
const nodemailer = require("nodemailer");
const otpStore = new Map(); // email -> { code, expiresAt }
const sessionsStore = new Map(); // token -> { email, studentId }
const OTP_EXPIRY_MS = 5 * 60 * 1000; // 5 minutes
 
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_APP_PASSWORD,
  },
});
 
function generateOtp() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}
 
// How often the QR code rotates (ms).
const QR_ROTATE_INTERVAL_MS = 10_000;
 
// ---- Database statements ---------------------------------------------
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
 
// ---- In-memory state (QR only) ----------------------------------------
// activeQr.get(sessionId) -> { qrToken, qrDataUrl, qrIssuedAt, rotateHandle }
const activeQr = new Map();
 
function generateToken() {
  return crypto.randomBytes(16).toString("hex");
}
 
async function rotateQr(sessionId, state) {
  state.qrToken = generateToken();
  state.qrIssuedAt = Date.now();
 
  // Payload the mobile app scans and sends back in /attendance/mark.
  const payload = JSON.stringify({ sessionId, token: state.qrToken });
 
  state.qrDataUrl = await QRCode.toDataURL(payload, {
    errorCorrectionLevel: "M",
    margin: 1,
    width: 320,
  });
}
 
// ---- Routes ------------------------------------------------------------
 
app.get("/ping", (req, res) => {
  res.json({ ok: true, time: Date.now() });
});
 
// Professor taps "Start Session" -> saves a session and starts rotating QR.
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
// studentId = the student's roll number (e.g. "25BCS108").
app.post("/attendance/mark", (req, res) => {
  const { sessionId: rawSessionId, studentId, token } = req.body || {};
 
  if (!rawSessionId || !studentId || !token) {
    return res.status(400).json({ error: "sessionId, studentId, token are required" });
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
 
  const student = q.studentByRoll.get(String(studentId).trim().toUpperCase());
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
 