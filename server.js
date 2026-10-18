import express from "express";
import dotenv from "dotenv";
import { google } from "googleapis";
import crypto from "crypto";
import fs from "fs";
import path from "path";
import multer from "multer";
import { fileURLToPath } from "url";
import pg from "pg";

dotenv.config();

const { Pool } = pg;

const pool = process.env.DATABASE_URL
  ? new Pool({
      connectionString: process.env.DATABASE_URL,
      ssl: { rejectUnauthorized: false }
    })
  : null;

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = Number(process.env.PORT || 8787);
const BASE =
  process.env.APP_BASE_URL ||
  `http://localhost:${PORT}`;

const DATA = path.join(__dirname, "data");
const DB = path.join(DATA, "store.json");
const TOKENS = path.join(DATA, "google.tokens.enc");

app.use(express.json({ limit: "4mb" }));
app.use(express.static(path.join(__dirname, "public")));

const APP_PASSWORD =
  process.env.APP_PASSWORD || "";

// ======================================
// LOGIN PROTECTION
// ======================================

app.use((req, res, next) => {
  if (
    req.path === "/login" ||
    req.path === "/api/login" ||
    req.path === "/api/logout" ||
    req.path.startsWith("/manifest") ||
    req.path.startsWith("/service-worker")
  ) {
    return next();
  }

  const cookie = req.headers.cookie || "";

  if (
    APP_PASSWORD &&
    cookie.includes("sj_dona_auth=1")
  ) {
    return next();
  }

  if (
    req.path.startsWith("/api/") ||
    req.path.startsWith("/auth/google")
  ) {
    return res.status(401).json({
      error: "SJ DONA 로그인이 필요합니다."
    });
  }

  return res.redirect("/login");
});

app.get("/login", (req, res) => {
  res.send(`<!doctype html>
<html lang="ko">
<head>
<meta charset="utf-8">
<meta name="viewport"
content="width=device-width,initial-scale=1">
<title>SJ DONA Login</title>
</head>

<body style="
font-family:sans-serif;
padding:40px;
max-width:420px;
margin:auto
">

<h1>SJ DONA</h1>

<p>개인 AI 매니저 로그인</p>

<form method="post" action="/api/login">

<input
name="password"
type="password"
placeholder="비밀번호"
style="
width:100%;
padding:15px;
font-size:18px;
box-sizing:border-box
">

<button
type="submit"
style="
margin-top:15px;
width:100%;
padding:15px;
font-size:18px
">
로그인
</button>

</form>

</body>
</html>`);
});

app.use(
  express.urlencoded({
    extended: false
  })
);

app.post("/api/login", (req, res) => {
  if (
    APP_PASSWORD &&
    req.body.password === APP_PASSWORD
  ) {
    res.setHeader(
      "Set-Cookie",
      "sj_dona_auth=1; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=2592000"
    );

    return res.redirect("/");
  }

  res
    .status(401)
    .send("비밀번호가 맞지 않습니다.");
});

app.post("/api/logout", (req, res) => {
  res.setHeader(
    "Set-Cookie",
    "sj_dona_auth=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0"
  );

  res.redirect("/login");
});

// ======================================
// LOCAL FALLBACK DATABASE
// ======================================

function loadDB() {
  try {
    return JSON.parse(
      fs.readFileSync(DB, "utf8")
    );
  } catch {
    return {
      tasks: [],
      events: [],
      notes: [],
      profile: {},
      settings: {
        briefTime: "08:00"
      }
    };
  }
}

function saveDB(db) {
  fs.mkdirSync(DATA, {
    recursive: true
  });

  fs.writeFileSync(
    DB,
    JSON.stringify(db, null, 2)
  );
}

// ======================================
// POSTGRES STATE DATABASE
// ======================================

async function initDatabase() {
  if (!pool) return;

  await pool.query(`
    CREATE TABLE IF NOT EXISTS sj_dona_state (
      id INTEGER PRIMARY KEY,
      data JSONB NOT NULL,
      updated_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);
}

async function loadDBFromPostgres() {
  if (!pool) {
    return loadDB();
  }

  try {
    await initDatabase();

    const result = await pool.query(
      "SELECT data FROM sj_dona_state WHERE id = 1"
    );

    if (result.rows.length) {
      return result.rows[0].data;
    }

    const initial = loadDB();

    await pool.query(
      `
      INSERT INTO sj_dona_state
      (id, data)
      VALUES (1, $1::jsonb)
      ON CONFLICT (id)
      DO NOTHING
      `,
      [JSON.stringify(initial)]
    );

    return initial;

  } catch (e) {
    console.error(
      "POSTGRES LOAD ERROR:",
      e
    );

    return loadDB();
  }
}

async function saveDBToPostgres(db) {
  if (!pool) {
    return saveDB(db);
  }

  try {
    await initDatabase();

    await pool.query(
      `
      INSERT INTO sj_dona_state
      (id, data, updated_at)

      VALUES
      (1, $1::jsonb, NOW())

      ON CONFLICT (id)

      DO UPDATE SET
        data = EXCLUDED.data,
        updated_at = NOW()
      `,
      [JSON.stringify(db)]
    );

  } catch (e) {
    console.error(
      "POSTGRES SAVE ERROR:",
      e
    );

    saveDB(db);
  }
}

// ======================================
// GOOGLE TOKEN ENCRYPTION
// ======================================

function key() {
  const raw =
    (
      process.env.TOKEN_ENCRYPTION_KEY ||
      ""
    ).trim();

  return raw
    ? crypto
        .createHash("sha256")
        .update(raw)
        .digest()
    : null;
}

function encrypt(obj) {
  const k = key();

  if (!k) {
    throw new Error(
      "TOKEN_ENCRYPTION_KEY is not set"
    );
  }

  const iv =
    crypto.randomBytes(12);

  const cipher =
    crypto.createCipheriv(
      "aes-256-gcm",
      k,
      iv
    );

  const enc =
    Buffer.concat([
      cipher.update(
        JSON.stringify(obj),
        "utf8"
      ),
      cipher.final()
    ]);

  const tag =
    cipher.getAuthTag();

  return Buffer.concat([
    iv,
    tag,
    enc
  ]).toString("base64");
}

function decrypt(s) {
  const k = key();

  if (!k) {
    throw new Error(
      "TOKEN_ENCRYPTION_KEY is not set"
    );
  }

  const b =
    Buffer.from(s, "base64");

  const iv =
    b.subarray(0, 12);

  const tag =
    b.subarray(12, 28);

  const enc =
    b.subarray(28);

  const decipher =
    crypto.createDecipheriv(
      "aes-256-gcm",
      k,
      iv
    );

  decipher.setAuthTag(tag);

  return JSON.parse(
    Buffer.concat([
      decipher.update(enc),
      decipher.final()
    ]).toString("utf8")
  );
}

function getTokens() {
  try {
    return decrypt(
      fs.readFileSync(
        TOKENS,
        "utf8"
      )
    );
  } catch {
    return null;
  }
}

function setTokens(tokens) {
  fs.mkdirSync(DATA, {
    recursive: true
  });

  fs.writeFileSync(
    TOKENS,
    encrypt(tokens)
  );
}

async function getGoogleTokensFromPostgres() {
  if (!pool) {
    return getTokens();
  }

  try {
    const db =
      await loadDBFromPostgres();

    if (db.googleTokens) {
      return decrypt(
        db.googleTokens
      );
    }

    return getTokens();

  } catch (e) {
    console.error(
      "GOOGLE TOKEN LOAD ERROR:",
      e
    );

    return getTokens();
  }
}

async function saveGoogleTokensToPostgres(
  tokens
) {
  if (!pool) {
    return setTokens(tokens);
  }

  try {
    await initDatabase();

    const db =
      await loadDBFromPostgres();

    db.googleTokens =
      encrypt(tokens);

    await saveDBToPostgres(db);

  } catch (e) {
    console.error(
      "GOOGLE TOKEN SAVE ERROR:",
      e
    );

    setTokens(tokens);
  }
}

// ======================================
// GOOGLE OAUTH
// ======================================

function oauth() {
  return new google.auth.OAuth2(
    process.env.GOOGLE_CLIENT_ID,
    process.env.GOOGLE_CLIENT_SECRET,
    `${BASE}/auth/google/callback`
  );
}

async function authedGoogle() {
  const tokens =
    await getGoogleTokensFromPostgres();

  if (!tokens) {
    return null;
  }

  const o = oauth();

  o.setCredentials(tokens);

  o.on("tokens", fresh => {
    saveGoogleTokensToPostgres({
      ...tokens,
      ...fresh
    }).catch(e => {
      console.error(
        "GOOGLE TOKEN REFRESH SAVE ERROR:",
        e
      );
    });
  });

  return o;
}

// ======================================
// STATUS / STATE
// ======================================

app.get(
  "/api/status",
  async (req, res) => {
    try {
      const googleTokens =
        await getGoogleTokensFromPostgres();

      res.json({
        ok: true,
        openai: Boolean(
          process.env.OPENAI_API_KEY
        ),
        google: Boolean(
          googleTokens
        ),
        model:
          process.env.OPENAI_MODEL ||
          "gpt-5.6"
      });

    } catch (e) {
      res.status(500).json({
        error: e.message
      });
    }
  }
);

app.get(
  "/api/state",
  async (req, res) => {
    try {
      res.json(
        await loadDBFromPostgres()
      );

    } catch (e) {
      console.error(
        "STATE LOAD ERROR:",
        e
      );

      res.status(500).json({
        error: e.message
      });
    }
  }
);

app.post(
  "/api/state",
  async (req, res) => {
    try {
      await saveDBToPostgres(
        req.body || {}
      );

      res.json({
        ok: true
      });

    } catch (e) {
      console.error(
        "STATE SAVE ERROR:",
        e
      );

      res.status(500).json({
        error: e.message
      });
    }
  }
);

// ======================================
// GOOGLE CONNECT / DISCONNECT
// ======================================

app.get(
  "/auth/google",
  (req, res) => {
    if (
      !process.env.GOOGLE_CLIENT_ID ||
      !process.env.GOOGLE_CLIENT_SECRET
    ) {
      return res
        .status(400)
        .send(
          "Google OAuth environment variables are not configured."
        );
    }

    const o = oauth();

    res.redirect(
      o.generateAuthUrl({
        access_type: "offline",
        prompt: "consent",
        scope: [
          "https://www.googleapis.com/auth/gmail.readonly",
          "https://www.googleapis.com/auth/calendar.readonly",
          "https://www.googleapis.com/auth/drive.readonly"
        ]
      })
    );
  }
);

app.get(
  "/auth/google/callback",
  async (req, res) => {
    try {
      const o = oauth();

      const { tokens } =
        await o.getToken(
          req.query.code
        );

      await saveGoogleTokensToPostgres(
        tokens
      );

      res.redirect(
        "/?google=connected"
      );

    } catch (e) {
      res
        .status(500)
        .send(
          "Google connection failed: " +
          e.message
        );
    }
  }
);

app.post(
  "/api/google/disconnect",
  async (req, res) => {
    try {
      const db =
        await loadDBFromPostgres();

      delete db.googleTokens;

      await saveDBToPostgres(db);

      try {
        if (
          fs.existsSync(TOKENS)
        ) {
          fs.unlinkSync(TOKENS);
        }
      } catch {}

      res.json({
        ok: true
      });

    } catch (e) {
      console.error(
        "GOOGLE DISCONNECT ERROR:",
        e
      );

      res.status(500).json({
        error: e.message
      });
    }
  }
);

// ======================================
// GMAIL HELPERS
// ======================================

function decodeGmailBody(data = "") {
  try {
    return Buffer.from(
      data
        .replace(/-/g, "+")
        .replace(/_/g, "/"),
      "base64"
    ).toString("utf8");

  } catch {
    return "";
  }
}

function gmailBody(payload) {
  if (!payload) {
    return "";
  }

  if (payload.body?.data) {
    return decodeGmailBody(
      payload.body.data
    );
  }

  const parts =
    payload.parts || [];

  for (const p of parts) {
    if (
      p.mimeType === "text/plain" &&
      p.body?.data
    ) {
      return decodeGmailBody(
        p.body.data
      );
    }
  }

  for (const p of parts) {
    const text =
      gmailBody(p);

    if (text) {
      return text;
    }
  }

  return "";
}

function gmailAttachments(
  payload,
  list = []
) {
  if (!payload) {
    return list;
  }

  for (
    const p of payload.parts || []
  ) {
    if (p.filename) {
      list.push({
        name: p.filename,
        mimeType:
          p.mimeType || "",
        attachmentId:
          p.body?.attachmentId ||
          ""
      });
    }

    gmailAttachments(
      p,
      list
    );
  }

  return list;
}

// ======================================
// GOOGLE WORKSPACE
// ======================================

async function getWorkspace() {
  const auth =
    await authedGoogle();

  if (!auth) {
    return {
      connected: false,
      gmail: [],
      calendar: [],
      drive: []
    };
  }

  const gmail =
    google.gmail({
      version: "v1",
      auth
    });

  const calendar =
    google.calendar({
      version: "v3",
      auth
    });

  const drive =
    google.drive({
      version: "v3",
      auth
    });

  let mail = [];
  let events = [];
  let files = [];

  // Gmail
  try {
    const l =
      await gmail.users.messages.list({
        userId: "me",
        maxResults: 15,
        q: "newer_than:14d"
      });

    for (
      const m of
      (l.data.messages || []).slice(
        0,
        15
      )
    ) {
      try {
        const r =
          await gmail.users.messages.get({
            userId: "me",
            id: m.id,
            format: "full"
          });

        const headers =
          r.data.payload?.headers ||
          [];

        const h =
          Object.fromEntries(
            headers.map(x => [
              String(
                x.name || ""
              ).toLowerCase(),
              x.value
            ])
          );

        let body =
          gmailBody(
            r.data.payload
          );

        body = body
          .replace(/\s+/g, " ")
          .trim()
          .slice(0, 4000);

        const attachments =
          gmailAttachments(
            r.data.payload,
            []
          );

        mail.push({
          id: m.id,
          threadId:
            r.data.threadId || "",
          subject:
            h.subject ||
            "(제목 없음)",
          from:
            h.from || "",
          to:
            h.to || "",
          date:
            h.date || "",
          snippet:
            r.data.snippet || "",
          body,
          hasAttachments:
            attachments.length > 0,
          attachments:
            attachments.map(a => ({
              name: a.name,
              mimeType:
                a.mimeType
            }))
        });

      } catch (err) {
        console.error(
          "GMAIL MESSAGE ERROR:",
          err.message
        );
      }
    }

  } catch (e) {
    console.error(
      "GMAIL ERROR:",
      e
    );

    mail = [{
      error: e.message
    }];
  }

  // Calendar
  try {
    const now =
      new Date();

    const end =
      new Date(
        now.getTime() +
        14 * 86400000
      );

    const r =
      await calendar.events.list({
        calendarId: "primary",
        timeMin:
          now.toISOString(),
        timeMax:
          end.toISOString(),
        singleEvents: true,
        orderBy: "startTime",
        maxResults: 30
      });

    events =
      (r.data.items || []).map(
        x => ({
          id:
            x.id || "",
          summary:
            x.summary ||
            "(제목 없음)",
          description:
            (
              x.description || ""
            ).slice(0, 2000),
          location:
            x.location || "",
          start:
            x.start?.dateTime ||
            x.start?.date ||
            "",
          end:
            x.end?.dateTime ||
            x.end?.date ||
            "",
          status:
            x.status || "",
          htmlLink:
            x.htmlLink || ""
        })
      );

  } catch (e) {
    console.error(
      "CALENDAR ERROR:",
      e
    );

    events = [{
      error: e.message
    }];
  }

  // Drive
  try {
    const r =
      await drive.files.list({
        pageSize: 25,
        orderBy:
          "modifiedTime desc",
        fields:
          "files(id,name,mimeType,modifiedTime,createdTime,size,webViewLink,description)"
      });

    files =
      (r.data.files || []).map(
        f => ({
          id: f.id,
          name:
            f.name ||
            "(이름 없음)",
          mimeType:
            f.mimeType || "",
          modifiedTime:
            f.modifiedTime || "",
          createdTime:
            f.createdTime || "",
          size:
            f.size || "",
          description:
            (
              f.description || ""
            ).slice(0, 1000),
          webViewLink:
            f.webViewLink || ""
        })
      );

  } catch (e) {
    console.error(
      "DRIVE ERROR:",
      e
    );

    files = [{
      error: e.message
    }];
  }

  return {
    connected: true,
    gmail: mail,
    calendar: events,
    drive: files
  };
}

app.get(
  "/api/workspace",
  async (req, res) => {
    try {
      res.json(
        await getWorkspace()
      );

    } catch (e) {
      res.status(500).json({
        error: e.message
      });
    }
  }
);

// ======================================
// AI CONTEXT
// ======================================

function localContext(
  db,
  workspace
) {
  const open =
    (db.tasks || [])
      .filter(x => !x.done);

  const today =
    new Date()
      .toISOString()
      .slice(0, 10);

  return {
    profile:
      db.profile || {},
    settings:
      db.settings || {},
    openTasks:
      open.slice(0, 30),
    todayLocalEvents:
      (db.events || [])
        .filter(
          x => x.date === today
        ),
    notes:
      (db.notes || [])
        .slice(0, 20),
    fileMemories:
      db.fileMemories || {},
    googleWorkspace:
      workspace
  };
}

async function openaiText(
  message,
  context
) {
  const r = await fetch(
    "https://api.openai.com/v1/responses",
    {
      method: "POST",

      headers: {
        "Content-Type":
          "application/json",
        Authorization:
          `Bearer ${process.env.OPENAI_API_KEY}`
      },

      body: JSON.stringify({
        model:
          process.env.OPENAI_MODEL ||
          "gpt-5.6",

        instructions:
          "You are SJ DONA, my private executive AI manager and personal secretary. Reply in Korean unless I ask otherwise. Act as a proactive executive assistant, not just a chatbot. Use the provided Context, including Google Calendar, Gmail, Google Drive, registered tasks, schedules, notes, file memories, and business information, before answering. When I ask what I should do today or what is important, check available information and prioritize: 1) urgent deadlines and today's schedule, 2) important Gmail requiring action, 3) unfinished high-priority tasks, 4) SJ GLOBAL and DE'CAFREE business operations, 5) export and logistics, 6) Korean government support and voucher work, 7) staff and finance matters, and 8) personal schedule. Clearly tell me what I should do first and what should follow. Never claim that you checked information that is not present in the Context. If information is missing, say exactly what is missing. Be concise, practical, accurate, and action-oriented. Do not invent facts.",

        input:
          `Context:\n${JSON.stringify(context)}\n\nUser request:\n${message}`
      })
    }
  );

  const j =
    await r.json();

  if (!r.ok) {
    throw new Error(
      j.error?.message ||
      "OpenAI request failed"
    );
  }

  return (
    (j.output || [])
      .flatMap(
        o => o.content || []
      )
      .filter(
        c =>
          c.type ===
          "output_text"
      )
      .map(c => c.text)
      .join("\n")
    ||
    j.output_text
    ||
    ""
  );
}

// ======================================
// AI CHAT
// ======================================

app.post(
  "/api/ai",
  async (req, res) => {
    try {
      if (
        !process.env.OPENAI_API_KEY
      ) {
        return res
          .status(400)
          .json({
            error:
              "OPENAI_API_KEY is not configured"
          });
      }

      const input =
        String(
          req.body?.message || ""
        ).trim();

      if (!input) {
        return res
          .status(400)
          .json({
            error:
              "message is required"
          });
      }

      const db =
        await loadDBFromPostgres();

      const workspace =
        await getWorkspace();

      const text =
        await openaiText(
          input,
          localContext(
            db,
            workspace
          )
        );

      res.json({
        text
      });

    } catch (e) {
      console.error(
        "AI ERROR:",
        e
      );

      res.status(500).json({
        error: e.message
      });
    }
  }
);

// ======================================
// DAILY BRIEF
// ======================================

app.get(
  "/api/brief",
  async (req, res) => {
    try {
      const db =
        await loadDBFromPostgres();

      const ws =
        await getWorkspace();

      const open =
        (db.tasks || [])
          .filter(
            x => !x.done
          );

      if (
        !process.env.OPENAI_API_KEY
      ) {
        return res.json({
          text:
            `오늘 미완료 업무 ${open.length}개입니다.`
        });
      }

      const text =
        await openaiText(
          "오늘 브리핑: 가장 중요한 일 3개, 가까운 일정, 확인할 이메일, 필요한 문서와 후속조치 순서로 정리해줘.",
          localContext(
            db,
            ws
          )
        );

      res.json({
        text
      });

    } catch (e) {
      console.error(
        "BRIEF ERROR:",
        e
      );

      res.status(500).json({
        error: e.message
      });
    }
  }
);

// ======================================
// FILE HELPERS
// ======================================

function fixFilename(name) {
  try {
    const fixed =
      Buffer
        .from(
          name,
          "latin1"
        )
        .toString("utf8");

    return fixed.includes(
      "\uFFFD"
    )
      ? name
      : fixed;

  } catch {
    return name;
  }
}

async function initFileDatabase() {
  if (!pool) {
    throw new Error(
      "DATABASE_URL is not configured"
    );
  }

  await pool.query(`
    CREATE TABLE IF NOT EXISTS sj_dona_files (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      mime_type TEXT,
      data BYTEA NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);
}

const upload =
  multer({
    storage:
      multer.memoryStorage(),

    limits: {
      fileSize:
        25 * 1024 * 1024
    }
  });

async function getFileFromPostgres(
  id
) {
  await initFileDatabase();

  const result =
    await pool.query(
      `
      SELECT
        id,
        name,
        mime_type,
        data,
        created_at
      FROM sj_dona_files
      WHERE id = $1
      `,
      [id]
    );

  return (
    result.rows[0] ||
    null
  );
}

// ======================================
// FILE LIST
// ======================================

app.get(
  "/api/files",
  async (req, res) => {
    try {
      await initFileDatabase();

      const result =
        await pool.query(`
          SELECT
            id,
            name,
            mime_type,
            octet_length(data)
              AS size,
            created_at
          FROM sj_dona_files
          ORDER BY
            created_at DESC
        `);

      const files =
        result.rows.map(
          x => ({
            id:
              x.id,
            name:
              x.name,
            type:
              x.mime_type ||
              "application/octet-stream",
            size:
              Number(
                x.size || 0
              ),
            modified:
              new Date(
                x.created_at
              ).toISOString()
          })
        );

      res.json({
        files
      });

    } catch (e) {
      console.error(
        "FILE LIST ERROR:",
        e
      );

      res.status(500).json({
        files: [],
        error: e.message
      });
    }
  }
);

// ======================================
// FILE UPLOAD
// ======================================

app.post(
  "/api/files",
  upload.single("file"),
  async (req, res) => {
    try {
      if (!req.file) {
        return res
          .status(400)
          .json({
            error:
              "파일이 없습니다."
          });
      }

      await initFileDatabase();

      const id =
        Date.now() +
        "-" +
        crypto
          .randomBytes(5)
          .toString("hex") +
        path.extname(
          req.file.originalname
        );

      const name =
        fixFilename(
          req.file.originalname
        );

      const type =
        req.file.mimetype ||
        "application/octet-stream";

      const result =
        await pool.query(
          `
          INSERT INTO sj_dona_files
          (
            id,
            name,
            mime_type,
            data
          )

          VALUES
          ($1, $2, $3, $4)

          RETURNING
            id,
            name,
            mime_type,
            octet_length(data)
              AS size,
            created_at
          `,
          [
            id,
            name,
            type,
            req.file.buffer
          ]
        );

      const x =
        result.rows[0];

      res.json({
        id:
          x.id,
        name:
          x.name,
        type:
          x.mime_type,
        size:
          Number(
            x.size || 0
          ),
        modified:
          new Date(
            x.created_at
          ).toISOString()
      });

    } catch (e) {
      console.error(
        "FILE UPLOAD ERROR:",
        e
      );

      res.status(500).json({
        error: e.message
      });
    }
  }
);

// ======================================
// FILE OPEN
// ======================================

app.get(
  "/api/files/:id",
  async (req, res) => {
    try {
      const id =
        path.basename(
          req.params.id
        );

      const file =
        await getFileFromPostgres(
          id
        );

      if (!file) {
        return res
          .status(404)
          .send("Not found");
      }

      res.setHeader(
        "Content-Type",
        file.mime_type ||
        "application/octet-stream"
      );

      res.setHeader(
        "Content-Disposition",
        "inline; filename*=UTF-8''" +
        encodeURIComponent(
          file.name || id
        )
      );

      res.send(
        file.data
      );

    } catch (e) {
      console.error(
        "FILE DOWNLOAD ERROR:",
        e
      );

      res
        .status(500)
        .send(
          "File download failed"
        );
    }
  }
);

// ======================================
// FILE DELETE
// ======================================

app.delete(
  "/api/files/:id",
  async (req, res) => {
    try {
      await initFileDatabase();

      const id =
        path.basename(
          req.params.id
        );

      await pool.query(
        `
        DELETE FROM sj_dona_files
        WHERE id = $1
        `,
        [id]
      );

      const db =
        await loadDBFromPostgres();

      if (
        db.fileMemories?.[id]
      ) {
        delete db.fileMemories[
          id
        ];

        await saveDBToPostgres(
          db
        );
      }

      res.json({
        ok: true
      });

    } catch (e) {
      console.error(
        "FILE DELETE ERROR:",
        e
      );

      res.status(500).json({
        error: e.message
      });
    }
  }
);

// ======================================
// FILE AI ANALYSIS
// ======================================

app.post(
  "/api/files/:id/analyze",
  async (req, res) => {
    try {
      if (
        !process.env.OPENAI_API_KEY
      ) {
        return res
          .status(400)
          .json({
            error:
              "OPENAI_API_KEY is not configured"
          });
      }

      const id =
        path.basename(
          req.params.id
        );

      const stored =
        await getFileFromPostgres(
          id
        );

      if (!stored) {
        return res
          .status(404)
          .json({
            error:
              "파일을 찾을 수 없습니다."
          });
      }

      const meta = {
        id:
          stored.id,
        name:
          stored.name,
        type:
          stored.mime_type ||
          "application/octet-stream",
        size:
          stored.data?.length ||
          0
      };

      const form =
        new FormData();

      form.append(
        "purpose",
        "user_data"
      );

      form.append(
        "file",
        new Blob(
          [stored.data],
          {
            type:
              meta.type
          }
        ),
        meta.name
      );

      const fr =
        await fetch(
          "https://api.openai.com/v1/files",
          {
            method: "POST",

            headers: {
              Authorization:
                `Bearer ${process.env.OPENAI_API_KEY}`
            },

            body: form
          }
        );

      const fj =
        await fr.json();

      if (!fr.ok) {
        throw new Error(
          fj.error?.message ||
          "OpenAI file upload failed"
        );
      }

      const instruction =
        String(
          req.body?.instruction ||
          "이 파일을 분석하고 핵심 내용, 중요한 숫자/날짜, 필요한 후속조치를 한국어로 정리해줘."
        );

      const isImage =
        /^image\/(jpeg|jpg|png|webp|gif)$/i
          .test(
            meta.type || ""
          );

      const fileContent =
        isImage
          ? {
              type:
                "input_image",
              file_id:
                fj.id
            }
          : {
              type:
                "input_file",
              file_id:
                fj.id
            };

      const rr =
        await fetch(
          "https://api.openai.com/v1/responses",
          {
            method: "POST",

            headers: {
              "Content-Type":
                "application/json",

              Authorization:
                `Bearer ${process.env.OPENAI_API_KEY}`
            },

            body:
              JSON.stringify({
                model:
                  process.env.OPENAI_MODEL ||
                  "gpt-5.6",

                instructions:
                  "You are SJ DONA. Analyze the attached user file carefully. Do not invent unreadable details. Reply in Korean unless requested otherwise.",

                input: [
                  {
                    role:
                      "user",

                    content: [
                      fileContent,
                      {
                        type:
                          "input_text",
                        text:
                          instruction
                      }
                    ]
                  }
                ]
              })
          }
        );

      const j =
        await rr.json();

      if (!rr.ok) {
        throw new Error(
          j.error?.message ||
          "File analysis failed"
        );
      }

      const text =
        (j.output || [])
          .flatMap(
            o =>
              o.content ||
              []
          )
          .filter(
            c =>
              c.type ===
              "output_text"
          )
          .map(
            c => c.text
          )
          .join("\n")
        ||
        j.output_text
        ||
        "";

      const db =
        await loadDBFromPostgres();

      if (!db.fileMemories) {
        db.fileMemories = {};
      }

      db.fileMemories[id] = {
        fileId:
          id,
        fileName:
          meta.name,
        fileType:
          meta.type,
        analyzedAt:
          new Date()
            .toISOString(),
        analysis:
          text
      };

      await saveDBToPostgres(
        db
      );

      res.json({
        text,
        memorySaved: true
      });

    } catch (e) {
      console.error(
        "FILE ANALYSIS ERROR:",
        e
      );

      res.status(500).json({
        error: e.message
      });
    }
  }
);

// ======================================
// START SERVER
// ======================================

app.listen(
  PORT,
  "0.0.0.0",
  () =>
    console.log(
      `SJ DONA running at ${BASE}`
    )
);
