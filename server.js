import express from "express";
import dotenv from "dotenv";
import { google } from "googleapis";
import crypto from "crypto";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

dotenv.config();
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const app = express();
const PORT = Number(process.env.PORT || 8787);
const BASE = process.env.APP_BASE_URL || `http://localhost:${PORT}`;
const DB = path.join(__dirname,"data","store.json");
const TOKENS = path.join(__dirname,"data","google.tokens.enc");

app.use(express.json({limit:"2mb"}));
app.use(express.static(path.join(__dirname,"public")));

function loadDB(){
  try { return JSON.parse(fs.readFileSync(DB,"utf8")); }
  catch { return { tasks:[], events:[], notes:[], profile:{}, settings:{briefTime:"08:00"} }; }
}
function saveDB(db){ fs.mkdirSync(path.dirname(DB),{recursive:true}); fs.writeFileSync(DB,JSON.stringify(db,null,2)); }

function key(){
  const raw=(process.env.TOKEN_ENCRYPTION_KEY||"").trim();
  if(!raw) return null;
  return crypto.createHash("sha256").update(raw).digest();
}
function encrypt(obj){
  const k=key(); if(!k) throw new Error("TOKEN_ENCRYPTION_KEY is not set");
  const iv=crypto.randomBytes(12);
  const c=crypto.createCipheriv("aes-256-gcm",k,iv);
  const enc=Buffer.concat([c.update(JSON.stringify(obj),"utf8"),c.final()]);
  const tag=c.getAuthTag();
  return Buffer.concat([iv,tag,enc]).toString("base64");
}
function decrypt(s){
  const k=key(); if(!k) throw new Error("TOKEN_ENCRYPTION_KEY is not set");
  const b=Buffer.from(s,"base64"),iv=b.subarray(0,12),tag=b.subarray(12,28),enc=b.subarray(28);
  const d=crypto.createDecipheriv("aes-256-gcm",k,iv); d.setAuthTag(tag);
  return JSON.parse(Buffer.concat([d.update(enc),d.final()]).toString("utf8"));
}
function getTokens(){ try{return decrypt(fs.readFileSync(TOKENS,"utf8"))}catch{return null} }
function setTokens(t){ fs.writeFileSync(TOKENS,encrypt(t)); }

function oauth(){
  return new google.auth.OAuth2(
    process.env.GOOGLE_CLIENT_ID,
    process.env.GOOGLE_CLIENT_SECRET,
    `${BASE}/auth/google/callback`
  );
}
async function authedGoogle(){
  const t=getTokens(); if(!t) return null;
  const o=oauth(); o.setCredentials(t);
  o.on("tokens",fresh=>{
    const merged={...t,...fresh};
    setTokens(merged);
  });
  return o;
}

app.get("/api/status",(req,res)=>{
  res.json({
    ok:true,
    openai:Boolean(process.env.OPENAI_API_KEY),
    google:Boolean(getTokens()),
    model:process.env.OPENAI_MODEL||"gpt-5.6"
  });
});

app.get("/api/state",(req,res)=>res.json(loadDB()));
app.post("/api/state",(req,res)=>{ saveDB(req.body||{}); res.json({ok:true}); });

app.get("/auth/google",(req,res)=>{
  if(!process.env.GOOGLE_CLIENT_ID || !process.env.GOOGLE_CLIENT_SECRET)
    return res.status(400).send("Google OAuth environment variables are not configured.");
  const o=oauth();
  const url=o.generateAuthUrl({
    access_type:"offline",
    prompt:"consent",
    scope:[
      "https://www.googleapis.com/auth/gmail.readonly",
      "https://www.googleapis.com/auth/calendar.readonly",
      "https://www.googleapis.com/auth/drive.readonly"
    ]
  });
  res.redirect(url);
});
app.get("/auth/google/callback",async(req,res)=>{
  try{
    const o=oauth();
    const {tokens}=await o.getToken(req.query.code);
    setTokens(tokens);
    res.redirect("/?google=connected");
  }catch(e){ res.status(500).send("Google connection failed: "+e.message); }
});
app.post("/api/google/disconnect",(req,res)=>{
  try{ if(fs.existsSync(TOKENS)) fs.unlinkSync(TOKENS); }catch{}
  res.json({ok:true});
});

async function getWorkspace(){
  const auth=await authedGoogle();
  if(!auth) return {connected:false, gmail:[], calendar:[], drive:[]};

  const gmail=google.gmail({version:"v1",auth});
  const calendar=google.calendar({version:"v3",auth});
  const drive=google.drive({version:"v3",auth});

  let mail=[], events=[], files=[];
  try{
    const l=await gmail.users.messages.list({userId:"me",maxResults:8,q:"newer_than:7d"});
    for(const m of (l.data.messages||[]).slice(0,8)){
      const r=await gmail.users.messages.get({userId:"me",id:m.id,format:"metadata",metadataHeaders:["Subject","From","Date"]});
      const h=Object.fromEntries((r.data.payload?.headers||[]).map(x=>[x.name,x.value]));
      mail.push({id:m.id,subject:h.Subject||"(제목 없음)",from:h.From||"",date:h.Date||"",snippet:r.data.snippet||""});
    }
  }catch(e){ mail=[{error:e.message}] }

  try{
    const now=new Date(), end=new Date(now.getTime()+7*86400000);
    const r=await calendar.events.list({calendarId:"primary",timeMin:now.toISOString(),timeMax:end.toISOString(),singleEvents:true,orderBy:"startTime",maxResults:15});
    events=(r.data.items||[]).map(x=>({summary:x.summary||"(제목 없음)",start:x.start?.dateTime||x.start?.date||"",end:x.end?.dateTime||x.end?.date||""}));
  }catch(e){ events=[{error:e.message}] }

  try{
    const r=await drive.files.list({pageSize:12,orderBy:"modifiedTime desc",fields:"files(id,name,mimeType,modifiedTime,webViewLink)"});
    files=r.data.files||[];
  }catch(e){ files=[{error:e.message}] }

  return {connected:true,gmail:mail,calendar:events,drive:files};
}
app.get("/api/workspace",async(req,res)=>{
  try{ res.json(await getWorkspace()); }catch(e){ res.status(500).json({error:e.message}); }
});

function localContext(db, workspace){
  const open=(db.tasks||[]).filter(x=>!x.done);
  const today=new Date().toISOString().slice(0,10);
  const events=(db.events||[]).filter(x=>x.date===today);
  return {
    profile:db.profile||{},
    settings:db.settings||{},
    openTasks:open.slice(0,30),
    todayLocalEvents:events,
    notes:(db.notes||[]).slice(0,20),
    googleWorkspace:workspace
  };
}

app.post("/api/ai",async(req,res)=>{
  try{
    if(!process.env.OPENAI_API_KEY) return res.status(400).json({error:"OPENAI_API_KEY is not configured"});
    const db=loadDB();
    const workspace=await getWorkspace();
    const input=String(req.body?.message||"").trim();
    if(!input) return res.status(400).json({error:"message is required"});

    const system=`You are SJ DONA, a private executive and life manager for one user.
Reply in Korean unless asked otherwise.
You manage personal life and work together: SJ GLOBAL, DE’CAFREE, export/logistics, government support programs, finance, staffing, documents, appointments and follow-ups.
Prioritize concrete next actions. Surface deadlines, conflicts, missing documents, risks, and dependencies proactively.
Do not invent facts. Clearly label anything that still needs confirmation.
When email/calendar/drive context exists, use it carefully and reference subject/title rather than exposing unnecessary personal data.
Keep the response practical and concise, with the most important item first.`;

    const r=await fetch("https://api.openai.com/v1/responses",{
      method:"POST",
      headers:{"Content-Type":"application/json","Authorization":`Bearer ${process.env.OPENAI_API_KEY}`},
      body:JSON.stringify({
        model:process.env.OPENAI_MODEL||"gpt-5.6",
        instructions:system,
        input:[
          {role:"user",content:[{type:"input_text",text:`현재 매니저 컨텍스트:\n${JSON.stringify(localContext(db,workspace))}\n\n사용자 요청:\n${input}`}]}
        ]
      })
    });
    const j=await r.json();
    if(!r.ok) return res.status(r.status).json({error:j.error?.message||"OpenAI request failed"});
    const text=(j.output||[]).flatMap(o=>o.content||[]).filter(c=>c.type==="output_text").map(c=>c.text).join("\n") || j.output_text || "";
    res.json({text});
  }catch(e){ res.status(500).json({error:e.message}); }
});

app.get("/api/brief",async(req,res)=>{
  try{
    const db=loadDB(), ws=await getWorkspace();
    const open=(db.tasks||[]).filter(x=>!x.done);
    const important=open.filter(x=>x.priority==="중요");
    const today=new Date().toISOString().slice(0,10);
    const localEvents=(db.events||[]).filter(x=>x.date===today);
    if(!process.env.OPENAI_API_KEY){
      return res.json({text:`오늘 미완료 업무 ${open.length}개, 중요 업무 ${important.length}개, 앱 일정 ${localEvents.length}개입니다.`});
    }
    const q="오늘 아침 브리핑을 만들어줘. 1) 가장 중요한 일 3개 2) 오늘/가까운 일정 3) 확인할 이메일 4) 필요한 문서/후속조치 5) 개인 일정 충돌 순서로.";
    const fakeReq={body:{message:q}}, chunks=[];
    // Directly repeat logic via internal HTTP is unnecessary; perform API call:
    const system="You are SJ DONA. Produce a concise Korean executive morning briefing. Do not invent facts.";
    const r=await fetch("https://api.openai.com/v1/responses",{
      method:"POST",
      headers:{"Content-Type":"application/json","Authorization":`Bearer ${process.env.OPENAI_API_KEY}`},
      body:JSON.stringify({model:process.env.OPENAI_MODEL||"gpt-5.6",instructions:system,input:`Context:\n${JSON.stringify(localContext(db,ws))}\n\nTask:\n${q}`})
    });
    const j=await r.json();
    if(!r.ok) return res.status(r.status).json({error:j.error?.message||"Brief failed"});
    const text=(j.output||[]).flatMap(o=>o.content||[]).filter(c=>c.type==="output_text").map(c=>c.text).join("\n") || j.output_text || "";
    res.json({text});
  }catch(e){res.status(500).json({error:e.message})}
});

app.listen(PORT, "0.0.0.0", () => console.log(`SJ DONA running at ${BASE}`));
