import express from "express";
import dotenv from "dotenv";
import { google } from "googleapis";
import crypto from "crypto";
import fs from "fs";
import path from "path";
import multer from "multer";
import { fileURLToPath } from "url";

dotenv.config();
const __filename=fileURLToPath(import.meta.url), __dirname=path.dirname(__filename);
const app=express(), PORT=Number(process.env.PORT||8787), BASE=process.env.APP_BASE_URL||`http://localhost:${PORT}`;
const DATA=path.join(__dirname,"data"), DB=path.join(DATA,"store.json"), TOKENS=path.join(DATA,"google.tokens.enc"), UPLOADS=path.join(DATA,"uploads");
fs.mkdirSync(UPLOADS,{recursive:true});
app.use(express.json({limit:"4mb"}));
app.use(express.static(path.join(__dirname,"public")));

function loadDB(){try{return JSON.parse(fs.readFileSync(DB,"utf8"))}catch{return{tasks:[],events:[],notes:[],profile:{},settings:{briefTime:"08:00"}}}}
function saveDB(db){fs.mkdirSync(DATA,{recursive:true});fs.writeFileSync(DB,JSON.stringify(db,null,2))}
function key(){const raw=(process.env.TOKEN_ENCRYPTION_KEY||"").trim();return raw?crypto.createHash("sha256").update(raw).digest():null}
function encrypt(obj){const k=key();if(!k)throw new Error("TOKEN_ENCRYPTION_KEY is not set");const iv=crypto.randomBytes(12),c=crypto.createCipheriv("aes-256-gcm",k,iv),enc=Buffer.concat([c.update(JSON.stringify(obj),"utf8"),c.final()]),tag=c.getAuthTag();return Buffer.concat([iv,tag,enc]).toString("base64")}
function decrypt(s){const k=key();if(!k)throw new Error("TOKEN_ENCRYPTION_KEY is not set");const b=Buffer.from(s,"base64"),iv=b.subarray(0,12),tag=b.subarray(12,28),enc=b.subarray(28),d=crypto.createDecipheriv("aes-256-gcm",k,iv);d.setAuthTag(tag);return JSON.parse(Buffer.concat([d.update(enc),d.final()]).toString("utf8"))}
function getTokens(){try{return decrypt(fs.readFileSync(TOKENS,"utf8"))}catch{return null}}
function setTokens(t){fs.mkdirSync(DATA,{recursive:true});fs.writeFileSync(TOKENS,encrypt(t))}
function oauth(){return new google.auth.OAuth2(process.env.GOOGLE_CLIENT_ID,process.env.GOOGLE_CLIENT_SECRET,`${BASE}/auth/google/callback`)}
async function authedGoogle(){const t=getTokens();if(!t)return null;const o=oauth();o.setCredentials(t);o.on("tokens",fresh=>setTokens({...t,...fresh}));return o}

app.get("/api/status",(req,res)=>res.json({ok:true,openai:Boolean(process.env.OPENAI_API_KEY),google:Boolean(getTokens()),model:process.env.OPENAI_MODEL||"gpt-5.6"}));
app.get("/api/state",(req,res)=>res.json(loadDB()));
app.post("/api/state",(req,res)=>{saveDB(req.body||{});res.json({ok:true})});

app.get("/auth/google",(req,res)=>{if(!process.env.GOOGLE_CLIENT_ID||!process.env.GOOGLE_CLIENT_SECRET)return res.status(400).send("Google OAuth environment variables are not configured.");const o=oauth();res.redirect(o.generateAuthUrl({access_type:"offline",prompt:"consent",scope:["https://www.googleapis.com/auth/gmail.readonly","https://www.googleapis.com/auth/calendar.readonly","https://www.googleapis.com/auth/drive.readonly"]}))});
app.get("/auth/google/callback",async(req,res)=>{try{const o=oauth(),{tokens}=await o.getToken(req.query.code);setTokens(tokens);res.redirect("/?google=connected")}catch(e){res.status(500).send("Google connection failed: "+e.message)}});
app.post("/api/google/disconnect",(req,res)=>{try{if(fs.existsSync(TOKENS))fs.unlinkSync(TOKENS)}catch{}res.json({ok:true})});

async function getWorkspace(){const auth=await authedGoogle();if(!auth)return{connected:false,gmail:[],calendar:[],drive:[]};const gmail=google.gmail({version:"v1",auth}),calendar=google.calendar({version:"v3",auth}),drive=google.drive({version:"v3",auth});let mail=[],events=[],files=[];try{const l=await gmail.users.messages.list({userId:"me",maxResults:8,q:"newer_than:7d"});for(const m of(l.data.messages||[]).slice(0,8)){const r=await gmail.users.messages.get({userId:"me",id:m.id,format:"metadata",metadataHeaders:["Subject","From","Date"]}),h=Object.fromEntries((r.data.payload?.headers||[]).map(x=>[x.name,x.value]));mail.push({id:m.id,subject:h.Subject||"(제목 없음)",from:h.From||"",date:h.Date||"",snippet:r.data.snippet||""})}}catch(e){mail=[{error:e.message}]};try{const now=new Date(),end=new Date(now.getTime()+7*86400000),r=await calendar.events.list({calendarId:"primary",timeMin:now.toISOString(),timeMax:end.toISOString(),singleEvents:true,orderBy:"startTime",maxResults:15});events=(r.data.items||[]).map(x=>({summary:x.summary||"(제목 없음)",start:x.start?.dateTime||x.start?.date||"",end:x.end?.dateTime||x.end?.date||""}))}catch(e){events=[{error:e.message}]};try{const r=await drive.files.list({pageSize:12,orderBy:"modifiedTime desc",fields:"files(id,name,mimeType,modifiedTime,webViewLink)"});files=r.data.files||[]}catch(e){files=[{error:e.message}]};return{connected:true,gmail:mail,calendar:events,drive:files}}
app.get("/api/workspace",async(req,res)=>{try{res.json(await getWorkspace())}catch(e){res.status(500).json({error:e.message})}});
function localContext(db,workspace){const open=(db.tasks||[]).filter(x=>!x.done),today=new Date().toISOString().slice(0,10);return{profile:db.profile||{},settings:db.settings||{},openTasks:open.slice(0,30),todayLocalEvents:(db.events||[]).filter(x=>x.date===today),notes:(db.notes||[]).slice(0,20),googleWorkspace:workspace}}
async function openaiText(message,context){const r=await fetch("https://api.openai.com/v1/responses",{method:"POST",headers:{"Content-Type":"application/json","Authorization":`Bearer ${process.env.OPENAI_API_KEY}`},body:JSON.stringify({model:process.env.OPENAI_MODEL||"gpt-5.6",instructions:"You are SJ DONA, a private executive and life manager. Reply in Korean unless asked otherwise. Be concise, practical, and do not invent facts.",input:`Context:\n${JSON.stringify(context)}\n\nUser request:\n${message}`})});const j=await r.json();if(!r.ok)throw new Error(j.error?.message||"OpenAI request failed");return (j.output||[]).flatMap(o=>o.content||[]).filter(c=>c.type==="output_text").map(c=>c.text).join("\n")||j.output_text||""}
app.post("/api/ai",async(req,res)=>{try{if(!process.env.OPENAI_API_KEY)return res.status(400).json({error:"OPENAI_API_KEY is not configured"});const input=String(req.body?.message||"").trim();if(!input)return res.status(400).json({error:"message is required"});res.json({text:await openaiText(input,localContext(loadDB(),await getWorkspace()))})}catch(e){res.status(500).json({error:e.message})}});
app.get("/api/brief",async(req,res)=>{try{const db=loadDB(),ws=await getWorkspace(),open=(db.tasks||[]).filter(x=>!x.done);if(!process.env.OPENAI_API_KEY)return res.json({text:`오늘 미완료 업무 ${open.length}개입니다.`});res.json({text:await openaiText("오늘 브리핑: 가장 중요한 일 3개, 가까운 일정, 확인할 이메일, 필요한 문서와 후속조치 순서로 정리해줘.",localContext(db,ws))})}catch(e){res.status(500).json({error:e.message})}});

const storage=multer.diskStorage({destination:(req,file,cb)=>cb(null,UPLOADS),filename:(req,file,cb)=>cb(null,`${Date.now()}-${crypto.randomBytes(5).toString("hex")}${path.extname(file.originalname)}`)});
const upload=multer({storage,limits:{fileSize:25*1024*1024}});
function fileList(){return fs.readdirSync(UPLOADS).filter(n=>!n.endsWith(".meta.json")).map(n=>{const p=path.join(UPLOADS,n),s=fs.statSync(p);const m=metaFor(n);return{id:n,name:m.name||n,type:m.type||"",size:s.size,modified:s.mtime.toISOString()}}).sort((a,b)=>b.modified.localeCompare(a.modified))}
app.get("/api/files",(req,res)=>res.json({files:fileList()}));
app.post("/api/files",upload.single("file"),(req,res)=>{if(!req.file)return res.status(400).json({error:"파일이 없습니다."});const meta={id:req.file.filename,name:req.file.originalname,type:req.file.mimetype,size:req.file.size,modified:new Date().toISOString()};fs.writeFileSync(path.join(UPLOADS,req.file.filename+".meta.json"),JSON.stringify(meta));res.json(meta)});
function metaFor(id){try{return JSON.parse(fs.readFileSync(path.join(UPLOADS,id+".meta.json"),"utf8"))}catch{return{id,name:id,type:"application/octet-stream"}}}
app.get("/api/files/:id",(req,res)=>{const p=path.join(UPLOADS,path.basename(req.params.id));if(!fs.existsSync(p))return res.status(404).send("Not found");res.download(p,metaFor(req.params.id).name)});
app.delete("/api/files/:id",(req,res)=>{const id=path.basename(req.params.id);for(const p of[path.join(UPLOADS,id),path.join(UPLOADS,id+".meta.json")])try{if(fs.existsSync(p))fs.unlinkSync(p)}catch{}res.json({ok:true})});
app.post("/api/files/:id/analyze",async(req,res)=>{try{if(!process.env.OPENAI_API_KEY)return res.status(400).json({error:"OPENAI_API_KEY is not configured"});const id=path.basename(req.params.id),p=path.join(UPLOADS,id);if(!fs.existsSync(p))return res.status(404).json({error:"파일을 찾을 수 없습니다."});const meta=metaFor(id),form=new FormData();form.append("purpose","user_data");form.append("file",new Blob([fs.readFileSync(p)],{type:meta.type}),meta.name);const fr=await fetch("https://api.openai.com/v1/files",{method:"POST",headers:{Authorization:`Bearer ${process.env.OPENAI_API_KEY}`},body:form}),fj=await fr.json();if(!fr.ok)throw new Error(fj.error?.message||"OpenAI file upload failed");const instruction=String(req.body?.instruction||"이 파일을 분석하고 핵심 내용, 중요한 숫자/날짜, 필요한 후속조치를 한국어로 정리해줘.");const rr=await fetch("https://api.openai.com/v1/responses",{method:"POST",headers:{"Content-Type":"application/json",Authorization:`Bearer ${process.env.OPENAI_API_KEY}`},body:JSON.stringify({model:process.env.OPENAI_MODEL||"gpt-5.6",instructions:"You are SJ DONA. Analyze the attached user file carefully. Do not invent unreadable details. Reply in Korean unless requested otherwise.",input:[{role:"user",content:[{type:"input_file",file_id:fj.id},{type:"input_text",text:instruction}]}]})}),j=await rr.json();if(!rr.ok)throw new Error(j.error?.message||"File analysis failed");const text=(j.output||[]).flatMap(o=>o.content||[]).filter(c=>c.type==="output_text").map(c=>c.text).join("\n")||j.output_text||"";res.json({text})}catch(e){res.status(500).json({error:e.message})}});

app.listen(PORT,"0.0.0.0",()=>console.log(`SJ DONA running at ${BASE}`));
