'use strict';
const express=require('express'),bcrypt=require('bcryptjs'),jwt=require('jsonwebtoken'),cookieParser=require('cookie-parser'),helmet=require('helmet'),{rateLimit}=require('express-rate-limit'),crypto=require('crypto'),path=require('path'),fs=require('fs');

if(!process.env.JWT_SECRET||process.env.JWT_SECRET.length<32){console.error('Set JWT_SECRET (at least 32 characters).');process.exit(1)}

const DATA_FILE=process.env.DATA_FILE||path.join(__dirname,'data.json');
fs.mkdirSync(path.dirname(DATA_FILE),{recursive:true});
const app=express();
app.disable('x-powered-by');
app.set('trust proxy',1);
app.use(helmet({contentSecurityPolicy:false}));
app.use(express.json({limit:'12kb'}));
app.use(cookieParser());

// ---- JSON store -------------------------------------------------------------
let db={users:[],platform_settings:{},audit_log:[],nextUserId:1,nextAuditId:1};
let writing=Promise.resolve();

function loadDb(){
  if(fs.existsSync(DATA_FILE)){
    try{db=JSON.parse(fs.readFileSync(DATA_FILE,'utf8'))}catch(e){throw new Error('data.json is corrupt: '+e.message)}
  }
  db.users||=[];db.platform_settings||={};db.audit_log||=[];
  db.nextUserId||=db.users.reduce((m,u)=>Math.max(m,u.id),0)+1;
  db.nextAuditId||=db.audit_log.reduce((m,a)=>Math.max(m,a.id),0)+1;
}

function saveDb(){
  writing=writing.catch(e=>{console.error('Previous write failed',e)}).then(()=>new Promise((res,rej)=>{
    const tmp=DATA_FILE+'.tmp';
    fs.writeFile(tmp,JSON.stringify(db,null,2),(err)=>{
      if(err)return rej(err);
      fs.rename(tmp,DATA_FILE,(err2)=>err2?rej(err2):res());
    });
  }));
  return writing;
}
// ----------------------------------------------------------------------------

// ---- CORS: accept every origin ---------------------------------------------
app.use((req,res,next)=>{
  const origin=req.get('Origin');
  const allowed=(process.env.FRONTEND_ORIGINS||'').split(',').map(s=>s.trim()).filter(Boolean);
  if(origin && (allowed.includes(origin) || (process.env.NODE_ENV!=='production' && /^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(origin)))){
    res.setHeader('Access-Control-Allow-Origin',origin);
    res.setHeader('Access-Control-Allow-Credentials','true');
    res.setHeader('Vary','Origin');
    res.setHeader('Access-Control-Allow-Headers','Content-Type, Authorization');
    res.setHeader('Access-Control-Allow-Methods','GET,POST,PUT,OPTIONS');
    res.setHeader('Access-Control-Max-Age','86400');
  }
  if(req.method==='OPTIONS')return res.sendStatus(204);
  next();
});
// ----------------------------------------------------------------------------

const limiter=rateLimit({windowMs:15*60*1000,limit:12,standardHeaders:'draft-7',legacyHeaders:false});
const cookieName='elite_session';
const auth=(req,res,next)=>{try{const bearer=/^Bearer (.+)$/i.exec(req.get('Authorization')||'');const token=bearer?.[1]||req.cookies?.[cookieName];const claims=jwt.verify(token,process.env.JWT_SECRET,{algorithms:['HS256']});const current=db.users.find(u=>String(u.id)===String(claims.id));if(!current)return res.status(401).json({error:'Session expired.'});req.user={id:current.id,role:current.role};next()}catch{return res.status(401).json({error:'Please sign in.'})}};
const admin=(req,res,next)=>req.user.role==='admin'?next():res.status(403).json({error:'Admin access required.'});

function addressOk(addr){if(typeof addr!=='string'||addr.length>100)return false;try{if(/^[13][1-9A-HJ-NP-Za-km-z]{25,34}$/.test(addr)){let v=0n;for(let c of addr){let n='123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'.indexOf(c);if(n<0)return false;v=v*58n+BigInt(n)}let hex=v.toString(16);if(hex.length%2)hex='0'+hex;let bytes=Buffer.from(hex,'hex');let leading=(addr.match(/^1*/)||[''])[0].length;bytes=Buffer.concat([Buffer.alloc(leading),bytes]);if(bytes.length!==25||![0,5].includes(bytes[0]))return false;let raw=bytes.subarray(0,-4),checksum=crypto.createHash('sha256').update(crypto.createHash('sha256').update(raw).digest()).digest();return checksum.subarray(0,4).equals(bytes.subarray(-4))}const s=addr.toLowerCase();if(s!==addr&&addr.toUpperCase()!==addr)return false;if(!s.startsWith('bc1'))return false;const alphabet='qpzry9x8gf2tvdw0s3jn54khce6mua7l',parts=[...s.slice(3)].map(x=>alphabet.indexOf(x));if(parts.some(x=>x<0)||parts.length<8)return false;let pm=1;for(const a of [...[3,3,0,2,3],0,...parts]){let top=pm>>>25;pm=((pm&0x1ffffff)<<5)^a;for(let j=0;j<5;j++)if((top>>>j)&1)pm^=[0x3b6a57b2,0x26508e6d,0x1ea119fa,0x3d4233dd,0x2a1462b3][j]}let version=parts[0];return version<=16&&(version===0?pm===1:pm===0x2bc830a3)}catch{return false}}

async function init(){
  loadDb();
  const email=(process.env.ADMIN_EMAIL||'').toLowerCase().trim(),password=process.env.ADMIN_PASSWORD;
  if(email&&password){
    if(password.length<12)throw Error('ADMIN_PASSWORD must be at least 12 characters.');
    const existing=db.users.find(u=>u.email===email);
    if(!existing){
      db.users.push({id:db.nextUserId++,full_name:'Platform Administrator',email,password_hash:await bcrypt.hash(password,12),role:'admin',balance_cents:0,created_at:new Date().toISOString()});
      await saveDb();
    }else if(existing.role!=='admin')throw Error('ADMIN_EMAIL is already registered as a standard user; resolve this in data.json.');
  }
  if(!fs.existsSync(DATA_FILE))await saveDb();
}

function session(res,u){
  res.cookie(cookieName,jwt.sign({id:String(u.id),role:u.role},process.env.JWT_SECRET,{expiresIn:'12h',algorithm:'HS256'}),{httpOnly:true,sameSite:process.env.COOKIE_SAMESITE==='none'?'none':'lax',secure:process.env.COOKIE_SAMESITE==='none'||process.env.NODE_ENV==='production',maxAge:12*3600e3,path:'/'});
  res.json({token:jwt.sign({id:String(u.id),role:u.role},process.env.JWT_SECRET,{expiresIn:'12h',algorithm:'HS256'}),user:{id:u.id,fullName:u.full_name,email:u.email,role:u.role,balanceUSD:u.balance_cents/100}});
}

app.get('/api/health',(_req,res)=>res.json({status:'ok'}));

app.post('/api/auth/signup',limiter,async(req,res,next)=>{try{
  let {fullName,email,password}=req.body;
  fullName=String(fullName||'').trim();email=String(email||'').toLowerCase().trim();
  if(fullName.length<2||fullName.length>100||!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)||email.length>254||typeof password!=='string'||password.length<10||password.length>128||!/[A-Z]/.test(password)||!/[a-z]/.test(password)||!/[0-9]/.test(password))return res.status(400).json({error:'Enter valid registration details and a stronger password.'});
  if(db.users.some(u=>u.email===email))return res.status(409).json({error:'This email is already registered.'});
  const u={id:db.nextUserId++,full_name:fullName,email,password_hash:await bcrypt.hash(password,12),role:'user',balance_cents:0,created_at:new Date().toISOString()};
  db.users.push(u);await saveDb();session(res,u);
}catch(e){next(e)}});

app.post('/api/auth/login',limiter,async(req,res,next)=>{try{
  const email=String(req.body.email||'').trim().toLowerCase(),password=String(req.body.password||'');
  const u=db.users.find(x=>x.email===email);
  if(!u||!await bcrypt.compare(password,u.password_hash))return res.status(401).json({error:'Invalid email or password.'});
  session(res,u);
}catch(e){next(e)}});

app.post('/api/auth/logout',(_req,res)=>{res.clearCookie(cookieName,{path:'/'});res.json({ok:true})});

app.get('/api/me',auth,(req,res)=>{
  const u=db.users.find(x=>String(x.id)===String(req.user.id));
  if(!u)return res.status(401).json({error:'Session expired.'});
  res.json({id:u.id,fullName:u.full_name,email:u.email,role:u.role,balanceUSD:u.balance_cents/100,createdAt:u.created_at});
});

app.get('/api/funding/config',auth,(_req,res)=>{
  res.json({btcAddress:db.platform_settings.btc_address||null,minimumUSD:20,feePercent:1});
});

app.get('/api/admin/users',auth,admin,(_req,res)=>{
  res.json({users:[...db.users].sort((a,b)=>b.created_at.localeCompare(a.created_at)).slice(0,500).map(x=>({id:x.id,fullName:x.full_name,email:x.email,role:x.role,balanceUSD:x.balance_cents/100,createdAt:x.created_at}))});
});

app.get('/api/admin/settings',auth,admin,(_req,res)=>{
  res.json({btcAddress:db.platform_settings.btc_address||''});
});

app.put('/api/admin/btc-address',auth,admin,async(req,res,next)=>{try{
  const address=String(req.body.address||'').trim();
  if(!addressOk(address))return res.status(400).json({error:'Enter a valid Bitcoin mainnet address, and confirm that your company controls it.'});
  db.platform_settings.btc_address=address;
  db.audit_log.push({id:db.nextAuditId++,actor_id:req.user.id,action:'btc_address_updated',details:{suffix:address.slice(-6)},created_at:new Date().toISOString()});
  await saveDb();
  res.json({ok:true,btcAddress:address});
}catch(e){next(e)}});

app.get('/api/market',async(_req,res)=>{try{
  const [a,b]=await Promise.allSettled([
    fetch('https://api.kraken.com/0/public/Ticker?pair=XBTUSD',{signal:AbortSignal.timeout(6500)}).then(r=>r.json()),
    fetch('https://api.coinbase.com/v2/prices/BTC-USD/spot',{signal:AbortSignal.timeout(6500)}).then(r=>r.json())
  ]);
  let v=null,source='';
  if(a.status==='fulfilled'&&a.value.result){v=Number(Object.values(a.value.result)[0]?.c?.[0]);source='Kraken'}
  if(!(v>0)&&b.status==='fulfilled'){v=Number(b.value.data?.amount);source='Coinbase'}
  if(!(v>0))return res.status(503).json({error:'Live market feed unavailable.'});
  res.set('Cache-Control','no-store');res.json({btcUSD:v,source,asOf:new Date().toISOString()});
}catch{res.status(503).json({error:'Live market feed unavailable.'})}});

app.use('/api',(_req,res)=>res.status(404).json({error:'API route not found.'}));

app.use((err,req,res,next)=>{console.error(err);res.status(500).json({error:'Request could not be completed.'})});

init().then(()=>app.listen(process.env.PORT||3000,'0.0.0.0',()=>console.log('Elite Trading server ready'))).catch(e=>{console.error('Initialization failed:',e);process.exit(1)});
