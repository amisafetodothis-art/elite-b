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
let db={users:[],platform_settings:{},audit_log:[],funding_requests:[],nextFundingId:1,nextUserId:1,nextAuditId:1};
let writing=Promise.resolve();

function loadDb(){
  if(fs.existsSync(DATA_FILE)){
    try{db=JSON.parse(fs.readFileSync(DATA_FILE,'utf8'))}catch(e){throw new Error('data.json is corrupt: '+e.message)}
  }
  db.users||=[];db.platform_settings||={};db.audit_log||=[];db.funding_requests||=[];
  db.nextFundingId||=db.funding_requests.reduce((m,x)=>Math.max(m,Number(x.id)||0),0)+1;
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

// Public cross-origin API: Bearer tokens are used for authentication.
app.use((req,res,next)=>{
  res.setHeader('Access-Control-Allow-Origin','*');
  res.setHeader('Access-Control-Allow-Methods','GET, POST, PUT, PATCH, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers','Content-Type, Authorization');
  res.setHeader('Access-Control-Max-Age','86400');
  if(req.method==='OPTIONS')return res.sendStatus(204);
  next();
});

const limiter=rateLimit({windowMs:15*60*1000,limit:12,standardHeaders:'draft-7',legacyHeaders:false});
const cookieName='elite_session';
const TOKEN_TTL='60d';
const COOKIE_TTL_MS=60*24*3600e3;

const auth=(req,res,next)=>{
  try{
    const bearer=/^Bearer (.+)$/i.exec(req.get('Authorization')||'');
    const token=bearer?.[1]||req.cookies?.[cookieName];
    const claims=jwt.verify(token,process.env.JWT_SECRET,{algorithms:['HS256']});
    const current=db.users.find(u=>String(u.id)===String(claims.id));
    if(!current||Number(claims.v||0)!==Number(current.session_version||0))return res.status(401).json({error:'Session expired.'});
    req.user={id:current.id,role:current.role};next();
  }catch{return res.status(401).json({error:'Please sign in.'})}
};
const admin=(req,res,next)=>req.user.role==='admin'?next():res.status(403).json({error:'Admin access required.'});

// Admin may enter ANY BTC address format. We only require a sane, non-empty string.
function addressOk(addr){
  return typeof addr==='string' && addr.trim().length>=1 && addr.trim().length<=200 && !/[\s<>"]/.test(addr.trim());
}

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
  const token=jwt.sign({id:String(u.id),role:u.role,v:u.session_version||0},process.env.JWT_SECRET,{expiresIn:TOKEN_TTL,algorithm:'HS256'});
  res.cookie(cookieName,token,{httpOnly:true,sameSite:process.env.COOKIE_SAMESITE==='none'?'none':'lax',secure:process.env.COOKIE_SAMESITE==='none'||process.env.NODE_ENV==='production',maxAge:COOKIE_TTL_MS,path:'/'});
  res.json({token,user:{id:u.id,fullName:u.full_name,email:u.email,role:u.role,balanceUSD:u.balance_cents/100}});
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
  if(!u||u.disabled||!await bcrypt.compare(password,u.password_hash))return res.status(401).json({error:'Invalid email or password.'});
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

app.get('/api/funding/requests',auth,(req,res)=>res.json({requests:db.funding_requests.filter(x=>String(x.user_id)===String(req.user.id)).slice(-100).reverse()}));
app.post('/api/funding/requests',auth,async(req,res,next)=>{try{
  const usd=Number(req.body.amountUSD),btc=Number(req.body.estimatedBTC);
  if(!Number.isFinite(usd)||usd<20||usd>1000000||!Number.isFinite(btc)||btc<=0||btc>100)return res.status(400).json({error:'Enter a funding amount of at least $20 with a valid BTC estimate.'});
  if(!db.platform_settings.btc_address)return res.status(503).json({error:'Payment instructions are being prepared. Please try again shortly.'});
  const now=new Date().toISOString();
  const entry={id:db.nextFundingId++,user_id:req.user.id,amount_usd_cents:Math.round(usd*100),estimated_btc:btc,status:'processing',address:db.platform_settings.btc_address,created_at:now};
  db.funding_requests.push(entry);await saveDb();res.status(201).json({request:entry});
}catch(e){next(e)}});
app.get('/api/admin/funding',auth,admin,(_req,res)=>res.json({requests:db.funding_requests.slice(-300).reverse().map(x=>({...x,userEmail:db.users.find(u=>String(u.id)===String(x.user_id))?.email||''}))}));
app.post('/api/admin/funding/:id/decision',auth,admin,async(req,res,next)=>{try{
  const id=Number(req.params.id);const status=String(req.body.status||'');
  if(!['credited','rejected'].includes(status))return res.status(400).json({error:'Invalid decision.'});
  const entry=db.funding_requests.find(x=>x.id===id);if(!entry)return res.status(404).json({error:'Funding request not found.'});
  if(entry.status!=='processing')return res.status(409).json({error:'Request has already been reviewed.'});
  const user=db.users.find(u=>String(u.id)===String(entry.user_id));if(!user)return res.status(404).json({error:'Account not found.'});
  if(status==='credited')user.balance_cents+=entry.amount_usd_cents;
  entry.status=status;entry.reviewed_at=new Date().toISOString();entry.reviewed_by=req.user.id;
  db.audit_log.push({id:db.nextAuditId++,actor_id:req.user.id,action:'funding_'+status,details:{request_id:id,user_id:entry.user_id,amount_cents:entry.amount_usd_cents},created_at:entry.reviewed_at});
  await saveDb();res.json({ok:true,request:entry});
}catch(e){next(e)}});
app.post('/api/admin/users/:id/adjust-balance',auth,admin,async(req,res,next)=>{try{
  const cents=Number(req.body.amountCents),reason=String(req.body.reason||'').trim();
  if(!Number.isSafeInteger(cents)||cents===0||Math.abs(cents)>100000000||reason.length<8||reason.length>300)return res.status(400).json({error:'Provide an adjustment amount and a reason (8–300 characters).'});
  const user=db.users.find(x=>String(x.id)===String(req.params.id));if(!user||user.role==='admin')return res.status(404).json({error:'User not found.'});
  if(user.balance_cents+cents<0)return res.status(409).json({error:'Insufficient available balance.'});
  user.balance_cents+=cents;db.audit_log.push({id:db.nextAuditId++,actor_id:req.user.id,action:'manual_balance_adjustment',details:{user_id:user.id,delta_cents:cents,reason},created_at:new Date().toISOString()});await saveDb();res.json({ok:true,balanceUSD:user.balance_cents/100});
}catch(e){next(e)}});
app.get('/api/admin/users',auth,admin,(_req,res)=>{
  res.json({users:[...db.users].sort((a,b)=>b.created_at.localeCompare(a.created_at)).slice(0,500).map(x=>({id:x.id,fullName:x.full_name,email:x.email,role:x.role,balanceUSD:x.balance_cents/100,createdAt:x.created_at}))});
});

app.patch('/api/admin/users/:id',auth,admin,async(req,res,next)=>{try{
  const user=db.users.find(x=>String(x.id)===String(req.params.id));
  if(!user||user.role==='admin')return res.status(404).json({error:'User not found.'});
  const changes={},body=req.body||{};
  if(Object.prototype.hasOwnProperty.call(body,'fullName')){
    const value=String(body.fullName||'').trim();if(value.length<2||value.length>100)return res.status(400).json({error:'Name must be 2–100 characters.'});
    changes.full_name=value;
  }
  if(Object.prototype.hasOwnProperty.call(body,'email')){
    const value=String(body.email||'').toLowerCase().trim();
    if(value.length>254||!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value))return res.status(400).json({error:'Enter a valid email.'});
    if(db.users.some(x=>x.id!==user.id&&x.email===value))return res.status(409).json({error:'Email already registered.'});
    changes.email=value;
  }
  if(Object.prototype.hasOwnProperty.call(body,'password')){
    const value=body.password;
    if(typeof value!=='string'||value.length<10||value.length>128||!/[A-Z]/.test(value)||!/[a-z]/.test(value)||!/[0-9]/.test(value))return res.status(400).json({error:'Password needs 10+ characters, upper/lowercase letters and a number.'});
    changes.password_hash=await bcrypt.hash(value,12);
  }
  if(!Object.keys(changes).length)return res.status(400).json({error:'No changes submitted.'});
  Object.assign(user,changes);user.session_version=(user.session_version||0)+1;
  db.audit_log.push({id:db.nextAuditId++,actor_id:req.user.id,action:'user_updated',details:{user_id:user.id,fields:Object.keys(changes).map(k=>k==='password_hash'?'password':k)},created_at:new Date().toISOString()});
  await saveDb();res.json({ok:true,user:{id:user.id,fullName:user.full_name,email:user.email,balanceUSD:user.balance_cents/100}});
}catch(e){next(e)}});
app.delete('/api/admin/users/:id',auth,admin,async(req,res,next)=>{try{
  const user=db.users.find(x=>String(x.id)===String(req.params.id));
  if(!user||user.role==='admin')return res.status(404).json({error:'User not found.'});
  if(db.funding_requests.some(x=>String(x.user_id)===String(user.id)&&x.status==='processing'))return res.status(409).json({error:'Review pending funding requests before deleting this account.'});
  db.users=db.users.filter(x=>x.id!==user.id);
  db.audit_log.push({id:db.nextAuditId++,actor_id:req.user.id,action:'user_deleted',details:{user_id:user.id,email:user.email,balance_cents:user.balance_cents},created_at:new Date().toISOString()});
  await saveDb();res.json({ok:true});
}catch(e){next(e)}});
app.get('/api/admin/audit',auth,admin,(_req,res)=>res.json({events:db.audit_log.slice(-150).reverse()}));

app.get('/api/admin/settings',auth,admin,(_req,res)=>{
  res.json({btcAddress:db.platform_settings.btc_address||''});
});

app.put('/api/admin/btc-address',auth,admin,async(req,res,next)=>{try{
  const address=String(req.body.address||'').trim();
  if(!addressOk(address))return res.status(400).json({error:'Enter a valid receiving address (no spaces, max 200 characters).'});
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
