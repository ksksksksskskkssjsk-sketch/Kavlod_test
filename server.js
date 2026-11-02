// Kavlod server — zero dependencies, Node 18+.   Run: node server.js   (PORT=8080, DATA_DIR=./data)
const http=require('http'),fs=require('fs'),path=require('path'),crypto=require('crypto'),zlib=require('zlib');
const PORT=process.env.PORT||8080,DIR=process.env.DATA_DIR||path.join(__dirname,'data'),PAGE=path.join(__dirname,'kavlod.html');
fs.mkdirSync(DIR,{recursive:true});
const DBF=path.join(DIR,'db.json');
let db={users:{},tokens:{}};try{db=JSON.parse(fs.readFileSync(DBF,'utf8'));}catch(e){}
const wfile=(f,d)=>{const t=f+'.tmp';fs.writeFileSync(t,d);fs.renameSync(t,f);};
let timer=0;const saveDb=()=>{if(!timer)timer=setTimeout(()=>{timer=0;wfile(DBF,JSON.stringify(db));},200);};
const bye=()=>{try{wfile(DBF,JSON.stringify(db));wfile(path.join(DIR,'msgs.json'),JSON.stringify(MS));}catch(e){}process.exit(0);};process.on('SIGTERM',bye);process.on('SIGINT',bye);

const sha=s=>crypto.createHash('sha256').update(s).digest('hex');
const scrypt=(p,s)=>new Promise((ok,no)=>crypto.scrypt(p,s,32,(e,k)=>e?no(e):ok(k)));
const send=(res,s,o)=>{res.writeHead(s,{'Content-Type':'application/json','Cache-Control':'no-store'});res.end(JSON.stringify(o||{}));};
const body=(req,max)=>new Promise((ok,no)=>{let b='',n=0;req.on('data',c=>{n+=c.length;if(n>max){no(new Error('big'));req.destroy();}else b+=c;});req.on('end',()=>ok(b));req.on('error',no);});
const hits=new Map();setInterval(()=>{const n=Date.now();hits.forEach((h,k)=>{if(n-h.t>6e5)hits.delete(k);});},6e4).unref();
const limited=(ip,max)=>{const n=Date.now(),h=hits.get(ip)||{n:0,t:n};if(n-h.t>6e5){h.n=0;h.t=n;}h.n++;hits.set(ip,h);return h.n>max;};
const pub=u=>({id:u.id,name:u.name,tag:u.tag,email:u.email});
const bearer=req=>(req.headers.authorization||'').slice(7);
const mint=uid=>{const t=crypto.randomBytes(32).toString('hex');db.tokens[sha(t)]={u:uid,e:Date.now()+30*864e5};
  const mine=Object.entries(db.tokens).filter(([,v])=>v.u===uid).sort((a,b)=>a[1].e-b[1].e);while(mine.length>10)delete db.tokens[mine.shift()[0]];saveDb();return t;};
const auth=req=>{const r=db.tokens[sha(bearer(req))];if(!r||r.e<Date.now())return null;
  if(r.e-Date.now()<15*864e5){r.e=Date.now()+30*864e5;saveDb();}return db.users[r.u]||null;};
const sf=id=>path.join(DIR,'state_'+id+'.json');
const rstate=id=>{try{return JSON.parse(fs.readFileSync(sf(id),'utf8'));}catch(e){return {v:0,state:null};}};
const wstate=(id,state)=>{const v=rstate(id).v+1;wfile(sf(id),JSON.stringify({v,state}));return v;};
const validState=s=>{if(typeof s!=='string')return false;try{const o=JSON.parse(s);return !!o&&Array.isArray(o.servers);}catch(e){return false;}};

/* ---- shared community chat: channels every user has (same ids as the default servers) ---- */
const SHARED=['general','g-chat','g-lfg','d-help','d-show'];
let MS={};try{MS=JSON.parse(fs.readFileSync(path.join(DIR,'msgs.json'),'utf8'));}catch(e){}
let mt=0;const saveMs=()=>{if(!mt)mt=setTimeout(()=>{mt=0;wfile(path.join(DIR,'msgs.json'),JSON.stringify(MS));},500);};
const subs=new Set(),sent=new Map();
const bc=o=>{const d='data: '+JSON.stringify(o)+'\n\n';subs.forEach(x=>{try{x.res.write(d);}catch(e){}});};

async function api(req,res,u,ip){
  const p=u.pathname.slice(5),m=req.method;
  if(p==='ping')return send(res,200,{ok:1});
  if(p==='stream')req.headers.authorization='Bearer '+(u.searchParams.get('t')||'');
  if(m==='POST'&&(p==='signup'||p==='login')){
    if(limited(ip,15))return send(res,429,{e:'محاولات كثيرة، حاول لاحقاً'});
    let d;try{d=JSON.parse(await body(req,9e6));}catch(e){return send(res,400,{e:'طلب غير صالح'});}
    if(p==='login'){
      const id=String(d.id||'').toLowerCase().trim(),pw=String(d.password||'').slice(0,200);
      const us=Object.values(db.users).find(x=>x.email===id||x.tag===id);
      const h=await scrypt(pw,us?us.salt:'0'.repeat(32));
      if(!us||!crypto.timingSafeEqual(h,Buffer.from(us.hash,'hex')))return send(res,401,{e:'بيانات الدخول غير صحيحة'});
      const s=rstate(us.id);return send(res,200,{token:mint(us.id),account:pub(us),state:s.state,v:s.v});}
    const name=String(d.name||'').trim().slice(0,20),tag=String(d.tag||'').toLowerCase().trim(),email=String(d.email||'').toLowerCase().trim(),pw=String(d.password||'');
    if(!name)return send(res,400,{e:'اكتب اسماً معروضاً'});
    if(!/^[a-z0-9._]{3,20}$/.test(tag))return send(res,400,{e:'اسم المستخدم 3-20 حرفاً: a-z و 0-9 . _'});
    if(!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email)||email.length>120)return send(res,400,{e:'البريد الإلكتروني غير صالح'});
    if(pw.length<6||pw.length>200)return send(res,400,{e:'كلمة المرور 6 أحرف على الأقل'});
    const salt=crypto.randomBytes(16).toString('hex'),hash=(await scrypt(pw,salt)).toString('hex'),us=Object.values(db.users); // hash first, then check+insert with no await in between
    if(us.some(x=>x.email===email))return send(res,409,{e:'البريد الإلكتروني مستخدم'});
    if(us.some(x=>x.tag===tag))return send(res,409,{e:'اسم المستخدم مستخدم'});
    const id=crypto.randomBytes(8).toString('hex');db.users[id]={id,name,tag,email,salt,hash,ts:Date.now()};
    let v=0,state=null;if(validState(d.state)){state=d.state;v=wstate(id,state);}
    return send(res,200,{token:mint(id),account:pub(db.users[id]),state,v});}
  const us=auth(req);if(!us)return send(res,401,{e:'unauthorized'});
  if(p==='stream'&&m==='GET'){res.writeHead(200,{'Content-Type':'text/event-stream','Cache-Control':'no-cache','Connection':'keep-alive','X-Accel-Buffering':'no'});res.write(': ok\n\n');
    const x={res,u:us.id};subs.add(x);const pi=setInterval(()=>{try{res.write(': p\n\n');}catch(e){}},15000);req.on('close',()=>{clearInterval(pi);subs.delete(x);});return;}
  if(p==='msgs'&&m==='GET'){const o={};SHARED.forEach(c=>{o[c]=(MS[c]||[]).slice(-100);});return send(res,200,o);}
  if(p==='msg'||p==='msgedit'||p==='msgdel'){
    if(m!=='POST')return send(res,405);let d;try{d=JSON.parse(await body(req,1e4));}catch(e){return send(res,400);}
    const ch=String(d.ch||'');if(!SHARED.includes(ch))return send(res,400,{e:'channel'});const l=MS[ch]||(MS[ch]=[]),t=String(d.t||'').trim().slice(0,2000);
    if(p==='msg'){if(!t)return send(res,400);const n=Date.now(),a=(sent.get(us.id)||[]).filter(x=>n-x<8000);if(a.length>=6)return send(res,429,{e:'slow'});a.push(n);sent.set(us.id,a);
      const o={id:crypto.randomBytes(6).toString('hex'),u:us.id,n:String(d.n||us.name).trim().slice(0,20)||us.name,g:us.tag,t,ts:n,rp:d.rp?String(d.rp).slice(0,20):undefined,cid:String(d.cid||'').slice(0,24)};
      l.push(o);if(l.length>300)l.splice(0,l.length-300);saveMs();bc({t:'msg',ch,m:o});return send(res,200,{id:o.id});}
    const x=l.find(y=>y.id===String(d.id||''));if(!x||x.u!==us.id)return send(res,404);
    if(p==='msgedit'){if(!t)return send(res,400);x.t=t;x.ed=1;saveMs();bc({t:'msg',ch,m:x});return send(res,200);}
    l.splice(l.indexOf(x),1);saveMs();bc({t:'del',ch,id:x.id});return send(res,200);}
  if(p==='logout'&&m==='POST'){delete db.tokens[sha(bearer(req))];saveDb();return send(res,200);}
  if(p==='password'&&m==='POST'){
    if(limited(ip,15))return send(res,429,{e:'محاولات كثيرة، حاول لاحقاً'});
    let d;try{d=JSON.parse(await body(req,1e4));}catch(e){return send(res,400,{e:'طلب غير صالح'});}
    const np=String(d.password||'');if(np.length<6||np.length>200)return send(res,400,{e:'كلمة المرور 6 أحرف على الأقل'});
    if(!crypto.timingSafeEqual(await scrypt(String(d.old||'').slice(0,200),us.salt),Buffer.from(us.hash,'hex')))return send(res,401,{e:'wrong'});
    us.salt=crypto.randomBytes(16).toString('hex');us.hash=(await scrypt(np,us.salt)).toString('hex');
    const cur=sha(bearer(req));Object.keys(db.tokens).forEach(k=>{if(db.tokens[k].u===us.id&&k!==cur)delete db.tokens[k];});saveDb();return send(res,200);}
  if(p==='state'){
    if(m==='GET'){const s=rstate(us.id),v=+u.searchParams.get('v')||0;return send(res,200,s.v>v?{v:s.v,state:s.state}:{v:s.v});}
    if(m==='PUT'){let b;try{b=await body(req,8e6);}catch(e){return send(res,413,{e:'too large'});}
      if(!validState(b))return send(res,400,{e:'bad state'});return send(res,200,{v:wstate(us.id,b)});}}
  send(res,404,{e:'not found'});
}

/* ---- voice/call signaling relay (same protocol as the original kavlod-server.js) ---- */
const clients=new Map();
const push=(c,m)=>{try{c.write('data: '+JSON.stringify(m)+'\n\n');}catch(e){}};
const route=m=>{if(!m||typeof m!=='object')return;if(m.to){const c=clients.get(m.to);if(c)push(c,m);}else clients.forEach((c,sid)=>{if(sid!==m.f)push(c,m);});};

/* ---- static page (cached, gzip) ---- */
let pg={t:0,raw:null,gz:null};
const page=()=>{const t=fs.statSync(PAGE).mtimeMs;if(t!==pg.t){const raw=fs.readFileSync(PAGE);pg={t,raw,gz:zlib.gzipSync(raw,{level:9})};}return pg;};
const SEC={'X-Content-Type-Options':'nosniff','Referrer-Policy':'same-origin','X-Frame-Options':'DENY','Permissions-Policy':'microphone=(self), camera=(self), display-capture=(self)'};

/* ---- website assets: PWA, SEO, legal pages ---- */
const CE=process.env.CONTACT_EMAIL||'مالك الموقع';
const ICON="<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'><rect width='64' height='64' rx='16' fill='#070707'/><text x='32' y='45' font-size='38' font-weight='700' text-anchor='middle' fill='#f6f6f6' font-family='sans-serif'>K</text></svg>";
const MANIFEST=JSON.stringify({name:'Kavlod',short_name:'Kavlod',start_url:'/',display:'standalone',background_color:'#070707',theme_color:'#070707',lang:'ar',dir:'rtl',icons:[{src:'/icon.svg',sizes:'any',type:'image/svg+xml',purpose:'any maskable'}]});
const SW=`const C='kv1';
self.addEventListener('install',e=>{e.waitUntil(caches.open(C).then(c=>c.add('/')).then(()=>self.skipWaiting()));});
self.addEventListener('activate',e=>{e.waitUntil(caches.keys().then(k=>Promise.all(k.filter(x=>x!==C).map(x=>caches.delete(x)))).then(()=>self.clients.claim()));});
self.addEventListener('fetch',e=>{const r=e.request,u=new URL(r.url);if(r.method!=='GET'||u.origin!==location.origin||u.pathname.startsWith('/api/')||u.pathname==='/events')return;
 e.respondWith(fetch(r).then(x=>{if(x.ok&&r.mode==='navigate'){const y=x.clone();caches.open(C).then(c=>c.put('/',y));}return x;}).catch(()=>caches.match(r.mode==='navigate'?'/':r)).then(x=>x||new Response('offline',{status:503})));});`;
const legal=(t,b)=>'<!doctype html><html lang="ar" dir="rtl"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>'+t+' — Kavlod</title><style>body{font:16px/1.9 Tajawal,system-ui,sans-serif;max-width:720px;margin:40px auto;padding:0 20px;background:#0d0d0d;color:#eee}a{color:#9cf}h1{font-size:26px}</style><h1>'+t+'</h1>'+b+'<p><a href="/">← العودة إلى Kavlod</a></p>';
const ASSET={'/manifest.webmanifest':['application/manifest+json',MANIFEST],'/sw.js':['text/javascript; charset=utf-8',SW],'/icon.svg':['image/svg+xml',ICON],'/favicon.ico':['image/svg+xml',ICON],
 '/robots.txt':['text/plain','User-agent: *\nAllow: /\nDisallow: /api/\n'],
 '/terms':['text/html; charset=utf-8',legal('شروط الاستخدام','<p>باستخدامك Kavlod فأنت توافق على هذه الشروط.</p><ul><li>احترم الآخرين؛ يُمنع التحرش والمحتوى غير القانوني والرسائل المزعجة.</li><li>أنت مسؤول عن حسابك وكلمة مرورك وما تنشره.</li><li>الرسائل في القنوات العامة مرئية لجميع الأعضاء.</li><li>يحق لنا حذف المحتوى أو إيقاف الحسابات المخالفة.</li><li>الخدمة مقدّمة «كما هي» دون ضمانات.</li></ul><p>للتواصل: '+CE+'</p>')],
 '/privacy':['text/html; charset=utf-8',legal('سياسة الخصوصية','<ul><li>نحفظ: الاسم المعروض واسم المستخدم والبريد الإلكتروني وكلمة المرور مشفّرة (لا تُخزَّن كنص) وبيانات تطبيقك لمزامنتها بين أجهزتك.</li><li>رسائل القنوات العامة تُخزَّن وتظهر لكل الأعضاء.</li><li>لا نستخدم إعلانات ولا نبيع بياناتك.</li><li>لطلب حذف حسابك وبياناتك راسلنا.</li></ul><p>للتواصل: '+CE+'</p>')]};
http.createServer((req,res)=>{
  if(process.env.FORCE_HTTPS&&req.headers['x-forwarded-proto']==='http'){res.writeHead(301,{Location:'https://'+req.headers.host+req.url});return res.end();}
  if(req.headers['x-forwarded-proto']==='https')res.setHeader('Strict-Transport-Security','max-age=31536000');
  {const a=ASSET[(req.url||'').split('?')[0]];if(a&&req.method==='GET'){res.writeHead(200,Object.assign({'Content-Type':a[0],'Cache-Control':req.url==='/sw.js'?'no-cache':'public, max-age=3600'},SEC));return res.end(a[1]);}}
  const u=new URL(req.url,'http://x'),ip=(req.headers['x-forwarded-for']||req.socket.remoteAddress||'').split(',')[0].trim();
  if(u.pathname.startsWith('/api/'))return api(req,res,u,ip).catch(()=>{try{send(res,500,{e:'خطأ في الخادم'});}catch(e){}});
  if(u.pathname==='/healthz'){res.writeHead(200);return res.end('ok');}
  if(u.pathname==='/'||u.pathname==='/kavlod.html'||u.pathname==='/index.html'){
    try{const g=page(),gz=/gzip/.test(req.headers['accept-encoding']||'');
      res.writeHead(200,Object.assign({'Content-Type':'text/html; charset=utf-8','Cache-Control':'no-cache','Vary':'Accept-Encoding'},SEC,gz?{'Content-Encoding':'gzip'}:{}));
      return res.end(gz?g.gz:g.raw);}catch(e){res.writeHead(500);return res.end('kavlod.html must be next to server.js');}}
  res.setHeader('Access-Control-Allow-Origin','*');res.setHeader('Access-Control-Allow-Headers','*');
  if(req.method==='OPTIONS'){res.writeHead(204);return res.end();}
  if(u.pathname==='/events'){
    const sid=(u.searchParams.get('sid')||'').slice(0,40);if(!sid){res.writeHead(400);return res.end();}
    res.writeHead(200,{'Content-Type':'text/event-stream','Cache-Control':'no-cache','Connection':'keep-alive','X-Accel-Buffering':'no'});
    res.write(': ok\n\n');const old=clients.get(sid);if(old&&old!==res){try{old.end();}catch(e){}}
    clients.set(sid,res);const ping=setInterval(()=>{try{res.write(': p\n\n');}catch(e){}},15000);
    req.on('close',()=>{clearInterval(ping);if(clients.get(sid)===res){clients.delete(sid);route({t:'bye',f:sid});}});return;}
  if(u.pathname.startsWith('/hook/')&&req.method==='POST'){let b='';req.on('data',c=>{b+=c;if(b.length>2e4)req.destroy();});
    req.on('end',()=>{let d=b;try{d=JSON.parse(b);}catch(e){}const k=sha(u.pathname.slice(6)).slice(0,16);route({t:'hook',k,b:d});res.writeHead(204);res.end();});return;}
  if(u.pathname==='/send'&&req.method==='POST'){let b='';req.on('data',c=>{b+=c;if(b.length>2e6)req.destroy();});
    req.on('end',()=>{try{route(JSON.parse(b));}catch(e){}res.writeHead(204);res.end();});return;}
  if(req.method==='GET'&&/html/.test(req.headers.accept||'')){res.writeHead(404,{'Content-Type':'text/html; charset=utf-8'});return res.end(legal('الصفحة غير موجودة','<p>الرابط الذي طلبته غير موجود.</p>'));}
  res.writeHead(404);res.end();
}).listen(PORT,()=>console.log('Kavlod running on http://localhost:'+PORT+'  (data: '+DIR+')'));
