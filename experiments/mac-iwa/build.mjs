// Local development keys persist only in ignored private/, never on a YubiKey.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import {BundleBuilder} from 'wbn';
import {WebBundleId,SignedWebBundle,NodeCryptoSigningStrategy} from 'wbn-sign';
process.umask(0o077);
for(const d of ['private','build','app/.well-known'])fs.mkdirSync(d,{recursive:true,mode:0o700});
function privateKey(path,algorithm,options={}) {
 if(!fs.existsSync(path))fs.writeFileSync(path,crypto.generateKeyPairSync(algorithm,options).privateKey.export({type:'pkcs8',format:'pem'}),{mode:0o600,flag:'wx'});
 return crypto.createPrivateKey(fs.readFileSync(path));
}
// Release builds explicitly select the established publisher key. Keep the
// local development key intact, and fail on a missing supplied key rather than
// silently generating a new app identity.
const key=process.env.PQ_MAIL_IWA_KEY_FILE
 ? crypto.createPrivateKey(fs.readFileSync(process.env.PQ_MAIL_IWA_KEY_FILE))
 : privateKey('private/iwa-key.pem','ed25519');
const origin=new WebBundleId(key).serializeWithIsolatedWebAppOrigin().replace(/\/$/,'');
const pub=crypto.createPublicKey(privateKey('private/extension-key.pem','rsa',{modulusLength:2048})).export({type:'spki',format:'der'});
const extensionId=crypto.createHash('sha256').update(pub).digest('hex').slice(0,32).replace(/[0-9a-f]/g,c=>String.fromCharCode(97+parseInt(c,16)));
// Chat attachment uploads/downloads need extension HTTPS permission because
// Google's upload response omits CORS access for the isolated-app origin.
// Restrict the host to Chat; the broker further restricts methods and paths.
fs.writeFileSync('extension/manifest.json',JSON.stringify({manifest_version:3,name:'Sequoia IWA native bridge (experiment)',version:'0.20.72',key:pub.toString('base64'),permissions:['nativeMessaging','identity'],host_permissions:['https://chat.googleapis.com/*'],background:{service_worker:'background.js'},externally_connectable:{matches:[origin+'/*']}},null,2));
fs.writeFileSync('extension/config.js','const IWA_ORIGIN = '+JSON.stringify(origin)+';\n');
// Only the installed Desktop app registration is bundled. Explicitly select
// its two configuration fields so this cannot ship a refresh/access token.
let desktopOAuth={};
if(process.env.PQ_MAIL_DESKTOP_OAUTH_JSON){
 const installed=JSON.parse(fs.readFileSync(process.env.PQ_MAIL_DESKTOP_OAUTH_JSON,'utf8')).installed;
 if(!installed || !/^[A-Za-z0-9_-]+\.apps\.googleusercontent\.com$/.test(installed.client_id) || typeof installed.client_secret!=='string')throw Error('Expected Google Desktop OAuth client JSON');
 desktopOAuth={clientId:installed.client_id,clientSecret:installed.client_secret};
}
fs.writeFileSync('app/config.js','const EXTENSION_ID = '+JSON.stringify(extensionId)+';\n'+'globalThis.IWA_BUNDLE_ID = '+JSON.stringify(origin.slice('isolated-app://'.length))+';\n'+'globalThis.PQ_MAIL_DESKTOP_OAUTH = Object.freeze('+JSON.stringify(desktopOAuth)+');\n');
// Normal unmanaged installations read this HTTPS feed from the signed manifest.
// This does not convert a developer installation: Chromium excludes those from
// background updates, regardless of whether an update URL is embedded.
const updateManifestUrl='https://raw.githubusercontent.com/ve7jtb/gws-sequoia-chat/main/experiments/mac-iwa/update-manifest.json';
// Keep the legacy capability for older builds and declare the two separate
// capabilities current Chromium checks before it requests user permission.
const selfPermissions=['smart-card','cross-origin-isolated','direct-sockets','direct-sockets-private','local-network','loopback-network'];
const permissionsPolicy=Object.fromEntries(selfPermissions.map(feature=>[feature,['self']]));
const permissionsHeader=selfPermissions.map(feature=>feature+'=(self)').join(', ');
fs.writeFileSync('app/.well-known/manifest.webmanifest',JSON.stringify({id:'/',name:'Sequoia Chat Lab',short_name:'Sequoia Lab',update_manifest_url:updateManifestUrl,version:'0.20.72',start_url:'/',scope:'/',display:'standalone',permissions_policy:permissionsPolicy,icons:[{src:'/icon.svg',sizes:'any',type:'image/svg+xml',purpose:'any'}]},null,2));
fs.writeFileSync('app/icon.svg','<svg xmlns="http://www.w3.org/2000/svg" width="256" height="256"><rect width="256" height="256" rx="50" fill="#00566c"/><path d="M60 50h136v90q0 45-68 72-68-27-68-72z" fill="#9bcd35"/><text x="128" y="143" text-anchor="middle" font-size="58" font-family="sans-serif" font-weight="bold" fill="#00566c">SQ</text></svg>');
// Fail early instead of shipping a diagnostic button with missing assets.
for(const asset of ['app/wasm/sequoia_iwa_verify.js','app/wasm/sequoia_iwa_verify_bg.wasm','app/wasm-fixtures.json','app/wasm-wide/sequoia_iwa_verify.js','app/wasm-wide/sequoia_iwa_verify_bg.wasm'])if(!fs.existsSync(asset))throw Error('Build WASM verifier and public fixtures first: '+asset);
// Ship the pinned, zero-network MIME parser with the signed IWA.
fs.mkdirSync('app/vendor/postal-mime',{recursive:true});
for(const name of fs.readdirSync('node_modules/postal-mime/dist/esm'))if(name.endsWith('.js'))fs.copyFileSync('node_modules/postal-mime/dist/esm/'+name,'app/vendor/postal-mime/'+name);
fs.copyFileSync('node_modules/postal-mime/LICENSE.txt','app/vendor/postal-mime/LICENSE.txt');
// The terminal renderer is pinned in package-lock and shipped locally; no CDN.
const terminalStyleNonce=crypto.randomBytes(18).toString('base64');
fs.mkdirSync('app/vendor/xterm',{recursive:true});
for(const [source,target] of [['lib/xterm.js','xterm.js'],['css/xterm.css','xterm.css'],['LICENSE','LICENSE.txt']])fs.copyFileSync('node_modules/@xterm/xterm/'+source,'app/vendor/xterm/'+target);
fs.copyFileSync('node_modules/@xterm/addon-fit/lib/addon-fit.mjs','app/vendor/xterm/addon-fit.js');
fs.copyFileSync('node_modules/@xterm/addon-fit/LICENSE','app/vendor/xterm/FIT-LICENSE.txt');
// xterm generates palette/dimension style elements. Give only those elements
// a build-specific style nonce instead of enabling arbitrary inline CSS.
const terminalSource=fs.readFileSync('app/vendor/xterm/xterm.js','utf8');
let terminalStyleSites=0;
const terminalPatched=terminalSource.replace(/([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\.createElement\("style"\)/g,(_,owner)=>{terminalStyleSites++;return 'Object.assign('+owner+'.createElement("style"),{nonce:'+JSON.stringify(terminalStyleNonce)+'})';});
if(!terminalStyleSites)throw Error('Terminal style adaptation failed');
fs.writeFileSync('app/vendor/xterm/xterm.js',terminalPatched);
for(const asset of ['app/ssh/engine.wasm','app/ssh/wasm_exec.js'])if(!fs.existsSync(asset))throw Error('Build SSH WASM first: ssh-engine/build.sh');
// Bundle pinned local cryptographic modules; no CDN or runtime network imports.
for(const library of ['curves','hashes']){
 const root='node_modules/@noble/'+library;
 function vendor(dir,rel=''){
  fs.mkdirSync('app/vendor/'+library+rel,{recursive:true});
  for(const entry of fs.readdirSync(dir,{withFileTypes:true})){
   if(entry.isDirectory()&&entry.name==='abstract')vendor(dir+'/'+entry.name,rel+'/'+entry.name);
   else if(entry.name.endsWith('.js')){
    const target='app/vendor/'+library+rel+'/'+entry.name;
    let source=fs.readFileSync(dir+'/'+entry.name,'utf8');
    source=source.replace(/@noble\/hashes\/([^'" ]+)/g,(_,file)=>{const relative=path.posix.relative(path.posix.dirname(target),'app/vendor/hashes/'+file);return relative.startsWith('.')?relative:'./'+relative;});
    fs.writeFileSync(target,source);
   }
  }
 }
 vendor(root);fs.copyFileSync(root+'/LICENSE','app/vendor/'+library+'/LICENSE.txt');
}
const builder=new BundleBuilder('b2');
const types={'.txt':'text/plain','.html':'text/html; charset=utf-8','.js':'text/javascript','.css':'text/css','.webmanifest':'application/manifest+json','.svg':'image/svg+xml','.wasm':'application/wasm','.json':'application/json'};
const csp="default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; worker-src 'self'; style-src 'self' 'nonce-"+terminalStyleNonce+"'; img-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-src 'none'; frame-ancestors 'none'; form-action 'none'";
function add(dir,rel='') {for(const f of fs.readdirSync(dir,{withFileTypes:true})) {const r=rel+'/'+f.name;if(f.isDirectory())add(dir+'/'+f.name,r);else {const type=types[r.slice(r.lastIndexOf('.'))];if(!type)throw Error('Unknown asset');builder.addExchange(origin+(r==='/index.html'?'/':r),200,{'Content-Type':type,'Content-Security-Policy':(r==='/header-probe.html'?csp.replace("frame-src 'none'","frame-src https://sequoia-iwa-header-test.ve7jtb.chatgpt.site"):(r==='/backup.html'?csp.replace("connect-src 'self'","connect-src 'self' https://oauth2.googleapis.com https://www.googleapis.com"):(r==='/oauth-probe.html'?csp.replace("connect-src 'self'","connect-src 'self' https://accounts.google.com https://oauth2.googleapis.com https://gmail.googleapis.com https://chat.googleapis.com"):(r==='/index.html'?csp.replace("frame-src 'none'","frame-src https://ve7jtb.github.io").replace("connect-src 'self'","connect-src 'self' https://oauth2.googleapis.com https://gmail.googleapis.com https://chat.googleapis.com https://www.googleapis.com"):csp)))),'Cross-Origin-Opener-Policy':'same-origin','Cross-Origin-Embedder-Policy':'require-corp','Cross-Origin-Resource-Policy':'same-origin','Permissions-Policy':permissionsHeader},fs.readFileSync(dir+'/'+f.name));}}}
add('app');
const signed=await SignedWebBundle.fromWebBundle(builder.createBundle(),[new NodeCryptoSigningStrategy(key)]);
fs.writeFileSync('build/sequoia-lab.swbn',signed.getSignedWebBundleBytes());
fs.writeFileSync('build/identity.json',JSON.stringify({origin,extensionId},null,2));
console.log(JSON.stringify({origin,extensionId,bundle:'build/sequoia-lab.swbn'}));
