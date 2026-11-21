// Local development keys persist only in ignored private/, never on a YubiKey.
import fs from 'node:fs';
import crypto from 'node:crypto';
import {BundleBuilder} from 'wbn';
import {WebBundleId,SignedWebBundle,NodeCryptoSigningStrategy} from 'wbn-sign';
process.umask(0o077);
for(const d of ['private','build','app/.well-known'])fs.mkdirSync(d,{recursive:true,mode:0o700});
function privateKey(path,algorithm,options={}) {
 if(!fs.existsSync(path))fs.writeFileSync(path,crypto.generateKeyPairSync(algorithm,options).privateKey.export({type:'pkcs8',format:'pem'}),{mode:0o600,flag:'wx'});
 return crypto.createPrivateKey(fs.readFileSync(path));
}
const key=privateKey('private/iwa-key.pem','ed25519');
const origin=new WebBundleId(key).serializeWithIsolatedWebAppOrigin().replace(/\/$/,'');
const pub=crypto.createPublicKey(privateKey('private/extension-key.pem','rsa',{modulusLength:2048})).export({type:'spki',format:'der'});
const extensionId=crypto.createHash('sha256').update(pub).digest('hex').slice(0,32).replace(/[0-9a-f]/g,c=>String.fromCharCode(97+parseInt(c,16)));
fs.writeFileSync('extension/manifest.json',JSON.stringify({manifest_version:3,name:'Sequoia IWA native bridge (experiment)',version:'0.4.3',key:pub.toString('base64'),permissions:['nativeMessaging'],background:{service_worker:'background.js'},externally_connectable:{matches:[origin+'/*']}},null,2));
fs.writeFileSync('extension/config.js','const IWA_ORIGIN = '+JSON.stringify(origin)+';\n');
fs.writeFileSync('app/config.js','const EXTENSION_ID = '+JSON.stringify(extensionId)+';\n');
fs.writeFileSync('app/.well-known/manifest.webmanifest',JSON.stringify({id:'/',name:'Sequoia Chat Lab',short_name:'Sequoia Lab',version:'0.4.3',start_url:'/',scope:'/',display:'standalone',icons:[{src:'/icon.svg',sizes:'any',type:'image/svg+xml',purpose:'any'}]},null,2));
fs.writeFileSync('app/icon.svg','<svg xmlns="http://www.w3.org/2000/svg" width="256" height="256"><rect width="256" height="256" rx="50" fill="#00566c"/><path d="M60 50h136v90q0 45-68 72-68-27-68-72z" fill="#9bcd35"/><text x="128" y="143" text-anchor="middle" font-size="58" font-family="sans-serif" font-weight="bold" fill="#00566c">SQ</text></svg>');
const builder=new BundleBuilder('b2');
const types={'.html':'text/html; charset=utf-8','.js':'text/javascript','.css':'text/css','.webmanifest':'application/manifest+json','.svg':'image/svg+xml'};
const csp="default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'none'; object-src 'none'; base-uri 'none'; frame-src 'none'; frame-ancestors 'none'; form-action 'none'";
function add(dir,rel='') {for(const f of fs.readdirSync(dir,{withFileTypes:true})) {const r=rel+'/'+f.name;if(f.isDirectory())add(dir+'/'+f.name,r);else {const type=types[r.slice(r.lastIndexOf('.'))];if(!type)throw Error('Unknown asset');builder.addExchange(origin+(r==='/index.html'?'/':r),200,{'Content-Type':type,'Content-Security-Policy':csp,'Cross-Origin-Opener-Policy':'same-origin','Cross-Origin-Embedder-Policy':'require-corp','Cross-Origin-Resource-Policy':'same-origin'},fs.readFileSync(dir+'/'+f.name));}}}
add('app');
const signed=await SignedWebBundle.fromWebBundle(builder.createBundle(),[new NodeCryptoSigningStrategy(key)]);
fs.writeFileSync('build/sequoia-lab.swbn',signed.getSignedWebBundleBytes());
fs.writeFileSync('build/identity.json',JSON.stringify({origin,extensionId},null,2));
console.log(JSON.stringify({origin,extensionId,bundle:'build/sequoia-lab.swbn'}));
