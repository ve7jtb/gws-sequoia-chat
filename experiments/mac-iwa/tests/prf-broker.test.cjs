const {test}=require('node:test'),assert=require('node:assert/strict'),vm=require('node:vm'),fs=require('node:fs'),crypto=require('node:crypto').webcrypto;
test('PRF result only reaches requesting IWA port from exact extension popup',async()=>{
 let listener,removed,win,reply=[],heartbeat,cleared=false;const chrome={runtime:{id:'test',getPlatformInfo:async()=>({os:'test'}),getURL:p=>'chrome-extension://test/'+p,onMessage:{addListener:f=>listener=f}},windows:{onRemoved:{addListener:f=>removed=f},create:async x=>{win=x;return {id:7}},remove:async()=>{}}};
 const c=vm.createContext({chrome,crypto,setTimeout,clearTimeout,setInterval:f=>{heartbeat=f;return 1;},clearInterval:()=>{cleared=true;}});vm.runInContext(fs.readFileSync(__dirname+'/../extension/prf-broker.js','utf8'),c);
 c.port={postMessage:r=>reply.push(r),onDisconnect:{addListener:()=>{}}};c.req={op:'vault-prf',name:'Test key',salt:Buffer.alloc(32,1).toString('base64'),credentialId:''};vm.runInContext('startPrf(port,req)',c);await new Promise(r=>setImmediate(r));
 assert.equal(reply[0].type,'progress');heartbeat();await new Promise(r=>setImmediate(r));assert.equal(reply.length,2);
 reply=reply.filter(r=>r.type!=='progress');
 const id=win.url.split('#')[1],msg={op:'vault-prf-result',id,result:{secret:Buffer.alloc(32,2).toString('base64'),credentialId:'test'}};
 listener(msg,{id:'evil',url:win.url},()=>{});assert.equal(reply.length,0);
 listener(msg,{id:'test',url:'chrome-extension://test/other.html#'+id},()=>{});assert.equal(reply.length,0);
 listener(msg,{id:'test',url:win.url},()=>{});assert.equal(reply.length,1);assert.equal(reply[0].data.secret,msg.result.secret);assert(cleared);
 listener(msg,{id:'test',url:win.url},()=>{});assert.equal(reply.length,1);
});
