// End-to-end compiled WASM SSH/PTY test. Direct Sockets is represented by the
// same read/write promises over a disposable local TCP server, not a real host.
import fs from 'node:fs';import vm from 'node:vm';import net from 'node:net';import crypto from 'node:crypto';import {spawn} from 'node:child_process';import readline from 'node:readline';import assert from 'node:assert/strict';
const child=spawn(process.env.SSH_TEST_SERVER,[],{stdio:['ignore','pipe','inherit']});
const timeout=setTimeout(()=>{child.kill();process.exit(2);},20000);
try{
 const rl=readline.createInterface({input:child.stdout});const [line]=await Promise.race([new Promise(r=>rl.once('line',x=>r([x]))),new Promise((_,r)=>child.once('exit',()=>r(Error('server exited'))))]);const config=JSON.parse(line);rl.close();
 const [host,port]=config.address.split(':'),socket=net.connect(Number(port),host);await new Promise((r,j)=>{socket.once('connect',r);socket.once('error',j)});
 const iterator=socket[Symbol.asyncIterator]();let signatures=0,hostChecked=false;
 globalThis.sshRead=async()=>{const r=await iterator.next();return r.done?null:new Uint8Array(r.value)};
 globalThis.sshWrite=data=>new Promise((r,j)=>socket.write(data,e=>e?j(e):r()));globalThis.sshClose=()=>socket.destroy();
 globalThis.sshVerifyHost=async(type,data)=>{assert.equal(type,'ssh-ed25519');assert.equal(Buffer.from(data).toString('base64'),config.hostKey);hostChecked=true;return true};
 const privateKey=crypto.createPrivateKey({key:Buffer.concat([Buffer.from('302e020100300506032b657004220420','hex'),Buffer.from(config.userSeed,'base64')]),format:'der',type:'pkcs8'});
 globalThis.sshSign=async data=>{assert.equal(hostChecked,true);signatures++;return new Uint8Array(crypto.sign(null,data,privateKey))};
 let resolve,reject;const done=new Promise((r,j)=>{resolve=r;reject=j});
 globalThis.sshFailure=message=>reject(Error(message));globalThis.sshReady=()=>globalThis.sshInput(new TextEncoder().encode('test'));
 let output='';globalThis.sshOutput=data=>{output+=new TextDecoder().decode(data);if(output==='test')resolve()};
 vm.runInThisContext(fs.readFileSync('../app/ssh/wasm_exec.js','utf8'));const go=new Go();const {instance}=await WebAssembly.instantiate(fs.readFileSync('../app/ssh/engine.wasm'),go.importObject);go.run(instance).catch(reject);
 globalThis.sshStart({publicKey:new Uint8Array(Buffer.from(config.userKey,'base64')),address:config.address,username:'disposable'});
 await done;
 let transferID=0;
 const transfer=(op,directory,fields={})=>new Promise((resolve,reject)=>{
  const id=++transferID;
  globalThis.sshTransferResult=(reply,error,result)=>{
   assert.equal(reply,id);
   if(error)reject(Error(error));else resolve(result);
  };
  globalThis.sshSFTP({op,id,directory,...fields});
 });
 const {directory}=await transfer('browse','.');
 const name='roundtrip.bin',bytes=Uint8Array.of(0,1,2,128,255);
 await transfer('put',directory,{name,bytes});
 const listing=await transfer('browse',directory);
 assert.deepEqual(listing.entries,[{name,directory:false,size:bytes.length}]);
 assert.deepEqual(await transfer('get',directory,{name}),bytes);
 await assert.rejects(transfer('put',directory,{name,bytes}),/already exists/);
 assert.equal(signatures,1);socket.destroy();
 console.log('PASS compiled WASM trusted SSH, PTY, SFTP upload/download and exclusive creation');
}finally{clearTimeout(timeout);child.kill()}
process.exit(0);
