const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const vm=require('node:vm');

const root='isolated-app://test';
const source=fs.readFileSync(__dirname+'/../extension/background.js','utf8');
function setup(){
 const calls=[];
 let connect;
 vm.runInNewContext(source,{
  IWA_ORIGIN:root,importScripts(){},
  startGoogleOAuth:(_port,services)=>calls.push({services}),
  startChatMedia:(_port,request)=>calls.push(request.op),
  chrome:{runtime:{
   onConnectExternal:{addListener:callback=>{connect=callback;}},
   connectNative:()=>assert.fail('Google broker must never open Native Messaging'),
  }},
 });
 return {calls,port(overrides={}){
  let receive,close,disconnected=false;
  const replies=[];
  connect({
   sender:{origin:root,url:root+'/',frameId:0,...overrides},
   disconnect(){disconnected=true;},
   onMessage:{addListener:fn=>{receive=fn;}},
   onDisconnect:{addListener:fn=>{close=fn;}},
   postMessage:reply=>replies.push(reply.type),
  });
  return {send:request=>receive?.(request),close:()=>close?.(),replies,disconnected};
 }};
}
test('only the signed IWA main frame can request Google OAuth and Chat attachments',()=>{
 const s=setup();
 for(const sender of [{origin:'https://other.invalid'},{frameId:1},{url:root+'/backup.html'}]){
  const port=s.port(sender);assert.equal(port.disconnected,true);
  port.send({op:'google-oauth-services'});
 }
 assert.deepEqual(s.calls,[]);
 const port=s.port();
 for(const op of ['google-oauth-test','google-oauth-services','google-chat-upload','google-chat-download'])
  port.send({op});
 assert.deepEqual(s.calls,[{services:false},{services:true},'google-chat-upload','google-chat-download']);
 port.close();port.send({op:'google-oauth-test'});
 assert.equal(s.calls.length,4);
});
test('the Google broker rejects retired hardware and migration routes',()=>{
 const s=setup(),port=s.port();
 for(const op of ['vault-prf','chat-vault-ecdh','chat-sign-digest','chat-decapsulate-components',
  'chat-identity-bundle-read','chat-certificate-migration','chat-state'])port.send({op});
 assert.deepEqual(port.replies,Array(7).fill('error'));
 assert.deepEqual(s.calls,[]);
});
