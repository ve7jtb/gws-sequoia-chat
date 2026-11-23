import test from 'node:test';import assert from 'node:assert/strict';
import {AUTH_ORIGIN,validReply,validToken} from '../app/google-browser.js';
test('message bound to exact origin, frame, nonce and time',()=>{
 const source={},e={origin:AUTH_ORIGIN,source,data:{nonce:'request'}};
 assert.ok(validReply(e,source,'request',20,10));
 for(const bad of [{...e,origin:'https://evil.example'},{...e,source:{}},{...e,data:{nonce:'old'}}])assert.equal(validReply(bad,source,'request',20,10),false);
 assert.equal(validReply(e,source,'request',20,20),false);
});
test('reject missing scope, invalid expiry and oversized token',()=>{
 const d={token:'synthetic'.repeat(5),expiresIn:3600,scope:'https://www.googleapis.com/auth/gmail.readonly'};
 assert.ok(validToken(d));for(const change of [{scope:'openid'},{expiresIn:0},{expiresIn:Infinity},{token:'x'.repeat(9000)}])assert.equal(validToken({...d,...change}),false);
});
