import test from 'node:test';import assert from 'node:assert/strict';
import {probe,authorizationURL} from '../app/oauth-probe.js';
test('anonymous HTTP rejection is distinct from network failure',async()=>{
 const r=await probe(async(url,options)=>{assert.equal(options.credentials,'omit');assert.equal(options.redirect,'error');assert.equal(options.headers['Content-Type'],'application/x-www-form-urlencoded');assert.equal(options.body,'grant_type=iwa_probe_invalid');return {status:400};},'https://oauth2.googleapis.com/token','POST');
 assert.equal(r.responseReadable,true);assert.equal(r.status,400);
 assert.equal((await probe(async()=>{throw Error('private diagnostic');},'x','GET')).responseReadable,false);
});
test('redirect probe uses public client, PKCE, isolated origin and no mailbox/offline scopes',()=>{
 const u=new URL(authorizationURL('123-example.apps.googleusercontent.com','isolated-app://abcdef','state','challenge'));
 assert.equal(u.searchParams.get('scope'),'openid');assert.equal(u.searchParams.get('code_challenge_method'),'S256');assert.equal(u.searchParams.get('access_type'),null);
 assert.equal(u.searchParams.get('redirect_uri'),'isolated-app://abcdef/oauth-callback.html');
 assert.throws(()=>authorizationURL('secret','isolated-app://abcdef','s','c'));
 assert.throws(()=>authorizationURL('123.apps.googleusercontent.com','https://untrusted.example','s','c'));
});
