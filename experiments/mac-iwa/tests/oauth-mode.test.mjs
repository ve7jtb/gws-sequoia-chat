import {test} from 'node:test';
import assert from 'node:assert/strict';
import {getOAuthMode,setOAuthMode} from '../app/google-loopback-oauth.js';
test('missing or unavailable settings default to IWA loopback OAuth',()=>{
 assert.equal(getOAuthMode({getItem:()=>null}),'loopback-pkce');
 assert.equal(getOAuthMode({getItem:()=>{throw Error('unavailable');}}),'loopback-pkce');
});
test('explicit OAuth choice survives reinitialization',()=>{
 const values=new Map(),storage={getItem:k=>values.get(k),setItem:(k,v)=>values.set(k,v)};
 for(const mode of ['extension','loopback-pkce']){setOAuthMode(mode,storage);assert.equal(getOAuthMode(storage),mode);}
});
