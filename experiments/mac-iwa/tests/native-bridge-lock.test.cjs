// Exercise the actual extension broker with deterministic Chrome-port events.
// Native operations are mocks: no helper process, PIN, key or account is used.
const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const source = fs.readFileSync(path.join(__dirname, '../extension/background.js'), 'utf8');
const origin = 'isolated-app://example-test-origin';

function event() {
  const listeners = [];
  return {addListener: fn => listeners.push(fn), emit: value => {
    for (const listener of [...listeners]) listener(value);
  }};
}

function port(sender) {
  return {sender, onMessage: event(), onDisconnect: event(), messages: [], disconnects: 0,
    postMessage(value) { this.messages.push(structuredClone(value)); },
    disconnect() { this.disconnects++; this.onDisconnect.emit(); }};
}

function setup() {
  const connections = [], external = event(), delegated = [];
  let failConnect = false;
  const chrome = {runtime: {onConnectExternal: external,
    connectNative(name) {
      assert.equal(name, 'org.pqmail.sequoia_iwa');
      if (failConnect) throw Error('Synthetic connection failure');
      const connection = port(); connections.push(connection); return connection;
    }}};
  const context = vm.createContext({chrome, IWA_ORIGIN: origin, importScripts() {},
    startPrf: (client, request) => delegated.push({kind: 'prf', client, request}),
    startGoogleOAuth: (client, full) => delegated.push({kind: 'google', client, full})});
  vm.runInContext(source, context);
  function client(sender = {origin, url: origin + '/', frameId: 0}) {
    const p = port(sender); external.emit(p); return p;
  }
  return {connections, delegated, client, failConnection(value) { failConnect = value; }};
}

test('late prepare-port cleanup cannot unlock a newer digest-signing connection', () => {
  const s = setup(), prepare = s.client();
  prepare.onMessage.emit({op: 'chat-browser-prepare'});
  const first = s.connections[0];
  first.onMessage.emit({type: 'result', data: {review: 'public ticket'}});
  const signing = s.client();
  signing.onMessage.emit({op: 'chat-sign-digest'});
  const second = s.connections[1];
  // Both events can arrive after the next Native Messaging port has opened.
  // Neither callback owns that new connection's in-flight signing lock.
  prepare.onDisconnect.emit();
  first.onDisconnect.emit();
  const competing = s.client();
  competing.onMessage.emit({op: 'status'});
  assert.equal(s.connections.length, 2);
  assert.equal(competing.messages.at(-1).type, 'error');
  assert.equal(second.disconnects, 0);
  second.onMessage.emit({type: 'result', data: {signature: 'synthetic'}});
  competing.onMessage.emit({op: 'status'});
  assert.equal(s.connections.length, 3, 'Only the signing owner may release its lock');
});

test('progress retains ownership; final reply and synchronous disconnect release once', () => {
  const s = setup(), signing = s.client(), other = s.client();
  signing.onMessage.emit({op: 'chat-sign-digest'});
  const connection = s.connections[0];
  connection.onMessage.emit({type: 'progress', message: 'Synthetic waiting status'});
  other.onMessage.emit({op: 'status'});
  assert.equal(s.connections.length, 1);
  connection.onMessage.emit({type: 'result', data: {signature: 'synthetic'}});
  assert.equal(connection.disconnects, 1);
  assert.deepEqual(signing.messages.map(r => r.type), ['progress', 'result']);
  other.onMessage.emit({op: 'status'});
  assert.equal(s.connections.length, 2);
});

test('closing an active IWA port discards late replies without affecting a replacement', () => {
  const s = setup(), first = s.client();
  first.onMessage.emit({op: 'chat-sign-digest'});
  const old = s.connections[0];
  first.onDisconnect.emit();
  assert.equal(old.disconnects, 1);
  const next = s.client(); next.onMessage.emit({op: 'status'});
  old.onMessage.emit({type: 'result', data: {signature: 'too late'}});
  old.onDisconnect.emit();
  first.onDisconnect.emit();
  first.onMessage.emit({op: 'status'});
  const third = s.client(); third.onMessage.emit({op: 'status'});
  assert.equal(first.messages.length, 0);
  assert.equal(s.connections.length, 2);
  assert.equal(third.messages.at(-1).type, 'error');
});

test('native startup failure releases only that attempted connection and never retries', () => {
  const s = setup(), first = s.client(); s.failConnection(true);
  first.onMessage.emit({op: 'chat-sign-digest'});
  assert.equal(first.messages.length, 1); assert.equal(first.messages[0].type, 'error');
  assert.equal(s.connections.length, 0);
  s.failConnection(false); const next = s.client(); next.onMessage.emit({op: 'status'});
  assert.equal(s.connections.length, 1);
  s.connections[0].onDisconnect.emit();
  assert.equal(next.messages.length, 1); assert.equal(next.messages[0].type, 'error');
  assert.equal(s.connections.length, 1, 'No automatic native retry');
});

test('origin boundary and existing PRF/OAuth delegation are preserved', () => {
  const s = setup();
  for (const sender of [undefined, {origin: 'https://wrong.invalid', url: origin + '/', frameId: 0},
    {origin, url: origin + '/other', frameId: 0}, {origin, url: origin + '/', frameId: 1}]) {
    // Use null for the missing sender so the helper's default does not apply.
    const bad = s.client(sender ?? null);
    assert.equal(bad.disconnects, 1); bad.onMessage.emit({op: 'status'});
  }
  assert.equal(s.connections.length, 0);
  const client = s.client();
  client.onMessage.emit({op: 'vault-prf'});
  client.onMessage.emit({op: 'google-oauth-services'});
  assert.deepEqual(s.delegated.map(r => r.kind), ['prf', 'google']);
  assert.equal(s.delegated[1].full, true);
  client.onMessage.emit({op: 'chat-sign-digest'});
  const blocked = s.client();
  blocked.onMessage.emit({op: 'vault-prf'});
  blocked.onMessage.emit({op: 'google-oauth-test'});
  assert.equal(s.delegated.length, 2, 'Native owner keeps existing ceremony exclusion');
});
