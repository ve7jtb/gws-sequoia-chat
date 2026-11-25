import test from 'node:test';
import assert from 'node:assert/strict';
import {
  generatePkce,
  parseLoopbackHttpRequest,
  runLoopbackPkceOAuth,
} from '../app/google-loopback-oauth.js';

function makeStreamFromBytes(bytes) {
  return new ReadableStream({
    start(controller) {
      controller.enqueue(bytes);
      controller.close();
    },
  });
}

test('generatePkce creates valid RFC 7636 S256 verifier and challenge', async () => {
  const { verifier, challenge, method } = await generatePkce();
  assert.equal(method, 'S256');
  assert.match(verifier, /^[A-Za-z0-9_-]{43}$/);
  assert.match(challenge, /^[A-Za-z0-9_-]{43}$/);
  assert.notEqual(verifier, challenge);
});

test('parseLoopbackHttpRequest validates method, path, state, and rejects errors', () => {
  const state = 'a'.repeat(64);
  assert.deepEqual(
    parseLoopbackHttpRequest(`GET /callback?code=4/0AbCdEfGhIjK&state=${state} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n`, state),
    { kind: 'callback', code: '4/0AbCdEfGhIjK', state }
  );
  assert.deepEqual(
    parseLoopbackHttpRequest('GET /favicon.ico HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n', state),
    { kind: 'ignore' }
  );
  assert.equal(
    parseLoopbackHttpRequest(`GET /callback?code=4/0AbCdEfGhIjK&state=${'b'.repeat(64)} HTTP/1.1\r\n\r\n`, state).kind,
    'error'
  );
  assert.equal(
    parseLoopbackHttpRequest(`GET /callback?error=access_denied&state=${state} HTTP/1.1\r\n\r\n`, state).kind,
    'error'
  );
  assert.equal(
    parseLoopbackHttpRequest(`POST /callback?code=4/0AbCdEfGhIjK&state=${state} HTTP/1.1\r\n\r\n`, state).kind,
    'invalid'
  );
});

test('runLoopbackPkceOAuth binds 127.0.0.1:0, verifies PKCE, drops refresh_token, and closes socket', async () => {
  const scopes = ['https://www.googleapis.com/auth/gmail.readonly'];
  let boundHost = null;
  let boundOpts = null;
  let serverClosed = false;
  let openedAuthUrl = null;
  let tokenPostBody = null;
  let writtenResponses = [];

  let enqueueClient;
  const acceptStream = new ReadableStream({
    start(controller) { enqueueClient = c => controller.enqueue(c); },
  });

  class FakeTCPServerSocket {
    constructor(host, opts) {
      boundHost = host;
      boundOpts = opts;
      this.opened = Promise.resolve({ readable: acceptStream, localPort: 54321 });
    }
    async close() { serverClosed = true; }
  }

  const fakeClient = rawReq => ({
    opened: Promise.resolve({
      readable: makeStreamFromBytes(new TextEncoder().encode(rawReq)),
      writable: new WritableStream({
        write(chunk) { writtenResponses.push(new TextDecoder().decode(chunk)); },
      }),
    }),
    async close() {},
  });

  const fakeFetch = async (url, init) => {
    assert.equal(url, 'https://oauth2.googleapis.com/token');
    assert.equal(init.method, 'POST');
    tokenPostBody = new URLSearchParams(init.body);
    return {
      ok: true,
      status: 200,
      async json() {
        return {
          access_token: 'ya29.fake_access_token_value_1234567890',
          expires_in: 3600,
          token_type: 'Bearer',
          scope: scopes.join(' '),
          refresh_token: '1//should-never-be-returned',
        };
      },
    };
  };

  const result = await runLoopbackPkceOAuth({
    clientId: '1234567890-abcdefg.apps.googleusercontent.com',
    scopes,
    ServerSocket: FakeTCPServerSocket,
    fetcher: fakeFetch,
    openUrl(url) {
      openedAuthUrl = new URL(url);
      const state = openedAuthUrl.searchParams.get('state');
      // First send a favicon request (must be ignored), then the real callback.
      enqueueClient(fakeClient('GET /favicon.ico HTTP/1.1\r\nHost: 127.0.0.1:54321\r\n\r\n'));
      enqueueClient(fakeClient(`GET /callback?code=4/0TestAuthCode12345&state=${state} HTTP/1.1\r\nHost: 127.0.0.1:54321\r\n\r\n`));
    },
  });

  assert.equal(boundHost, '127.0.0.1');
  assert.equal(boundOpts, undefined);
  assert.equal(serverClosed, true);
  assert.equal(openedAuthUrl.searchParams.get('redirect_uri'), 'http://127.0.0.1:54321/callback');
  assert.equal(openedAuthUrl.searchParams.get('code_challenge_method'), 'S256');
  assert.equal(tokenPostBody.get('code'), '4/0TestAuthCode12345');
  assert.equal(tokenPostBody.get('redirect_uri'), 'http://127.0.0.1:54321/callback');
  assert.ok(tokenPostBody.get('code_verifier').length === 43);
  assert.equal(result.token, 'ya29.fake_access_token_value_1234567890');
  assert.equal(result.expiresIn, 3600);
  assert.equal('refresh_token' in result, false);
  assert.ok(writtenResponses.some(r => r.startsWith('HTTP/1.1 200 OK')));
});

test('shared Desktop defaults never leak into a custom client registration', async () => {
  const {getLoopbackClientId,setLoopbackClientId,getLoopbackClientSecret}=await import('../app/google-loopback-oauth.js');
  const previous=globalThis.PQ_MAIL_DESKTOP_OAUTH;
  const values=new Map();
  const storage={getItem:k=>values.get(k),setItem:(k,v)=>values.set(k,v),removeItem:k=>values.delete(k)};
  try {
    globalThis.PQ_MAIL_DESKTOP_OAUTH={clientId:'shared-client.apps.googleusercontent.com',clientSecret:'public-desktop-config'};
    assert.equal(getLoopbackClientId(storage),'shared-client.apps.googleusercontent.com');
    assert.equal(getLoopbackClientSecret(getLoopbackClientId(storage)),'public-desktop-config');
    setLoopbackClientId('custom-client.apps.googleusercontent.com',storage);
    assert.equal(getLoopbackClientSecret(getLoopbackClientId(storage)),'');
    assert.equal(getLoopbackClientSecret(getLoopbackClientId(storage),' custom-secret '),'custom-secret');
    assert.equal(setLoopbackClientId('',storage),'shared-client.apps.googleusercontent.com');
    assert.equal(getLoopbackClientId(storage),'shared-client.apps.googleusercontent.com');
  } finally { if(previous===undefined)delete globalThis.PQ_MAIL_DESKTOP_OAUTH;else globalThis.PQ_MAIL_DESKTOP_OAUTH=previous; }
});
