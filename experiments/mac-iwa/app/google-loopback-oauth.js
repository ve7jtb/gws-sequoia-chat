// Extensionless Google OAuth 2.0 Authorization Code + PKCE (RFC 8252 loopback)
// using the IWA Direct Sockets API (TCPServerSocket on 127.0.0.1:0).
// No native helper, no Chrome extension, no external redirect server, and no
// refresh token persistence: the returned access token lives only in memory.

export const AUTH_ENDPOINT = 'https://accounts.google.com/o/oauth2/v2/auth';
export const TOKEN_ENDPOINT = 'https://oauth2.googleapis.com/token';
export const STORAGE_MODE_KEY = 'sequoia_google_oauth_mode';
export const STORAGE_CLIENT_ID_KEY = 'sequoia_google_loopback_client_id';
const MAX_HTTP_BYTES = 8192;

export function base64Url(bytes) {
  const b = new Uint8Array(bytes);
  let bin = '';
  for (let i = 0; i < b.length; i++) bin += String.fromCharCode(b[i]);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

export async function generatePkce() {
  const raw = new Uint8Array(32);
  crypto.getRandomValues(raw);
  const verifier = base64Url(raw);
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier));
  const challenge = base64Url(new Uint8Array(digest));
  return { verifier, challenge, method: 'S256' };
}

export function generateState() {
  const raw = new Uint8Array(32);
  crypto.getRandomValues(raw);
  return Array.from(raw, b => b.toString(16).padStart(2, '0')).join('');
}

export function validateClientId(clientId) {
  const trimmed = typeof clientId === 'string' ? clientId.trim() : '';
  if (!/^[A-Za-z0-9_-]{8,128}\.apps\.googleusercontent\.com$/.test(trimmed)) {
    throw Error('Enter a valid Google Desktop OAuth client ID (*.apps.googleusercontent.com).');
  }
  return trimmed;
}

export function parseLoopbackHttpRequest(rawText, expectedState) {
  if (typeof rawText !== 'string' || !rawText.includes('\r\n')) {
    return { kind: 'invalid', message: 'Malformed HTTP request.' };
  }
  const requestLine = rawText.slice(0, rawText.indexOf('\r\n'));
  const parts = requestLine.split(' ');
  if (parts.length !== 3 || parts[0] !== 'GET' || !parts[2].startsWith('HTTP/1.')) {
    return { kind: 'invalid', message: 'Only HTTP/1.x GET is accepted on loopback callback.' };
  }
  let url;
  try {
    url = new URL(parts[1], 'http://127.0.0.1');
  } catch (_) {
    return { kind: 'invalid', message: 'Invalid callback request target.' };
  }
  if (url.pathname === '/favicon.ico') {
    return { kind: 'ignore' };
  }
  if (url.pathname !== '/callback') {
    return { kind: 'invalid', message: 'Unexpected callback path.' };
  }
  const params = url.searchParams;
  if (params.has('error')) {
    return { kind: 'error', message: 'Google authorization was denied or cancelled.' };
  }
  if (params.getAll('state').length !== 1 || params.getAll('code').length !== 1) {
    return { kind: 'error', message: 'Missing or duplicate OAuth callback parameters.' };
  }
  const state = params.get('state');
  const code = params.get('code');
  if (state !== expectedState) {
    return { kind: 'error', message: 'OAuth state mismatch; authorization rejected.' };
  }
  if (!code || code.length < 8 || code.length > 2048) {
    return { kind: 'error', message: 'Invalid OAuth authorization code.' };
  }
  return { kind: 'callback', code, state };
}

export function buildLoopbackHttpResponse(status, title, bodyText) {
  const html =
    '<!doctype html><html lang="en"><head><meta charset="utf-8"><title>' + title + '</title></head>' +
    '<body style="font-family:-apple-system,sans-serif;padding:24px;max-width:520px">' +
    '<h2>' + title + '</h2><p>' + bodyText + '</p></body></html>';
  const body = new TextEncoder().encode(html);
  const header =
    `HTTP/1.1 ${status}\r\n` +
    'Content-Type: text/html; charset=utf-8\r\n' +
    `Content-Length: ${body.length}\r\n` +
    'Cache-Control: no-store\r\n' +
    'Connection: close\r\n\r\n';
  const head = new TextEncoder().encode(header);
  const out = new Uint8Array(head.length + body.length);
  out.set(head, 0);
  out.set(body, head.length);
  return out;
}

export function getOAuthMode(storage = globalThis.localStorage) {
  try {
    const v = storage?.getItem?.(STORAGE_MODE_KEY);
    if (v === 'loopback-pkce' || v === 'extension') return v;
  } catch (_) {}
  return 'extension';
}

export function setOAuthMode(mode, storage = globalThis.localStorage) {
  if (mode !== 'extension' && mode !== 'loopback-pkce') {
    throw Error('Unsupported Google OAuth mode: ' + mode);
  }
  try { storage?.setItem?.(STORAGE_MODE_KEY, mode); } catch (_) {}
  return mode;
}

export function getLoopbackClientId(storage = globalThis.localStorage) {
  try { return storage?.getItem?.(STORAGE_CLIENT_ID_KEY) || ''; } catch (_) { return ''; }
}

export function setLoopbackClientId(clientId, storage = globalThis.localStorage) {
  const trimmed = typeof clientId === 'string' ? clientId.trim() : '';
  if (trimmed) validateClientId(trimmed);
  try {
    if (trimmed) storage?.setItem?.(STORAGE_CLIENT_ID_KEY, trimmed);
    else storage?.removeItem?.(STORAGE_CLIENT_ID_KEY);
  } catch (_) {}
  return trimmed;
}

async function readHttpHeader(readable) {
  const reader = readable.getReader();
  const chunks = [];
  let total = 0;
  const decoder = new TextDecoder();
  try {
    while (total < MAX_HTTP_BYTES) {
      const { done, value } = await reader.read();
      if (done) break;
      const chunk = new Uint8Array(value);
      if (total + chunk.length > MAX_HTTP_BYTES) {
        throw Error('Loopback HTTP request exceeded 8 KiB limit.');
      }
      chunks.push(chunk);
      total += chunk.length;
      const joined = new Uint8Array(total);
      let off = 0;
      for (const c of chunks) { joined.set(c, off); off += c.length; }
      const text = decoder.decode(joined);
      if (text.includes('\r\n\r\n')) return text;
    }
    const joined = new Uint8Array(total);
    let off = 0;
    for (const c of chunks) { joined.set(c, off); off += c.length; }
    return decoder.decode(joined);
  } finally {
    try { reader.releaseLock(); } catch (_) {}
  }
}

export async function runLoopbackPkceOAuth({
  clientId,
  clientSecret = '',
  scopes,
  ServerSocket = globalThis.TCPServerSocket,
  fetcher = globalThis.fetch,
  openUrl = url => globalThis.open?.(url, '_blank', 'noopener,noreferrer'),
  onAuthUrl = null,
  signal = null,
  timeoutMs = 600000,
}) {
  if (typeof ServerSocket !== 'function') {
    throw Error('Direct Sockets TCPServerSocket is unavailable in this browser/IWA.');
  }
  const cleanClientId = validateClientId(clientId);
  if (!Array.isArray(scopes) || !scopes.length) {
    throw Error('At least one Google OAuth scope is required.');
  }
  if (signal?.aborted) throw Error('Google sign-in cancelled.');

  const { verifier, challenge, method } = await generatePkce();
  const state = generateState();

  const server = new ServerSocket('127.0.0.1', { localPort: 0 });
  const { readable: acceptStream, localPort } = await server.opened;
  const acceptReader = acceptStream.getReader();

  const redirectUri = `http://127.0.0.1:${localPort}/callback`;
  const authUrl = new URL(AUTH_ENDPOINT);
  authUrl.search = new URLSearchParams({
    client_id: cleanClientId,
    redirect_uri: redirectUri,
    response_type: 'code',
    scope: scopes.join(' '),
    state,
    code_challenge: challenge,
    code_challenge_method: method,
    prompt: 'select_account',
    include_granted_scopes: 'false',
  }).toString();

  let timer = null;
  let closed = false;
  const closeServer = async () => {
    if (closed) return;
    closed = true;
    clearTimeout(timer);
    try { await acceptReader.cancel(); } catch (_) {}
    try { await server.close(); } catch (_) {}
  };

  const onAbort = () => { void closeServer(); };
  signal?.addEventListener('abort', onAbort, { once: true });

  let code = null;
  try {
    onAuthUrl?.(authUrl.href);
    openUrl(authUrl.href);

    code = await new Promise((resolve, reject) => {
      timer = setTimeout(() => {
        void closeServer();
        reject(Error('Google sign-in timed out waiting for loopback callback.'));
      }, timeoutMs);

      const handleAbort = () => {
        void closeServer();
        reject(Error('Google sign-in cancelled.'));
      };
      signal?.addEventListener('abort', handleAbort, { once: true });

      (async () => {
        try {
          while (!closed) {
            const { done, value: clientSocket } = await acceptReader.read();
            if (done || !clientSocket) break;
            const { readable, writable } = await clientSocket.opened;
            const writer = writable.getWriter();
            try {
              const raw = await readHttpHeader(readable);
              const parsed = parseLoopbackHttpRequest(raw, state);
              if (parsed.kind === 'ignore') {
                await writer.write(buildLoopbackHttpResponse('404 Not Found', 'Not Found', 'Ignored.'));
                await writer.close();
                try { await clientSocket.close(); } catch (_) {}
                continue;
              }
              if (parsed.kind === 'callback') {
                await writer.write(buildLoopbackHttpResponse(
                  '200 OK',
                  'Google sign-in received',
                  'Authorization code received by Sequoia Chat Lab. You may close this tab.'
                ));
                await writer.close();
                try { await clientSocket.close(); } catch (_) {}
                signal?.removeEventListener('abort', handleAbort);
                resolve(parsed.code);
                return;
              }
              await writer.write(buildLoopbackHttpResponse(
                '400 Bad Request',
                'Sign-in rejected',
                parsed.message
              ));
              await writer.close();
              try { await clientSocket.close(); } catch (_) {}
              signal?.removeEventListener('abort', handleAbort);
              reject(Error(parsed.message));
              return;
            } catch (err) {
              try { await writer.close(); } catch (_) {}
              try { await clientSocket.close(); } catch (_) {}
              signal?.removeEventListener('abort', handleAbort);
              reject(err);
              return;
            }
          }
          signal?.removeEventListener('abort', handleAbort);
          reject(Error('Loopback OAuth listener closed before receiving callback.'));
        } catch (err) {
          signal?.removeEventListener('abort', handleAbort);
          reject(err);
        }
      })();
    });
  } finally {
    signal?.removeEventListener('abort', onAbort);
    await closeServer();
  }

  // Exchange code + PKCE code_verifier directly from the IWA.
  const body = new URLSearchParams({
    client_id: cleanClientId,
    code,
    code_verifier: verifier,
    grant_type: 'authorization_code',
    redirect_uri: redirectUri,
  });
  const cleanSecret = typeof clientSecret === 'string' ? clientSecret.trim() : '';
  if (cleanSecret) body.set('client_secret', cleanSecret);

  const resp = await fetcher(TOKEN_ENDPOINT, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: body.toString(),
    credentials: 'omit',
    cache: 'no-store',
    redirect: 'error',
    signal: signal || undefined,
  });
  if (!resp.ok) {
    throw Error('Google token exchange failed (HTTP ' + resp.status + ').');
  }
  const data = await resp.json();
  const token = data?.access_token;
  const expiresIn = Number(data?.expires_in);
  const scope = typeof data?.scope === 'string' ? data.scope : '';
  const tokenType = typeof data?.token_type === 'string' ? data.token_type.toLowerCase() : '';
  if (
    tokenType !== 'bearer' ||
    typeof token !== 'string' || token.length < 20 || token.length > 8192 ||
    !Number.isFinite(expiresIn) || expiresIn <= 30 || expiresIn > 86400 ||
    !scopes.every(s => scope.split(' ').includes(s))
  ) {
    throw Error('Google token response was invalid or missing required scopes.');
  }
  // Never retain or expose refresh_token; keep only the short-lived bearer token.
  return { token, expiresIn, scope };
}
