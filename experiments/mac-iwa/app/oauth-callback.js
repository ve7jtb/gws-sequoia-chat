// Never render, log or persist the authorization code, error description or URL.
// Immediately remove the query/fragment from the current history entry.
const query=new URLSearchParams(location.search);
const expected=sessionStorage.getItem('iwa-oauth-probe-state');
sessionStorage.removeItem('iwa-oauth-probe-state');
history.replaceState(null,'',location.pathname);
const matched=!!expected && query.get('state')===expected;
document.getElementById('callback-result').textContent='IWA callback reached. State: '+(matched?'matched':'not verified; reject authorization')+'. Authorization code present: '+query.has('code')+'. OAuth error present: '+query.has('error')+'.';
