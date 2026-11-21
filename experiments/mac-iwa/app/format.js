// Produce a deliberately small HTML vocabulary. User text is escaped before
// adding formatting, so raw HTML cannot introduce links or active resources.
function escapeText(s){return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}
function formatMessage(text){return text.split('\n').map(line=>{let kind='p';if(line.startsWith('# ')){kind='h2';line=line.slice(2);}else if(line.startsWith('- ')){kind='li';line=line.slice(2);}const value=escapeText(line).replace(/\*\*([^*]+)\*\*/g,'<strong>$1</strong>').replace(/\*([^*]+)\*/g,'<em>$1</em>');return '<'+kind+'>'+value+'</'+kind+'>';}).join('\n');}
// Never parse remote markup with innerHTML, srcdoc or DOMParser. Tokenize it
// into inert text and a tiny element allowlist; discard every attribute. This
// prevents even image fetches during parsing, before sanitation could occur.
function renderSafeHtml(target,html){target.replaceChildren();const allowed=new Set(['p','br','strong','b','em','i','u','h1','h2','h3','ul','ol','li','blockquote','pre','code']);const stack=[target];const decode=s=>s.replace(/&(amp|lt|gt|quot|apos|#39|#\d+|#x[\da-f]+);/gi,(whole,e)=>{const map={amp:'&',lt:'<',gt:'>',quot:'"',apos:"'",'#39':"'"};if(map[e])return map[e];const n=e[1].toLowerCase()==='x'?parseInt(e.slice(2),16):parseInt(e.slice(1),10);return n>0&&n<=0x10ffff?String.fromCodePoint(n):'�';});for(const token of html.match(/<[^>]*>|[^<]+|</g)||[]){if(token.startsWith('<')){const m=token.match(/^<\s*(\/?)\s*([a-z0-9]+)/i);if(!m||!allowed.has(m[2].toLowerCase()))continue;const tag=m[2].toLowerCase();if(m[1]){if(stack.length>1&&stack[stack.length-1].tagName.toLowerCase()===tag)stack.pop();}else{const el=document.createElement(tag);stack[stack.length-1].append(el);if(tag!=='br'&&stack.length<32)stack.push(el);}}else stack[stack.length-1].append(document.createTextNode(decode(token)));}}
if(typeof module!=='undefined')module.exports={formatMessage,escapeText};

// Encryption, mathematical signature validity and local trust are independent.
function mailSecuritySummary(r){
 const statuses={'valid':'Valid','invalid':'Invalid or rejected by policy','unknown-key':'Cannot verify — certificate unavailable','unsupported':'Unsupported signature format','not-signed':'Not signed'};
 const trust={'trusted':'Trusted for the displayed From address (outer header unauthenticated)','untrusted':'Not trusted for the displayed From address','unknown':'Unknown','not-applicable':'Not applicable'};
 return 'Encryption: '+(r.encrypted?'Encrypted':'Not encrypted')+'\nSignature: '+(statuses[r.signatureStatus]||'Not verified')+'\nCertificate trust: '+(trust[r.certificateTrust]||'Unknown');
}
