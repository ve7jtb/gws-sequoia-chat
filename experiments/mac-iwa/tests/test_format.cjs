const fs=require('node:fs'),vm=require('node:vm'),assert=require('node:assert/strict');
class Element{constructor(tag){this.tagName=tag.toUpperCase();this.children=[];}append(x){this.children.push(x);}replaceChildren(){this.children=[];}}
const document={createElement:tag=>new Element(tag),createTextNode:text=>({text})};const ctx={document,module:{exports:{}}};vm.createContext(ctx);vm.runInContext(fs.readFileSync(__dirname+'/../app/format.js','utf8'),ctx);
assert.equal(ctx.formatMessage('**bold** *italic*'),'<p><strong>bold</strong> <em>italic</em></p>');assert.ok(ctx.formatMessage('<img src=x>').includes('&lt;img'));
const root=new Element('div');ctx.renderSafeHtml(root,'<img src="https://invalid.test/a"><p onclick="evil()"><strong>Safe</strong><a href="javascript:x">text</a></p><script>evil()</script>');
const tags=[];function walk(n){if(n.tagName)tags.push(n.tagName);for(const c of n.children||[])walk(c);}walk(root);assert.deepEqual(tags,['DIV','P','STRONG']);console.log('PASS formatting and inert allowlist rendering');
const validUntrusted=ctx.mailSecuritySummary({encrypted:false,signatureStatus:'valid',certificateTrust:'untrusted'});
assert.ok(validUntrusted.includes('Encryption: Not encrypted'));
assert.ok(validUntrusted.includes('Signature: Valid'));
assert.ok(validUntrusted.includes('Certificate trust: Not trusted'));
assert.ok(ctx.mailSecuritySummary({encrypted:false,signatureStatus:'invalid',certificateTrust:'untrusted'}).includes('Signature: Invalid'));
console.log('PASS independent encryption, signature and trust indicators');
