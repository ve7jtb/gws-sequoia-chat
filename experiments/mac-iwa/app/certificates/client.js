// Only this bundled URL is permitted by Trusted Types. Certificates and messages
// cannot choose scripts or cause the parser to fetch remote keys.
const policy = globalThis.trustedTypes?.createPolicy('sequoia-certificate-worker', {
 createScriptURL:url => { if (url !== '/certificates/worker.js') throw Error('Unexpected certificate worker'); return url; }
});
export function inspectCertificate(certificate) {
 return new Promise((resolve,reject) => {
  let worker, timer, finished=false;
  const finish=(error,value) => {
   if (finished) return;
   finished=true; clearTimeout(timer); worker?.terminate();
   error ? reject(Error(error)) : resolve(value);
  };
  try {
   if (typeof certificate !== 'string' || !certificate.length || certificate.length > 349528) throw Error();
   worker=new Worker(policy ? policy.createScriptURL('/certificates/worker.js') : '/certificates/worker.js', {type:'module'});
   timer=setTimeout(() => finish('Certificate inspection timed out; no native fallback.'),30000);
   worker.onerror=() => finish('Certificate inspector unavailable; no native fallback.');
   worker.onmessage=({data}) => finish(data?.ok ? null : 'Public certificate rejected.',data?.result);
   worker.postMessage({certificate});
  } catch (_) { finish('Could not start public certificate inspection.'); }
 });
}
