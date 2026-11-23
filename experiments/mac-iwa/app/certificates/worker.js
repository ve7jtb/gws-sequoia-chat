// A fresh worker isolates certificate parsing and current self-signature policy.
// It accepts public certificate bytes only; no URL, native operation or trust
// mutation can be requested through this worker.
import init, {inspect_public} from '../wasm/sequoia_iwa_verify.js';
self.onmessage = async ({data}) => {
 try {
  if (!data || Object.keys(data).join() !== 'certificate' || typeof data.certificate !== 'string' || data.certificate.length > 349528) throw Error();
  await init();
  self.postMessage({ok:true, result:JSON.parse(inspect_public(JSON.stringify(data)))});
 } catch (_) { self.postMessage({ok:false, error:'Public certificate rejected. No native fallback was used.'}); }
};
