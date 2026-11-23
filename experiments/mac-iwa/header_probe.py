"""PIN-free local fixture for IWA normal-iframe popup isolation tests.
No OAuth, credentials, files, or token operations. Bind only loopback and serve
fixed routes; two ports model the companion and a separate authorization origin.
"""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
import json
IWA="isolated-app://xk6yfmgz7ckh2kpx2clfmy3yeibdnlw526gs3amhkuaedvmt4ijaaaic"
FRAME="""<!doctype html><meta charset="utf-8"><h2>Normal iframe header test</h2><p id="state">Waiting for IWA</p><button id="open">Open separate-origin test popup</button><script src="/frame.js"></script>"""
FRAME_JS=r"""
const IWA=IWA_PLACEHOLDER; let nonce=null, popup=null;
const say=s=>document.getElementById('state').textContent=s;
function reply(data){parent.postMessage({type:'header-probe',nonce,...data},IWA);}
addEventListener('message',e=>{
 if(e.origin===IWA&&e.source===parent&&e.data?.type==='init'&&/^[a-f0-9]{64}$/.test(e.data.nonce)){
  nonce=e.data.nonce; say('Normal iframe ready; credentialless='+window.credentialless);
  reply({stage:'frame',credentialless:window.credentialless===true,isolated:crossOriginIsolated});
 }
 if(e.origin==='http://localhost:8128'&&e.source===popup&&e.data?.type==='popup-reply'&&e.data.nonce===nonce){say('PASS popup reply received');reply({stage:'popup-reply',pass:true});}
});
document.getElementById('open').onclick=()=>{
 if(!nonce)return;
 popup=window.open('http://localhost:8128/popup#'+nonce,'_blank','popup,width=500,height=400');
 say('window.open returned '+(popup?'a WindowProxy':'null'));
 reply({stage:'popup-open',handle:!!popup});
 setTimeout(()=>{let closed=null;try{closed=popup?.closed??null;}catch(_){}reply({stage:'popup-check',handle:!!popup,closed});},1500);
};
""".replace('IWA_PLACEHOLDER',json.dumps(IWA))
POPUP="""<!doctype html><meta charset="utf-8"><h2>Separate-origin popup test</h2><p id="state"></p><script src="/popup.js"></script>"""
POPUP_JS="""const nonce=location.hash.slice(1);document.getElementById('state').textContent='window.opener is '+(opener?'present':'null');if(opener&&/^[a-f0-9]{64}$/.test(nonce))opener.postMessage({type:'popup-reply',nonce},'http://localhost:8127');"""
class Handler(BaseHTTPRequestHandler):
 def log_message(self,*args):pass
 def do_GET(self):
  port=self.server.server_port
  routes={'/frame':(FRAME,'text/html'),'/frame.js':(FRAME_JS,'text/javascript')} if port==8127 else {'/popup':(POPUP,'text/html'),'/popup.js':(POPUP_JS,'text/javascript')}
  if self.path not in routes:self.send_error(404);return
  body,mime=routes[self.path];self.send_response(200)
  self.send_header('Content-Type',mime+'; charset=utf-8')
  self.send_header('Cache-Control','no-store')
  self.send_header('Cross-Origin-Resource-Policy','cross-origin')
  if port==8127:
   self.send_header('Cross-Origin-Embedder-Policy','require-corp')
   self.send_header('Cross-Origin-Opener-Policy','same-origin-allow-popups')
  self.send_header('Content-Security-Policy',"default-src 'none'; script-src 'self'; base-uri 'none'; form-action 'none'")
  self.end_headers();self.wfile.write(body.encode())
if __name__=='__main__':
 a=ThreadingHTTPServer(('127.0.0.1',8127),Handler);b=ThreadingHTTPServer(('127.0.0.1',8128),Handler)
 Thread(target=a.serve_forever,daemon=True).start();print('Header-only fixture listening on localhost:8127 and localhost:8128',flush=True);b.serve_forever()
