import init,{local_file_public,local_file_encapsulate,local_file_decapsulate} from '../wasm/sequoia_iwa_verify.js';
import {operateLocalFile} from './crypto.js';

self.onmessage=async({data:{operation,input}})=>{
 try{
  await init();
  const result=await operateLocalFile({local_file_public,local_file_encapsulate,local_file_decapsulate},operation,input);
  const output=result.fileBox||result.plain;
  self.postMessage({ok:true,result},output?[output.buffer]:[]);
 }catch{
  self.postMessage({ok:false});
 }
};
