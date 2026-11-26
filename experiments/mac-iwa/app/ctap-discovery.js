// Silent discovery is only a public hint. credProtect/alwaysUV may hide an
// existing credential, so NO_CREDENTIALS here must never authorize creation.
export async function silentDiscovery(send,rpId,clientHash){
 const request=new Map([[1,rpId],[2,clientHash],[5,new Map([['uv',false],['up',false]])]]);
 try{
  const response=await send(request),id=response.get(1)?.get('id');
  if(!(id instanceof Uint8Array)||!id.length||id.length>1024)throw Error('Invalid silent credential descriptor');
  return id;
 }catch(error){
  // These policy responses require authenticated discovery. Transport errors,
  // malformed results and cancellation propagate without another operation.
  if([0x2e,0x36,0x3b,0x2b].includes(error.ctapStatus))return null;
  throw error;
 }
}
