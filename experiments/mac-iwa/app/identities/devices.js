// Enumeration is a public-only step. Never substitute the helper's configured
// default serial after the user selected a different card, including when that
// card disappears between enumeration and the subsequent read.
export async function discoverIdentityDevices(request,{allowEmpty=false}={}){
 const result=await request('chat-identity-devices');
 if(!result||typeof result!=='object'||Array.isArray(result)||Object.keys(result).join()!=='devices'||!Array.isArray(result.devices)||result.devices.length>32)throw Error('Invalid connected YubiKey inventory.');
 const seen=new Set(),devices=[];
 for(const item of result.devices){
  if(!item||typeof item!=='object'||Array.isArray(item)||Object.keys(item).join()!=='serial'||typeof item.serial!=='string'||! /^[1-9][0-9]{0,9}$/.test(item.serial)||Number(item.serial)>0xffffffff||seen.has(item.serial))throw Error('Invalid connected YubiKey serial.');
  seen.add(item.serial);devices.push({serial:item.serial});
 }
 if(!devices.length&&!allowEmpty)throw Error('Connect the YubiKey whose public certificates you want to restore. No key was changed.');
 return devices;
}
