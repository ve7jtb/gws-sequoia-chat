// A failed assertion is not permission to create a credential. Only the
// authenticator's explicit NO_CREDENTIALS response permits a separate offer.
export async function discoverOrCreate({assertExisting,createNew,confirmCreate}){
 try{return {result:await assertExisting(),created:false};}
 catch(error){
  if(error.ctapStatus!==0x2e)throw error;
  if(!await confirmCreate())throw Error('No existing credential found. Creation cancelled.');
  return {result:await createNew(),created:true};
 }
}
// A public PIV probe must belong to the same physical key as FIDO enrollment.
// Finding arbitrary signing certificates alone does not establish a usable
// vault unlock key: require the existing wrapping material as well.
export function hasMatchingPiv(material,serial){
 return String(material?.serial)===String(serial)&&!!(material?.certificate||material?.classical);
}
