// Count parsed instructions, not byte patterns that could occur in data sections.
use wasmparser::{Parser,Payload,Operator};
fn main()->Result<(),Box<dyn std::error::Error>>{
 for path in std::env::args().skip(1){
  let bytes=std::fs::read(&path)?;let mut counts=[0usize;4];
  for payload in Parser::new(0).parse_all(&bytes){
   if let Payload::CodeSectionEntry(body)=payload?{
    let mut ops=body.get_operators_reader()?;
    while !ops.eof(){match ops.read()?{
     Operator::I64Add128=>counts[0]+=1,Operator::I64Sub128=>counts[1]+=1,
     Operator::I64MulWideS=>counts[2]+=1,Operator::I64MulWideU=>counts[3]+=1,_=>{}
    }}
   }
  }
  println!("{} bytes={} add128={} sub128={} mul_wide_s={} mul_wide_u={}",path,bytes.len(),counts[0],counts[1],counts[2],counts[3]);
 }
 Ok(())
}
