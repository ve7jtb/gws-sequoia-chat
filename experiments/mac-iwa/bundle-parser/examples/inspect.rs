//! Public-only diagnostic for independent fixtures. This example reads no
//! device and is excluded from the installed native helper distribution.
use anyhow::{Context,Result};
use std::{env,fs};
fn main()->Result<()> {
 let mut args=env::args().skip(1);
 let path=args.next().context("Public bundle path required")?;
 let bundle=sequoia_public_bundle::verify(&fs::read(path)?)?;
 let mut preview=bundle.preview()?;
 if let Some(path)=args.next(){
  preview["certificates"].as_array_mut().context("Certificates")?.push(bundle.v5_view(&fs::read(path)?,sequoia_public_bundle::current_time()?)?);
 }
 println!("{}",preview);
 Ok(())
}
