use std::io::{Read, Result, Write};

pub struct VigenereCypher;

impl VigenereCypher {
  pub fn decipher<R: Read, W: Write>(
    input: &mut R,
    output: &mut W,
  ) -> Result<()> {
    Ok(())
  }
}
