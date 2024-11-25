use std::io::{Read, Write};

#[derive(Default, PartialEq, Eq)]
pub struct ManyTimePad;

impl ManyTimePad {
  pub fn encrypt<R: Read, W: Write>(
    _input: &mut R,
    _output: &mut W,
  ) -> std::io::Result<()> {
    Ok(())
  }

  pub fn decrypt<R: Read, W: Write>(
    _input: &mut R,
    _output: &mut W,
  ) -> std::io::Result<()> {
    Ok(())
  }
}

#[cfg(test)]
mod tests {}
