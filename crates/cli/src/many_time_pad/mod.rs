use std::io::{Read, Write};

#[derive(Default, PartialEq, Eq)]
pub struct ManyTimePad;

impl ManyTimePad {
  pub fn encrypt<R: Read, W: Write>(
    input: &mut R,
    output: &mut W,
  ) -> std::io::Result<()> {
    Ok(())
  }

  pub fn decrypt<R: Read, W: Write>(
    input: &mut R,
    output: &mut W,
  ) -> std::io::Result<()> {
    Ok(())
  }
}

#[cfg(test)]
mod tests {
  use super::*;
}
