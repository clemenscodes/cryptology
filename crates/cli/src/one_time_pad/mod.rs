use std::io::{Read, Result, Write};

pub struct OneTimePad;

impl OneTimePad {
  pub fn decrypt<R: Read, W: Write>(
    input: &mut R,
    output: &mut W,
  ) -> Result<()> {
    let mut content = String::new();
    input.read_to_string(&mut content)?;

    write!(output, "{content}")?;
    Ok(())
  }
}
