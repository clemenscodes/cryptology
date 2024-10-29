use std::io::Result;
use std::{io::Read, io::Write};

pub struct MonoalphabeticSubstition;

impl MonoalphabeticSubstition {
  pub fn analyze<R: Read, W: Write>(
    input: &mut R,
    output: &mut W,
  ) -> Result<()> {
    let mut content = String::new();
    input.read_to_string(&mut content)?;

    writeln!(output, "{content}").unwrap();
    Ok(())
  }
}
