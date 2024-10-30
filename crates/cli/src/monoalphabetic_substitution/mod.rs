use std::io::Result;
use std::{io::Read, io::Write};

use crate::frequency_analysis::FrequencyAnalyzer;

pub struct MonoalphabeticSubstition;

impl MonoalphabeticSubstition {
  pub fn analyze<R: Read, W: Write>(
    input: &mut R,
    output: &mut W,
  ) -> Result<()> {
    let mut content = String::new();
    let mut output_buffer = Vec::new();

    input.read_to_string(&mut content)?;

    FrequencyAnalyzer::analyze(&mut content.as_bytes(), &mut output_buffer)?;

    let output_string = String::from_utf8(output_buffer)
      .expect("Failed to convert output buffer to UTF-8 string");

    write!(output, "{output_string}")?;
    Ok(())
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::env;
  use std::fs::File;
  use std::path::PathBuf;

  #[test]
  fn test_monoalphabetic_substitution_analysis_output() -> Result<()> {
    let path = match env::var("CARGO_MANIFEST_DIR") {
      Ok(manifest_dir) => PathBuf::from(manifest_dir)
        .join("src/monoalphabetic_substitution/assets"),
      Err(_) => env::current_dir()
        .expect("Failed to get current directory")
        .join("crates/cli/src/monoalphabetic_substitution/assets"),
    };

    let input_path = path.join("input.txt");
    let output_path = path.join("output.txt");

    let mut input_file = File::open(&input_path)?;
    let mut output_buffer = Vec::new();

    MonoalphabeticSubstition::analyze(&mut input_file, &mut output_buffer)?;

    let mut expected_output = String::new();
    File::open(&output_path)?.read_to_string(&mut expected_output)?;

    let output_string = String::from_utf8(output_buffer)
      .expect("Failed to convert output buffer to UTF-8 string");

    assert_eq!(output_string, expected_output);
    Ok(())
  }
}
