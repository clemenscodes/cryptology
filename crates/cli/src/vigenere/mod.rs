use std::io::{Read, Result, Write};

use crate::Command;

pub struct VigenereConfig {
  max_key_length: u8,
}

impl VigenereConfig {
  pub fn new(max_key_length: Option<u8>) -> Self {
    Self {
      max_key_length: max_key_length.unwrap_or(20),
    }
  }
}

impl Default for VigenereConfig {
  fn default() -> Self {
    Self { max_key_length: 20 }
  }
}

impl From<&Command> for VigenereConfig {
  fn from(value: &Command) -> Self {
    match value {
      Command::Vigenere { max_key_length, .. } => {
        VigenereConfig::new(*max_key_length)
      }
      _ => VigenereConfig::default(),
    }
  }
}

pub struct VigenereCypher;

impl VigenereCypher {
  pub fn decrypt<R: Read, W: Write>(
    input: &mut R,
    output: &mut W,
    config: VigenereConfig,
  ) -> Result<()> {
    let mut content = String::new();
    input.read_to_string(&mut content)?;

    for i in 1..=config.max_key_length {
      println!("Checking keylength {i}");
    }

    write!(output, "{content}")?;
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
  fn test_example_output() -> Result<()> {
    let assets = "src/vigenere/assets";
    let path = env::var("CARGO_MANIFEST_DIR")
      .map(|dir| PathBuf::from(dir).join(assets))
      .unwrap_or_else(|_| {
        env::current_dir()
          .expect("Failed to get current directory")
          .join("crates/cli")
          .join(assets)
      });

    let input_path = path.join("input.txt");
    let output_path = path.join("output.txt");

    let mut input_file = File::open(&input_path)?;
    let mut output_buffer = Vec::new();
    let config = VigenereConfig::default();

    VigenereCypher::decrypt(&mut input_file, &mut output_buffer, config)?;

    let mut expected_output = String::new();
    File::open(&output_path)?.read_to_string(&mut expected_output)?;

    let output_string = String::from_utf8(output_buffer)
      .expect("Failed to convert output buffer to UTF-8 string");

    assert_eq!(output_string, expected_output);
    Ok(())
  }
}
