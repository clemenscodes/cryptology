use std::io::{Cursor, Read, Result, Write};

use crate::frequency_analysis::FrequencyAnalyzer;

pub struct CaesarCipher;

impl CaesarCipher {
  pub fn decipher<R: Read, W: Write>(
    input: &mut R,
    output: &mut W,
  ) -> Result<()> {
    let mut content = String::new();
    input.read_to_string(&mut content)?;

    let decrypted_lines: Vec<String> = content
      .lines()
      .map(|line| {
        Self::find_best_caesar_shift(&mut Cursor::new(line.as_bytes()))
          .map(|(decipher, _)| decipher)
          .unwrap_or(String::from(line))
      })
      .collect();

    for line in decrypted_lines {
      writeln!(output, "{line}")?;
    }

    Ok(())
  }

  pub fn find_best_caesar_shift<R: Read>(
    input: &mut R,
  ) -> Result<(String, u8)> {
    let mut best_score = f32::MAX;
    let mut best_plaintext = String::new();
    let mut best_shift = 0;

    for shift in 0..26 {
      let candidate = Self::decrypt_caesar_cipher(input, shift)?;
      let mut output = Vec::new();
      let fa = FrequencyAnalyzer::analyze(input, &mut output)?;
      let score = FrequencyAnalyzer::chi_square_score(&fa);

      if score < best_score {
        best_score = score;
        best_plaintext = candidate;
        best_shift = shift;
      }
    }

    Ok((best_plaintext, best_shift))
  }

  fn decrypt_caesar_cipher<R: Read>(
    input: &mut R,
    shift: u8,
  ) -> Result<String> {
    let mut buf = String::new();
    input.read_to_string(&mut buf)?;

    let decipher = buf
      .chars()
      .map(|c| {
        if c.is_ascii_alphabetic() {
          let base = if c.is_ascii_uppercase() { b'A' } else { b'a' };
          ((c as u8 - base + 26 - shift) % 26 + base) as char
        } else {
          c
        }
      })
      .collect();

    Ok(decipher)
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
    let assets = "src/caesar/assets";
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

    CaesarCipher::decipher(&mut input_file, &mut output_buffer)?;

    let mut expected_output = String::new();
    File::open(&output_path)?.read_to_string(&mut expected_output)?;

    let output_string = String::from_utf8(output_buffer)
      .expect("Failed to convert output buffer to UTF-8 string");

    assert_eq!(output_string, expected_output);
    Ok(())
  }
}
