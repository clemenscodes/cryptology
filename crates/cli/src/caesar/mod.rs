use std::io::{Cursor, Read, Result, Write};

use crate::{frequency_analysis::FrequencyAnalyzer, Decipher};

pub struct CaesarCipher;

impl Decipher<()> for CaesarCipher {
  fn decipher<R: Read, W: Write>(input: &mut R, output: &mut W) -> Result<()> {
    let mut content = String::new();
    input.read_to_string(&mut content)?;

    let decrypted_lines: Vec<String> = content
      .lines()
      .map(|line| {
        let mut content = Cursor::new(line);
        Self::find_best_caesar_shift(&mut content)
          .map(|(decipher, _)| decipher)
          .unwrap_or(String::from(line))
      })
      .collect();

    for line in decrypted_lines {
      writeln!(output, "{line}")?;
    }

    Ok(())
  }
}

impl CaesarCipher {
  pub fn find_best_caesar_shift<R: Read>(
    input: &mut R,
  ) -> Result<(String, u8)> {
    let mut best_score = f32::MAX;
    let mut best_plaintext = String::new();
    let mut best_shift = 0;
    let mut buf = String::new();

    input.read_to_string(&mut buf)?;

    for shift in 0..26 {
      let copy = buf.clone();
      let mut cursor = Cursor::new(copy.as_bytes());
      let candidate = Self::decrypt_caesar_cipher(&mut cursor, shift)?;
      let mut buf = Cursor::new(candidate.as_bytes());
      let mut output = Vec::new();
      let fa = FrequencyAnalyzer::analyze(&mut buf, &mut output)?;
      let score = FrequencyAnalyzer::chi_square_score(&fa);

      if score < best_score {
        best_score = score;
        best_plaintext = candidate;
        best_shift = shift;
      }
    }

    Ok((best_plaintext, best_shift))
  }

  pub fn decrypt_caesar_cipher<R: Read>(
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

    let output_string = String::from_utf8(output_buffer).unwrap();

    assert_eq!(output_string, expected_output);
    Ok(())
  }

  #[test]
  fn test_decipher_with_shift_0() -> Result<()> {
    let mut input = Cursor::new("No shift should keep the text unchanged.");
    let mut output = Vec::new();

    CaesarCipher::decipher(&mut input, &mut output)?;

    let output_string = String::from_utf8(output).unwrap();

    assert_eq!(
      output_string.trim(),
      "No shift should keep the text unchanged."
    );
    Ok(())
  }

  #[test]
  fn test_decipher_with_known_shift() -> Result<()> {
    let mut input = Cursor::new("Uif tfdsfu jt tbgf!");
    let mut output = Vec::new();

    CaesarCipher::decipher(&mut input, &mut output)?;

    let output_string = String::from_utf8(output).unwrap();

    assert_eq!(output_string.trim(), "The secret is safe!");
    Ok(())
  }

  #[test]
  fn test_decipher_with_punctuation() -> Result<()> {
    let mut input = Cursor::new("Efgfoe! B cpoh.");
    let mut output = Vec::new();

    CaesarCipher::decipher(&mut input, &mut output)?;

    let output_string = String::from_utf8(output).unwrap();

    assert_eq!(output_string.trim(), "Defend! A bong.");
    Ok(())
  }

  #[test]
  fn test_decipher_handles_empty_input() -> Result<()> {
    let mut input = Cursor::new("");
    let mut output = Vec::new();

    CaesarCipher::decipher(&mut input, &mut output)?;

    let output_string = String::from_utf8(output).unwrap();

    assert_eq!(output_string.trim(), "");
    Ok(())
  }

  #[test]
  fn test_decipher_handles_non_ascii_characters() -> Result<()> {
    let mut input = Cursor::new("¡Hola! ¿Cómo estás?");
    let mut output = Vec::new();

    CaesarCipher::decipher(&mut input, &mut output)?;

    let output_string = String::from_utf8(output).unwrap();

    assert_eq!(output_string.trim(), "¡Hola! ¿Cómo estás?");
    Ok(())
  }

  #[test]
  fn test_find_best_caesar_shift() -> Result<()> {
    let mut input = Cursor::new("Dro aesmu lbygx pyh tewzc yfob dro vkji nyq.");
    let (plaintext, shift) = CaesarCipher::find_best_caesar_shift(&mut input)?;

    assert_eq!(plaintext, "The quick brown fox jumps over the lazy dog.");
    assert_eq!(shift, 10);
    Ok(())
  }

  #[test]
  fn test_decrypt_caesar_cipher_shift_0() -> Result<()> {
    let mut input = Cursor::new("No shift should keep the text unchanged.");
    let decrypted = CaesarCipher::decrypt_caesar_cipher(&mut input, 0)?;

    assert_eq!(decrypted, "No shift should keep the text unchanged.");
    Ok(())
  }

  #[test]
  fn test_decrypt_caesar_cipher_shift_13() -> Result<()> {
    let mut input = Cursor::new("Gur fhowrpg vf onfrq ba gur cnfg.");
    let decrypted = CaesarCipher::decrypt_caesar_cipher(&mut input, 13)?;

    assert_eq!(decrypted, "The subject is based on the past.");
    Ok(())
  }

  #[test]
  fn test_decrypt_caesar_cipher_with_mixed_case() -> Result<()> {
    let mut input =
      Cursor::new("Uifsf bsf TPNF ipnf ubtl uibu offet pme GFEvsbujpo.");

    let decrypted = CaesarCipher::decrypt_caesar_cipher(&mut input, 1)?;

    assert_eq!(
      decrypted,
      "There are SOME home task that needs old FEDuration."
    );
    Ok(())
  }

  #[test]
  fn test_decrypt_caesar_cipher_empty_string() -> Result<()> {
    let mut input = Cursor::new("");
    let decrypted = CaesarCipher::decrypt_caesar_cipher(&mut input, 5)?;

    assert_eq!(decrypted, "");
    Ok(())
  }

  #[test]
  fn test_decrypt_caesar_cipher_all_letters_shift_13() -> Result<()> {
    let mut input =
      Cursor::new("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz");
    let decrypted = CaesarCipher::decrypt_caesar_cipher(&mut input, 13)?;

    assert_eq!(
      decrypted,
      "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm"
    );
    Ok(())
  }

  #[test]
  fn test_decrypt_caesar_cipher_numbers_and_symbols() -> Result<()> {
    let mut input = Cursor::new("12345 !@#$%^&*()_+");
    let decrypted = CaesarCipher::decrypt_caesar_cipher(&mut input, 7)?;

    assert_eq!(decrypted, "12345 !@#$%^&*()_+");
    Ok(())
  }
}
