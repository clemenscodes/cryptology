use rayon::prelude::*;

use std::{
  io::{Cursor, Read, Result, Write},
  sync::{Arc, Mutex},
};

use crate::frequency_analysis::FrequencyAnalyzer;

pub struct Caesar;

impl Caesar {
  pub fn decrypt<R: Read, W: Write>(
    input: &mut R,
    output: &mut W,
  ) -> Result<()> {
    let mut content = String::new();
    input.read_to_string(&mut content)?;

    let plaintext: Vec<String> = content
      .lines()
      .map(|line| {
        let mut content = Cursor::new(line);
        Self::find_best_shift(&mut content)
          .map(|(decipher, _)| decipher)
          .unwrap_or(String::from(line))
      })
      .collect();

    for line in plaintext {
      writeln!(output, "{line}")?;
    }

    Ok(())
  }
}

impl Caesar {
  pub fn find_best_shift<R: Read>(input: &mut R) -> Result<(String, u8)> {
    let best_score = Arc::new(Mutex::new(f32::MAX));
    let best_plaintext = Arc::new(Mutex::new(String::new()));
    let best_shift = Arc::new(Mutex::new(0u8));
    let mut buf = String::new();

    input.read_to_string(&mut buf)?;

    (0..26).into_par_iter().for_each(|shift| {
      let copy = buf.clone();
      let mut cursor = Cursor::new(copy.as_bytes());
      let candidate = Self::decrypt_cipher(&mut cursor, shift).unwrap();
      let mut buf = Cursor::new(candidate.as_bytes());

      if let Ok(score) = FrequencyAnalyzer::score_text(&mut buf) {
        let mut best_score_guard = best_score.lock().unwrap();
        if score < *best_score_guard {
          *best_score_guard = score;
          *best_plaintext.lock().unwrap() = candidate;
          *best_shift.lock().unwrap() = shift;
        }
      }
    });

    let plaintext = Arc::try_unwrap(best_plaintext)
      .unwrap()
      .into_inner()
      .unwrap();

    let shift = Arc::try_unwrap(best_shift).unwrap().into_inner().unwrap();

    Ok((plaintext, shift))
  }

  pub fn decrypt_cipher<R: Read>(input: &mut R, shift: u8) -> Result<String> {
    let mut buf = String::new();
    input.read_to_string(&mut buf)?;

    let plaintext = buf
      .chars()
      .map(|c| {
        c.is_ascii_alphabetic()
          .then(|| Self::shift(c, (b'A' + shift) as char, -1))
          .unwrap_or(c)
      })
      .collect();

    Ok(plaintext)
  }

  pub fn shift(c: char, key_char: char, direction: i8) -> char {
    let base = if c.is_ascii_lowercase() { b'a' } else { b'A' };
    let key_shift = key_char as u8 - b'A';
    let shift = (26 + direction * (key_shift as i8)) % 26;
    (((c as u8 - base + shift as u8) % 26) + base) as char
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

    Caesar::decrypt(&mut input_file, &mut output_buffer)?;

    let mut expected_output = String::new();
    File::open(&output_path)?.read_to_string(&mut expected_output)?;

    let output_string = String::from_utf8(output_buffer).unwrap();

    assert_eq!(output_string, expected_output);
    Ok(())
  }

  #[test]
  fn test_example_output_2() -> Result<()> {
    let assets = "src/caesar/assets";
    let path = env::var("CARGO_MANIFEST_DIR")
      .map(|dir| PathBuf::from(dir).join(assets))
      .unwrap_or_else(|_| {
        env::current_dir()
          .expect("Failed to get current directory")
          .join("crates/cli")
          .join(assets)
      });

    let input_path = path.join("input2.txt");
    let output_path = path.join("output2.txt");

    let mut input_file = File::open(&input_path)?;
    let mut output_buffer = Vec::new();

    Caesar::decrypt(&mut input_file, &mut output_buffer)?;

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

    Caesar::decrypt(&mut input, &mut output)?;

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

    Caesar::decrypt(&mut input, &mut output)?;

    let output_string = String::from_utf8(output).unwrap();

    assert_eq!(output_string.trim(), "The secret is safe!");
    Ok(())
  }

  #[test]
  fn test_decipher_with_punctuation() -> Result<()> {
    let mut input = Cursor::new("Efgfoe! B cpoh.");
    let mut output = Vec::new();

    Caesar::decrypt(&mut input, &mut output)?;

    let output_string = String::from_utf8(output).unwrap();

    assert_eq!(output_string.trim(), "Defend! A bong.");
    Ok(())
  }

  #[test]
  fn test_decipher_handles_empty_input() -> Result<()> {
    let mut input = Cursor::new("");
    let mut output = Vec::new();

    Caesar::decrypt(&mut input, &mut output)?;

    let output_string = String::from_utf8(output).unwrap();

    assert_eq!(output_string.trim(), "");
    Ok(())
  }

  #[test]
  fn test_decipher_handles_non_ascii_characters() -> Result<()> {
    let mut input = Cursor::new("¡Hola! ¿Cómo estás?");
    let mut output = Vec::new();

    Caesar::decrypt(&mut input, &mut output)?;

    let output_string = String::from_utf8(output).unwrap();

    assert_eq!(output_string.trim(), "¡Hola! ¿Cómo estás?");
    Ok(())
  }

  #[test]
  fn test_find_best_shift() -> Result<()> {
    let mut input = Cursor::new("Dro aesmu lbygx pyh tewzc yfob dro vkji nyq.");
    let (plaintext, shift) = Caesar::find_best_shift(&mut input)?;

    assert_eq!(plaintext, "The quick brown fox jumps over the lazy dog.");
    assert_eq!(shift, 10);
    Ok(())
  }

  #[test]
  fn test_decrypt_cipher_shift_0() -> Result<()> {
    let mut input = Cursor::new("No shift should keep the text unchanged.");
    let decrypted = Caesar::decrypt_cipher(&mut input, 0)?;

    assert_eq!(decrypted, "No shift should keep the text unchanged.");
    Ok(())
  }

  #[test]
  fn test_decrypt_cipher_shift_13() -> Result<()> {
    let mut input = Cursor::new("Gur fhowrpg vf onfrq ba gur cnfg.");
    let decrypted = Caesar::decrypt_cipher(&mut input, 13)?;

    assert_eq!(decrypted, "The subject is based on the past.");
    Ok(())
  }

  #[test]
  fn test_decrypt_cipher_with_mixed_case() -> Result<()> {
    let mut input =
      Cursor::new("Uifsf bsf TPNF ipnf ubtl uibu offet pme GFEvsbujpo.");

    let decrypted = Caesar::decrypt_cipher(&mut input, 1)?;

    assert_eq!(
      decrypted,
      "There are SOME home task that needs old FEDuration."
    );
    Ok(())
  }

  #[test]
  fn test_decrypt_cipher_empty_string() -> Result<()> {
    let mut input = Cursor::new("");
    let decrypted = Caesar::decrypt_cipher(&mut input, 5)?;

    assert_eq!(decrypted, "");
    Ok(())
  }

  #[test]
  fn test_decrypt_cipher_all_letters_shift_13() -> Result<()> {
    let mut input =
      Cursor::new("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz");
    let decrypted = Caesar::decrypt_cipher(&mut input, 13)?;

    assert_eq!(
      decrypted,
      "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm"
    );
    Ok(())
  }

  #[test]
  fn test_decrypt_cipher_numbers_and_symbols() -> Result<()> {
    let mut input = Cursor::new("12345 !@#$%^&*()_+");
    let decrypted = Caesar::decrypt_cipher(&mut input, 7)?;

    assert_eq!(decrypted, "12345 !@#$%^&*()_+");
    Ok(())
  }
}
