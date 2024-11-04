use std::io::{Cursor, Read, Result, Write};

use crate::{
  caesar::CaesarCipher, frequency_analysis::FrequencyAnalyzer, DecryptCipher,
  EncryptCipher,
};

pub struct VigenereDecryptConfig {
  max_key_length: u8,
}

impl VigenereDecryptConfig {
  pub fn new(max_key_length: Option<u8>) -> Self {
    Self {
      max_key_length: max_key_length.unwrap_or(20),
    }
  }
}

impl Default for VigenereDecryptConfig {
  fn default() -> Self {
    Self { max_key_length: 20 }
  }
}

impl From<&DecryptCipher> for VigenereDecryptConfig {
  fn from(value: &DecryptCipher) -> Self {
    match value {
      DecryptCipher::Vigenere { max_key_length, .. } => {
        VigenereDecryptConfig::new(*max_key_length)
      }
      _ => VigenereDecryptConfig::default(),
    }
  }
}

pub struct VigenereEncryptConfig {
  key: String,
}

impl VigenereEncryptConfig {
  pub fn new(key: &str) -> Self {
    Self {
      key: key.to_string(),
    }
  }
}

impl Default for VigenereEncryptConfig {
  fn default() -> Self {
    Self {
      key: String::from("key"),
    }
  }
}

impl From<&EncryptCipher> for VigenereEncryptConfig {
  fn from(value: &EncryptCipher) -> Self {
    match value {
      EncryptCipher::Vigenere { key, .. } => VigenereEncryptConfig::new(key),
      _ => VigenereEncryptConfig::default(),
    }
  }
}

pub struct VigenereCipher;

impl VigenereCipher {
  pub fn encrypt<R: Read, W: Write>(
    input: &mut R,
    output: &mut W,
    config: VigenereEncryptConfig,
  ) -> Result<()> {
    let key = config.key.to_uppercase();
    let key_length = key.len();
    let mut content = String::new();
    let mut key_index = 0;

    input.read_to_string(&mut content)?;

    let cipher: String = content
      .chars()
      .map(|c| {
        if c.is_ascii_alphabetic() {
          let key_char = key.chars().nth(key_index % key_length).unwrap();
          key_index += 1;

          let base = if c.is_ascii_lowercase() { b'a' } else { b'A' };
          let key_shift = key_char as u8 - b'A';

          (((c as u8 - base + key_shift) % 26) + base) as char
        } else {
          c
        }
      })
      .collect();

    write!(output, "{cipher}")?;
    Ok(())
  }

  pub fn decrypt<R: Read, W: Write>(
    input: &mut R,
    output: &mut W,
    config: VigenereDecryptConfig,
  ) -> Result<()> {
    let mut content = String::new();

    input.read_to_string(&mut content)?;

    let mut best_decryption = String::new();
    let mut best_score = f32::MAX;

    for key_length in 1..=config.max_key_length {
      let mut columns: Vec<Vec<char>> = vec![Vec::new(); key_length as usize];

      for (i, c) in content.chars().enumerate() {
        columns[i % key_length as usize].push(c);
      }

      let mut key = String::new();

      for column in columns.iter() {
        let input: String = column.iter().collect();
        let mut buf = Cursor::new(input.into_bytes());

        let best_shift = Self::find_best_shift_for_column(&mut buf)?;
        key.push((b'A' + best_shift) as char);
      }

      let decipher = Self::decrypt_vigenere(&content, &key);
      let mut input = Cursor::new(decipher.clone().into_bytes());
      let mut output = Vec::new();
      let fa = FrequencyAnalyzer::analyze(&mut input, &mut output)?;
      let score = FrequencyAnalyzer::chi_square_score(&fa);

      if score < best_score {
        best_score = score;
        best_decryption = decipher;
      }
    }

    write!(output, "{best_decryption}")?;
    Ok(())
  }

  fn find_best_shift_for_column<R: Read>(column: &mut R) -> Result<u8> {
    let mut best_shift = 0;
    let mut best_score = f32::MAX;
    let mut buf = String::new();

    column.read_to_string(&mut buf)?;

    for shift in 0..26 {
      let copy = buf.clone();
      let mut cursor = Cursor::new(copy.as_bytes());
      let decipher = CaesarCipher::decrypt_caesar_cipher(&mut cursor, shift)?;
      let mut input = Cursor::new(decipher.into_bytes());
      let mut output = Vec::new();
      let fa = FrequencyAnalyzer::analyze(&mut input, &mut output)?;
      let score = FrequencyAnalyzer::chi_square_score(&fa);

      if score < best_score {
        best_score = score;
        best_shift = shift;
      }
    }

    Ok(best_shift)
  }

  fn decrypt_vigenere(content: &str, key: &str) -> String {
    content
      .chars()
      .enumerate()
      .map(|(i, c)| {
        if c.is_ascii_alphabetic() {
          let key_char = key.as_bytes()[i % key.len()];
          let offset = if c.is_ascii_uppercase() { b'A' } else { b'a' };
          let c_value = c as u8 - offset;
          let key_value = key_char - b'A';
          let shifted = (26 + c_value - key_value) % 26;
          (shifted + offset) as char
        } else {
          c
        }
      })
      .collect()
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
    let config = VigenereDecryptConfig::default();

    VigenereCipher::decrypt(&mut input_file, &mut output_buffer, config)?;

    let mut expected_output = String::new();
    File::open(&output_path)?.read_to_string(&mut expected_output)?;

    let output_string = String::from_utf8(output_buffer)
      .expect("Failed to convert output buffer to UTF-8 string");

    assert_eq!(output_string, expected_output);
    Ok(())
  }

  #[test]
  fn test_vigenere_encrypt() {
    let input_text = "HELLO WORLD";
    let key = "KEY";
    let mut input = Cursor::new(input_text);
    let mut output = Vec::new();
    let config = VigenereEncryptConfig::new(key);

    VigenereCipher::encrypt(&mut input, &mut output, config).unwrap();
    let encrypted_text = String::from_utf8(output).unwrap();

    assert_eq!(encrypted_text, "RIJVS UYVJN");
  }

  #[test]
  fn test_vigenere_encrypt_with_lowercase() {
    let input_text = "hello world";
    let key = "key";
    let mut input = Cursor::new(input_text);
    let mut output = Vec::new();
    let config = VigenereEncryptConfig::new(key);

    VigenereCipher::encrypt(&mut input, &mut output, config).unwrap();
    let encrypted_text = String::from_utf8(output).unwrap();

    assert_eq!(encrypted_text, "rijvs uyvjn");
  }

  #[test]
  fn test_vigenere_encrypt_with_non_alpha_chars() {
    let input_text = "HELLO, WORLD!";
    let key = "KEY";
    let mut input = Cursor::new(input_text);
    let mut output = Vec::new();
    let config = VigenereEncryptConfig::new(key);

    VigenereCipher::encrypt(&mut input, &mut output, config).unwrap();
    let encrypted_text = String::from_utf8(output).unwrap();

    assert_eq!(encrypted_text, "RIJVS, UYVJN!");
  }
}
