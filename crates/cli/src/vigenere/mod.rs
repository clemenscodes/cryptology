use rayon::prelude::*;

use std::{
  io::{Cursor, Read, Result, Write},
  sync::{Arc, Mutex},
};

use crate::{
  caesar::Caesar, frequency_analysis::FrequencyAnalyzer, DecryptCipher,
  EncryptCipher,
};

pub struct VigenereDecryptConfig {
  pub key: Option<String>,
  pub key_length: Option<u8>,
  pub max_key_length: u8,
}

impl VigenereDecryptConfig {
  /// Creates a new `VigenereDecryptConfig`.
  ///
  /// - `key`: The decryption key, if known.
  /// - `key_length`: The key length, if known.
  /// - `max_key_length`: The upper bound for key length to attempt a full crack. Defaults to 20.
  pub fn new(
    key: Option<String>,
    key_length: Option<u8>,
    max_key_length: Option<u8>,
  ) -> Self {
    Self {
      key,
      key_length,
      max_key_length: max_key_length.unwrap_or(20),
    }
  }
}

impl Default for VigenereDecryptConfig {
  fn default() -> Self {
    Self {
      key: None,
      key_length: None,
      max_key_length: 20,
    }
  }
}

impl From<&DecryptCipher> for VigenereDecryptConfig {
  fn from(value: &DecryptCipher) -> Self {
    match value {
      DecryptCipher::Vigenere {
        key,
        key_length,
        max_key_length,
        ..
      } => {
        VigenereDecryptConfig::new(key.clone(), *key_length, *max_key_length)
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

pub struct Vigenere;

impl Vigenere {
  pub fn encrypt<R: Read, W: Write>(
    input: &mut R,
    output: &mut W,
    config: VigenereEncryptConfig,
  ) -> Result<()> {
    let key = config.key.to_uppercase();
    let mut content = String::new();
    let mut key_chars = key.chars().cycle();

    input.read_to_string(&mut content)?;

    let cipher: String = content
      .chars()
      .map(|c| {
        if c.is_ascii_alphabetic() {
          let key_char = key_chars.next().unwrap();
          Caesar::shift(c, key_char, 1)
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

    for line in content.lines() {
      let plaintext = Self::decrypt_line(line, &config);
      writeln!(output, "{plaintext}")?;
    }

    Ok(())
  }

  fn decrypt_line(line: &str, config: &VigenereDecryptConfig) -> String {
    let mut input = Self::get_readable(line);
    let mut output = Vec::new();

    let result = if let Some(key) = &config.key {
      Self::decrypt_with_key(&mut input, &mut output, key)
    } else if let Some(key_length) = config.key_length {
      Self::decrypt_with_key_length(&mut input, &mut output, key_length)
    } else {
      Self::decrypt_with_max_key_length(
        &mut input,
        &mut output,
        config.max_key_length,
      )
    };

    result
      .map(|_| String::from_utf8(output).unwrap_or_else(|_| line.to_string()))
      .unwrap_or_else(|_| line.to_string())
  }

  fn decrypt_with_key<R: Read, W: Write>(
    input: &mut R,
    output: &mut W,
    key: &str,
  ) -> Result<()> {
    let mut content = String::new();
    input.read_to_string(&mut content)?;

    let key = key.to_uppercase();
    let mut key_chars = key.chars().cycle();

    let decipher: String = content
      .chars()
      .map(|c| {
        if c.is_ascii_alphabetic() {
          let key_char = key_chars.next().unwrap();
          Caesar::shift(c, key_char, -1)
        } else {
          c
        }
      })
      .collect();

    write!(output, "{decipher}")?;
    Ok(())
  }

  fn decrypt_with_key_length<R: Read, W: Write>(
    input: &mut R,
    output: &mut W,
    key_length: u8,
  ) -> Result<()> {
    let mut content = String::new();

    input.read_to_string(&mut content)?;

    let mut shifts: Vec<u8> = Vec::new();
    let mut buf = Self::get_readable(&content);
    let segments = Vigenere::segment_text(&mut buf, key_length)?;
    let caesars = Vigenere::create_caesars(segments, key_length);

    for caesar in &caesars {
      let mut buf = Self::get_readable(caesar);
      let (_, shift) = Caesar::find_best_shift(&mut buf)?;
      shifts.push(shift);
    }

    let mut input = Self::get_readable(&content);
    let mut buf = Vec::new();
    let key = Self::derive_key(shifts);

    Vigenere::decrypt_with_key(&mut input, &mut buf, &key)?;

    let plaintext = String::from_utf8(buf).unwrap();

    write!(output, "{plaintext}")?;
    Ok(())
  }

  fn decrypt_with_max_key_length<R: Read, W: Write>(
    input: &mut R,
    output: &mut W,
    max_key_length: u8,
  ) -> Result<()> {
    let mut content = String::new();
    input.read_to_string(&mut content)?;

    let content = Arc::new(content);
    let best_result = Arc::new(Mutex::new((String::new(), f32::MAX)));

    (2..=max_key_length).into_par_iter().for_each(|key_length| {
      let mut shifts = vec![0u8; key_length as usize];
      let mut input = Self::get_readable(&content);
      let segments = Self::segment_text(&mut input, key_length).unwrap();
      let caesars = Vigenere::create_caesars(segments, key_length);

      caesars.into_iter().enumerate().for_each(|(index, caesar)| {
        let mut buf = Self::get_readable(&caesar);
        let (_, s) = Caesar::find_best_shift(&mut buf).unwrap();
        shifts[index] = s;
      });

      let key = Self::derive_key(shifts);

      let mut buf = Vec::new();
      let mut input = Self::get_readable(&content);
      Self::decrypt_with_key(&mut input, &mut buf, &key).unwrap();

      let candidate = String::from_utf8(buf).unwrap();
      let mut input = Self::get_readable(&candidate);
      let mut output = Vec::new();

      if let Ok(fa) = FrequencyAnalyzer::analyze(&mut input, &mut output) {
        let score = FrequencyAnalyzer::chi_square_score(&fa);

        let mut best_result = best_result.lock().unwrap();
        if score < best_result.1 {
          *best_result = (candidate, score);
        }
      }
    });

    let best_plaintext = best_result.lock().unwrap().0.clone();
    write!(output, "{best_plaintext}")?;
    Ok(())
  }

  fn segment_text<R: Read>(
    input: &mut R,
    key_length: u8,
  ) -> Result<Vec<String>> {
    let mut chunks: Vec<String> = Vec::new();
    let mut text = String::new();

    input.read_to_string(&mut text)?;

    let mut chars = text.chars();

    loop {
      let mut chunk: Vec<char> = Vec::new();

      while chunk.len() < key_length as usize {
        if let Some(c) = chars.next() {
          if c.is_ascii_alphabetic() {
            chunk.push(c);
          }
        } else {
          break;
        }
      }

      if chunk.is_empty() {
        break;
      }

      chunks.push(chunk.into_iter().collect());
    }

    Ok(chunks)
  }

  fn create_caesars(chunks: Vec<String>, key_length: u8) -> Vec<String> {
    let mut caesars: Vec<String> = vec![String::new(); key_length as usize];

    for chunk in chunks {
      for (index, c) in chunk.chars().enumerate() {
        caesars[index].push(c);
      }
    }

    caesars
  }

  fn get_readable(input: &str) -> Cursor<Vec<u8>> {
    Cursor::new(input.as_bytes().to_vec())
  }

  fn derive_key(shifts: Vec<u8>) -> String {
    shifts.iter().map(|&shift| (b'A' + shift) as char).collect()
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::env;
  use std::fs::File;
  use std::io::Cursor;
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

    Vigenere::decrypt(&mut input_file, &mut output_buffer, config)?;

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

    Vigenere::encrypt(&mut input, &mut output, config).unwrap();
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

    Vigenere::encrypt(&mut input, &mut output, config).unwrap();
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

    Vigenere::encrypt(&mut input, &mut output, config).unwrap();
    let encrypted_text = String::from_utf8(output).unwrap();

    assert_eq!(encrypted_text, "RIJVS, UYVJN!");
  }

  #[test]
  fn test_decrypt_with_known_key() {
    let encrypted_text = "RIJVS UYVJN";
    let key = "KEY";
    let mut input = Cursor::new(encrypted_text);
    let mut output = Vec::new();

    Vigenere::decrypt_with_key(&mut input, &mut output, key).unwrap();
    let decrypted_text = String::from_utf8(output).unwrap();

    assert_eq!(decrypted_text, "HELLO WORLD");
  }

  #[test]
  fn test_decrypt_with_known_key_lowercase() {
    let encrypted_text = "rijvs uyvjn";
    let key = "key";
    let mut input = Cursor::new(encrypted_text);
    let mut output = Vec::new();

    Vigenere::decrypt_with_key(&mut input, &mut output, key).unwrap();
    let decrypted_text = String::from_utf8(output).unwrap();

    assert_eq!(decrypted_text, "hello world");
  }

  #[test]
  fn test_decrypt_with_known_key_mixed_case() {
    let encrypted_text = "RiJvS UyVjN";
    let key = "KeY";
    let mut input = Cursor::new(encrypted_text);
    let mut output = Vec::new();

    Vigenere::decrypt_with_key(&mut input, &mut output, key).unwrap();
    let decrypted_text = String::from_utf8(output).unwrap();

    assert_eq!(decrypted_text, "HeLlO WoRlD");
  }

  #[test]
  fn test_decrypt_with_known_key_special_chars() {
    let encrypted_text = "RIJVS, UYVJN!";
    let key = "KEY";
    let mut input = Cursor::new(encrypted_text);
    let mut output = Vec::new();

    Vigenere::decrypt_with_key(&mut input, &mut output, key).unwrap();
    let decrypted_text = String::from_utf8(output).unwrap();

    assert_eq!(decrypted_text, "HELLO, WORLD!");
  }

  #[test]
  fn test_segment_text_by_key_length_basic() {
    let mut text = Cursor::new("VIGENERE");
    let key_length = 3;
    let segments = Vigenere::segment_text(&mut text, key_length).unwrap();

    assert_eq!(
      segments,
      vec!["VIG".to_string(), "ENE".to_string(), "RE".to_string()]
    );
  }

  #[test]
  fn test_segment_text_by_key_length_with_spaces() {
    let mut text = Cursor::new("VIGENERE CIPHER");
    let key_length = 4;
    let segments = Vigenere::segment_text(&mut text, key_length).unwrap();
    assert_eq!(
      segments,
      vec![
        "VIGE".to_string(),
        "NERE".to_string(),
        "CIPH".to_string(),
        "ER".to_string()
      ]
    );
  }

  #[test]
  fn test_segment_text_by_key_length_with_non_alpha() {
    let mut text = Cursor::new("V1G3N!E#R$E%");
    let key_length = 5;
    let segments = Vigenere::segment_text(&mut text, key_length).unwrap();
    assert_eq!(segments, vec!["VGNER".to_string(), "E".to_string()]);
  }

  #[test]
  fn test_create_caesars() {
    let mut text = Cursor::new("VIGENERE");
    let key_length = 3;
    let segments = Vigenere::segment_text(&mut text, key_length).unwrap();
    let caesars = Vigenere::create_caesars(segments, key_length);

    assert_eq!(
      caesars,
      vec!["VER".to_string(), "INE".to_string(), "GE".to_string()]
    );
  }
}
