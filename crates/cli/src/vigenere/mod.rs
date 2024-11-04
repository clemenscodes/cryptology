use std::io::{Cursor, Read, Result, Write};

use crate::{caesar::CaesarCipher, DecryptCipher, EncryptCipher};

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
    if let Some(key) = config.key {
      Self::decrypt_with_key(input, output, &key)
    } else if let Some(key_length) = config.key_length {
      Self::decrypt_with_key_length(input, output, key_length)
    } else {
      Self::decrypt_with_max_key_length(input, output, config.max_key_length)
    }
  }

  fn decrypt_with_key<R: Read, W: Write>(
    input: &mut R,
    output: &mut W,
    key: &str,
  ) -> Result<()> {
    let mut content = String::new();
    input.read_to_string(&mut content)?;

    let key = key.to_uppercase();
    let mut key_index = 0;
    let key_length = key.len();

    let decrypted_content: String = content
      .chars()
      .map(|c| {
        if c.is_ascii_alphabetic() {
          let key_char = key.chars().nth(key_index % key_length).unwrap();
          key_index += 1;

          let base = if c.is_ascii_lowercase() { b'a' } else { b'A' };
          let key_shift = key_char as u8 - b'A';

          (((c as u8 - base + 26 - key_shift) % 26) + base) as char
        } else {
          c
        }
      })
      .collect();

    write!(output, "{}", decrypted_content)?;
    Ok(())
  }

  fn decrypt_with_key_length<R: Read, W: Write>(
    input: &mut R,
    output: &mut W,
    key_length: u8,
  ) -> Result<()> {
    let mut content = String::new();
    input.read_to_string(&mut content)?;

    // Prepare to collect characters from each segment based on the known key length
    let mut key = String::new();

    for i in 0..key_length {
      // Collect characters from the current segment (i, i + key_length, i + 2 * key_length, ...)
      let nth_chars: String = content
        .chars()
        .enumerate()
        .filter_map(|(index, c)| {
          if c.is_ascii_alphabetic()
            && index % key_length as usize == i as usize
          {
            Some(c)
          } else {
            None
          }
        })
        .collect();

      // Use the frequency analysis method to determine the best Caesar shift
      let mut input = Cursor::new(nth_chars);
      let (_, shift) = CaesarCipher::find_best_caesar_shift(&mut input)?;

      // Convert the shift to the corresponding key character (assuming uppercase)
      let key_char = (b'A' + shift) as char;
      key.push(key_char);
    }

    // Use the derived key to decrypt the content
    Self::decrypt_with_key(&mut content.as_bytes(), output, &key)
  }

  fn decrypt_with_max_key_length<R: Read, W: Write>(
    input: &mut R,
    _output: &mut W,
    _max_key_length: u8,
  ) -> Result<()> {
    let mut content = String::new();

    input.read_to_string(&mut content)?;

    todo!();
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::env;
  use std::fs::File;
  use std::path::PathBuf;

  #[test]
  fn test_decrypt_with_key_length_basic() {
    let encrypted_text = "RIJVS UYVJN";
    let key_length = 3;
    let mut input = Cursor::new(encrypted_text);
    let mut output = Vec::new();

    VigenereCipher::decrypt_with_key_length(
      &mut input,
      &mut output,
      key_length,
    )
    .unwrap();
    let decrypted_text = String::from_utf8(output).unwrap();

    assert_eq!(decrypted_text, "HELLO WORLD");
  }

  #[test]
  #[ignore]
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

  #[test]
  fn test_decrypt_with_known_key() {
    let encrypted_text = "RIJVS UYVJN";
    let key = "KEY";
    let mut input = Cursor::new(encrypted_text);
    let mut output = Vec::new();

    VigenereCipher::decrypt_with_key(&mut input, &mut output, key).unwrap();
    let decrypted_text = String::from_utf8(output).unwrap();

    assert_eq!(decrypted_text, "HELLO WORLD");
  }

  #[test]
  fn test_decrypt_with_known_key_lowercase() {
    let encrypted_text = "rijvs uyvjn";
    let key = "key";
    let mut input = Cursor::new(encrypted_text);
    let mut output = Vec::new();

    VigenereCipher::decrypt_with_key(&mut input, &mut output, key).unwrap();
    let decrypted_text = String::from_utf8(output).unwrap();

    assert_eq!(decrypted_text, "hello world");
  }

  #[test]
  fn test_decrypt_with_known_key_mixed_case() {
    let encrypted_text = "RiJvS UyVjN";
    let key = "KeY";
    let mut input = Cursor::new(encrypted_text);
    let mut output = Vec::new();

    VigenereCipher::decrypt_with_key(&mut input, &mut output, key).unwrap();
    let decrypted_text = String::from_utf8(output).unwrap();

    assert_eq!(decrypted_text, "HeLlO WoRlD");
  }

  #[test]
  fn test_decrypt_with_known_key_special_chars() {
    let encrypted_text = "RIJVS, UYVJN!";
    let key = "KEY";
    let mut input = Cursor::new(encrypted_text);
    let mut output = Vec::new();

    VigenereCipher::decrypt_with_key(&mut input, &mut output, key).unwrap();
    let decrypted_text = String::from_utf8(output).unwrap();

    assert_eq!(decrypted_text, "HELLO, WORLD!");
  }

  #[test]
  #[ignore]
  fn test_decrypt_with_key_length_lowercase() {
    let encrypted_text = "rijvs uyvjn";
    let key_length = 3;
    let mut input = Cursor::new(encrypted_text);
    let mut output = Vec::new();

    VigenereCipher::decrypt_with_key_length(
      &mut input,
      &mut output,
      key_length,
    )
    .unwrap();
    let decrypted_text = String::from_utf8(output).unwrap();

    assert_eq!(decrypted_text, "hello world");
  }

  #[test]
  #[ignore]
  fn test_decrypt_with_key_length_special_chars() {
    let encrypted_text = "RIJVS, UYVJN!";
    let key_length = 3;
    let mut input = Cursor::new(encrypted_text);
    let mut output = Vec::new();

    VigenereCipher::decrypt_with_key_length(
      &mut input,
      &mut output,
      key_length,
    )
    .unwrap();
    let decrypted_text = String::from_utf8(output).unwrap();

    assert_eq!(decrypted_text, "HELLO, WORLD!");
  }

  #[test]
  #[ignore]
  fn test_decrypt_with_key_length_longer_text() {
    let encrypted_text = "QEB NRFZH YOLTK CLU GRJMP LSBO QEB IXWV ALD";
    let key_length = 7;
    let mut input = Cursor::new(encrypted_text);
    let mut output = Vec::new();

    VigenereCipher::decrypt_with_key_length(
      &mut input,
      &mut output,
      key_length,
    )
    .unwrap();
    let decrypted_text = String::from_utf8(output).unwrap();

    assert_eq!(
      decrypted_text,
      "THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG"
    );
  }
}
