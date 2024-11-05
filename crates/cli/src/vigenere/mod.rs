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

  pub fn segment_text<R: Read>(
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

  pub fn create_caesars(chunks: Vec<String>, key_length: u8) -> Vec<String> {
    let mut caesars: Vec<String> = vec![String::new(); key_length as usize];

    for chunk in chunks {
      for (index, c) in chunk.chars().enumerate() {
        caesars[index].push(c);
      }
    }

    caesars
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

    let decipher: String = content
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

    let mut buf = Cursor::new(content.clone().into_bytes());

    let segments = VigenereCipher::segment_text(&mut buf, key_length).unwrap();

    let caesars = VigenereCipher::create_caesars(segments, key_length);

    let mut shifts: Vec<u8> = Vec::new();

    for caesar in &caesars {
      let mut buf = Cursor::new(caesar.clone().into_bytes());
      let (_, shift) = CaesarCipher::find_best_caesar_shift(&mut buf).unwrap();
      shifts.push(shift);
    }

    let key: String =
      shifts.iter().map(|&shift| (b'A' + shift) as char).collect();

    let mut buf = Vec::new();

    VigenereCipher::decrypt_with_key(
      &mut Cursor::new(content.into_bytes()),
      &mut buf,
      &key,
    )
    .unwrap();

    let plaintext = String::from_utf8(buf).unwrap();

    write!(output, "{plaintext}")?;
    Ok(())
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
  use crate::caesar::CaesarCipher;

  use super::*;
  use std::env;
  use std::fs::File;
  use std::io::Cursor;
  use std::path::PathBuf;

  #[test]
  fn test_decrypt_vigenere() {
    let assets = "src/vigenere/assets";
    let path = env::var("CARGO_MANIFEST_DIR")
      .map(|dir| PathBuf::from(dir).join(assets))
      .unwrap_or_else(|_| {
        env::current_dir()
          .expect("Failed to get current directory")
          .join("crates/cli")
          .join(assets)
      });

    let input_path = path.join("input1.txt");
    let output_path = path.join("output1.txt");

    let mut input_file = File::open(&input_path).unwrap();

    let mut input = String::new();

    input_file.read_to_string(&mut input).unwrap();

    let key_length = 16;

    let segments = VigenereCipher::segment_text(
      &mut Cursor::new(input.clone().into_bytes()),
      key_length,
    )
    .unwrap();

    let caesars = VigenereCipher::create_caesars(segments, key_length);

    let mut shifts: Vec<u8> = Vec::new();

    for caesar in &caesars {
      let mut buf = Cursor::new(caesar.clone().into_bytes());
      let (_, shift) = CaesarCipher::find_best_caesar_shift(&mut buf).unwrap();
      shifts.push(shift);
    }

    let key: String =
      shifts.iter().map(|&shift| (b'A' + shift) as char).collect();

    let mut output = Vec::new();

    VigenereCipher::decrypt_with_key(
      &mut Cursor::new(input.into_bytes()),
      &mut output,
      &key,
    )
    .unwrap();

    let plaintext = String::from_utf8(output).unwrap();

    let mut expected_output = String::new();

    File::open(&output_path)
      .unwrap()
      .read_to_string(&mut expected_output)
      .unwrap();

    assert_eq!(plaintext, expected_output);
  }

  #[test]
  fn test_decrypt_vigenere2() {
    let assets = "src/vigenere/assets";
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

    let mut input_file = File::open(&input_path).unwrap();

    let mut input = String::new();

    input_file.read_to_string(&mut input).unwrap();

    let key_length = 3;

    let segments = VigenereCipher::segment_text(
      &mut Cursor::new(input.clone().into_bytes()),
      key_length,
    )
    .unwrap();

    let caesars = VigenereCipher::create_caesars(segments, key_length);

    let mut shifts: Vec<u8> = Vec::new();

    for caesar in &caesars {
      let mut buf = Cursor::new(caesar.clone().into_bytes());
      let (_, shift) = CaesarCipher::find_best_caesar_shift(&mut buf).unwrap();
      shifts.push(shift);
    }

    let key: String =
      shifts.iter().map(|&shift| (b'A' + shift) as char).collect();

    let mut output = Vec::new();

    VigenereCipher::decrypt_with_key(
      &mut Cursor::new(input.into_bytes()),
      &mut output,
      &key,
    )
    .unwrap();

    let plaintext = String::from_utf8(output).unwrap();

    let mut expected_output = String::new();

    File::open(&output_path)
      .unwrap()
      .read_to_string(&mut expected_output)
      .unwrap();

    assert_eq!(plaintext, expected_output);
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
  fn test_segment_text_by_key_length_basic() {
    let mut text = Cursor::new("VIGENERE");
    let key_length = 3;
    let segments = VigenereCipher::segment_text(&mut text, key_length).unwrap();

    assert_eq!(
      segments,
      vec!["VIG".to_string(), "ENE".to_string(), "RE".to_string()]
    );
  }

  #[test]
  fn test_segment_text_by_key_length_with_spaces() {
    let mut text = Cursor::new("VIGENERE CIPHER");
    let key_length = 4;
    let segments = VigenereCipher::segment_text(&mut text, key_length).unwrap();
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
    let segments = VigenereCipher::segment_text(&mut text, key_length).unwrap();
    assert_eq!(segments, vec!["VGNER".to_string(), "E".to_string()]);
  }

  #[test]
  fn test_create_caesars() {
    let mut text = Cursor::new("VIGENERE");
    let key_length = 3;
    let segments = VigenereCipher::segment_text(&mut text, key_length).unwrap();
    let caesars = VigenereCipher::create_caesars(segments, key_length);

    assert_eq!(
      caesars,
      vec!["VER".to_string(), "INE".to_string(), "GE".to_string()]
    );
  }

  #[test]
  fn test_decrypt_caesars() {
    let input = "VIGENERE";
    let mut text = Cursor::new(input.as_bytes());

    let key_length = 3;
    let segments = VigenereCipher::segment_text(&mut text, key_length).unwrap();
    let caesars = VigenereCipher::create_caesars(segments, key_length);
    let mut shifts: Vec<u8> = Vec::new();

    for caesar in &caesars {
      let mut buf = Cursor::new(caesar.clone().into_bytes());
      let (_, shift) = CaesarCipher::find_best_caesar_shift(&mut buf).unwrap();
      shifts.push(shift);
    }

    let key: String =
      shifts.iter().map(|&shift| (b'A' + shift) as char).collect();

    let mut output = Vec::new();

    VigenereCipher::decrypt_with_key(
      &mut Cursor::new(input.as_bytes()),
      &mut output,
      &key,
    )
    .unwrap();

    let plaintext = String::from_utf8(output).unwrap();

    assert_eq!(plaintext, "EITNNRAE");
  }

  #[test]
  #[ignore]
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
