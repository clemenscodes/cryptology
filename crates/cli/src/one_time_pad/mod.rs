use std::{
  fmt::Display,
  io::{Error, ErrorKind, Read, Write},
  num::ParseIntError,
};

use crate::{DecryptCipher, EncryptCipher};

#[derive(Default, Debug)]
pub struct OneTimePadDecryptConfig {
  pub key: Option<String>,
}

impl OneTimePadDecryptConfig {
  pub fn new(key: Option<String>) -> Self {
    Self { key }
  }

  pub fn validate(&self, input_length: usize) -> std::io::Result<()> {
    if let Some(key) = &self.key {
      let expected = key.len();

      if expected < input_length {
        let message = format!("Key length must be at least as long as the input length. [{expected}/{input_length}]");
        return Err(Error::new(ErrorKind::InvalidInput, message));
      }
    }

    Ok(())
  }
}

impl From<&DecryptCipher> for OneTimePadDecryptConfig {
  fn from(value: &DecryptCipher) -> Self {
    match value {
      DecryptCipher::OneTimePad { key, .. } => {
        OneTimePadDecryptConfig::new(key.key.clone())
      }
      _ => OneTimePadDecryptConfig::default(),
    }
  }
}

#[derive(Default, Debug)]
pub struct OneTimePadEncryptConfig {
  key: String,
}

impl OneTimePadEncryptConfig {
  pub fn new(key: &str) -> Self {
    Self {
      key: key.to_string(),
    }
  }

  pub fn validate(&self, input_length: usize) -> std::io::Result<()> {
    let expected = self.key.len();
    if expected < input_length {
      let message = format!("Key length must be at least as long as the input length. [{expected}/{input_length}]");
      return Err(Error::new(ErrorKind::InvalidInput, message));
    }
    Ok(())
  }
}

impl From<&EncryptCipher> for OneTimePadEncryptConfig {
  fn from(value: &EncryptCipher) -> Self {
    match value {
      EncryptCipher::OneTimePad { key, .. } => {
        OneTimePadEncryptConfig::new(&key.key)
      }
      _ => OneTimePadEncryptConfig::default(),
    }
  }
}

pub struct OneTimePad {
  bytes: Vec<u8>,
}

impl Display for OneTimePad {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    let hex = self
      .bytes
      .iter()
      .map(|byte| format!("{byte:02x}"))
      .collect::<Vec<_>>()
      .join("");
    write!(f, "{hex}")
  }
}

impl OneTimePad {
  pub fn encrypt<R: Read, W: Write>(
    input: &mut R,
    output: &mut W,
    config: OneTimePadEncryptConfig,
  ) -> std::io::Result<Self> {
    let mut plaintext = String::new();

    input.read_to_string(&mut plaintext)?;

    config.validate(plaintext.len())?;

    let alpha = plaintext.as_bytes();
    let beta = config.key.as_bytes();
    let bytes = Self::xor(alpha, beta);
    let otp = Self { bytes };

    write!(output, "{otp}")?;

    Ok(otp)
  }

  pub fn decrypt<R: Read, W: Write>(
    input: &mut R,
    output: &mut W,
    config: OneTimePadDecryptConfig,
  ) -> std::io::Result<Self> {
    let mut ciphertext = String::new();

    input.read_to_string(&mut ciphertext)?;

    let otp = Self::parse_hex_string(&ciphertext).unwrap();

    config.validate(ciphertext.len())?;

    if let Some(key) = &config.key {
      let alpha = format!("{otp}");
      let beta = key.as_bytes();
      let bytes = Self::xor(alpha.as_bytes(), beta);
      let otp = Self { bytes };

      write!(output, "{otp}")?;

      return Ok(otp);
    }

    todo!();
  }

  fn xor(alpha: &[u8], beta: &[u8]) -> Vec<u8> {
    let max_len = std::cmp::max(alpha.len(), beta.len());
    let alpha_padded = alpha.iter().chain(std::iter::repeat(&0)).take(max_len);
    let beta_padded = beta.iter().chain(std::iter::repeat(&0)).take(max_len);

    alpha_padded.zip(beta_padded).map(|(a, b)| a ^ b).collect()
  }

  fn parse_hex_string(hex: &str) -> Result<Self, HexParseError> {
    if hex.len() % 2 != 0 {
      return Err(HexParseError::InvalidLength);
    }

    let mut bytes = Vec::new();

    for index in (0..hex.len()).step_by(2) {
      let hex_pair = &hex[index..index + 2];
      let byte = u8::from_str_radix(hex_pair, 16)?;
      bytes.push(byte);
    }

    Ok(Self { bytes })
  }
}

#[derive(Debug)]
enum HexParseError {
  InvalidLength,
  InvalidHex(ParseIntError),
}

impl std::fmt::Display for HexParseError {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      HexParseError::InvalidLength => {
        write!(f, "Hex string must have an even length.")
      }
      HexParseError::InvalidHex(err) => {
        write!(f, "Failed to parse hex: {err}")
      }
    }
  }
}

impl From<ParseIntError> for HexParseError {
  fn from(err: ParseIntError) -> Self {
    HexParseError::InvalidHex(err)
  }
}

#[cfg(test)]
mod tests {
  use crate::Command;

  use super::*;

  #[test]
  fn test_otp_encrypt() {
    let mut input = Command::get_readable("Hello");
    let mut output = Vec::new();

    let config = OneTimePadEncryptConfig {
      key: String::from("World"),
    };

    let otp = OneTimePad::encrypt(&mut input, &mut output, config).unwrap();

    let expected = vec![
      b'H' ^ b'W',
      b'e' ^ b'o',
      b'l' ^ b'r',
      b'l' ^ b'l',
      b'o' ^ b'd',
    ];

    assert_eq!(otp.bytes, expected);
  }

  #[test]
  fn test_otp_decrypt() {
    let mut input = Command::get_readable("Hello");
    let mut output = Vec::new();

    let config = OneTimePadDecryptConfig {
      key: Some(String::from("World")),
    };

    let otp = OneTimePad::decrypt(&mut input, &mut output, config).unwrap();

    let expected = vec![
      b'H' ^ b'W',
      b'e' ^ b'o',
      b'l' ^ b'r',
      b'l' ^ b'l',
      b'o' ^ b'd',
    ];

    assert_eq!(otp.bytes, expected);
  }

  #[test]
  fn test_xor() {
    let alpha = b"Hell0";
    let beta = b"World";

    let result = OneTimePad::xor(alpha, beta);

    let expected = vec![
      b'H' ^ b'W',
      b'e' ^ b'o',
      b'l' ^ b'r',
      b'l' ^ b'l',
      b'o' ^ b'd',
    ];

    assert_eq!(result, expected);
  }

  #[test]
  fn test_otp_display() {
    let alpha = b"Hello";
    let beta = b"Hello";

    let bytes = OneTimePad::xor(alpha, beta);
    let otp = OneTimePad { bytes };

    let result = format!("{otp}");
    let expected = String::from("0000000000");

    assert_eq!(result, expected);
  }

  #[test]
  fn test_parse_hex() {
    let input = "e508";

    let otp = OneTimePad::parse_hex_string(input).unwrap();

    let expected = vec![229_u8, 8_u8];

    assert_eq!(otp.bytes, expected);
  }

  #[test]
  fn test_xor_with_key_longer_than_plaintext() {
    let plaintext = b"HELLO";
    let key = b"SECRETKEY";

    let expected_result = vec![27, 0, 15, 30, 10, 84, 75, 69, 89];
    let result = OneTimePad::xor(plaintext, key);

    assert_eq!(result, expected_result);
  }

  #[test]
  fn test_xor_with_plaintext_longer_than_key() {
    let plaintext = b"HELLOTHERE";
    let key = b"KEY";

    let expected_result = vec![3, 0, 21, 76, 79, 84, 72, 69, 82, 69];
    let result = OneTimePad::xor(plaintext, key);

    assert_eq!(result, expected_result);
  }

  #[test]
  fn test_xor_with_empty_inputs() {
    let alpha = b"";
    let beta = b"";

    let expected_result: Vec<u8> = vec![];
    let result = OneTimePad::xor(alpha, beta);

    assert_eq!(result, expected_result);
  }
}
