use std::{
  fmt::Display,
  io::{Error, ErrorKind, Read, Result, Write},
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

  pub fn validate(&self, input_length: usize) -> Result<()> {
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

  pub fn validate(&self, input_length: usize) -> Result<()> {
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
  ) -> Result<Self> {
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
  ) -> Result<Self> {
    let mut ciphertext = String::new();

    input.read_to_string(&mut ciphertext)?;

    config.validate(ciphertext.len())?;

    if let Some(key) = &config.key {
      let alpha = ciphertext.as_bytes();
      let beta = key.as_bytes();
      let bytes = Self::xor(alpha, beta);
      let otp = Self { bytes };

      write!(output, "{otp}")?;

      return Ok(otp);
    }

    todo!();
  }

  fn xor(alpha: &[u8], beta: &[u8]) -> Vec<u8> {
    alpha
      .iter()
      .zip(beta.iter())
      .map(|(alpha, beta)| alpha ^ beta)
      .collect()
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
    let alpha = b"Hello";
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
}
