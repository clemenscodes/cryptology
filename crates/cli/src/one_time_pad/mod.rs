use std::io::{Read, Result, Write};

use crate::{Command, DecryptCipher, EncryptCipher};

#[derive(Default, Debug)]
pub struct OneTimePadDecryptConfig {
  pub key: Option<String>,
}

impl OneTimePadDecryptConfig {
  pub fn new(key: Option<String>) -> Self {
    Self { key }
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

pub struct OneTimePad;

impl OneTimePad {
  pub fn encrypt<R: Read, W: Write>(
    input: &mut R,
    output: &mut W,
    config: OneTimePadEncryptConfig,
  ) -> Result<()> {
    Ok(())
  }

  pub fn decrypt<R: Read, W: Write>(
    input: &mut R,
    output: &mut W,
    config: OneTimePadDecryptConfig,
  ) -> Result<()> {
    Ok(())
  }

  /// Performs XOR operation between two buffers of equal length.
  fn xor_buffers(input: &[u8], key: &[u8]) -> Vec<u8> {
    input.iter().zip(key.iter()).map(|(x, y)| x ^ y).collect()
  }
}
