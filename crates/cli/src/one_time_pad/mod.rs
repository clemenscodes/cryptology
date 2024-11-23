use std::{
  fmt::Display,
  io::{Error, ErrorKind, Read, Write},
};

use crate::{hex::Hex, xor::Xor, DecryptCipher, EncryptCipher};

#[derive(Default, Debug)]
pub struct OneTimePadDecryptConfig {
  pub key: Option<String>,
  pub raw_input: bool,
  pub raw_key: bool,
  alpha: Option<Vec<u8>>,
  beta: Option<Vec<u8>>,
}

impl OneTimePadDecryptConfig {
  pub fn new(
    key: Option<String>,
    raw_input: bool,
    raw_key: bool,
    alpha: Option<Vec<u8>>,
    beta: Option<Vec<u8>>,
  ) -> Self {
    Self {
      key,
      raw_input,
      raw_key,
      alpha,
      beta,
    }
  }

  pub fn set_alpha(&mut self, alpha: Option<Vec<u8>>) {
    self.alpha = alpha;
  }

  pub fn set_beta(&mut self, beta: Option<Vec<u8>>) {
    self.beta = beta;
  }

  pub fn validate(&self) -> std::io::Result<()> {
    let alpha = self.alpha()?;
    let beta = self.beta()?;

    if alpha.len() > beta.len() {
      let message = "Key must not have less bytes than the input";
      return Err(Error::new(ErrorKind::Other, message));
    }

    Ok(())
  }

  pub fn alpha(&self) -> std::io::Result<Vec<u8>> {
    if let Some(alpha) = &self.alpha {
      Ok(alpha.to_vec())
    } else {
      let message = "Could not get input bytes";
      Err(Error::new(ErrorKind::Other, message))
    }
  }

  pub fn beta(&self) -> std::io::Result<Vec<u8>> {
    if let Some(beta) = &self.beta {
      Ok(beta.to_vec())
    } else {
      let message = "Could not get key bytes";
      Err(Error::new(ErrorKind::Other, message))
    }
  }
}

impl From<&DecryptCipher> for OneTimePadDecryptConfig {
  fn from(value: &DecryptCipher) -> Self {
    match value {
      DecryptCipher::OneTimePad {
        key,
        raw_input,
        raw_key,
        ..
      } => OneTimePadDecryptConfig::new(
        key.key.clone(),
        *raw_input,
        *raw_key,
        None,
        None,
      ),
      _ => OneTimePadDecryptConfig::default(),
    }
  }
}

#[derive(Default, Debug)]
pub struct OneTimePadEncryptConfig {
  pub key: String,
  pub raw_input: bool,
  pub raw_key: bool,
  alpha: Option<Vec<u8>>,
  beta: Option<Vec<u8>>,
}

impl OneTimePadEncryptConfig {
  pub fn new(
    key: String,
    raw_input: bool,
    raw_key: bool,
    alpha: Option<Vec<u8>>,
    beta: Option<Vec<u8>>,
  ) -> Self {
    Self {
      key,
      raw_input,
      raw_key,
      alpha,
      beta,
    }
  }

  pub fn set_alpha(&mut self, alpha: Option<Vec<u8>>) {
    self.alpha = alpha;
  }

  pub fn set_beta(&mut self, beta: Option<Vec<u8>>) {
    self.beta = beta;
  }

  pub fn validate(&self) -> std::io::Result<()> {
    let alpha = self.alpha()?;
    let beta = self.beta()?;

    if alpha.len() > beta.len() {
      let message = "Key must not have less bytes than the input";
      return Err(Error::new(ErrorKind::Other, message));
    }

    Ok(())
  }

  pub fn alpha(&self) -> std::io::Result<Vec<u8>> {
    if let Some(alpha) = &self.alpha {
      Ok(alpha.to_vec())
    } else {
      let message = "Could not get input bytes";
      Err(Error::new(ErrorKind::Other, message))
    }
  }

  pub fn beta(&self) -> std::io::Result<Vec<u8>> {
    if let Some(beta) = &self.beta {
      Ok(beta.to_vec())
    } else {
      let message = "Could not get key bytes";
      Err(Error::new(ErrorKind::Other, message))
    }
  }
}

impl From<&EncryptCipher> for OneTimePadEncryptConfig {
  fn from(value: &EncryptCipher) -> Self {
    match value {
      EncryptCipher::OneTimePad {
        key,
        raw_input,
        raw_key,
        ..
      } => OneTimePadEncryptConfig::new(
        key.key.clone(),
        *raw_input,
        *raw_key,
        None,
        None,
      ),
      _ => OneTimePadEncryptConfig::default(),
    }
  }
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct OneTimePad {
  pub xor: Xor,
}

impl Display for OneTimePad {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    let xor = &self.xor;
    write!(f, "{xor}")
  }
}

impl OneTimePad {
  pub fn new(xor: Xor) -> Self {
    Self { xor }
  }

  pub fn encrypt<R: Read, W: Write>(
    input: &mut R,
    output: &mut W,
    config: &mut OneTimePadEncryptConfig,
  ) -> std::io::Result<Self> {
    let mut plaintext = String::new();

    input.read_to_string(&mut plaintext)?;

    let alpha = if config.raw_input {
      Hex::parse_hex(&plaintext).unwrap()
    } else {
      plaintext.try_into().unwrap()
    };

    let beta = if config.raw_key {
      Hex::parse_hex(&config.key).unwrap()
    } else {
      config.key.as_str().try_into().unwrap()
    };

    config.set_alpha(Some(alpha.bytes.clone()));
    config.set_beta(Some(beta.bytes.clone()));

    config.validate()?;

    let xor = Xor::xor_bytes_padded(&alpha.bytes, &beta.bytes, 0);
    let otp = Self::new(xor);

    write!(output, "{otp}")?;

    Ok(otp)
  }

  pub fn decrypt<R: Read, W: Write>(
    input: &mut R,
    output: &mut W,
    config: &mut OneTimePadDecryptConfig,
  ) -> std::io::Result<Self> {
    let mut ciphertext = String::new();

    input.read_to_string(&mut ciphertext)?;

    if let Some(key) = &config.key {
      let alpha = if config.raw_input {
        Hex::parse_hex(&ciphertext).unwrap()
      } else {
        ciphertext.try_into().unwrap()
      };

      let beta = if config.raw_key {
        Hex::parse_hex(key).unwrap()
      } else {
        key.as_str().try_into().unwrap()
      };

      config.set_alpha(Some(alpha.bytes.clone()));
      config.set_beta(Some(beta.bytes.clone()));

      config.validate()?;

      let xor = Xor::xor_bytes_padded(&alpha.bytes, &beta.bytes, 0);
      let otp = Self::new(xor);

      write!(output, "{otp}")?;

      return Ok(otp);
    }

    todo!();
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

    let mut cfg = OneTimePadEncryptConfig {
      key: String::from("World"),
      raw_input: false,
      raw_key: false,
      alpha: None,
      beta: None,
    };

    let otp = OneTimePad::encrypt(&mut input, &mut output, &mut cfg).unwrap();

    let expected = vec![
      b'H' ^ b'W',
      b'e' ^ b'o',
      b'l' ^ b'r',
      b'l' ^ b'l',
      b'o' ^ b'd',
    ];

    assert_eq!(otp.xor.hex.bytes, expected);
  }

  #[test]
  fn test_otp_decrypt() {
    let mut input = Command::get_readable("Hello");
    let mut output = Vec::new();

    let mut cfg = OneTimePadDecryptConfig {
      key: Some(String::from("World")),
      raw_input: false,
      raw_key: false,
      alpha: None,
      beta: None,
    };

    let otp = OneTimePad::decrypt(&mut input, &mut output, &mut cfg).unwrap();

    let expected = vec![
      b'H' ^ b'W',
      b'e' ^ b'o',
      b'l' ^ b'r',
      b'l' ^ b'l',
      b'o' ^ b'd',
    ];

    assert_eq!(otp.xor.hex.bytes, expected);
  }

  #[test]
  fn test_otp_decrypt_key_length_too_short() {
    let mut input = Command::get_readable("ABC");
    let mut output = Vec::new();

    let mut cfg = OneTimePadDecryptConfig {
      key: Some(String::from("0000")),
      raw_input: false,
      raw_key: true,
      alpha: None,
      beta: None,
    };

    let otp = OneTimePad::decrypt(&mut input, &mut output, &mut cfg);

    let otp_err = otp.unwrap_err();

    let message = "Key must not have less bytes than the input";

    assert_eq!(otp_err.to_string(), message);
  }

  #[test]
  fn test_otp_example() {
    let mut input = Command::get_readable("attack at dawn");
    let mut output = Vec::new();

    let ciphertext = String::from("09e1c5f70a65ac519458e7e53f36");

    let mut cfg = OneTimePadEncryptConfig {
      key: ciphertext,
      raw_input: false,
      raw_key: true,
      alpha: None,
      beta: None,
    };

    let key = OneTimePad::encrypt(&mut input, &mut output, &mut cfg).unwrap();

    let mut input = Command::get_readable("attack at dusk");

    let key = format!("{key}");

    let mut cfg = OneTimePadEncryptConfig {
      key,
      raw_input: false,
      raw_key: true,
      alpha: None,
      beta: None,
    };

    let otp = OneTimePad::encrypt(&mut input, &mut output, &mut cfg).unwrap();

    let result = format!("{otp}");

    let expected = "09e1c5f70a65ac519458e7f13b33";

    assert_eq!(result, expected)
  }
}
