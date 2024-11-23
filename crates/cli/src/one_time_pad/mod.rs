use std::{
  fmt::Display,
  io::{Read, Write},
};

use crate::{hex::Hex, xor::Xor, DecryptCipher, EncryptCipher};

#[derive(Default, Debug)]
pub struct OneTimePadDecryptConfig {
  pub key: Option<String>,
  pub raw_input: bool,
  pub raw_key: bool,
}

impl OneTimePadDecryptConfig {
  pub fn new(key: Option<String>, raw_input: bool, raw_key: bool) -> Self {
    Self {
      key,
      raw_input,
      raw_key,
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
      } => OneTimePadDecryptConfig::new(key.key.clone(), *raw_input, *raw_key),
      _ => OneTimePadDecryptConfig::default(),
    }
  }
}

#[derive(Default, Debug)]
pub struct OneTimePadEncryptConfig {
  pub key: String,
  pub raw_input: bool,
  pub raw_key: bool,
}

impl OneTimePadEncryptConfig {
  pub fn new(key: String, raw_input: bool, raw_key: bool) -> Self {
    Self {
      key,
      raw_input,
      raw_key,
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
      } => OneTimePadEncryptConfig::new(key.key.clone(), *raw_input, *raw_key),
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

    let xor = Xor::xor_bytes_padded(&alpha.bytes, &beta.bytes, 0);
    let otp = Self::new(xor);

    write!(output, "{otp}")?;

    Ok(otp)
  }

  pub fn decrypt<R: Read, W: Write>(
    input: &mut R,
    output: &mut W,
    config: &mut OneTimePadDecryptConfig,
  ) -> std::io::Result<()> {
    let mut ciphertext = String::new();

    input.read_to_string(&mut ciphertext)?;

    for line in ciphertext.lines() {
      let plaintext = Self::decrypt_line(line, config)?;
      write!(output, "{plaintext}")?;
    }

    Ok(())
  }

  pub fn decrypt_line(
    line: &str,
    config: &mut OneTimePadDecryptConfig,
  ) -> std::io::Result<String> {
    let key = config.key.clone().unwrap_or_default();

    let alpha = if config.raw_input {
      Hex::parse_hex(line).unwrap()
    } else {
      line.try_into().unwrap()
    };

    let beta = if config.raw_key {
      Hex::parse_hex(key.as_str()).unwrap()
    } else {
      key.try_into().unwrap()
    };

    let xor = Xor::xor_bytes_padded(&alpha.bytes, &beta.bytes, 0);
    let otp = Self::new(xor);

    Ok(format!("{otp}"))
  }
}

#[cfg(test)]
mod tests {
  use std::{fs::File, path::PathBuf};

  use crate::Command;

  use super::*;

  #[test]
  fn test_otp() {
    let mut input = Command::get_readable("Hello");
    let mut output = Vec::new();

    let mut cfg = OneTimePadDecryptConfig {
      key: Some(String::from("World")),
      raw_input: false,
      raw_key: false,
    };

    OneTimePad::decrypt(&mut input, &mut output, &mut cfg).unwrap();

    let result = Hex::new(output);

    let expected = vec![
      b'H' ^ b'W',
      b'e' ^ b'o',
      b'l' ^ b'r',
      b'l' ^ b'l',
      b'o' ^ b'd',
    ];

    println!("{result}");
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
    };

    let key = OneTimePad::encrypt(&mut input, &mut output, &mut cfg).unwrap();

    let mut input = Command::get_readable("attack at dusk");

    let key = format!("{key}");

    let mut cfg = OneTimePadEncryptConfig {
      key,
      raw_input: false,
      raw_key: true,
    };

    let otp = OneTimePad::encrypt(&mut input, &mut output, &mut cfg).unwrap();

    let result = format!("{otp}");

    let expected = "09e1c5f70a65ac519458e7f13b33";

    assert_eq!(result, expected)
  }

  #[test]
  fn test_otp_derive_plaintexts() -> std::io::Result<()> {
    let assets = "src/one_time_pad/assets";
    let path = std::env::var("CARGO_MANIFEST_DIR")
      .map(|dir| PathBuf::from(dir).join(assets))
      .unwrap_or_else(|_| {
        std::env::current_dir()
          .expect("Failed to get current directory")
          .join("crates/cli")
          .join(assets)
      });

    let ciphertext = path.join("ciphertext-otp1.txt");
    let plaintext = path.join("plaintext-otp1.txt");
    let output_path = path.join("output-otp1.txt");

    let mut ciphertext = File::open(&ciphertext)?;
    let plaintext = std::fs::read(&plaintext)?;
    let plaintext = String::from_utf8(plaintext).unwrap();

    let mut output = Vec::new();

    let mut cfg = OneTimePadDecryptConfig {
      key: Some(plaintext.trim_end().to_string()),
      raw_input: true,
      raw_key: false,
    };

    OneTimePad::decrypt(&mut ciphertext, &mut output, &mut cfg)?;

    println!("{output:#?}");

    Ok(())
  }
}
