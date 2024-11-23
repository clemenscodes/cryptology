use std::{fmt::Display, io::Write, iter::repeat, path::PathBuf};

use crate::{hex::Hex, Command};

#[derive(Default, Debug, PartialEq, Eq)]
pub struct XorConfig {
  alpha: PathBuf,
  beta: PathBuf,
  raw_alpha: bool,
  raw_beta: bool,
}

impl XorConfig {
  pub fn new(
    alpha: PathBuf,
    beta: PathBuf,
    raw_alpha: bool,
    raw_beta: bool,
  ) -> Self {
    Self {
      alpha,
      beta,
      raw_alpha,
      raw_beta,
    }
  }
}

impl From<&Command> for XorConfig {
  fn from(value: &Command) -> Self {
    match value {
      Command::Xor {
        alpha,
        beta,
        raw_alpha,
        raw_beta,
        ..
      } => Self::new(
        alpha.to_path_buf(),
        beta.to_path_buf(),
        *raw_alpha,
        *raw_beta,
      ),
      _ => Self::default(),
    }
  }
}

#[derive(Default, PartialEq, Eq)]
pub struct Xor {
  pub hex: Hex,
}

impl Xor {
  pub fn new(hex: Hex) -> Self {
    Self { hex }
  }

  pub fn xor<W: Write>(
    config: XorConfig,
    output: &mut W,
  ) -> std::io::Result<()> {
    let alpha = std::fs::read(config.alpha)?;
    let beta = std::fs::read(config.beta)?;

    let alpha = if config.raw_alpha {
      let alpha = String::from_utf8(alpha).unwrap();
      Hex::parse_hex(&alpha).unwrap().bytes
    } else {
      let hex: Hex = alpha.try_into().unwrap();
      hex.bytes
    };

    let beta = if config.raw_beta {
      let beta = String::from_utf8(beta).unwrap();
      Hex::parse_hex(&beta).unwrap().bytes
    } else {
      let hex: Hex = beta.try_into().unwrap();
      hex.bytes
    };

    let xor = Self::xor_bytes_padded(&alpha, &beta, 0);

    write!(output, "{xor}")
  }

  pub fn xor_bytes(alpha: &[u8], beta: &[u8]) -> Self {
    let bytes = alpha
      .iter()
      .zip(beta.iter())
      .map(|(alpha, beta)| alpha ^ beta)
      .collect();

    Self::new(Hex::new(bytes))
  }

  pub fn xor_bytes_padded(alpha: &[u8], beta: &[u8], pad: u8) -> Self {
    let max_len = std::cmp::max(alpha.len(), beta.len());
    let alpha_padded = alpha.iter().chain(repeat(&pad)).take(max_len);
    let beta_padded = beta.iter().chain(repeat(&pad)).take(max_len);
    let bytes = alpha_padded.zip(beta_padded).map(|(a, b)| a ^ b).collect();

    Self::new(Hex::new(bytes))
  }
}

impl Display for Xor {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    let hex = &self.hex;
    write!(f, "{hex}")
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_xor() {
    let alpha = b"Hello";
    let beta = b"World";

    let result = Xor::xor_bytes(alpha, beta);

    let expected = vec![
      b'H' ^ b'W',
      b'e' ^ b'o',
      b'l' ^ b'r',
      b'l' ^ b'l',
      b'o' ^ b'd',
    ];

    assert_eq!(result.hex.bytes, expected);
  }

  #[test]
  fn test_xor_display() {
    let alpha = b"Hello";
    let beta = b"Hello";

    let xor = Xor::xor_bytes(alpha, beta);

    let result = format!("{xor}");
    let expected = String::from("0000000000");

    assert_eq!(result, expected);
  }

  #[test]
  fn test_xor_with_key_longer_than_plaintext() {
    let plaintext = b"HELLO";
    let key = b"SECRETKEY";

    let expected = vec![27, 0, 15, 30, 10, 84, 75, 69, 89];
    let result = Xor::xor_bytes_padded(plaintext, key, 0);

    assert_eq!(result.hex.bytes, expected);
  }

  #[test]
  fn test_xor_with_plaintext_longer_than_key() {
    let plaintext = b"HELLOTHERE";
    let key = b"KEY";

    let expected = vec![3, 0, 21, 76, 79, 84, 72, 69, 82, 69];
    let result = Xor::xor_bytes_padded(plaintext, key, 0);

    assert_eq!(result.hex.bytes, expected);
  }

  #[test]
  fn test_xor_with_empty_inputs() {
    let alpha = b"";
    let beta = b"";

    let expected: Vec<u8> = vec![];
    let result = Xor::xor_bytes(alpha, beta);

    assert_eq!(result.hex.bytes, expected);
  }
}
