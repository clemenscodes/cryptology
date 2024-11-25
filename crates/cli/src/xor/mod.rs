use std::{
  fmt::Display,
  io::Write,
  iter::{Chain, Copied, Repeat, Take},
  path::PathBuf,
  slice::Iter,
};

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

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Xor {
  pub hex: Hex,
}

impl From<Vec<u8>> for Xor {
  fn from(value: Vec<u8>) -> Self {
    let hex = value.into();
    Self { hex }
  }
}

impl From<&[u8]> for Xor {
  fn from(value: &[u8]) -> Self {
    value.to_vec().into()
  }
}

impl From<&str> for Xor {
  fn from(value: &str) -> Self {
    value.as_bytes().into()
  }
}

impl From<String> for Xor {
  fn from(value: String) -> Self {
    value.as_str().into()
  }
}

impl From<Hex> for Xor {
  fn from(value: Hex) -> Self {
    Self { hex: value }
  }
}

impl Display for Xor {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    let hex = &self.hex;
    write!(f, "{hex}")
  }
}

impl Xor {
  pub fn xor<W: Write>(
    config: XorConfig,
    output: &mut W,
  ) -> std::io::Result<()> {
    let alpha = std::fs::read(config.alpha)?;
    let beta = std::fs::read(config.beta)?;
    let alpha = Self::prepare_input(alpha, config.raw_alpha)?;
    let beta = Self::prepare_input(beta, config.raw_beta)?;
    let xor = Self::xor_bytes(&alpha, &beta, 0);

    write!(output, "{xor}")
  }

  pub fn xor_bytes(alpha: &[u8], beta: &[u8], pad: u8) -> Self {
    let max_len = std::cmp::max(alpha.len(), beta.len());
    let alpha = Self::pad_slice(alpha, max_len, pad);
    let beta = Self::pad_slice(beta, max_len, pad);
    let bytes = alpha.zip(beta).map(|(a, b)| a ^ b).collect::<Vec<u8>>();
    bytes.into()
  }

  pub fn bytes(&self) -> &[u8] {
    self.hex.bytes()
  }

  pub fn to_ascii(&self) -> String {
    self.hex.to_ascii()
  }

  fn prepare_input(input: Vec<u8>, is_raw: bool) -> std::io::Result<Vec<u8>> {
    if is_raw {
      let input_str = String::from_utf8(input)
        .expect("Input is not valid UTF-8")
        .trim_end()
        .to_string();

      let bytes = Hex::parse_hex(&input_str)
        .expect("Failed to parse raw hex")
        .bytes;

      Ok(bytes)
    } else {
      Ok(input)
    }
  }

  fn pad_slice(
    slice: &[u8],
    max_len: usize,
    pad: u8,
  ) -> Chain<Take<Repeat<u8>>, Copied<Iter<'_, u8>>> {
    std::iter::repeat(pad)
      .take(max_len - slice.len())
      .chain(slice.iter().copied())
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_xor() {
    let alpha = b"Hello";
    let beta = b"World";

    let result = Xor::xor_bytes(alpha, beta, 0x00);

    let expected = vec![
      b'H' ^ b'W',
      b'e' ^ b'o',
      b'l' ^ b'r',
      b'l' ^ b'l',
      b'o' ^ b'd',
    ];

    assert_eq!(result.bytes(), expected);
  }

  #[test]
  fn test_xor_display() {
    let alpha = b"Hello";
    let beta = b"Hello";

    let xor = Xor::xor_bytes(alpha, beta, 0x00);

    let result = format!("{xor}");
    let expected = String::from("0000000000");

    assert_eq!(result, expected);
  }

  #[test]
  fn test_xor_with_empty_inputs() {
    let alpha = b"";
    let beta = b"";

    let expected: Vec<u8> = vec![];
    let result = Xor::xor_bytes(alpha, beta, 0x00);

    assert_eq!(result.bytes(), expected);
  }

  #[test]
  fn test_xor_bytes_padded_same_length() {
    let alpha = vec![0b1100_1100, 0b1010_1010];
    let beta = vec![0b0011_0011, 0b0101_0101];
    let result = Xor::xor_bytes(&alpha, &beta, 0x00);
    let expected = vec![0b1111_1111, 0b1111_1111];
    assert_eq!(result.bytes(), expected);
  }

  #[test]
  fn test_xor_bytes_padded_alpha_shorter() {
    let alpha = vec![0b1100_1100];
    let beta = vec![0b0011_0011, 0b0101_0101];
    let result = Xor::xor_bytes(&alpha, &beta, 0x00);
    let expected = vec![0b0011_0011, 0b1001_1001];
    assert_eq!(result.bytes(), expected);
  }

  #[test]
  fn test_xor_bytes_padded_beta_shorter() {
    let alpha = vec![0b1100_1100, 0b1010_1010];
    let beta = vec![0b0011_0011];
    let result = Xor::xor_bytes(&alpha, &beta, 0x00);
    let expected = vec![0b1100_1100, 0b1001_1001];
    assert_eq!(result.bytes(), expected);
  }

  #[test]
  fn test_xor_bytes_padded_with_non_zero_pad() {
    let alpha = vec![0b1100_1100];
    let beta = vec![0b0011_0011, 0b0101_0101];
    let pad = 0b1111_1111;
    let result = Xor::xor_bytes(&alpha, &beta, pad);
    let expected = vec![0b1100_1100, 0b1001_1001];
    assert_eq!(result.bytes(), expected);
  }

  #[test]
  fn test_xor_bytes_padded_empty_alpha() {
    let alpha: Vec<u8> = vec![];
    let beta = vec![0b0011_0011, 0b0101_0101];
    let result = Xor::xor_bytes(&alpha, &beta, 0x00);
    assert_eq!(result.bytes(), beta);
  }

  #[test]
  fn test_xor_bytes_padded_empty_beta() {
    let alpha = vec![0b1100_1100, 0b1010_1010];
    let beta: Vec<u8> = vec![];
    let result = Xor::xor_bytes(&alpha, &beta, 0x00);
    assert_eq!(result.bytes(), alpha);
  }

  #[test]
  fn test_xor_bytes_padded_empty_both() {
    let alpha: Vec<u8> = vec![];
    let beta: Vec<u8> = vec![];
    let result = Xor::xor_bytes(&alpha, &beta, 0x00);
    let expected: Vec<u8> = vec![];
    assert_eq!(result.bytes(), expected);
  }
}
