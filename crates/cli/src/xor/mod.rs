use std::{collections::BTreeMap, fmt::Display, io::Write, path::PathBuf};

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
      let alpha = alpha.trim_end().to_string();
      Hex::parse_hex(&alpha)
        .expect("Failed to parse raw alpha")
        .bytes
    } else {
      let hex: Hex = alpha.try_into().expect("Failed to parse ascii alpha");
      hex.bytes().to_vec()
    };

    let beta = if config.raw_beta {
      let beta = String::from_utf8(beta).unwrap();
      let beta = beta.trim_end().to_string();
      Hex::parse_hex(&beta)
        .expect("Failed to parse raw beta")
        .bytes
    } else {
      let hex: Hex = beta.try_into().expect("Failed to parse ascii beta");
      hex.bytes().to_vec()
    };

    let xor = Self::xor_bytes(&alpha, &beta, 0);

    write!(output, "{xor}")
  }

  pub fn xor_bytes(alpha: &[u8], beta: &[u8], pad: u8) -> Self {
    let max_len = std::cmp::max(alpha.len(), beta.len());

    let alpha_padded = std::iter::repeat(&pad)
      .take(max_len - alpha.len())
      .chain(alpha.iter());
    let beta_padded = std::iter::repeat(&pad)
      .take(max_len - beta.len())
      .chain(beta.iter());

    let bytes = alpha_padded.zip(beta_padded).map(|(a, b)| a ^ b).collect();

    Self::new(Hex::new(bytes))
  }

  pub fn xor_all_combinations(
    ciphertexts: &[Vec<u8>],
    pad: u8,
  ) -> BTreeMap<(usize, usize), Self> {
    let mut results = BTreeMap::new();

    for (i, alpha) in ciphertexts.iter().enumerate() {
      for (j, beta) in ciphertexts.iter().enumerate().skip(i + 1) {
        let xor_result = Self::xor_bytes(alpha, beta, pad);
        results.insert((i, j), xor_result);
      }
    }

    results
  }

  pub fn bytes(&self) -> &[u8] {
    self.hex.bytes()
  }

  pub fn to_ascii(&self) -> String {
    self.hex.to_ascii()
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

  #[test]
  fn test_xor_all_combinations_basic() {
    let ciphertexts = vec![
      vec![0x4c, 0xa0, 0x0f, 0xf4],
      vec![0x5b, 0x1e, 0x39, 0x41],
      vec![0x6a, 0xd3, 0xf3, 0xbc],
    ];

    let pad = 0x00;

    let results = Xor::xor_all_combinations(&ciphertexts, pad);

    let expected_1_2 = vec![0x17, 0xbe, 0x36, 0xb5];
    let expected_1_3 = vec![0x26, 0x73, 0xfc, 0x48];
    let expected_2_3 = vec![0x31, 0xcd, 0xca, 0xfd];

    assert_eq!(results.get(&(0, 1)).unwrap().bytes(), expected_1_2);
    assert_eq!(results.get(&(0, 2)).unwrap().bytes(), expected_1_3);
    assert_eq!(results.get(&(1, 2)).unwrap().bytes(), expected_2_3);
  }

  #[test]
  fn test_xor_all_combinations_with_padding() {
    let ciphers = vec![vec![0x4c, 0xa0, 0x0f], vec![0x5b, 0x1e, 0x39, 0x41]];

    let pad = 0x00;

    let results = Xor::xor_all_combinations(&ciphers, pad);

    // Adjust the shorter ciphertext to prepend the padding
    // Cipher 1: [0x00, 0x4c, 0xa0, 0x0f]
    // Cipher 2: [0x5b, 0x1e, 0x39, 0x41]
    // XOR:      [0x5b, 0x52, 0x99, 0x4e]
    let expected_1_2 = vec![0x5b, 0x52, 0x99, 0x4e];

    assert_eq!(results.get(&(0, 1)).unwrap().bytes(), expected_1_2);
  }
}
