use std::{
  collections::BTreeMap,
  io::{Read, Write},
};

use crate::xor::Xor;

pub type XorCombination = BTreeMap<(usize, usize), Xor>;

#[derive(Default, PartialEq, Eq)]
pub struct ManyTimePad {
  combination: XorCombination,
}

impl ManyTimePad {
  pub fn encrypt<R: Read, W: Write>(
    _input: &mut R,
    _output: &mut W,
  ) -> std::io::Result<()> {
    Ok(())
  }

  pub fn decrypt<R: Read, W: Write>(
    _input: &mut R,
    _output: &mut W,
  ) -> std::io::Result<()> {
    Ok(())
  }

  pub fn is_space_candidate(byte: u8) -> bool {
    let candidate = Self::get_candidate(byte);
    candidate.is_ascii_alphabetic()
  }

  pub fn get_candidate(byte: u8) -> u8 {
    let space = 0x20;
    byte ^ space
  }

  pub fn xor_all_combinations(
    ciphertexts: &[Vec<u8>],
    pad: u8,
  ) -> XorCombination {
    let mut results = XorCombination::new();

    for (i, alpha) in ciphertexts.iter().enumerate() {
      for (j, beta) in ciphertexts.iter().enumerate().skip(i + 1) {
        let xor_result = Xor::xor_bytes(alpha, beta, pad);
        results.insert((i, j), xor_result);
      }
    }

    results
  }

  /// Map a single vector of bytes to possible plaintext bytes where a space is a candidate
  pub fn map_plaintext_candidates(xor_result: &[u8]) -> Vec<Option<u8>> {
    xor_result
      .iter()
      .map(|&byte| {
        if Self::is_space_candidate(byte) {
          Some(Self::get_candidate(byte))
        } else {
          None
        }
      })
      .collect()
  }

  /// Map all XOR combinations to potential plaintext candidates
  pub fn map_all_combinations_to_candidates(
    combinations: &XorCombination,
  ) -> BTreeMap<(usize, usize), Vec<Option<u8>>> {
    combinations
      .iter()
      .map(|(&(i, j), xor)| {
        let candidates = Self::map_plaintext_candidates(xor.bytes());
        ((i, j), candidates)
      })
      .collect()
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_is_space_candidate() {
    assert!(ManyTimePad::is_space_candidate(0x41));
    assert!(ManyTimePad::is_space_candidate(0x61));
    assert!(!ManyTimePad::is_space_candidate(b'@'));
    assert!(!ManyTimePad::is_space_candidate(b'`'));
    assert!(!ManyTimePad::is_space_candidate(b'*'));
    assert!(!ManyTimePad::is_space_candidate(0x00));
    assert!(!ManyTimePad::is_space_candidate(0x01));
    assert!(!ManyTimePad::is_space_candidate(0x7F));
    assert!(!ManyTimePad::is_space_candidate(0xFF));
  }

  #[test]
  fn test_xor_all_combinations_basic() {
    let ciphertexts = vec![
      vec![0x4c, 0xa0, 0x0f, 0xf4],
      vec![0x5b, 0x1e, 0x39, 0x41],
      vec![0x6a, 0xd3, 0xf3, 0xbc],
    ];
    let pad = 0x00;
    let results = ManyTimePad::xor_all_combinations(&ciphertexts, pad);
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
    let results = ManyTimePad::xor_all_combinations(&ciphers, pad);
    let expected_1_2 = vec![0x5b, 0x52, 0x99, 0x4e];
    assert_eq!(results.get(&(0, 1)).unwrap().bytes(), expected_1_2);
  }

  #[test]
  fn test_map_plaintext_candidates_valid() {
    let xor_result = vec![b'A', b'a', b'.'];
    let candidates = ManyTimePad::map_plaintext_candidates(&xor_result);
    assert_eq!(candidates[0], Some(b'a'));
    assert_eq!(candidates[1], Some(b'A'));
    assert_eq!(candidates[2], None);
  }
}
