use std::{
  collections::BTreeMap,
  io::{Read, Write},
};

use crate::{hex::Hex, xor::Xor};

pub type XorCombination = BTreeMap<(usize, usize), Xor>;

pub type PlaintextCandidates = BTreeMap<(usize, usize), BTreeMap<u8, usize>>;

pub type PlaintextDeductions = BTreeMap<(usize, usize), u8>;

const SPACE: u8 = 0x20;

#[derive(Default, PartialEq, Eq)]
pub struct ManyTimePad {
  combination: XorCombination,
}

impl ManyTimePad {
  pub fn decrypt<R: Read, W: Write>(
    input: &mut R,
    output: &mut W,
  ) -> std::io::Result<()> {
    let mut buf = String::new();

    input.read_to_string(&mut buf)?;

    let ciphertexts: Vec<Hex> = buf
      .lines()
      .map(|line| {
        Hex::parse_hex(line).expect("Failed to parse line {line} as hex")
      })
      .collect();

    let combinations = Self::xor_all_combinations(&ciphertexts);
    let candidates = Self::candidates(&combinations, &ciphertexts);
    let deductions = Self::deduce_plaintexts(candidates);
    let plaintexts = Self::get_plaintexts(&deductions);
    let key = Self::recover_key(&ciphertexts, &plaintexts);
    let plaintexts = Self::derive_plaintexts(&ciphertexts, &key.into());
    let message = plaintexts.last().unwrap();

    writeln!(output, "{message}")?;

    Ok(())
  }

  pub fn get_candidate(byte: u8) -> u8 {
    byte ^ SPACE
  }

  pub fn is_space_candidate(byte: u8) -> bool {
    let candidate = Self::get_candidate(byte);
    candidate.is_ascii_alphabetic()
  }

  pub fn xor_all_combinations(ciphertexts: &[Hex]) -> XorCombination {
    let mut results = XorCombination::new();

    for (i, alpha) in ciphertexts.iter().enumerate() {
      for (j, beta) in ciphertexts
        .iter()
        .enumerate()
        .skip(i + 1)
      {
        results.insert((i, j), Xor::xor_key(alpha.bytes(), beta.bytes()));
      }
    }

    results
  }

  pub fn candidates(
    combinations: &XorCombination,
    ciphertexts: &[Hex],
  ) -> PlaintextCandidates {
    let mut candidates: PlaintextCandidates = PlaintextCandidates::new();

    for (&(alpha_index, beta_index), xor) in combinations {
      let c1_len = ciphertexts[alpha_index].bytes().len();
      let c2_len = ciphertexts[beta_index].bytes().len();

      for (pos, &byte) in xor.bytes().iter().enumerate() {
        if !Self::is_space_candidate(byte) {
          continue;
        }

        let p2 = Self::get_candidate(byte);

        if p2.is_ascii_graphic() || p2 == SPACE {
          if pos < c1_len {
            Self::update_candidates(&mut candidates, alpha_index, pos, SPACE);
          }

          if pos < c2_len {
            Self::update_candidates(&mut candidates, beta_index, pos, p2);
          }
        }

        let p1 = Self::get_candidate(byte);

        if p1.is_ascii_graphic() || p1 == SPACE {
          if pos < c1_len {
            Self::update_candidates(&mut candidates, alpha_index, pos, p1);
          }

          if pos < c2_len {
            Self::update_candidates(&mut candidates, beta_index, pos, SPACE);
          }
        }
      }
    }

    candidates
  }

  fn update_candidates(
    candidates: &mut PlaintextCandidates,
    alpha_index: usize,
    beta_index: usize,
    candidate: u8,
  ) {
    *candidates
      .entry((alpha_index, beta_index))
      .or_default()
      .entry(candidate)
      .or_insert(0) += 1
  }

  pub fn deduce_plaintexts(
    candidates: PlaintextCandidates,
  ) -> PlaintextDeductions {
    candidates
      .into_iter()
      .filter_map(|((ciphertext_index, pos), char_counts)| {
        let mut sorted_counts: Vec<_> = char_counts.into_iter().collect();
        sorted_counts.sort_by_key(|&(_, count)| std::cmp::Reverse(count));

        if let Some((best_byte, best_count)) = sorted_counts.first() {
          let next_count = sorted_counts
            .get(1)
            .map(|&(_, count)| count)
            .unwrap_or(0);
          if *best_byte == SPACE {
            if (*best_count as f64) >= 1.7 * (next_count as f64) {
              return Some(((ciphertext_index, pos), *best_byte));
            } else if let Some((next_byte, _)) = sorted_counts.get(1) {
              return Some(((ciphertext_index, pos), *next_byte));
            }
          } else {
            return Some(((ciphertext_index, pos), *best_byte));
          }
        }
        None
      })
      .collect()
  }

  pub fn get_plaintexts(deductions: &PlaintextDeductions) -> Vec<String> {
    let mut plaintexts: Vec<Vec<char>> = vec![];

    for ((plaintext_index, character_index), &byte) in deductions.iter() {
      if plaintexts.len() <= *plaintext_index {
        plaintexts.resize(*plaintext_index + 1, Vec::new());
      }

      if plaintexts[*plaintext_index].len() <= *character_index {
        plaintexts[*plaintext_index].resize(*character_index + 1, ' ');
      }

      plaintexts[*plaintext_index][*character_index] = byte as char;
    }

    plaintexts
      .into_iter()
      .map(|chars| chars.into_iter().collect())
      .collect()
  }

  pub fn recover_key(ciphertexts: &[Hex], plaintexts: &[String]) -> Vec<u8> {
    let max_length = ciphertexts
      .iter()
      .map(|ct| ct.bytes().len())
      .min()
      .unwrap_or(0);

    let mut key: Vec<Option<u8>> = vec![None; max_length];

    for i in 0..max_length {
      let mut possible_key_bytes = std::collections::BTreeMap::new();

      for (ciphertext, plaintext) in ciphertexts
        .iter()
        .zip(plaintexts.iter())
      {
        if i < ciphertext.bytes().len() && i < plaintext.len() {
          let ct_byte = ciphertext.bytes()[i];
          let pt_byte = plaintext.as_bytes()[i];

          if pt_byte != b' ' {
            let key_byte = ct_byte ^ pt_byte;
            *possible_key_bytes
              .entry(key_byte)
              .or_insert(0) += 1;
          }
        }
      }

      if let Some((&key_byte, _)) = possible_key_bytes
        .iter()
        .max_by_key(|&(_, count)| count)
      {
        key[i] = Some(key_byte);
      } else {
        key[i] = Some(0x00);
      }
    }

    key
      .into_iter()
      .map(|byte| byte.unwrap_or(0x00))
      .collect()
  }

  pub fn derive_plaintexts(ciphers: &[Hex], key: &Hex) -> Vec<String> {
    ciphers
      .iter()
      .map(|cipher| {
        Xor::xor_key(cipher.bytes(), key.bytes())
          .hex
          .to_ascii()
      })
      .collect()
  }

  pub fn test_key<R: Read, W: Write>(
    input: &mut R,
    output: &mut W,
  ) -> std::io::Result<()> {
    let mut buf = String::new();

    input.read_to_string(&mut buf)?;

    let ciphertexts: Vec<Hex> = buf
      .lines()
      .map(|line| {
        Hex::parse_hex(line).expect("Failed to parse line {line} as hex")
      })
      .collect();

    let combinations = Self::xor_all_combinations(&ciphertexts);
    let candidates = Self::candidates(&combinations, &ciphertexts);
    let deductions = Self::deduce_plaintexts(candidates);
    let plaintexts = Self::get_plaintexts(&deductions);
    let key: Hex = Self::recover_key(&ciphertexts, &plaintexts).into();

    write!(output, "{key}")?;

    Ok(())
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
    let ciphertexts: Vec<Hex> = vec![
      vec![0x4c, 0xa0, 0x0f, 0xf4].into(),
      vec![0x5b, 0x1e, 0x39, 0x41].into(),
      vec![0x6a, 0xd3, 0xf3, 0xbc].into(),
    ];
    let results = ManyTimePad::xor_all_combinations(&ciphertexts);
    let expected_1_2 = vec![0x17, 0xbe, 0x36, 0xb5];
    let expected_1_3 = vec![0x26, 0x73, 0xfc, 0x48];
    let expected_2_3 = vec![0x31, 0xcd, 0xca, 0xfd];
    assert_eq!(results.get(&(0, 1)).unwrap().bytes(), expected_1_2);
    assert_eq!(results.get(&(0, 2)).unwrap().bytes(), expected_1_3);
    assert_eq!(results.get(&(1, 2)).unwrap().bytes(), expected_2_3);
  }

  #[test]
  fn test_map_plaintext_candidates_valid() {
    let key = Hex::from("f g h");
    let plains = vec!["a b c", " d e ", "efghy"];
    let hexs: Vec<Hex> = plains
      .clone()
      .into_iter()
      .map(Hex::from)
      .collect();

    let ciphers: Vec<Hex> = hexs
      .into_iter()
      .map(|hex| Xor::xor_key(hex.bytes(), key.bytes()).hex)
      .collect();

    let combinations = ManyTimePad::xor_all_combinations(&ciphers);
    let candidates = ManyTimePad::candidates(&combinations, &ciphers);
    let deductions = ManyTimePad::deduce_plaintexts(candidates);
    let plaintexts = ManyTimePad::get_plaintexts(&deductions);

    assert_eq!(plains, plaintexts);
  }

  #[test]
  fn test_recover_key() -> std::io::Result<()> {
    let assets = "src/many_time_pad/assets";
    let path = std::env::var("CARGO_MANIFEST_DIR")
      .map(|dir| std::path::PathBuf::from(dir).join(assets))
      .unwrap_or_else(|_| {
        std::env::current_dir()
          .expect("Failed to get current directory")
          .join("crates/cli")
          .join(assets)
      });

    let input_path = path.join("ciphertext.txt");
    let output_path = path.join("key.txt");

    let mut input_file = std::fs::File::open(&input_path)?;
    let mut output_file = std::fs::File::open(&output_path)?;
    let mut output_buffer = Vec::new();

    ManyTimePad::test_key(&mut input_file, &mut output_buffer)?;

    let result = String::from_utf8(output_buffer).unwrap();
    let mut expected = String::new();

    output_file.read_to_string(&mut expected)?;

    assert_eq!(result, expected.trim_end().to_string());

    Ok(())
  }

  #[test]
  fn test_mtp_decrypt() -> std::io::Result<()> {
    let assets = "src/many_time_pad/assets";
    let path = std::env::var("CARGO_MANIFEST_DIR")
      .map(|dir| std::path::PathBuf::from(dir).join(assets))
      .unwrap_or_else(|_| {
        std::env::current_dir()
          .expect("Failed to get current directory")
          .join("crates/cli")
          .join(assets)
      });

    let input_path = path.join("ciphertext.txt");
    let output_path = path.join("plaintext.txt");

    let mut input_file = std::fs::File::open(&input_path)?;
    let mut output_file = std::fs::File::open(&output_path)?;
    let mut output_buffer = Vec::new();

    ManyTimePad::decrypt(&mut input_file, &mut output_buffer)?;

    let result = String::from_utf8(output_buffer).unwrap();
    let mut expected = String::new();

    output_file.read_to_string(&mut expected)?;

    assert_eq!(result, expected.trim_end().to_string());

    Ok(())
  }
}
