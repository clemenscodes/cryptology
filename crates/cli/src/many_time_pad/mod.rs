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

    let ciphertexts: Vec<Vec<u8>> = buf
      .lines()
      .map(|line| {
        let message = format!("Failed to parse line {line} as hex");
        let hex = Hex::parse_hex(line).expect(&message);
        hex.bytes().to_vec()
      })
      .collect();

    let combinations = Self::xor_all_combinations(&ciphertexts);
    let candidates = Self::candidates(&combinations, &ciphertexts);
    let deductions = Self::deduce_plaintexts(candidates);
    let plaintexts = Self::get_plaintexts(deductions);

    for plaintext in plaintexts {
      writeln!(output, "{plaintext}")?;
    }

    Ok(())
  }

  pub fn get_candidate(byte: u8) -> u8 {
    byte ^ SPACE
  }

  pub fn is_space_candidate(byte: u8) -> bool {
    let candidate = Self::get_candidate(byte);
    candidate.is_ascii_alphabetic()
  }

  pub fn xor_all_combinations(ciphertexts: &[Vec<u8>]) -> XorCombination {
    let mut results = XorCombination::new();

    for (i, alpha) in ciphertexts.iter().enumerate() {
      for (j, beta) in ciphertexts.iter().enumerate().skip(i + 1) {
        let max_length = alpha.len().max(beta.len());

        let xor_result: Vec<u8> = (0..max_length)
          .map(|k| {
            let byte_a = alpha.get(k).copied().unwrap_or(0x00);
            let byte_b = beta.get(k).copied().unwrap_or(0x00);
            byte_a ^ byte_b
          })
          .collect();

        results.insert((i, j), Xor::from(xor_result));
      }
    }

    results
  }

  pub fn candidates(
    combinations: &XorCombination,
    ciphertexts: &[Vec<u8>],
  ) -> PlaintextCandidates {
    let mut candidates: PlaintextCandidates = BTreeMap::new();

    for (&(i, j), xor) in combinations {
      let xor_bytes = xor.bytes();

      for (pos, &byte) in xor_bytes.iter().enumerate() {
        if pos >= ciphertexts[i].len() || pos >= ciphertexts[j].len() {
          continue;
        }

        if !Self::is_space_candidate(byte) {
          continue;
        }

        let p2 = Self::get_candidate(byte);

        if p2.is_ascii_graphic() || p2 == SPACE {
          *candidates
            .entry((i, pos))
            .or_default()
            .entry(SPACE)
            .or_insert(0) += 1;

          *candidates
            .entry((j, pos))
            .or_default()
            .entry(p2)
            .or_insert(0) += 1;
        }

        let p1 = Self::get_candidate(byte);

        if p1.is_ascii_graphic() || p1 == SPACE {
          *candidates
            .entry((i, pos))
            .or_default()
            .entry(p1)
            .or_insert(0) += 1;

          *candidates
            .entry((j, pos))
            .or_default()
            .entry(SPACE)
            .or_insert(0) += 1;
        }
      }
    }

    candidates
  }

  pub fn deduce_plaintexts(
    candidates: PlaintextCandidates,
  ) -> PlaintextDeductions {
    candidates
      .into_iter()
      .filter_map(|((ciphertext_index, pos), char_counts)| {
        char_counts
          .into_iter()
          .max_by_key(|&(_, count)| count)
          .map(|(byte, _)| ((ciphertext_index, pos), byte))
      })
      .collect()
  }

  pub fn get_plaintexts(deductions: PlaintextDeductions) -> Vec<String> {
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
    let plains = vec!["a b c", " d e ", "efghya"];
    let hexs: Vec<Hex> = plains.clone().into_iter().map(Hex::from).collect();

    let ciphers: Vec<Vec<u8>> = hexs
      .into_iter()
      .map(|hex| Xor::xor_key(hex.bytes(), key.bytes()))
      .map(|cipher| cipher.bytes().to_vec())
      .collect();

    let combinations = ManyTimePad::xor_all_combinations(&ciphers);

    println!("{combinations:#?}");

    let candidates = ManyTimePad::candidates(&combinations, &ciphers);

    println!("{candidates:#?}");

    let deductions = ManyTimePad::deduce_plaintexts(candidates);
    let derived_plaintexts = ManyTimePad::get_plaintexts(deductions);

    assert_eq!(plains, derived_plaintexts);
  }

  // #[test]
  // fn test_mtp_decrypt() -> std::io::Result<()> {
  //   let assets = "src/many_time_pad/assets";
  //   let path = std::env::var("CARGO_MANIFEST_DIR")
  //     .map(|dir| std::path::PathBuf::from(dir).join(assets))
  //     .unwrap_or_else(|_| {
  //       std::env::current_dir()
  //         .expect("Failed to get current directory")
  //         .join("crates/cli")
  //         .join(assets)
  //     });
  //
  //   let input_path = path.join("input.txt");
  //   let output_path = path.join("output.txt");
  //   let mut input_file = std::fs::File::open(&input_path)?;
  //   let mut output_buffer = Vec::new();
  //
  //   Ok(())
  // }
}
