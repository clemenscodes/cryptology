use std::{
  collections::BTreeMap,
  io::{Read, Write},
};

use crate::{hex::Hex, xor::Xor};

pub type XorCombination = BTreeMap<(usize, usize), Xor>;

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

    let combinations = Self::xor_all_combinations(&ciphertexts, 0x00);

    // combinations.iter().for_each(|(_, xor)| println!("{xor}"));

    let candidates = Self::combined_candidates(&combinations);

    candidates
      .iter()
      .for_each(|(_, candidate)| println!("{candidate:#?}"));

    // let key = Self::deduce_key(&candidates, &ciphertexts);
    // let plaintexts = Self::decrypt_with_key(&ciphertexts, &key);

    // for plaintext in plaintexts {
    //   writeln!(output, "{plaintext}")?;
    // }

    Ok(())
  }

  pub fn get_candidate(byte: u8) -> u8 {
    let space = 0x20;
    byte ^ space
  }

  pub fn is_space_candidate(byte: u8) -> bool {
    let candidate = Self::get_candidate(byte);
    candidate.is_ascii_alphabetic()
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

  pub fn combined_candidates(
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

  fn map_plaintext_candidates(xor_result: &[u8]) -> Vec<Option<u8>> {
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

  pub fn deduce_key(
    combined_candidates: &BTreeMap<(usize, usize), Vec<Option<u8>>>,
    ciphertexts: &[Vec<u8>],
  ) -> Vec<Option<u8>> {
    let max_len = ciphertexts.iter().map(|c| c.len()).max().unwrap_or(0);
    let mut key: Vec<Option<u8>> = vec![None; max_len];

    for ((i, j), candidates) in combined_candidates {
      let c1 = &ciphertexts[*i];
      let c2 = &ciphertexts[*j];

      for (pos, &candidate) in candidates.iter().enumerate() {
        if let Some(plaintext_byte) = candidate {
          if pos < c1.len() {
            let k1 = c1[pos] ^ plaintext_byte;
            key[pos] = Some(k1);
          }

          if pos < c2.len() {
            let k2 = c2[pos] ^ plaintext_byte;
            key[pos] = Some(k2);
          }
        }
      }
    }

    key
  }

  pub fn decrypt_with_key(
    ciphertexts: &[Vec<u8>],
    key: &[Option<u8>],
  ) -> Vec<String> {
    ciphertexts
      .iter()
      .map(|ciphertext| {
        ciphertext
          .iter()
          .enumerate()
          .map(|(i, &byte)| match key.get(i).and_then(|&k| k) {
            Some(k) => (byte ^ k) as char,
            None => '*',
          })
          .collect()
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
  fn test_map_plaintext_candidates() {
    let xor_result = vec![b'A', b'a', b'.'];
    let candidates = ManyTimePad::map_plaintext_candidates(&xor_result);
    assert_eq!(candidates[0], Some(b'a'));
    assert_eq!(candidates[1], Some(b'A'));
    assert_eq!(candidates[2], None);
  }

  #[test]
  fn test_map_plaintext_candidates_valid() {
    let ciphers = vec![
      vec![0x4c, 0xa0, 0x0f, 0xf4],
      vec![0x5b, 0x1e, 0x39, 0x41],
      vec![0x6a, 0xd3, 0xf3, 0xbc],
    ];
    let pad = 0x00;
    let combinations = ManyTimePad::xor_all_combinations(&ciphers, pad);
    let candidates = ManyTimePad::combined_candidates(&combinations);
    println!("{candidates:#?}");
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
