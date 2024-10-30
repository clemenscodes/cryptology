use std::{collections::HashMap, sync::LazyLock};

use super::Frequency;

pub static ENGLISH_FREQUENCY: LazyLock<Frequency> = LazyLock::new(|| {
  let frequencies = HashMap::from([
    ('E', 12359),
    ('T', 8952),
    ('A', 8050),
    ('O', 7715),
    ('N', 6958),
    ('I', 6871),
    ('H', 6502),
    ('S', 6290),
    ('R', 5746),
    ('D', 4537),
    ('L', 4030),
    ('U', 2805),
    ('M', 2591),
    ('C', 2378),
    ('W', 2354),
    ('F', 2181),
    ('Y', 2119),
    ('G', 2042),
    ('P', 1682),
    ('B', 1494),
    ('V', 1032),
    ('K', 853),
    ('X', 145),
    ('J', 127),
    ('Q', 99),
    ('Z', 88),
  ]);
  Frequency::new(frequencies)
});

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_english_frequency_contains_all_characters() {
    let frequency = &ENGLISH_FREQUENCY.frequencies;

    assert_eq!(frequency.len(), 26);

    for ch in 'A'..='Z' {
      assert!(frequency.contains_key(&ch), "Missing character {}", ch);
    }
  }

  #[test]
  fn test_english_frequency_does_not_contain_extra_characters() {
    let frequency = &ENGLISH_FREQUENCY.frequencies;

    for ch in 'a'..='z' {
      assert!(
        !frequency.contains_key(&ch),
        "Unexpected lowercase character {}",
        ch
      );
    }
    assert!(!frequency.contains_key(&' '), "Unexpected space character");
    assert!(
      !frequency.contains_key(&'#'),
      "Unexpected special character #"
    );
  }
}
