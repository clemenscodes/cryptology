pub mod frequencies;

use std::fmt::{Debug, Display, Formatter, Result as FmtResult};
use std::io::{Read, Result, Write};

use frequencies::english::ENGLISH;
use frequencies::Frequency;

pub struct FrequencyAnalyzer;

impl FrequencyAnalyzer {
  pub fn analyze<R: Read, W: Write>(
    input: &mut R,
    output: &mut W,
  ) -> Result<FrequencyResult> {
    let mut frequency = Frequency::new();
    let mut total_count = 0;
    let mut content = String::new();

    input.read_to_string(&mut content)?;

    for c in content.chars() {
      if c.is_ascii_alphabetic() {
        *frequency.entry(c.to_ascii_uppercase()).or_insert(0) += 1;
        total_count += 1;
      }
    }

    let result = FrequencyResult {
      frequency,
      total_count,
    };

    write!(output, "{result}")?;
    Ok(result)
  }

  pub fn chi_square_score(observed: &Frequency, total_count: usize) -> f32 {
    const MAX: f32 = 100_000.0;

    let mut score = 0.0;

    for (letter, &expected_raw_count) in ENGLISH.iter() {
      let normalized_expected_frequency = expected_raw_count as f32 / MAX;
      let expected_count = normalized_expected_frequency * total_count as f32;

      if expected_count > 0.0 {
        let observed_count = *observed.get(letter).unwrap_or(&0) as f32;
        let difference = observed_count - expected_count;
        let chi_square_component = difference.powi(2) / expected_count;
        score += chi_square_component;
      }
    }

    score
  }
}

#[derive(PartialEq, Eq)]
pub struct FrequencyResult {
  pub frequency: Frequency,
  pub total_count: usize,
}

impl FrequencyResult {
  fn percentage(&self, count: usize) -> f64 {
    (count as f64 / self.total_count as f64) * 100.0
  }
}

impl Display for FrequencyResult {
  fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
    writeln!(f, "| Letter | Occurrences | Percentage |")?;
    writeln!(f, "| ------ | ----------- | ---------- |")?;

    let mut entries = self.frequency.iter().collect::<Vec<(&char, &usize)>>();

    entries.sort_by(|a, b| b.1.cmp(a.1));

    for (char, count) in entries {
      writeln!(
        f,
        "| {:<6} | {:<11} | {:>8.3} % |",
        char,
        count,
        self.percentage(*count)
      )?;
    }
    Ok(())
  }
}

impl Debug for FrequencyResult {
  fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
    write!(f, "{:?}", self.frequency)
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::collections::BTreeMap;
  use std::env;
  use std::fs::File;
  use std::path::PathBuf;

  #[test]
  fn test_example_output() -> Result<()> {
    let assets = "src/frequency_analysis/assets";
    let path = env::var("CARGO_MANIFEST_DIR")
      .map(|dir| PathBuf::from(dir).join(assets))
      .unwrap_or_else(|_| {
        env::current_dir()
          .expect("Failed to get current directory")
          .join("crates/cli")
          .join(assets)
      });

    let input_path = path.join("input.txt");
    let output_path = path.join("output.txt");

    let mut input_file = File::open(&input_path)?;
    let mut output_buffer = Vec::new();

    FrequencyAnalyzer::analyze(&mut input_file, &mut output_buffer)?;

    let mut expected_output = String::new();
    File::open(&output_path)?.read_to_string(&mut expected_output)?;

    let output_string = String::from_utf8(output_buffer)
      .expect("Failed to convert output buffer to UTF-8 string");

    assert_eq!(output_string, expected_output);
    Ok(())
  }

  #[test]
  fn test_chi_square_perfect_match() {
    let observed: Frequency = ENGLISH.clone();
    let total_count: usize = observed.values().sum();
    let score = FrequencyAnalyzer::chi_square_score(&observed, total_count);
    assert!(
      score < 1.0,
      "Chi-square score should be close to 0 for a perfect match"
    );
  }

  #[test]
  fn test_chi_square_slight_variation() {
    let observed: Frequency = BTreeMap::from([
      ('E', 12300),
      ('T', 8900),
      ('A', 8100),
      ('O', 7800),
      ('N', 6900),
      ('I', 6800),
      ('H', 6400),
      ('S', 6300),
      ('R', 5700),
      ('D', 4500),
      ('L', 4000),
      ('U', 2700),
      ('M', 2500),
      ('C', 2400),
      ('W', 2300),
      ('F', 2200),
      ('Y', 2100),
      ('G', 2000),
      ('P', 1600),
      ('B', 1500),
      ('V', 1000),
      ('K', 800),
      ('X', 150),
      ('J', 130),
      ('Q', 100),
      ('Z', 90),
    ]);
    let total_count: usize = observed.values().sum();
    let score = FrequencyAnalyzer::chi_square_score(&observed, total_count);
    assert!(
      score > 1.0 && score < 50.0,
      "Chi-square score should be moderate for slight variations"
    );
  }

  #[test]
  fn test_chi_square_large_variation() {
    let observed: Frequency = BTreeMap::from([
      ('E', 5000),
      ('T', 5000),
      ('A', 5000),
      ('O', 5000),
      ('N', 5000),
      ('I', 5000),
      ('H', 5000),
      ('S', 5000),
      ('R', 5000),
      ('D', 5000),
      ('L', 5000),
      ('U', 5000),
      ('M', 5000),
      ('C', 5000),
      ('W', 5000),
      ('F', 5000),
      ('Y', 5000),
      ('G', 5000),
      ('P', 5000),
      ('B', 5000),
      ('V', 5000),
      ('K', 5000),
      ('X', 5000),
      ('J', 5000),
      ('Q', 5000),
      ('Z', 5000),
    ]);
    let total_count: usize = observed.values().sum();
    let score = FrequencyAnalyzer::chi_square_score(&observed, total_count);
    assert!(
      score > 1000.0,
      "Chi-square score should be high for large variations"
    );
  }
}
