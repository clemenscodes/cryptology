use std::collections::HashMap;
use std::fmt::{Debug, Display, Formatter, Result as FmtResult};
use std::io::{Read, Result, Write};

pub struct FrequencyAnalyzer;

impl FrequencyAnalyzer {
  pub fn analyze<R: Read, W: Write>(
    input: &mut R,
    output: &mut W,
  ) -> Result<()> {
    let mut content = String::new();
    input.read_to_string(&mut content)?;

    let mut frequency = HashMap::new();
    let mut total_count = 0;

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
    Ok(())
  }
}

#[derive(PartialEq, Eq)]
pub struct FrequencyResult {
  frequency: HashMap<char, usize>,
  total_count: usize,
}

impl FrequencyResult {
  fn percentage(&self, count: usize) -> f64 {
    (count as f64 / self.total_count as f64) * 100.0
  }
}

impl Debug for FrequencyResult {
  fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
    write!(f, "{:?}", self.frequency)
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

#[cfg(test)]
mod tests {
  use super::*;
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
}
