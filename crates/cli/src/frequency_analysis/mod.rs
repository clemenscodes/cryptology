use std::collections::HashMap;
use std::fmt::{Debug, Display, Formatter, Result as FmtResult};
use std::io::{Read, Result, Write};

pub struct FrequencyAnalyzer;

impl FrequencyAnalyzer {
  pub fn analyze<R: Read, W: Write>(
    input: &mut R,
    output: &mut W,
  ) -> Result<FrequencyResult> {
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
    Ok(result)
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
    write!(f, "FrequencyResult: {:?}", self.frequency)
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
  fn test_example_output() -> std::io::Result<()> {
    let (root, relative_root) =
      if let Ok(manifest_dir) = env::var("CARGO_MANIFEST_DIR") {
        (PathBuf::from(manifest_dir), "src/frequency_analysis/assets")
      } else {
        (
          env::current_dir().expect("Failed to get current directory"),
          "crates/cli/src/frequency_analysis/assets",
        )
      };

    let input_path = root.join(relative_root).join("input.txt");
    let output_path = root.join(relative_root).join("output.txt");

    let mut input_file = File::open(input_path)?;
    let mut output_buffer = Vec::new();

    FrequencyAnalyzer::analyze(&mut input_file, &mut output_buffer)?;

    let mut expected_output = String::new();
    File::open(output_path)?.read_to_string(&mut expected_output)?;

    let output_string = String::from_utf8(output_buffer).unwrap();

    assert_eq!(output_string, expected_output);
    Ok(())
  }
}
