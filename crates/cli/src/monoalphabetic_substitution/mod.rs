pub mod substitution_map;

use std::io::Result;
use std::{io::Read, io::Write};

use substitution_map::SubstitutionMap;

use crate::frequency_analysis::frequencies::english::ENGLISH;
use crate::frequency_analysis::FrequencyAnalyzer;

pub struct MonoalphabeticSubstition;

impl MonoalphabeticSubstition {
  pub fn analyze<R: Read, W: Write>(
    input: &mut R,
    output: &mut W,
  ) -> Result<()> {
    let mut content = String::new();
    let mut buf = Vec::new();
    let mut substitution_map = SubstitutionMap::default();

    input.read_to_string(&mut content)?;

    let fa = FrequencyAnalyzer::analyze(&mut content.as_bytes(), &mut buf)?;

    let mut sorted_frequencies: Vec<_> = fa.frequency.iter().collect();

    sorted_frequencies.sort_by(|a, b| b.1.cmp(a.1));

    for (analyzed, english) in sorted_frequencies.iter().zip(ENGLISH.iter()) {
      substitution_map.insert(*analyzed.0, *english.0);
    }

    write!(output, "{substitution_map}")?;

    substitution_map.apply(&mut content.as_bytes(), output)?;
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
  fn test_monoalphabetic_substitution_analysis_output() -> Result<()> {
    let assets = "src/monoalphabetic_substitution/assets";
    let path = env::var("CARGO_MANIFEST_DIR")
      .map(|dir| PathBuf::from(dir).join(assets))
      .unwrap_or_else(|_| {
        env::current_dir()
          .expect("Failed to get current directory")
          .join("crates/cli")
          .join(assets)
      });

    let input_path = path.join("input.txt");

    let mut input_file = File::open(&input_path)?;
    let mut output_buffer = Vec::new();

    MonoalphabeticSubstition::analyze(&mut input_file, &mut output_buffer)?;

    Ok(())
  }
}
