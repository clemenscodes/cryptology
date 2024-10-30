use std::collections::HashMap;
use std::fmt::{Debug, Display};
use std::io::{Read, Result, Write};

pub type SubstitionMapType = HashMap<char, char>;

pub struct SubstitutionMap(pub SubstitionMapType);

impl SubstitutionMap {}

impl SubstitutionMap {
  pub fn apply<R: Read, W: Write>(
    &self,
    input: &mut R,
    output: &mut W,
  ) -> Result<()> {
    let mut content = String::new();
    input.read_to_string(&mut content)?;

    let transformed: String = content
      .chars()
      .map(|c| *self.0.get(&c).unwrap_or(&c))
      .collect();

    output.write_all(transformed.as_bytes())
  }
}

impl Debug for SubstitutionMap {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(f, "{self}")
  }
}

impl Display for SubstitutionMap {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    for (source, target) in &self.0 {
      writeln!(f, "  {} -> {}", source, target)?;
    }
    Ok(())
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::env;
  use std::fs::File;
  use std::io::Read;
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
    let output_path = path.join("output.txt");

    let mut input_file = File::open(&input_path)?;
    let mut output_file = File::open(&output_path)?;
    let mut output = Vec::new();
    let mut expected_output = String::new();

    let mut substitution_map = SubstitutionMap(HashMap::new());

    substitution_map.0.insert('Q', 'E');
    substitution_map.0.insert('G', 'T');
    substitution_map.0.insert('D', 'O');
    substitution_map.0.insert('R', 'A');
    substitution_map.0.insert('X', 'I');
    substitution_map.0.insert('U', 'N');
    substitution_map.0.insert('K', 'S');
    substitution_map.0.insert('P', 'H');
    substitution_map.0.insert('Y', 'R');
    substitution_map.0.insert('V', 'L');
    substitution_map.0.insert('E', 'D');
    substitution_map.0.insert('I', 'W');
    substitution_map.0.insert('S', 'F');
    substitution_map.0.insert('N', 'C');
    substitution_map.0.insert('H', 'U');
    substitution_map.0.insert('T', 'G');
    substitution_map.0.insert('O', 'Y');
    substitution_map.0.insert('L', 'M');
    substitution_map.0.insert('A', 'P');
    substitution_map.0.insert('W', 'B');
    substitution_map.0.insert('M', 'V');
    substitution_map.0.insert('C', 'K');
    substitution_map.0.insert('J', 'Z');
    substitution_map.0.insert('B', 'Q');

    substitution_map
      .apply(&mut input_file, &mut output)
      .unwrap();

    let result = String::from_utf8(output).unwrap();

    // George Orwell, 1984, chapter 1, first passage
    output_file.read_to_string(&mut expected_output)?;

    assert_eq!(result, expected_output);
    Ok(())
  }
}
