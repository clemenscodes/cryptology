use std::collections::BTreeMap;
use std::fmt::{Debug, Display};
use std::io::{Read, Result, Write};

pub type SubstitionMapType = BTreeMap<char, char>;

pub struct SubstitutionMap(SubstitionMapType);

impl SubstitutionMap {
  pub fn new(map: SubstitionMapType) -> Self {
    Self(map)
  }

  pub fn insert(&mut self, source: char, target: char) {
    self.0.insert(source, target);
  }
}

impl Default for SubstitutionMap {
  fn default() -> Self {
    Self::new(SubstitionMapType::default())
  }
}

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

    write!(output, "{transformed}")
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
      writeln!(f, "{source} -> {target}")?;
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
    let mut substitution_map = SubstitutionMap::default();

    substitution_map.insert('Q', 'E');
    substitution_map.insert('G', 'T');
    substitution_map.insert('D', 'O');
    substitution_map.insert('R', 'A');
    substitution_map.insert('X', 'I');
    substitution_map.insert('U', 'N');
    substitution_map.insert('K', 'S');
    substitution_map.insert('P', 'H');
    substitution_map.insert('Y', 'R');
    substitution_map.insert('V', 'L');
    substitution_map.insert('E', 'D');
    substitution_map.insert('I', 'W');
    substitution_map.insert('S', 'F');
    substitution_map.insert('N', 'C');
    substitution_map.insert('H', 'U');
    substitution_map.insert('T', 'G');
    substitution_map.insert('O', 'Y');
    substitution_map.insert('L', 'M');
    substitution_map.insert('A', 'P');
    substitution_map.insert('W', 'B');
    substitution_map.insert('M', 'V');
    substitution_map.insert('C', 'K');
    substitution_map.insert('J', 'Z');
    substitution_map.insert('B', 'Q');

    substitution_map
      .apply(&mut input_file, &mut output)
      .unwrap();

    let result = String::from_utf8(output).unwrap();

    // George Orwell, 1984, chapter 1, first passage
    output_file.read_to_string(&mut expected_output)?;

    assert_eq!(result, expected_output);
    Ok(())
  }

  #[test]
  fn test_substitution_map_display_alphabetical_order() {
    let mut map = SubstitionMapType::new();
    map.insert('b', 'y');
    map.insert('a', 'x');
    map.insert('c', 'z');

    let substitution_map = SubstitutionMap(map);

    let output = format!("{substitution_map}");
    let expected_output = "a -> x\nb -> y\nc -> z\n";

    assert_eq!(output, expected_output);
  }
}
