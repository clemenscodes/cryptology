use std::{fmt::Display, num::ParseIntError};

#[derive(Debug)]
pub enum HexParseError {
  InvalidLength,
  InvalidHex(ParseIntError),
}

impl std::fmt::Display for HexParseError {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      HexParseError::InvalidLength => {
        write!(f, "Hex string must have an even length.")
      }
      HexParseError::InvalidHex(err) => {
        write!(f, "Failed to parse hex: {err}")
      }
    }
  }
}

impl From<ParseIntError> for HexParseError {
  fn from(err: ParseIntError) -> Self {
    HexParseError::InvalidHex(err)
  }
}

#[derive(Default, PartialEq, Eq)]
pub struct Hex {
  pub bytes: Vec<u8>,
}

impl TryFrom<&str> for Hex {
  type Error = HexParseError;

  fn try_from(value: &str) -> Result<Self, Self::Error> {
    if value.len() % 2 != 0 {
      return Err(HexParseError::InvalidLength);
    }

    let mut bytes = Vec::new();

    for index in (0..value.len()).step_by(2) {
      let hex_pair = &value[index..index + 2];
      let byte = u8::from_str_radix(hex_pair, 16)?;
      bytes.push(byte);
    }

    Ok(Self::new(bytes))
  }
}

impl Hex {
  pub fn new(bytes: Vec<u8>) -> Self {
    Self { bytes }
  }
}

impl Display for Hex {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    let hex = self
      .bytes
      .iter()
      .map(|byte| format!("{byte:02x}"))
      .collect::<Vec<_>>()
      .join("");
    write!(f, "{hex}")
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_hex_display() {
    let input = "Hello";

    let hex: Hex = input.try_into().unwrap();

    let result = format!("{hex}");
    let expected = String::from("0000000000");

    assert_eq!(result, expected);
  }
}
