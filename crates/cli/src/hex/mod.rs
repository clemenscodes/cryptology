use std::{
  convert::TryFrom,
  fs,
  io::{ErrorKind, Read, Write},
  path::PathBuf,
};

use crate::Command;

#[derive(Debug, PartialEq, Eq)]
pub enum HexParseError {
  InvalidLength,
  InvalidHex,
  FileReadError,
  IOError,
}

impl From<std::io::Error> for HexParseError {
  fn from(_value: std::io::Error) -> Self {
    HexParseError::FileReadError
  }
}

impl std::fmt::Display for HexParseError {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      HexParseError::InvalidLength => {
        writeln!(f, "Hex string must have an even length.")
      }
      HexParseError::InvalidHex => {
        writeln!(f, "Failed to parse input as raw hex")
      }
      HexParseError::FileReadError => {
        writeln!(f, "Failed to read file")
      }
      HexParseError::IOError => {
        writeln!(f, "Failed to perform I/O")
      }
    }
  }
}

impl From<HexParseError> for std::io::Error {
  fn from(value: HexParseError) -> Self {
    match value {
      HexParseError::InvalidLength => {
        let message = "Hex has invalid length".to_string();
        Self::new(ErrorKind::InvalidInput, message)
      }
      HexParseError::InvalidHex => {
        let message = "Invalid hex was detected".to_string();
        Self::new(ErrorKind::InvalidInput, message)
      }
      HexParseError::FileReadError => {
        let message = "Failed to read file containing hex".to_string();
        Self::new(ErrorKind::InvalidInput, message)
      }
      HexParseError::IOError => {
        let message = "Could not write or read hex".to_string();
        Self::new(ErrorKind::InvalidData, message)
      }
    }
  }
}

#[derive(Default, Debug, PartialEq, Eq)]
pub struct HexConfig {
  raw: bool,
}

impl HexConfig {
  pub fn new(raw: bool) -> Self {
    Self { raw }
  }
}

impl From<&Command> for HexConfig {
  fn from(value: &Command) -> Self {
    match value {
      Command::Hex { raw, .. } => Self::new(*raw),
      _ => Self::default(),
    }
  }
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Hex {
  pub bytes: Vec<u8>,
}

impl Hex {
  pub fn new(bytes: Vec<u8>) -> Self {
    Self { bytes }
  }

  pub fn parse<R: Read, W: Write>(
    input: &mut R,
    output: &mut W,
    config: HexConfig,
  ) -> Result<(), HexParseError> {
    let mut buf = String::new();

    input.read_to_string(&mut buf)?;

    let hex: Self = if config.raw {
      Self::parse_hex(&buf)?
    } else {
      buf.try_into()?
    };

    write!(output, "{hex}")?;

    Ok(())
  }

  pub fn is_valid_hex(s: &str) -> bool {
    s.len() % 2 == 0 && s.chars().all(|c| c.is_ascii_hexdigit())
  }

  pub fn parse_hex(value: &str) -> Result<Self, HexParseError> {
    if Self::is_valid_hex(value) {
      let mut bytes = Vec::new();
      for index in (0..value.len()).step_by(2) {
        let hex_pair = &value[index..index + 2];
        let byte = u8::from_str_radix(hex_pair, 16)
          .map_err(|_| HexParseError::InvalidHex)?;
        bytes.push(byte);
      }
      Ok(Self::new(bytes))
    } else {
      Err(HexParseError::InvalidHex)
    }
  }
}

impl TryFrom<Box<dyn Read>> for Hex {
  type Error = HexParseError;

  fn try_from(mut value: Box<dyn Read>) -> Result<Self, Self::Error> {
    let mut buffer = Vec::new();
    value
      .read_to_end(&mut buffer)
      .map_err(|_| HexParseError::FileReadError)?;
    Ok(Hex::new(buffer))
  }
}

impl TryFrom<&str> for Hex {
  type Error = HexParseError;

  fn try_from(value: &str) -> Result<Self, Self::Error> {
    Ok(Self::new(value.as_bytes().to_vec()))
  }
}

impl TryFrom<Vec<u8>> for Hex {
  type Error = ();

  fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
    Ok(Self::new(value))
  }
}

impl TryFrom<&[u8]> for Hex {
  type Error = ();

  fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
    Ok(Self::new(value.to_vec()))
  }
}

impl TryFrom<PathBuf> for Hex {
  type Error = HexParseError;

  fn try_from(path: PathBuf) -> Result<Self, Self::Error> {
    let bytes = fs::read(path).map_err(|_| HexParseError::FileReadError)?;
    Ok(Self::new(bytes))
  }
}

impl TryFrom<String> for Hex {
  type Error = HexParseError;

  fn try_from(value: String) -> Result<Self, Self::Error> {
    Self::try_from(value.as_str())
  }
}

impl TryFrom<&PathBuf> for Hex {
  type Error = HexParseError;

  fn try_from(path: &PathBuf) -> Result<Self, Self::Error> {
    let bytes = fs::read(path).map_err(|_| HexParseError::FileReadError)?;
    Ok(Self::new(bytes))
  }
}

impl std::fmt::Display for Hex {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    for byte in &self.bytes {
      write!(f, "{:02x}", byte)?;
    }
    Ok(())
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_parse_hex() {
    let input = "48656c6c6f";
    let hex = Hex::parse_hex(input).unwrap();
    assert_eq!(hex.bytes, vec![0x48, 0x65, 0x6c, 0x6c, 0x6f]);
  }

  #[test]
  fn test_invalid_hex_string() {
    let input = "48656c6g6f"; // Contains a non-hex character
    let result = Hex::parse_hex(input).unwrap_err();
    assert_eq!(result, HexParseError::InvalidHex);
  }

  #[test]
  fn test_regular_string_to_hex() {
    let input = "World";
    let hex: Hex = input.try_into().unwrap();
    assert_eq!(hex.bytes, b"World".to_vec());
    assert_eq!(format!("{hex}"), "576f726c64");
  }

  #[test]
  fn test_from_vec_u8() {
    let bytes = vec![0x01, 0x02, 0x03, 0x04];
    let hex: Hex = Hex::try_from(bytes.clone()).unwrap();
    assert_eq!(hex.bytes, bytes);
  }

  #[test]
  fn test_from_u8_slice() {
    let bytes = vec![0x01, 0x02, 0x03, 0x04];
    let hex: Hex = Hex::try_from(bytes.as_slice()).unwrap();
    assert_eq!(hex.bytes, bytes.to_vec());
  }

  #[test]
  fn test_invalid_file_path() {
    let path = PathBuf::from("non_existent_file.txt");
    let result: Result<Hex, HexParseError> = Hex::try_from(path);
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), HexParseError::FileReadError));
  }

  #[test]
  fn test_is_valid_hex() {
    assert!(Hex::is_valid_hex("deadbeef"));
    assert!(Hex::is_valid_hex("DEADBEEF"));
    assert!(!Hex::is_valid_hex("deadbee"));
    assert!(!Hex::is_valid_hex("deadg123"));
  }
}
