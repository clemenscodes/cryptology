use std::{
  convert::TryFrom,
  fs,
  io::{ErrorKind, Read, Write},
  path::PathBuf,
};

use crate::{xor::Xor, Command};

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
  to_ascii: bool,
}

impl HexConfig {
  pub fn new(raw: bool, to_ascii: bool) -> Self {
    Self { raw, to_ascii }
  }
}

impl From<&Command> for HexConfig {
  fn from(value: &Command) -> Self {
    match value {
      Command::Hex { raw, to_ascii, .. } => Self::new(*raw, *to_ascii),
      _ => Self::default(),
    }
  }
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Hex {
  pub bytes: Vec<u8>,
}

impl From<Xor> for Hex {
  fn from(value: Xor) -> Self {
    value.hex
  }
}

impl From<Vec<u8>> for Hex {
  fn from(value: Vec<u8>) -> Self {
    Self { bytes: value }
  }
}

impl From<&[u8]> for Hex {
  fn from(value: &[u8]) -> Self {
    value.to_vec().into()
  }
}

impl From<&str> for Hex {
  fn from(value: &str) -> Self {
    value.as_bytes().into()
  }
}

impl From<String> for Hex {
  fn from(value: String) -> Self {
    value.as_str().into()
  }
}

impl TryFrom<Box<dyn Read>> for Hex {
  type Error = HexParseError;

  fn try_from(mut value: Box<dyn Read>) -> Result<Self, Self::Error> {
    let mut buffer = Vec::new();
    value
      .read_to_end(&mut buffer)
      .map_err(|_| HexParseError::FileReadError)?;
    Ok(buffer.into())
  }
}

impl TryFrom<PathBuf> for Hex {
  type Error = HexParseError;

  fn try_from(path: PathBuf) -> Result<Self, Self::Error> {
    let bytes = fs::read(path).map_err(|_| HexParseError::FileReadError)?;
    Ok(bytes.into())
  }
}

impl TryFrom<&PathBuf> for Hex {
  type Error = HexParseError;

  fn try_from(path: &PathBuf) -> Result<Self, Self::Error> {
    let bytes = fs::read(path).map_err(|_| HexParseError::FileReadError)?;
    Ok(bytes.into())
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

impl Hex {
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
      buf.into()
    };

    if config.to_ascii {
      let ascii = hex.to_ascii();
      write!(output, "{ascii}")?;
    } else {
      write!(output, "{hex}")?;
    }

    Ok(())
  }

  pub fn is_valid_hex(s: &str) -> Result<(), HexParseError> {
    if s.len() % 2 != 0 {
      return Err(HexParseError::InvalidLength);
    }
    if !(s.chars().all(|c| c.is_ascii_hexdigit())) {
      return Err(HexParseError::InvalidHex);
    }
    Ok(())
  }

  pub fn parse_hex(value: &str) -> Result<Self, HexParseError> {
    if let Err(err) = Self::is_valid_hex(value) {
      Err(err)
    } else {
      let mut bytes = Vec::new();
      for index in (0..value.len()).step_by(2) {
        let hex_pair = &value[index..index + 2];
        let byte = u8::from_str_radix(hex_pair, 16)
          .map_err(|_| HexParseError::InvalidHex)?;
        bytes.push(byte);
      }
      Ok(bytes.into())
    }
  }

  pub fn to_ascii(&self) -> String {
    self
      .bytes
      .iter()
      .map(|&b| {
        if b.is_ascii_graphic() || b.is_ascii_whitespace() {
          b as char
        } else {
          '.'
        }
      })
      .collect()
  }

  pub fn bytes(&self) -> &[u8] {
    &self.bytes
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
    let hex: Hex = input.into();
    assert_eq!(hex.bytes, b"World".to_vec());
    assert_eq!(format!("{hex}"), "576f726c64");
  }

  #[test]
  fn test_from_vec_u8() {
    let bytes = vec![0x01, 0x02, 0x03, 0x04];
    let hex: Hex = Hex::from(bytes.clone());
    assert_eq!(hex.bytes, bytes);
  }

  #[test]
  fn test_from_u8_slice() {
    let bytes = vec![0x01, 0x02, 0x03, 0x04];
    let hex: Hex = Hex::from(bytes.as_slice());
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
    assert!(Hex::is_valid_hex("deadbeef").is_ok());
    assert!(Hex::is_valid_hex("DEADBEEF").is_ok());
    assert_eq!(
      Hex::is_valid_hex("deadbee").unwrap_err(),
      HexParseError::InvalidLength
    );
    assert_eq!(
      Hex::is_valid_hex("deadg123").unwrap_err(),
      HexParseError::InvalidHex
    );
  }

  #[test]
  fn test_to_ascii() {
    let hex = Hex::from(vec![
      72, 101, 108, 108, 111, 44, 32, 87, 111, 114, 108, 100, 33,
    ]);
    assert_eq!(hex.to_ascii(), "Hello, World!");

    let hex = Hex::from(vec![
      72, 101, 108, 108, 111, 0xFF, 44, 32, 87, 111, 114, 108, 100, 33,
    ]);
    assert_eq!(hex.to_ascii(), "Hello., World!");

    let hex = Hex::from(vec![]);
    assert_eq!(hex.to_ascii(), "");

    let hex = Hex::from(vec![0x80, 0xFF, 0xAB]);
    assert_eq!(hex.to_ascii(), "...");

    let hex = Hex::from(vec![9, 10, 32, 65, 66, 67]);
    assert_eq!(hex.to_ascii(), "\t\n ABC");
  }
}
