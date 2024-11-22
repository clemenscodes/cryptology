pub mod caesar;
pub mod frequency_analysis;
pub mod monoalphabetic_substitution;
pub mod one_time_pad;
pub mod vigenere;

use clap::{Parser, Subcommand};

use std::fs::File;
use std::io::{self, Cursor, Read, Result, Write};
use std::path::PathBuf;

use caesar::Caesar;
use frequency_analysis::FrequencyAnalyzer;
use monoalphabetic_substitution::MonoalphabeticSubstition;
use one_time_pad::OneTimePad;
use vigenere::Vigenere;

/// Cryptology CLI tool for cryptographic operations.
///
/// This tool provides various cryptographic utilities, including
/// frequency analysis for cryptology studies.
///
/// It supports reading
/// input from files or standard input and outputting results to
/// files or standard output.
#[derive(Debug, Parser)]
#[command(
  name = "cryptology",
  version,
  author,
  about,
  help_template = "\
{before-help}{name} {version}
{author-section}{about-section}
{usage-heading} {usage}

{all-args}{after-help}
"
)]
pub struct Cryptology {
  #[command(subcommand)]
  pub command: Command,
}

impl Cryptology {
  pub fn execute() -> Result<()> {
    let cli = Self::parse();
    cli.command.execute()
  }
}

#[derive(Debug, Parser)]
pub struct CryptologyDefaultArgs {
  /// Path to the input file.
  ///
  /// If not provided, reads from standard input.
  #[arg(
    short = 'i',
    long = "input",
    value_name = "INPUT",
    help = "Specify the input file"
  )]
  input: Option<PathBuf>,

  /// Path to the output file for saving results.
  ///
  /// If not provided, outputs to standard output.
  #[arg(
    short = 'o',
    long = "output",
    value_name = "OUTPUT",
    help = "Specify the output file for saving result."
  )]
  output: Option<PathBuf>,
}

#[derive(Debug, Parser)]
pub struct CryptologyEncryptKeyArg {
  /// Key used for encryption
  #[arg(
    short = 'k',
    long = "key",
    value_name = "KEY",
    help = "Key used for encryption"
  )]
  key: String,
}

#[derive(Debug, Parser)]
pub struct CryptologyDecryptKeyArg {
  /// Key used for decryption if known.
  #[arg(
    short = 'k',
    long = "key",
    value_name = "KEY",
    help = "The decryption key if known"
  )]
  key: Option<String>,
}

#[derive(Debug, Subcommand)]
pub enum Command {
  /// Perform frequency analysis on text data.
  ///
  /// This command counts the occurrences of each character
  /// in the input text, useful for cryptographic studies.
  ///
  /// Input can be provided from a file or standard input, and
  /// output can be directed to a file or standard output.
  #[command(name = "frequency-analysis", visible_aliases = ["freq", "fa"])]
  FrequencyAnalysis {
    #[command(flatten)]
    default_args: CryptologyDefaultArgs,
  },

  /// Encrypt text using a specified cipher.
  #[command(name = "encrypt", visible_aliases = ["enc", "e"])]
  Encrypt {
    #[command(subcommand)]
    cipher: EncryptCipher,
  },

  /// Decrypt text using a specified cipher.
  #[command(name = "decrypt", visible_aliases = ["dec", "d"])]
  Decrypt {
    #[command(subcommand)]
    cipher: DecryptCipher,
  },
}

#[derive(Debug, Subcommand)]
pub enum EncryptCipher {
  /// Use the Caesar cipher for encryption.
  #[command(name = "caesar", visible_alias = "c")]
  Caesar {
    #[command(flatten)]
    default_args: CryptologyDefaultArgs,
  },

  /// Use the Vigenere cipher for encryption.
  #[command(name = "vigenere", visible_alias = "v")]
  Vigenere {
    #[command(flatten)]
    default_args: CryptologyDefaultArgs,

    #[command(flatten)]
    key: CryptologyEncryptKeyArg,
  },

  /// Use the One Time Pad cipher for encryption.
  #[command(name = "one-time-pad", visible_alias = "otp")]
  OneTimePad {
    #[command(flatten)]
    default_args: CryptologyDefaultArgs,

    #[command(flatten)]
    key: CryptologyEncryptKeyArg,
  },
}

#[derive(Debug, Subcommand)]
pub enum DecryptCipher {
  /// Use monoalphabetic substitution cipher for decryption.
  #[command(name = "monoalphabetic-substitution", visible_aliases = ["monosub", "ms"])]
  MonoalphabeticSubstitution {
    #[command(flatten)]
    default_args: CryptologyDefaultArgs,
  },

  /// Use the Caesar cipher for decryption.
  #[command(name = "caesar", visible_alias = "c")]
  Caesar {
    #[command(flatten)]
    default_args: CryptologyDefaultArgs,
  },

  /// Use the Vigenere cipher for decryption.
  #[command(name = "vigenere", visible_alias = "v")]
  Vigenere {
    #[command(flatten)]
    default_args: CryptologyDefaultArgs,

    #[command(flatten)]
    key: CryptologyDecryptKeyArg,

    /// Specify the key length if known.
    #[arg(
      short = 'n',
      long = "key-length",
      value_name = "KEY_LENGTH",
      help = "The key length if known"
    )]
    key_length: Option<u8>,

    /// Specify the maximum length for the key. Defaults to 20.
    #[arg(
      short = 'l',
      long = "max-key-length",
      value_name = "MAX_KEY_LENGTH",
      help = "Specify the maximum length for the key. 20 by default"
    )]
    max_key_length: Option<u8>,
  },

  /// Use the One-Time-Pad cipher for decryption.
  #[command(name = "one-time-pad", visible_alias = "otp")]
  OneTimePad {
    #[command(flatten)]
    default_args: CryptologyDefaultArgs,

    #[command(flatten)]
    key: CryptologyDecryptKeyArg,
  },
}

impl Command {
  pub fn execute(&self) -> Result<()> {
    match self {
      Command::FrequencyAnalysis { default_args } => {
        let (mut input, mut output) = Command::get_files(default_args);
        FrequencyAnalyzer::analyze(&mut input, &mut output)?;
        Ok(())
      }
      Command::Encrypt { cipher } => cipher.execute(),
      Command::Decrypt { cipher } => cipher.execute(),
    }
  }
}

impl EncryptCipher {
  pub fn execute(&self) -> Result<()> {
    match self {
      EncryptCipher::Caesar { .. } => {
        todo!()
      }
      EncryptCipher::Vigenere { default_args, .. } => {
        let (mut input, mut output) = Command::get_files(default_args);
        let config = self.into();
        Vigenere::encrypt(&mut input, &mut output, config)
      }
      EncryptCipher::OneTimePad { default_args, .. } => {
        let (mut input, mut output) = Command::get_files(default_args);
        let config = self.into();
        OneTimePad::encrypt(&mut input, &mut output, config)?;
        Ok(())
      }
    }
  }
}

impl DecryptCipher {
  pub fn execute(&self) -> Result<()> {
    match self {
      DecryptCipher::MonoalphabeticSubstitution { default_args } => {
        let (mut input, mut output) = Command::get_files(default_args);
        MonoalphabeticSubstition::analyze(&mut input, &mut output)?;
        Ok(())
      }
      DecryptCipher::Caesar { default_args } => {
        let (mut input, mut output) = Command::get_files(default_args);
        Caesar::decrypt(&mut input, &mut output)
      }
      DecryptCipher::Vigenere { default_args, .. } => {
        let (mut input, mut output) = Command::get_files(default_args);
        let config = self.into();
        Vigenere::decrypt(&mut input, &mut output, config)
      }
      DecryptCipher::OneTimePad { default_args, .. } => {
        let (mut input, mut output) = Command::get_files(default_args);
        let config = self.into();
        OneTimePad::decrypt(&mut input, &mut output, config)?;
        Ok(())
      }
    }
  }
}

impl Command {
  fn get_files(
    default_args: &CryptologyDefaultArgs,
  ) -> (Box<dyn Read>, Box<dyn Write>) {
    let input_data = Self::open_input(&default_args.input);
    let output_data = Self::create_output(&default_args.output);
    (input_data, output_data)
  }

  fn open_input(input: &Option<PathBuf>) -> Box<dyn Read> {
    match input {
      Some(path) => {
        Box::new(File::open(path).expect("Failed to open input file"))
      }
      None => Box::new(io::stdin()),
    }
  }

  fn create_output(output: &Option<PathBuf>) -> Box<dyn Write> {
    match output {
      Some(path) => {
        Box::new(File::create(path).expect("Failed to create output file"))
      }
      None => Box::new(io::stdout()),
    }
  }

  fn get_readable(input: &str) -> Cursor<Vec<u8>> {
    Cursor::new(input.as_bytes().to_vec())
  }
}
