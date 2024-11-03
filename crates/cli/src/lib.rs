pub mod caesar;
pub mod frequency_analysis;
pub mod monoalphabetic_substitution;
pub mod vigenere;

use caesar::CaesarCipher;
use clap::{Parser, Subcommand};
use monoalphabetic_substitution::MonoalphabeticSubstition;
use std::fs::File;
use std::io::{self, Read, Result, Write};
use std::path::PathBuf;
use vigenere::{VigenereConfig, VigenereCypher};

use frequency_analysis::FrequencyAnalyzer;

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

#[derive(Debug, Subcommand)]
pub enum Command {
  /// Perform frequency analysis on text data.
  ///
  /// This command counts the occurrences of each character
  /// in the input text, useful for cryptographic studies.
  ///
  /// Input can be provided from a file or standard input, and
  /// output can be directed to a file or standard output.
  #[command(
    name = "frequency-analysis",
    visible_aliases = ["freq", "fa"],
    version,
  )]
  FrequencyAnalysis {
    #[command(flatten)]
    default_args: CryptologyDefaultArgs,
  },

  /// Decrypt monoalphabetic substitution ciphers by frequency analysis.
  ///
  /// This command sorts the ciphertext letters by frequency and provides
  /// hints based on common letter frequencies for decryption.
  #[command(
    name = "monoalphabetic-substitution",
    visible_aliases = ["monosub", "ms"],
    version,
  )]
  MonoalphabeticSubstitution {
    #[command(flatten)]
    default_args: CryptologyDefaultArgs,
  },

  /// Decrypt a Caesar cipher using chi-square analysis.
  ///
  /// This command automatically finds the correct shift to decipher
  /// the text based on English letter frequency.
  #[command(
    name = "caesar",
    visible_aliases = ["c"],
    version,
  )]
  Caesar {
    #[command(flatten)]
    default_args: CryptologyDefaultArgs,
  },

  /// Decrypt a Vigenere cipher
  ///
  #[command(
    name = "vigenere",
    visible_aliases = ["v"],
    version,
  )]
  Vigenere {
    #[command(flatten)]
    default_args: CryptologyDefaultArgs,

    /// Path to the output file for saving results.
    ///
    /// If not provided, outputs to standard output.
    #[arg(
      short = 'l',
      long = "max-key-length",
      value_name = "MAX_KEY_LENGTH",
      help = "Specify the maximum length for the key. 20 by default"
    )]
    max_key_length: Option<u8>,
  },
}

impl Command {
  pub fn execute(&self) -> Result<()> {
    match self {
      Command::FrequencyAnalysis { default_args } => {
        let (mut input, mut output) = Self::get_files(default_args);
        FrequencyAnalyzer::analyze(&mut input, &mut output)?;
        Ok(())
      }
      Command::MonoalphabeticSubstitution { default_args } => {
        let (mut input, mut output) = Self::get_files(default_args);
        MonoalphabeticSubstition::analyze(&mut input, &mut output)?;
        Ok(())
      }
      Command::Caesar { default_args } => {
        let (mut input, mut output) = Self::get_files(default_args);
        CaesarCipher::decrypt(&mut input, &mut output)
      }
      Command::Vigenere { default_args, .. } => {
        let (mut input, mut output) = Self::get_files(default_args);
        let config: VigenereConfig = self.into();
        VigenereCypher::decrypt(&mut input, &mut output, config)
      }
    }
  }

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
}

pub trait Decrypt<T> {
  fn decrypt<R: Read, W: Write>(input: &mut R, output: &mut W) -> Result<T>;
}

pub trait Encrypt<T> {
  fn encrypt<R: Read, W: Write>(input: &mut R, output: &mut W) -> Result<T>;
}
