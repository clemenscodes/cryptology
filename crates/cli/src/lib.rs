pub mod frequency_analysis;

use clap::{Parser, Subcommand};
use std::error::Error;
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::PathBuf;

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
  pub fn execute() -> Result<(), Box<dyn Error>> {
    let cli = Self::parse();
    cli.command.execute()?;
    Ok(())
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
    about,
  )]
  FrequencyAnalysis {
    #[command(flatten)]
    default_args: CryptologyDefaultArgs,
  },
}

impl Command {
  pub fn execute(&self) -> Result<(), Box<dyn Error>> {
    match self {
      Command::FrequencyAnalysis { default_args } => {
        let mut input_data = self.open_input(&default_args.input)?;
        let mut output_data = self.create_output(&default_args.output)?;

        FrequencyAnalyzer::analyze(&mut input_data, &mut output_data)
          .expect("Frequency analysis failed");

        Ok(())
      }
    }
  }

  fn open_input(
    &self,
    input: &Option<PathBuf>,
  ) -> Result<Box<dyn Read>, Box<dyn Error>> {
    match input {
      Some(path) => Ok(Box::new(
        File::open(path).expect("Failed to open input file"),
      )),
      None => Ok(Box::new(io::stdin())),
    }
  }

  fn create_output(
    &self,
    output: &Option<PathBuf>,
  ) -> Result<Box<dyn Write>, Box<dyn Error>> {
    match output {
      Some(path) => Ok(Box::new(
        File::create(path).expect("Failed to create output file"),
      )),
      None => Ok(Box::new(io::stdout())),
    }
  }
}
