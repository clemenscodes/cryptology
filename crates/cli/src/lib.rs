pub mod frequency_analysis;

use clap::{Parser, Subcommand};

use std::error::Error;
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::PathBuf;

use frequency_analysis::FrequencyAnalyzer;

#[derive(Parser)]
#[command(name = "cryptology")]
#[command(version = "0.0.1")]
#[command(about = "Cryptology CLI tool for cryptographic operations")]
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

#[derive(Subcommand)]
pub enum Command {
  FrequencyAnalysis {
    #[arg(value_name = "INPUT", help = "Input file for analysis")]
    input: Option<PathBuf>,
    #[arg(value_name = "OUTPUT", help = "Output file to save the result")]
    output: Option<PathBuf>,
  },
}

impl Command {
  pub fn execute(&self) -> Result<(), Box<dyn Error>> {
    match self {
      Command::FrequencyAnalysis { input, output } => {
        let mut input_data = self.open_input(input);
        let mut output_data = self.create_output(output);

        FrequencyAnalyzer::analyze(&mut input_data, &mut output_data)
          .expect("Analysis failed");

        Ok(())
      }
    }
  }

  fn open_input(&self, input: &Option<PathBuf>) -> Box<dyn Read> {
    match input {
      Some(path) => {
        Box::new(File::open(path).expect("Failed to open input file"))
      }
      None => Box::new(io::stdin()),
    }
  }

  fn create_output(&self, output: &Option<PathBuf>) -> Box<dyn Write> {
    match output {
      Some(path) => {
        Box::new(File::create(path).expect("Failed to create output file"))
      }
      None => Box::new(io::stdout()),
    }
  }
}
