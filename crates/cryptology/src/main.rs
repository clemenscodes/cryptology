use std::error::Error;

use cli::Cryptology;

fn main() -> Result<(), Box<dyn Error>> {
  Cryptology::execute()?;
  Ok(())
}
