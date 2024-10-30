pub mod english;

use std::collections::HashMap;

#[derive(Debug, PartialEq, Eq)]
pub struct Frequency {
  pub frequencies: HashMap<char, usize>,
}

impl Frequency {
  pub const fn new(frequencies: HashMap<char, usize>) -> Self {
    Self { frequencies }
  }
}
