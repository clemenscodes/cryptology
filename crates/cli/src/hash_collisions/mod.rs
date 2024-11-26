use rand::Rng;
use std::collections::HashSet;

pub struct HashCollision;

impl HashCollision {
  /// Simulates weak and strong hash collisions
  pub fn exec(rounds: u32) {
    println!("Executing hash collision for {rounds} rounds");

    let output_bits = 16;
    let max_output_value = 2u32.pow(output_bits);

    let weak_collision_avg =
      HashCollision::simulate_weak_collisions(rounds, max_output_value);
    println!("Average attempts for weak collision: {weak_collision_avg}");

    let strong_collision_avg =
      HashCollision::simulate_strong_collisions(rounds, max_output_value);

    println!("Average attempts for strong collision: {strong_collision_avg}",);
  }

  /// Simulates weak collisions
  fn simulate_weak_collisions(rounds: u32, max_value: u32) -> f64 {
    let mut total_attempts = 0;

    for _ in 0..rounds {
      let target = rand::thread_rng().gen_range(0..max_value);
      let mut attempts = 1;

      loop {
        let generated = rand::thread_rng().gen_range(0..max_value);
        if generated == target {
          break;
        }
        attempts += 1;
      }
      total_attempts += attempts;
    }

    total_attempts as f64 / rounds as f64
  }

  /// Simulates strong collisions
  fn simulate_strong_collisions(rounds: u32, max_value: u32) -> f64 {
    let mut total_attempts = 0;

    for _ in 0..rounds {
      let mut seen_values = HashSet::new();
      let mut attempts = 0;

      loop {
        let generated = rand::thread_rng().gen_range(0..max_value);
        attempts += 1;
        if seen_values.contains(&generated) {
          break;
        }
        seen_values.insert(generated);
      }
      total_attempts += attempts;
    }

    total_attempts as f64 / rounds as f64
  }
}
