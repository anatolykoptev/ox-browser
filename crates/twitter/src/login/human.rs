//! Human-like browser interaction: typing delays, click offsets, pauses.

use std::time::Duration;

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use rand_distr::{Distribution, Normal};

/// Typing speed preset.
#[derive(Debug, Clone, Copy)]
pub enum Speed {
    /// Username: 50-150ms base delay
    Fast,
    /// Password: 80-180ms base delay
    Slow,
}

impl Speed {
    fn base_delay_ms(self) -> (f64, f64) {
        match self {
            Speed::Fast => (100.0, 25.0),
            Speed::Slow => (130.0, 25.0),
        }
    }

    fn min_max_ms(self) -> (u64, u64) {
        match self {
            Speed::Fast => (50, 150),
            Speed::Slow => (80, 180),
        }
    }
}

pub struct HumanBehavior {
    rng: StdRng,
}

impl HumanBehavior {
    pub fn new() -> Self {
        Self {
            rng: StdRng::from_entropy(),
        }
    }

    /// Delay for typing a single character.
    pub fn char_delay(&mut self, speed: Speed) -> Duration {
        let (mean, stddev) = speed.base_delay_ms();
        let (min, max) = speed.min_max_ms();
        let normal = Normal::new(mean, stddev).unwrap();
        let ms = normal.sample(&mut self.rng).clamp(min as f64, max as f64);
        Duration::from_millis(ms as u64)
    }

    /// Occasional micro-pause (200-400ms) — call every 3-7 chars.
    pub fn should_micro_pause(&mut self) -> bool {
        self.rng.gen_range(0..7) < 1
    }

    pub fn micro_pause_delay(&mut self) -> Duration {
        Duration::from_millis(self.rng.gen_range(200..400))
    }

    /// Delay before clicking (100-300ms).
    pub fn pre_click_delay(&mut self) -> Duration {
        Duration::from_millis(self.rng.gen_range(100..300))
    }

    /// Random click offset from center (±5px).
    pub fn click_offset(&mut self) -> (f64, f64) {
        let dx = self.rng.gen_range(-5.0..5.0);
        let dy = self.rng.gen_range(-5.0..5.0);
        (dx, dy)
    }

    /// Pause between steps (500-2000ms) — simulates reading.
    pub fn reading_pause(&mut self) -> Duration {
        Duration::from_millis(self.rng.gen_range(500..2000))
    }

    /// Pause after page load (1-3s).
    pub fn page_load_pause(&mut self) -> Duration {
        Duration::from_millis(self.rng.gen_range(1000..3000))
    }
}

impl Default for HumanBehavior {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn char_delay_within_bounds() {
        let mut h = HumanBehavior::new();
        for _ in 0..100 {
            let d = h.char_delay(Speed::Fast);
            assert!(d.as_millis() >= 50 && d.as_millis() <= 150);
        }
        for _ in 0..100 {
            let d = h.char_delay(Speed::Slow);
            assert!(d.as_millis() >= 80 && d.as_millis() <= 180);
        }
    }

    #[test]
    fn click_offset_within_bounds() {
        let mut h = HumanBehavior::new();
        for _ in 0..100 {
            let (dx, dy) = h.click_offset();
            assert!(dx.abs() <= 5.0 && dy.abs() <= 5.0);
        }
    }

    #[test]
    fn reading_pause_within_bounds() {
        let mut h = HumanBehavior::new();
        for _ in 0..50 {
            let d = h.reading_pause();
            assert!(d.as_millis() >= 500 && d.as_millis() <= 2000);
        }
    }
}
