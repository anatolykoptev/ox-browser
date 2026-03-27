//! Cubic Bezier curve path generation for mouse movements.

use rand::Rng;

#[derive(Debug, Clone, Copy)]
pub struct Point {
    pub x: f64,
    pub y: f64,
}

impl Point {
    pub fn new(x: f64, y: f64) -> Self { Self { x, y } }
    pub fn distance(&self, other: &Point) -> f64 {
        ((self.x - other.x).powi(2) + (self.y - other.y).powi(2)).sqrt()
    }
}

/// Generate points along a cubic Bezier curve from start to end.
/// Control points randomized for natural-looking curves.
pub fn bezier_path(start: Point, end: Point, steps: usize) -> Vec<Point> {
    let mut rng = rand::thread_rng();
    let dx = end.x - start.x;
    let dy = end.y - start.y;
    let spread = start.distance(&end) * 0.3;

    // Avoid empty-range panic when start == end (zero spread).
    let (cp1, cp2) = if spread < 1e-9 {
        (
            Point::new(start.x + dx * 0.25, start.y + dy * 0.25),
            Point::new(start.x + dx * 0.75, start.y + dy * 0.75),
        )
    } else {
        (
            Point::new(
                start.x + dx * 0.25 + rng.gen_range(-spread..spread),
                start.y + dy * 0.25 + rng.gen_range(-spread..spread),
            ),
            Point::new(
                start.x + dx * 0.75 + rng.gen_range(-spread..spread),
                start.y + dy * 0.75 + rng.gen_range(-spread..spread),
            ),
        )
    };

    (0..=steps)
        .map(|i| {
            let t = i as f64 / steps as f64;
            let it = 1.0 - t;
            Point::new(
                it.powi(3) * start.x + 3.0 * it.powi(2) * t * cp1.x
                    + 3.0 * it * t.powi(2) * cp2.x + t.powi(3) * end.x,
                it.powi(3) * start.y + 3.0 * it.powi(2) * t * cp1.y
                    + 3.0 * it * t.powi(2) * cp2.y + t.powi(3) * end.y,
            )
        })
        .collect()
}

/// Add overshoot past target then correct back (Fitts's Law correction).
///
/// The approach direction is derived from the second-to-last → last segment of
/// the existing path, so this works correctly even when the path already ends
/// exactly at `target` (which is the normal case from `bezier_path`).
pub fn with_overshoot(path: &mut Vec<Point>, target: Point, overshoot_px: f64) {
    if path.len() < 2 { return; }

    // Use the final movement direction (approach vector) for the overshoot.
    let n = path.len();
    let prev = path[n - 2];
    let last = path[n - 1];
    let dx = last.x - prev.x;
    let dy = last.y - prev.y;
    let dist = (dx * dx + dy * dy).sqrt().max(1.0);
    let over = Point::new(
        target.x + (dx / dist) * overshoot_px,
        target.y + (dy / dist) * overshoot_px,
    );
    path.push(over);
    let correction = bezier_path(over, target, 3);
    path.extend_from_slice(&correction[1..]);
}
