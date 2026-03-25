/// Cubic bezier easing, linear interpolation, and rotation matrix utilities.
/// Ported from go-twitter cubic.go / interpolate.go / rotation.go.
/// Fix vs go-twitter: epsilon is 1e-6 (not 1e-5).
use std::f64::consts::PI;

pub(crate) struct Cubic {
    curves: [f64; 4],
}

impl Cubic {
    pub(crate) fn new(curves: &[f64]) -> Self {
        assert!(curves.len() >= 4, "curves must have at least 4 elements");
        Self { curves: [curves[0], curves[1], curves[2], curves[3]] }
    }

    pub(crate) fn get_value(&self, t: f64) -> f64 {
        let c = &self.curves;

        if t <= 0.0 {
            let start_gradient = if c[0] > 0.0 {
                c[1] / c[0]
            } else if c[1] == 0.0 && c[2] > 0.0 {
                c[3] / c[2]
            } else {
                0.0
            };
            return start_gradient * t;
        }

        if t >= 1.0 {
            let end_gradient = if c[2] < 1.0 {
                (c[3] - 1.0) / (c[2] - 1.0)
            } else if c[2] == 1.0 && c[0] < 1.0 {
                (c[1] - 1.0) / (c[0] - 1.0)
            } else {
                0.0
            };
            return 1.0 + end_gradient * (t - 1.0);
        }

        let mut start = 0.0_f64;
        let mut end = 1.0_f64;
        let mut mid = 0.0_f64;

        while start < end {
            mid = (start + end) / 2.0;
            let x_est = cubic_calc(c[0], c[2], mid);
            if (t - x_est).abs() < 1e-6 {
                return cubic_calc(c[1], c[3], mid);
            }
            if x_est < t {
                start = mid;
            } else {
                end = mid;
            }
        }
        cubic_calc(c[1], c[3], mid)
    }
}

pub(crate) fn cubic_calc(a: f64, b: f64, m: f64) -> f64 {
    3.0 * a * (1.0 - m) * (1.0 - m) * m
        + 3.0 * b * (1.0 - m) * m * m
        + m * m * m
}

pub(crate) fn interpolate(from: &[f64], to: &[f64], progress: f64) -> Vec<f64> {
    from.iter()
        .zip(to.iter())
        .map(|(f, t)| f * (1.0 - progress) + t * progress)
        .collect()
}

pub(crate) fn rotation_to_matrix(degrees: f64) -> [f64; 4] {
    let rad = degrees * PI / 180.0;
    [rad.cos(), -rad.sin(), rad.sin(), rad.cos()]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::f64::consts::SQRT_2;

    #[test]
    fn test_cubic_calc_known_values() {
        // m=0 → 0, m=1 → 1
        assert!((cubic_calc(0.25, 0.75, 0.0)).abs() < 1e-10);
        assert!((cubic_calc(0.25, 0.75, 1.0) - 1.0).abs() < 1e-10);
        // m=0.5, a=0.25, b=0.75: 3*0.25*0.25*0.5 + 3*0.75*0.5*0.25 + 0.125 = 0.09375+0.28125+0.125 = 0.5
        assert!((cubic_calc(0.25, 0.75, 0.5) - 0.5).abs() < 1e-10);
    }

    #[test]
    fn test_cubic_get_value_edges() {
        // ease: (0.25, 0.1, 0.25, 1.0)
        let c = Cubic::new(&[0.25, 0.1, 0.25, 1.0]);
        assert!((c.get_value(0.0)).abs() < 1e-9);
        assert!((c.get_value(1.0) - 1.0).abs() < 1e-9);
    }

    #[test]
    fn test_cubic_get_value_linear() {
        // linear: (0, 0, 1, 1) — bezier is identity
        let c = Cubic::new(&[0.0, 0.0, 1.0, 1.0]);
        assert!((c.get_value(0.5) - 0.5).abs() < 1e-4);
    }

    #[test]
    fn test_interpolate() {
        let from = vec![0.0, 10.0, 100.0];
        let to = vec![10.0, 20.0, 200.0];
        let result = interpolate(&from, &to, 0.5);
        assert_eq!(result, vec![5.0, 15.0, 150.0]);

        let result0 = interpolate(&from, &to, 0.0);
        assert_eq!(result0, from);

        let result1 = interpolate(&from, &to, 1.0);
        assert_eq!(result1, to);
    }

    #[test]
    fn test_rotation_to_matrix() {
        let eps = 1e-10;

        // 0°: identity-like [1, 0, 0, 1]
        let m0 = rotation_to_matrix(0.0);
        assert!((m0[0] - 1.0).abs() < eps);
        assert!(m0[1].abs() < eps);
        assert!(m0[2].abs() < eps);
        assert!((m0[3] - 1.0).abs() < eps);

        // 90°: [0, -1, 1, 0]
        let m90 = rotation_to_matrix(90.0);
        assert!(m90[0].abs() < eps);
        assert!((m90[1] + 1.0).abs() < eps);
        assert!((m90[2] - 1.0).abs() < eps);
        assert!(m90[3].abs() < eps);

        // 180°: [-1, 0, 0, -1]
        let m180 = rotation_to_matrix(180.0);
        assert!((m180[0] + 1.0).abs() < eps);
        assert!(m180[1].abs() < eps);
        assert!(m180[2].abs() < eps);
        assert!((m180[3] + 1.0).abs() < eps);

        // 45°: [cos45, -sin45, sin45, cos45]
        let m45 = rotation_to_matrix(45.0);
        let c = SQRT_2 / 2.0;
        assert!((m45[0] - c).abs() < eps);
        assert!((m45[1] + c).abs() < eps);
        assert!((m45[2] - c).abs() < eps);
        assert!((m45[3] - c).abs() < eps);
    }
}
