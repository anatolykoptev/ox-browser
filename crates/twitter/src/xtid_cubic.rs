/// Cubic bezier easing, linear interpolation, and rotation matrix utilities.
///
/// `Cubic` is a port of Chromium's `gfx::CubicBezier` (ui/gfx/geometry/cubic_bezier.cc):
/// X's loading animation runs in the browser, so the easing value is whatever the
/// browser computes: a piecewise-linear first guess from 11 samples of x(t), up to
/// four Newton steps, then bisection inside the sample bracket, tolerance 1e-7.
/// Plain bisection (the reference implementation's method) returns a different t
/// for some keys and moves a printed digit. `testdata/browser` holds the browser's
/// own answers.
use std::f64::consts::PI;

/// `kBezierEpsilon`, the tolerance `CubicBezier::Solve` uses.
const EPSILON: f64 = 1e-7;
/// `kMaxNewtonIterations`.
const NEWTON_ITERATIONS: usize = 4;
/// `CUBIC_BEZIER_SPLINE_SAMPLES`.
const SPLINE_SAMPLES: usize = 11;

pub(crate) struct Cubic {
    ax: f64,
    bx: f64,
    cx: f64,
    ay: f64,
    by: f64,
    cy: f64,
    start_gradient: f64,
    end_gradient: f64,
    spline_samples: [f64; SPLINE_SAMPLES],
}

impl Cubic {
    /// Builds the curve from `[x1, y1, x2, y2]`.
    pub(crate) fn new(curves: &[f64]) -> Self {
        assert!(curves.len() >= 4, "curves must have at least 4 elements");
        let (x1, y1, x2, y2) = (curves[0], curves[1], curves[2], curves[3]);
        let cx = 3.0 * x1;
        let bx = 3.0 * (x2 - x1) - cx;
        let ax = 1.0 - cx - bx;
        let cy = 3.0 * y1;
        let by = 3.0 * (y2 - y1) - cy;
        let ay = 1.0 - cy - by;

        let start_gradient = if x1 > 0.0 {
            y1 / x1
        } else if y1 == 0.0 && x2 > 0.0 {
            y2 / x2
        } else if y1 == 0.0 && y2 == 0.0 {
            1.0
        } else {
            0.0
        };
        let end_gradient = if x2 < 1.0 {
            (y2 - 1.0) / (x2 - 1.0)
        } else if y2 == 1.0 && x1 < 1.0 {
            (y1 - 1.0) / (x1 - 1.0)
        } else if y2 == 1.0 && y1 == 1.0 {
            1.0
        } else {
            0.0
        };

        let mut c = Self {
            ax,
            bx,
            cx,
            ay,
            by,
            cy,
            start_gradient,
            end_gradient,
            spline_samples: [0.0; SPLINE_SAMPLES],
        };
        let delta_t = 1.0 / (SPLINE_SAMPLES as f64 - 1.0);
        for i in 0..SPLINE_SAMPLES {
            c.spline_samples[i] = c.sample_x(i as f64 * delta_t);
        }
        c
    }

    fn sample_x(&self, t: f64) -> f64 {
        ((self.ax * t + self.bx) * t + self.cx) * t
    }

    fn sample_y(&self, t: f64) -> f64 {
        ((self.ay * t + self.by) * t + self.cy) * t
    }

    fn sample_derivative_x(&self, t: f64) -> f64 {
        (3.0 * self.ax * t + 2.0 * self.bx) * t + self.cx
    }

    /// `CubicBezier::SolveCurveX`: finds t with `sample_x(t) ~= x`.
    fn solve_curve_x(&self, x: f64, epsilon: f64) -> f64 {
        let (mut t0, mut t1, mut t2) = (0.0_f64, 1.0_f64, x);
        let delta_t = 1.0 / (SPLINE_SAMPLES as f64 - 1.0);
        for i in 1..SPLINE_SAMPLES {
            if x <= self.spline_samples[i] {
                t1 = delta_t * i as f64;
                t0 = t1 - delta_t;
                t2 = t0
                    + (t1 - t0) * (x - self.spline_samples[i - 1])
                        / (self.spline_samples[i] - self.spline_samples[i - 1]);
                break;
            }
        }

        // Newton's method. `x2` keeps the residual of the last point evaluated,
        // the one before the final step: Chromium tests that stale value too.
        let mut x2 = 0.0_f64;
        let newton_epsilon = EPSILON.min(epsilon);
        for _ in 0..NEWTON_ITERATIONS {
            x2 = self.sample_x(t2) - x;
            if x2.abs() < newton_epsilon {
                return t2;
            }
            let d2 = self.sample_derivative_x(t2);
            if d2.abs() < EPSILON {
                break;
            }
            t2 -= x2 / d2;
        }
        if x2.abs() < epsilon {
            return t2;
        }

        // Bisection, for reliability.
        while t0 < t1 {
            x2 = self.sample_x(t2);
            if (x2 - x).abs() < epsilon {
                return t2;
            }
            if x > x2 {
                t0 = t2;
            } else {
                t1 = t2;
            }
            t2 = (t1 + t0) * 0.5;
        }
        t2
    }

    /// `CubicBezier::Solve`: the eased value at progress `t`, extended linearly by
    /// the end gradients outside [0, 1].
    pub(crate) fn get_value(&self, t: f64) -> f64 {
        if t < 0.0 {
            return self.start_gradient * t;
        }
        if t > 1.0 {
            return 1.0 + self.end_gradient * (t - 1.0);
        }
        self.sample_y(self.solve_curve_x(t, EPSILON))
    }
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
