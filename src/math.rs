use ethnum::U256;

pub fn add_mod(a: U256, b: U256, n: U256) -> U256 {
    let space = (n - 1) - a;

    if b <= space {
        a + b
    } else {
        b - space - 1
    }
}

pub fn sub_mod(a: U256, b: U256, n: U256) -> U256 {
    if a >= b {
        a - b
    } else {
        n - (b - a)
    }
}

pub fn mul_mod(mut a: U256, mut b: U256, n: U256) -> U256 {
    let mut result = U256::ZERO;
    a %= n;
    b %= n;

    while b != 0 {
        if (b & 1) == 1 {
            result = add_mod(result, a, n);
        }

        b >>= 1;

        if a < n - a {
            a <<= 1;
        } else {
            a -= n - a;
        }
    }

    result % n
}

pub fn mod_inverse(mut a: U256, mut b: U256) -> U256 {
    #[derive(Clone, Copy, Debug)]
    struct U256WithSign {
        value: U256,
        is_negative: bool,
    }

    if b <= 1 {
        return U256::ZERO;
    }

    let b0 = b;
    let mut x0 = U256WithSign { value: U256::ZERO, is_negative: false };
    let mut x1 = U256WithSign { value: U256::ONE, is_negative: false };

    while a > 1 {
        if b == 0 {
            return U256::ZERO;
        }

        let q = a / b;
        (b, a) = (a % b, b);

        let t = x0;
        let qx0 = q * x0.value;

        if x0.is_negative != x1.is_negative {
            x0.value = x1.value + qx0;
            x0.is_negative = x1.is_negative;
        } else {
            if x1.value > qx0 {
                x0.value = x1.value - qx0;
                x0.is_negative = x1.is_negative;
            } else {
                x0.value = qx0 - x1.value;
                x0.is_negative = !x0.is_negative;
            }
        }

        x1 = t;
    }

    if x1.is_negative {
        b0 - x1.value
    } else {
        x1.value
    }
}

pub type Point = (U256, U256);

#[derive(Debug, Copy, Clone)]
// we don't use the `b` curve parameter, but we might as well include the full curve constants
#[allow(dead_code)]
pub struct Curve {
    pub a: U256,
    pub b: U256,
    pub p: U256,
    pub g: Point,
    pub n: U256,
}

impl Curve {
    pub fn add_points(&self, p1: Point, p2: Point) -> Point {
        let (x1, y1) = p1;
        let (x2, y2) = p2;

        let m = if x1 == x2 {
            assert!(y1 == y2 && y1 != 0);

            // a = (3 * x1 * x1 + self.a)
            let a = add_mod(
                mul_mod(
                    mul_mod(x1, x1, self.p),
                    U256::new(3u128), self.p
                ),
                self.a,
                self.p
            );

            // b = pow(2 * y1, -1, self.p)
            let b = mod_inverse(mul_mod(U256::new(2u128), y1, self.p), self.p);

            // m = (a * b) % self.p
            mul_mod(a, b, self.p)
        } else {
            // a = (y2 - y1)
            let a = sub_mod(y2, y1, self.p);

            // b = pow(x2 - x1, -1, self.p)
            let b = mod_inverse(sub_mod(x2, x1, self.p), self.p);

            // m = (a * b) % self.p
            mul_mod(a, b, self.p)
        };

        // x3 = (m * m - x1 - x2) % self.p
        let x3 = sub_mod(sub_mod(mul_mod(m, m, self.p), x1, self.p), x2, self.p);

        // y3 = (m * (x1 - x3) - y1) % self.p
        let y3 = sub_mod(mul_mod(m, sub_mod(x1, x3, self.p), self.p), y1, self.p);

        (x3, y3)
    }

    pub fn scalar_multiply(&self, mut k: U256, point: Point) -> Point {
        let mut addend = point;
        let mut result = None;

        while k != 0 {
            if (k & 1) == 1 {
                result = Some(match result {
                    None => addend,
                    Some(p) => self.add_points(p, addend),
                });
            }

            addend = self.add_points(addend, addend);
            k >>= 1;
        }

        result.unwrap()
    }
}