use rand::prelude::*;
use serde_derive::{Deserialize, Serialize};
use std::{
    fmt::{self, Debug},
    hash::{Hash, Hasher},
};

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Sign {
    Signed,
    Unsigned,
    Unknown,
}
impl Debug for Sign {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            Self::Signed => write!(f, "S"),
            Self::Unsigned => write!(f, "U"),
            Self::Unknown => write!(f, "X"),
        }
    }
}

impl Default for Sign {
    fn default() -> Self {
        Sign::Unknown
    }
}

impl From<bool> for Sign {
    fn from(sign: bool) -> Self {
        if sign {
            Sign::Signed
        } else {
            Sign::Unsigned
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Copy)]
pub struct SignInfo {
    static_sign: Sign,
    dyn_n_sign: Sign,
    dyn_s_sign: Sign,
    prob: f64,
}

impl PartialEq for SignInfo {
    fn eq(&self, other: &Self) -> bool {
        self.static_sign == other.static_sign
            && self.dyn_n_sign == other.dyn_n_sign
            && self.dyn_s_sign == other.dyn_s_sign
    }
}
impl Eq for SignInfo {}

impl Hash for SignInfo {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.static_sign.hash(state);
        self.dyn_n_sign.hash(state);
        self.dyn_s_sign.hash(state);
    }
}

impl Debug for SignInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(
            f,
            "{:?}{:?}{:?}({:.02})",
            self.static_sign, self.dyn_n_sign, self.dyn_s_sign, self.prob
        )
    }
}

impl SignInfo {
    pub fn from_static_sign(sign: bool) -> Self {
        Self::new(sign.into(), Sign::Unknown, Sign::Unknown)
    }
    pub fn update_dyn_sign(&mut self, dyn_n_sign: Sign, dyn_s_sign: Sign) {
        *self = Self::new(self.static_sign, dyn_n_sign, dyn_s_sign);
    }
    pub fn new(static_sign: Sign, dyn_n_sign: Sign, dyn_s_sign: Sign) -> Self {
        let prob = match (static_sign, dyn_n_sign, dyn_s_sign) {
            // Static unknown, shouldn't happen.
            (Sign::Unknown, _, _) => panic!("Static sign shouldn't be unknown"),

            // Static and dynamic agrees
            (Sign::Signed, Sign::Signed, Sign::Signed) => 1f64,
            (Sign::Unsigned, Sign::Unsigned, Sign::Unsigned) => 0f64,

            // Dynamic agrees, static disagrees
            (Sign::Unsigned, Sign::Signed, Sign::Signed) => 0.95,
            (Sign::Signed, Sign::Unsigned, Sign::Unsigned) => 0.05,

            // Disagree, random, but we trust dynamic more.
            (stat, dyn_n, dyn_s) => {
                let mut signed = 0.0;
                let mut unsigned = 0.0;
                let mut assign_prob = |s, inc| match s {
                    Sign::Signed => signed += inc,
                    Sign::Unsigned => unsigned += inc,
                    _ => {}
                };
                assign_prob(stat, 1.0);
                // We trust dynamic more.
                assign_prob(dyn_n, 2.0);
                assign_prob(dyn_s, 2.0);
                signed / (signed + unsigned)
            }
        };
        Self {
            static_sign,
            dyn_n_sign,
            dyn_s_sign,
            prob,
        }
    }
    /// Get the sign based on the probability we just calculated.
    #[allow(unused)]
    pub fn get_random_sign<R: Rng>(&self, rng: &mut R) -> bool {
        rng.gen_bool(self.prob)
    }
    /// Deterministic get sign based on concensus.
    #[allow(unused)]
    pub fn get_concensus_sign(&self) -> bool {
        self.prob > 0.5
    }
}
