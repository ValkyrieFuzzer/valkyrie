/*
get the output(objective) of the conds.
*/

use angora_common::{cond_stmt_base::CondStmtBase, defs};
use std;

const EPS: i128 = 1;
pub trait CondOutput {
    fn get_output(&self) -> i128;
}

impl CondOutput for CondStmtBase {
    // relu
    fn get_output(&self) -> i128 {
        let mut a = self.arg1;
        let mut b = self.arg2;

        if self.is_signed() {
            a = translate_signed_value(a, self.size);
            b = translate_signed_value(b, self.size);
        }
        let a = a as i128;
        let b = b as i128;
        /*
        let a = if self.is_signed() {
            translate_to_i128(a, self.size)
        } else {
            a as i128
        };
        let b = if self.is_signed() {
            translate_to_i128(b, self.size)
        } else {
            b as i128
        };
        */
        // Add special judge for special OP.
        // This used to be taken care of as the default branch
        // in the next match, but it's not making sense.
        if self.op == defs::COND_AFL_OP
            || self.op == defs::COND_FN_OP
            || self.op == defs::COND_LEN_OP
        {
            return sub_abs(a, b);
        }

        let mut op = self.op & defs::COND_BASIC_MASK;

        if op == defs::COND_SW_OP {
            op = defs::COND_ICMP_EQ_OP;
        }

        // if its condition is true, we want its opposite constraint.
        if self.is_explore() && self.condition == defs::COND_TRUE_ST {
            op = match op {
                defs::COND_ICMP_EQ_OP => defs::COND_ICMP_NE_OP,
                defs::COND_ICMP_NE_OP => defs::COND_ICMP_EQ_OP,
                defs::COND_ICMP_UGT_OP => defs::COND_ICMP_ULE_OP,
                defs::COND_ICMP_UGE_OP => defs::COND_ICMP_ULT_OP,
                defs::COND_ICMP_ULT_OP => defs::COND_ICMP_UGE_OP,
                defs::COND_ICMP_ULE_OP => defs::COND_ICMP_UGT_OP,
                defs::COND_ICMP_SGT_OP => defs::COND_ICMP_SLE_OP,
                defs::COND_ICMP_SGE_OP => defs::COND_ICMP_SLT_OP,
                defs::COND_ICMP_SLT_OP => defs::COND_ICMP_SGE_OP,
                defs::COND_ICMP_SLE_OP => defs::COND_ICMP_SGT_OP,
                _ => op,
            };
        }

        let output = match op {
            defs::COND_ICMP_EQ_OP => {
                // a == b : f = a - b
                a - b
            }
            defs::COND_ICMP_NE_OP => {
                // a != b :
                // f = 0 if a != b, and f = 1 if a == b
                if a == b {
                    1
                } else {
                    0
                }
            }
            defs::COND_ICMP_SGT_OP | defs::COND_ICMP_UGT_OP => {
                // a > b :
                b - a + EPS
            }
            defs::COND_ICMP_UGE_OP | defs::COND_ICMP_SGE_OP => {
                // a > = b
                b - a
            }
            defs::COND_ICMP_ULT_OP | defs::COND_ICMP_SLT_OP => {
                // a < b :
                a - b + EPS
            }
            defs::COND_ICMP_ULE_OP | defs::COND_ICMP_SLE_OP => {
                // a < = b
                a - b
            }
            _ => {
                //TODO : support float.
                // if self.is_float() {
                a - b
            }
        };

        output
    }
}

fn sub_abs(arg1: i128, arg2: i128) -> i128 {
    (arg1 - arg2).abs()
}

#[allow(unused)]
fn translate_to_i128(v: u64, size: u32) -> i128 {
    match size {
        1 => v as i8 as i128,
        2 => v as i16 as i128,
        4 => v as i32 as i128,
        8 => v as i64 as i128,
        _ => v as i128,
    }
}

#[allow(unused)]
fn translate_signed_value(v: u64, size: u32) -> u64 {
    match size {
        1 => {
            let mut s = v as i8;
            if s < 0 {
                // [-128, -1] => [0, 127]
                s = s + std::i8::MAX;
                s = s + 1;
                s as u8 as u64
            } else {
                // [0, 127] -> [128, 255]
                v + (std::i8::MAX as u64 + 1)
            }
        }

        2 => {
            let mut s = v as i16;
            if s < 0 {
                s = s + std::i16::MAX;
                s = s + 1;
                s as u16 as u64
            } else {
                v + (std::i16::MAX as u64 + 1)
            }
        }

        4 => {
            let mut s = v as i32;
            if s < 0 {
                s = s + std::i32::MAX;
                s = s + 1;
                s as u32 as u64
            } else {
                v + (std::i32::MAX as u64 + 1)
            }
        }

        8 => {
            let mut s = v as i64;
            if s < 0 {
                s = s + std::i64::MAX;
                s = s + 1;
                s as u64
            } else {
                v + (std::i64::MAX as u64 + 1)
            }
        }

        _ => v,
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_translate_sign() {
        assert_eq!(
            translate_signed_value(0xffffffff80000000, 8),
            0x7fffffff80000000
        );
        assert_eq!(translate_signed_value(255, 1), 127);
    }
}
