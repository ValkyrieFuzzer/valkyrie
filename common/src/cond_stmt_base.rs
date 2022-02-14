use crate::defs::*;
use serde_derive::{Deserialize, Serialize};
use std::hash::{Hash, Hasher};

#[derive(Debug, Clone, Default, Copy, Serialize, Deserialize)]
#[repr(C)] // It should be repr C since we will used it in shared memory
pub struct CondStmtBase {
    pub cmpid: u32,
    pub context: u32,
    pub order: u32,
    pub belong: u32,

    pub condition: u32,
    pub level: u32,
    pub op: u32,
    pub size: u32,

    pub lb1: u32,
    pub lb2: u32,

    pub arg1: u64,
    pub arg2: u64,
}

/*
#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub struct CondStmtMb {
    pub base: CondStmtBase,
    pub magic_bytes: Option<(Vec<u8>, Vec<u8>)>,
}
*/
/*
impl PartialEq for CondStmtBase {
    fn eq(&self, other: &CondStmtBase) -> bool {
        self.cmpid == other.cmpid && self.context == other.context && self.belong == other.belong
    }
}
impl Eq for CondStmtBase {}

impl Hash for CondStmtBase {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.cmpid.hash(state);
        self.context.hash(state);
        self.belong.hash(state);
    }
}
*/
impl CondStmtBase {
    pub fn flip_condition(&mut self) {
        if self.condition == COND_FALSE_ST {
            self.condition = COND_TRUE_ST;
        } else {
            self.condition = COND_FALSE_ST;
        }
    }
    pub fn is_explore(&self) -> bool {
        (self.op & COND_SPECIAL_MASK) == 0 && (self.op & COND_EXPLOIT_MASK) == 0
    }

    pub fn is_exploitable(&self) -> bool {
        (self.op & COND_SPECIAL_MASK) == 0 && (self.op & COND_EXPLOIT_MASK) != 0
    }
    pub fn is_exploit_int(&self) -> bool {
        (self.op & COND_EXPLOIT_MASK) == COND_EXPLOIT_INT_MASK
    }
    pub fn is_exploit_mem(&self) -> bool {
        (self.op & COND_EXPLOIT_MASK) == COND_EXPLOIT_MEM_MASK
    }
    pub fn is_exploit_rand(&self) -> bool {
        (self.op & COND_EXPLOIT_MASK) == COND_EXPLOIT_RAND_MASK
    }

    pub fn is_signed(&self) -> bool {
        (self.op & COND_SIGN_MASK) > 0
            || ((self.op & COND_BASIC_MASK) >= COND_ICMP_SGT_OP
                && (self.op & COND_BASIC_MASK) <= COND_ICMP_SLE_OP)
    }

    pub fn is_afl(&self) -> bool {
        self.op == COND_AFL_OP
    }

    pub fn may_be_bool(&self) -> bool {
        // sign or unsigned
        self.op & 0xFF == COND_ICMP_EQ_OP && self.arg1 <= 1 && self.arg2 <= 1
    }

    pub fn is_float(&self) -> bool {
        (self.op & COND_BASIC_MASK) <= COND_FCMP_TRUE
    }

    pub fn is_switch(&self) -> bool {
        (self.op & COND_BASIC_MASK) == COND_SW_OP
    }

    pub fn is_done(&self) -> bool {
        self.condition == COND_DONE_ST
    }

    pub fn is_strict_equality(&self) -> bool {
        let mut op = self.op & COND_BASIC_MASK;
        if op == COND_SW_OP {
            op = COND_ICMP_EQ_OP;
        }
        op == COND_ICMP_EQ_OP || op == COND_ICMP_NE_OP
    }

    pub fn is_gd_search(&self) -> bool {
        debug_assert!(
            (self.op < COND_SPECIAL_MASK && self.op != COND_EXPLOIT_RAND_MASK)
                == (self.is_exploitable() || self.is_explore())
        );
        self.op < COND_SPECIAL_MASK && self.op != COND_EXPLOIT_RAND_MASK
    }
}
