use super::CondState;
use crate::fuzz_type::FuzzType;
use angora_common::{cond_stmt_base::CondStmtBase, defs, tag::TagSeg};
use serde_derive::{Deserialize, Serialize};
use std::hash::{Hash, Hasher};

#[derive(Debug, Default, Clone, Deserialize, Serialize)]
pub struct CondStmt {
    pub base: CondStmtBase,
    pub offsets: Vec<TagSeg>,
    pub offsets_opt: Vec<TagSeg>,
    pub variables: Vec<u8>,

    pub speed: u32,
    pub is_desirable: bool, // non-convex
    pub is_consistent: bool,
    pub fuzz_times: usize,
    pub state_times: usize,
    pub state: CondState,
    pub num_minimal_optima: usize,
    pub linear: bool,
}

impl PartialEq for CondStmt {
    fn eq(&self, other: &CondStmt) -> bool {
        self.base == other.base
    }
}

impl Eq for CondStmt {}

impl Hash for CondStmt {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.base.cmpid.hash(state);
        self.base.context.hash(state);
        self.base.order.hash(state);
    }
}

impl CondStmt {
    pub fn new() -> Self {
        let cond_base = Default::default();
        Self {
            base: cond_base,
            offsets: vec![],
            offsets_opt: vec![],
            variables: vec![],
            speed: 0,
            is_consistent: true,
            is_desirable: true,
            fuzz_times: 0,
            state_times: 0,
            state: CondState::default(),
            num_minimal_optima: 0,
            linear: false,
        }
    }

    pub fn from(cond_base: CondStmtBase) -> Self {
        let mut cond = Self::new();
        cond.base = cond_base;
        cond
    }

    pub fn get_fuzz_type(&self) -> FuzzType {
        match self.base.op {
            defs::COND_AFL_OP => FuzzType::AFLFuzz,
            defs::COND_LEN_OP => FuzzType::LenFuzz,
            defs::COND_FN_OP => FuzzType::CmpFnFuzz,
            _ => {
                if self.base.is_explore() {
                    FuzzType::ExploreFuzz
                } else if self.base.is_exploitable() {
                    FuzzType::ExploitFuzz
                } else {
                    FuzzType::OtherFuzz
                }
            }
        }
    }

    pub fn is_tainted(&self) -> bool {
        self.offsets.len() > 0
    }

    pub fn is_bool(&self) -> bool {
        (self.base.may_be_bool() && !self.is_desirable) || (self.base.op & defs::COND_BOOL_MASK) > 0
    }

    pub fn mark_as_done(&mut self) {
        self.base.condition = defs::COND_DONE_ST;
        self.clear();
    }

    pub fn clear(&mut self) {
        self.offsets = vec![];
        self.offsets_opt = vec![];
        self.variables = vec![];
    }

    #[inline(always)]
    pub fn is_discarded(&self) -> bool {
        self.is_done() || self.state.is_unsolvable() || self.state.is_timeout()
    }

    #[inline(always)]
    pub fn is_first_time(&self) -> bool {
        self.state_times == 1
    }

    /// The second time we try to solve a predicate,
    /// we enable all possible dyn analysis to get a
    /// more accurate information. Therefore, at some point
    /// "second time" should be treated just like first time.
    /// Thus the following call `more_than_twice` is equal
    /// than previous `!is_first_time()`
    #[inline(always)]
    pub fn is_second_time(&self) -> bool {
        self.state_times == 2
    }
    #[inline(always)]
    pub fn more_than_twice(&self) -> bool {
        self.state_times > 2
    }

    pub fn get_afl_cond(id: usize, speed: u32, edge_num: usize) -> Self {
        let mut afl_cond = Self::new();
        afl_cond.speed = speed;
        afl_cond.base.op = defs::COND_AFL_OP;
        afl_cond.base.cmpid = id as u32;
        afl_cond.base.context = 0;
        afl_cond.base.order = 0;
        afl_cond.base.arg1 = edge_num as u64;
        afl_cond
    }

    /// Shows if cond is marked as done.
    #[inline(always)]
    pub fn is_done(&self) -> bool {
        self.base.is_done()
    }
    /// Shows if current cond output means its solved.
    ///
    /// `solved` is different from `done`.
    /// If a cond is `done`, both sides has been reached, but the solver may have no idea of it.
    /// On the other hand, the solver may have `solved` the cond, but due to control change, it's
    /// not reached.
    #[inline(always)]
    pub fn is_solved(&self, output: i128) -> bool {
        let exact = self.base.is_strict_equality();
        (exact && output == 0) || (!exact && output <= 0)
    }
}
