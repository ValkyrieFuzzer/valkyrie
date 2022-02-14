use angora_common::{config::FuzzerConfig, defs};
use std::{self, cmp::Ordering, fmt};

const EXPLORE_INIT_PRIORITY: u16 = 0;
const AFL_INIT_PRIORITY: u16 = 1;
const EXPLOIT_INIT_PRIORITY: u16 = 2;

const DONE_PRIORITY: u16 = std::u16::MAX;

/// QPriority manages the priority of the condition based on op.
///
/// Unlike before where conditions can have same priority, here we partition
/// the u16 space into 3 sections, each representing a category of conditions.
///
/// We use `3k+0` for explore priority, which is the conditions that are originally
/// in the program, `3k+1` for AFL proiroty, and `3k+2` for exploit priority.
///
/// Everytime the priority is dropped by 3(# of categories), wihch makes sure
/// that all conditions in `3k + 0 ~ 3k + 2` can be tried before it is tried again.
#[derive(Eq, PartialEq, Clone, Copy, Debug)]
pub struct QPriority(pub u16);

impl QPriority {
    pub fn inc(&self, _op: u32) -> Self {
        if self.0 > FuzzerConfig::get().max_priority() {
            Self::done()
        } else {
            QPriority(self.0 + 3)
        }
    }

    pub fn init(op: u32) -> Self {
        if op == defs::COND_AFL_OP {
            Self::afl_init()
        } else if op & defs::COND_EXPLOIT_MASK != 0 {
            Self::exp_init()
        } else {
            Self::base_init()
        }
    }

    fn base_init() -> Self {
        QPriority(EXPLORE_INIT_PRIORITY)
    }

    fn afl_init() -> Self {
        QPriority(AFL_INIT_PRIORITY)
    }

    fn exp_init() -> Self {
        QPriority(EXPLOIT_INIT_PRIORITY)
    }

    pub fn done() -> Self {
        QPriority(DONE_PRIORITY)
    }

    pub fn is_done(&self) -> bool {
        self.0 == DONE_PRIORITY
    }

    pub fn get(&self) -> u16 {
        self.0
    }
}

// Make the queue get smallest priority first.
impl Ord for QPriority {
    fn cmp(&self, other: &QPriority) -> Ordering {
        other.0.cmp(&self.0)
    }
}

impl PartialOrd for QPriority {
    fn partial_cmp(&self, other: &QPriority) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Display for QPriority {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
