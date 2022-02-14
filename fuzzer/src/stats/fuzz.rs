use super::*;
use crate::cond_stmt::CondStmt;
use serde_derive::Serialize;

#[derive(Clone, Copy, Default, Serialize)]
pub struct StrategyStats {
    pub time: TimeDuration,
    pub num_conds: usize,
    pub active_conds: usize,
    pub num_exec: Counter,
    pub num_inputs: Counter,
    pub num_hangs: Counter,
    pub num_crashes: Counter,
}

impl fmt::Display for StrategyStats {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{:7} {:7} {} {} {} {}   {}",
            self.num_conds,
            self.active_conds,
            self.num_exec,
            self.num_inputs,
            self.num_hangs,
            self.num_crashes,
            self.time,
        )
    }
}

#[derive(Clone, Default, Serialize)]
pub struct FuzzStats([StrategyStats; fuzz_type::FUZZ_TYPE_NUM]);

impl FuzzStats {
    #[inline]
    pub fn get_mut(&mut self, i: usize) -> &mut StrategyStats {
        debug_assert!(i < fuzz_type::FUZZ_TYPE_NUM);
        &mut self.0[i]
    }

    pub fn get(&self, i: usize) -> &StrategyStats {
        debug_assert!(i < fuzz_type::FUZZ_TYPE_NUM);
        &self.0[i]
    }

    pub fn clear(&mut self) {
        for s in self.0.iter_mut() {
            s.num_conds = Default::default();
            s.active_conds = Default::default();
        }
    }

    pub fn count(&mut self, cond: &CondStmt) {
        let stat = &mut self.0[cond.get_fuzz_type().index()];
        stat.num_conds += 1;
        if !cond.is_done() {
            stat.active_conds += 1;
        }
    }

    pub fn may_be_model_failure(&self) -> bool {
        self.0[fuzz_type::FuzzType::ExploreFuzz.index()].num_conds + 1
            < (self.0[fuzz_type::FuzzType::AFLFuzz.index()].num_conds
                + self.0[fuzz_type::FuzzType::OtherFuzz.index()].num_conds)
    }
}

impl fmt::Display for FuzzStats {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let _ = writeln!(
            f,
            "           | {:>7} {:>7} {:>7} {:>7} {:>7} {:>7}   {:>10}",
            "CONDS", "ACTIVE", "EXEC", "NORMAL", "HANG", "CRASH", "TIME",
        )?;
        let contents = self
            .0
            .iter()
            .enumerate()
            .map(|(i, s)| {
                format!(
                    "  {:>8} | {}",
                    fuzz_type::get_fuzz_type_name(i).to_uppercase(),
                    s
                )
            })
            .collect::<Vec<_>>()
            .join("\n");
        write!(f, "{}", contents)
    }
}
