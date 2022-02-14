use crate::{
    branches::GlobalBranches, command::CommandOpt, cond_stmt::NextState, depot::Depot,
    executor::Executor, fuzz_type::FuzzType, search::*, stats,
};
use angora_common::{config::FuzzerConfig, debug_cmpid};
use rand::prelude::*;
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, RwLock,
    },
    time::Instant,
};

#[cfg(debug_assertions)]
use lazy_static::lazy_static;
#[cfg(debug_assertions)]
use parse_int::parse;
#[cfg(debug_assertions)]
lazy_static! {
    /// Halt the fuzzer after a certain cmpid
    static ref HALT_AFTER_CMPID: Option<u32> = {
        std::env::var("HALT_AFTER_CMPID").ok().and_then(|s| parse::<u32>(&s).ok())
    };
}

pub fn fuzz_loop(
    running: Arc<AtomicBool>,
    cmd_opt: CommandOpt,
    depot: Arc<Depot>,
    global_branches: Arc<GlobalBranches>,
    global_stats: Arc<RwLock<stats::ChartStats>>,
) {
    // let search_method = cmd_opt.search_method;
    let mut executor = Executor::new(
        cmd_opt,
        global_branches,
        depot.clone(),
        global_stats.clone(),
    );

    info!(
        "Starting fuzzing loop on thread {:?}",
        std::thread::current().id()
    );
    let mut now = Instant::now();

    // Actual fuzz loop, most of fuzzer time spent here
    while running.load(Ordering::Relaxed) {
        let (mut cond, priority) = match depot.get_entry() {
            Some(e) => e,
            None => break,
        };

        if priority.is_done() {
            break;
        }
        if cond.is_done() {
            depot.update_entry(cond);
            continue;
        }

        let belong_input = cond.base.belong as usize;

        /*
        if config::ENABLE_PREFER_FAST_COND && cond.base.op == defs::COND_AFL_OP {
            let mut rng = thread_rng();
            let speed_ratio = depot.get_speed_ratio(belong_input);
            if speed_ratio > 1 {
                // [2, 3] -> 2
                // [4, 7] -> 3
                // [7, 15] -> 4
                // [16, ..] -> 5
                let weight = ((speed_ratio + 1) as f32).log2().ceil() as u32;
                if !rng.gen_weighted_bool(weight) {
                    continue;
                }
            }
        }
        */

        let buf = depot.get_input_buf(belong_input);
        {
            // When debugging a certain cmpid, don't waste time on other
            // exploitable constraints.
            #[cfg(debug_assertions)]
            {
                if let Some(halt_after_cmpid) = *HALT_AFTER_CMPID {
                    if cond.base.is_exploitable() && cond.base.cmpid != halt_after_cmpid {
                        continue;
                    }
                }
                use angora_common::DEBUG_CMPID;
                if let Some(cmpid) = *DEBUG_CMPID {
                    if cond.base.is_exploitable() && cond.base.cmpid != cmpid {
                        continue;
                    }
                }
            }
            let fuzz_type = cond.get_fuzz_type();
            let handler = SearchHandler::new(running.clone(), &mut executor, &mut cond, buf);
            match fuzz_type {
                FuzzType::ExploreFuzz | FuzzType::ExploitIntFuzz | FuzzType::ExploitMemFuzz => {
                    debug_cmpid!(handler.cond.base.cmpid, "cond: {:?}", handler.cond);
                    if handler.cond.is_time_expired() {
                        handler.cond.next_state();
                    }
                    if handler.cond.state.is_one_byte() {
                        OneByteFuzz::new(handler).run();
                    } else if handler.cond.state.is_det() {
                        DetFuzz::new(handler).run();
                    } else {
                        IntGdSearch::new(handler, 25, false).run(&mut thread_rng());
                    }
                },
                FuzzType::ExploitRandFuzz => {
                    // Use angora's random exploit, i.e. byte matching, etc.
                    if handler.cond.state.is_one_byte() {
                        OneByteFuzz::new(handler).run();
                    } else {
                        ExploitFuzz::new(handler).run();
                    }
                },
                FuzzType::AFLFuzz => {
                    AFLFuzz::new(handler).run();
                },
                FuzzType::LenFuzz => {
                    LenFuzz::new(handler).run();
                },
                FuzzType::CmpFnFuzz => {
                    FnFuzz::new(handler).run();
                },
                FuzzType::OtherFuzz => {
                    warn!("Unknown fuzz type!!");
                },
            }
        }
        #[cfg(debug_assertions)]
        {
            let mills = now.elapsed().as_millis();
            info!(
                "cmpid: 0x{:08x}, type: {:?}, priority: {}, elapsed: {:1}.{:03}s, solved: {}",
                cond.base.cmpid,
                cond.get_fuzz_type(),
                priority.get(),
                mills / 1000,
                mills % 1000,
                cond.is_done(),
            );
            now = Instant::now();

            if let Some(halt_after_cmpid) = *HALT_AFTER_CMPID {
                if cond.base.cmpid == halt_after_cmpid && cond.is_done() {
                    info!(
                        "Fuzzer halted after cmpid: 0x{:08x} is done.",
                        halt_after_cmpid
                    );
                    std::process::exit(1);
                }
            }
        }

        depot.update_entry(cond);
    }
}
