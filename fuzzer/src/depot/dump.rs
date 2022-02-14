use super::*;
use angora_common::{config::FuzzerConfig, defs};
use std::{fs, io::prelude::*};

impl Drop for Depot {
    fn drop(&mut self) {
        let dir = self.dirs.inputs_dir.parent().unwrap();

        info!("dump config");
        let mut config_f = fs::File::create(dir.join(defs::CONFIG_FILE)).unwrap();
        writeln!(config_f, "{:#?}", FuzzerConfig::get());

        if FuzzerConfig::get().belong() {
            return;
        }
        info!("dump constraints and chart..");
        let mut log_q = fs::File::create(dir.join(defs::COND_QUEUE_FILE)).unwrap();
        writeln!(
            log_q,
            "cmpid, context, order, belong, op, p, condition, is_desirable, offsets, state"
        )
        .unwrap();
        let q = self.queue.lock().unwrap();

        for (cond, p) in q.iter() {
            if !cond.base.is_afl() {
                let mut offsets = vec![];
                for off in &cond.offsets {
                    offsets.push(format!("[{}:{})", off.begin, off.end));
                }

                writeln!(
                    log_q,
                    "0x{:08x}, {}, {}, {}, 0x{:x}, {}, {}, {}, {}, {:?}",
                    cond.base.cmpid,
                    cond.base.context,
                    cond.base.order,
                    cond.base.belong,
                    cond.base.op,
                    p,
                    cond.base.condition,
                    cond.is_desirable,
                    offsets.join("&"),
                    cond.state
                )
                .unwrap();
            }
        }
    }
}
