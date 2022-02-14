use super::*;
use angora_common::debug_cmpid;
use std::cmp;

pub struct DetFuzz<'a> {
    handler: SearchHandler<'a>,
}

impl<'a> DetFuzz<'a> {
    pub fn new(handler: SearchHandler<'a>) -> Self {
        Self { handler }
    }
    pub fn bitflip1(&mut self) {
        debug_cmpid!(self.handler.cond.base.cmpid, "detministic steps");
        let mut input = self.handler.get_f_input();
        let n = cmp::min(input.val_len() * 8, config::MAX_SEARCH_EXEC_NUM);

        // Flip every single bit of input
        for i in 0..n {
            // Early exit if condition solved by chance
            if self.handler.cond.is_done() {
                break;
            }
            input.bitflip(i);
            self.handler.execute_cond(&input);
            input.bitflip(i);
        }
    }

    pub fn run(&mut self) {
        self.bitflip1();
    }
}
