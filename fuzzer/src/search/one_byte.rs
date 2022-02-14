use super::*;
use crate::cond_stmt::NextState;
use angora_common::debug_cmpid;

pub struct OneByteFuzz<'a> {
    pub handler: SearchHandler<'a>,
}

impl<'a> OneByteFuzz<'a> {
    pub fn new(handler: SearchHandler<'a>) -> Self {
        Self { handler }
    }

    fn execute(&mut self, input: &MutInput) {
        debug_cmpid!(self.handler.cond.base.cmpid, "input : {:?}", input);
        if self.handler.cond.base.is_explore() {
            self.handler.execute_cond(input);
        } else {
            self.handler.execute_input(input);
        }
    }

    fn execute_direct(&mut self) {
        if self.handler.cond.base.is_explore() {
            self.handler.execute_cond_direct();
        } else {
            self.handler.execute_input_direct();
        }
    }

    pub fn run(&mut self) {
        if !self.handler.cond.is_first_time() {
            warn!("fuzz one byte more than one time");
            return;
        }
        self.handler.max_times = 257.into();
        let mut input = self.handler.get_f_input();
        if input.val_len() != 1 {
            error!("one byte len > 1, cond: {:?}", self.handler.cond);
            panic!();
        }
        self.execute_direct();

        // Enumerate all possible values of a byte
        for i in 0..256 {
            if self.handler.cond.is_done() {
                return;
            }
            input.set(0, i);
            self.execute(&input);
        }
        // Regardless, we don't need to try it again.
        self.handler.cond.to_unsolvable();
        debug_cmpid!(
            self.handler.cond.base.cmpid,
            "Can't solve one-byte cond with all possible values"
        );
    }
}
