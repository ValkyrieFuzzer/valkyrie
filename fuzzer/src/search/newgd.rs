use super::*;
use crate::mut_input::sign::{Sign, SignInfo};
use angora_common::{
    config::{self},
    defs,
};
use log::debug;

enum DescendStatus {
    /// The preidcate is solved while we are descending.
    SolvedHalfWay,
    /// Unable to move to a lower value for given step size,
    /// the gradient may not be accurate anymore given this
    /// huge step, recalculate gradient(i.e. next epoch)
    StepTooLarge,
    /// Unable to move even if step size is 1.
    /// This means there are nested constraints trapping us.
    Unable,
    /// Unable to move to a lower value if step size is 1.
    /// We are in a local minima
    LeadsToHigherValue,
    /// The gradient is zero.
    ZeroGrad,
}

/// Some useful traits of f64.
///
/// We didn't use `f64::is_sign_negative` and `f64::is_sign_positive`
/// as it will return true on -0.0 and +0.0.
/// For computation purposes, this is useless.
trait IsZero {
    const EPS: f64 = 1e-10;
    fn equal_to(&self, other: &f64) -> bool;
    fn greater_than(&self, other: &f64) -> bool;
    fn less_than(&self, other: &f64) -> bool;
    fn equal_to_zero(&self) -> bool {
        self.equal_to(&0.0)
    }
    fn greater_than_zero(&self) -> bool {
        self.greater_than(&0.0)
    }
    fn less_than_zero(&self) -> bool {
        self.less_than(&0.0)
    }
}
impl IsZero for f64 {
    fn equal_to(&self, other: &f64) -> bool {
        (self - other).abs() <= Self::EPS
    }
    fn greater_than(&self, other: &f64) -> bool {
        self - other > Self::EPS
    }
    fn less_than(&self, other: &f64) -> bool {
        self - other < -Self::EPS
    }
}

#[derive(Debug, Clone)]
struct Gradient {
    raw_grad: Vec<f64>,
    norm: f64,
}

impl Gradient {
    pub fn new(raw_grad: Vec<f64>) -> Self {
        let norm = raw_grad.iter().fold(0.0, |acc, x| acc + x * x).sqrt();
        Self { raw_grad, norm }
    }

    fn grad(&self, norm: f64) -> impl Iterator<Item = f64> + '_ {
        GradIter::new(self.raw_grad.iter(), norm)
    }

    pub fn iter_raw(&self) -> impl Iterator<Item = f64> + '_ {
        self.grad(1.0)
    }

    /// Returns if a dimension is positive(1.0), negative(-1.0) or 0.
    pub fn get_nth_direction(&self, idx: usize) -> f64 {
        debug_assert!(idx < self.raw_grad.len());
        if self.raw_grad[idx].equal_to_zero() {
            0.0
        } else if self.raw_grad[idx].greater_than_zero() {
            1.0
        } else if self.raw_grad[idx].less_than_zero() {
            -1.0
        } else {
            panic!("Shouldn't happen.");
        }
    }
    #[allow(dead_code)]
    pub fn iter_norm(&self) -> impl Iterator<Item = f64> + '_ {
        self.grad(self.norm)
    }
}

struct GradIter<'a, I: Iterator<Item = &'a f64>> {
    inner: I,
    norm: f64,
}

impl<'a, I: Iterator<Item = &'a f64>> GradIter<'a, I> {
    pub fn new(inner: I, norm: f64) -> Self {
        Self { inner, norm }
    }
}

impl<'a, I: Iterator<Item = &'a f64>> Iterator for GradIter<'a, I> {
    type Item = f64;
    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(|x| x / self.norm)
    }
}

pub struct IntGdSearch<'a> {
    pub handler: SearchHandler<'a>,
    cmpid: u32,
    max_epoch: usize,
    exact: bool,
    sample_index: (usize, usize),
    num_restart: usize,
}

impl<'a> IntGdSearch<'a> {
    pub fn new(handler: SearchHandler<'a>, max_epoch: usize, exact: bool) -> Self {
        let cmpid = handler.cond.base.cmpid;
        Self {
            handler,
            cmpid,
            max_epoch,
            exact,
            sample_index: (0, 0),
            num_restart: 0,
        }
    }

    // TODO: What's the sense of this execute.
    fn execute(&mut self, input: &MutInput) -> i128 {
        if self.handler.skip {
            return self.handler.executor.last_f;
        }
        debug!("input: {:?}", input);
        let f = self.handler.execute_cond(input);
        f
    }
    fn execute_cond(&mut self, input: &MutInput) -> f64 {
        debug!("input: {:?}", input);
        let f_new = self.handler.execute_cond(input);
        if f_new == defs::UNREACHABLE {
            f64::INFINITY
        } else {
            f_new as f64
        }
    }

    fn gradient(&mut self, x: &mut MutInput, fx: f64) -> Gradient {
        let n = x.len();
        let mut grad = vec![0f64; n];
        for i in 0..n {
            grad[i] = self.partial_gradient(x, i, fx);
        }
        Gradient::new(grad)
    }

    /// Calculate the gradient. It will also do dynamic endianness analysis
    /// and may split certain input into multiple bytes or switch endianess
    ///  of inputs.
    fn gradient_may_split(&mut self, x: &mut MutInput, fx: f64, ep_i: usize) -> Gradient {
        let mut idx = 0;
        let mut grad = Vec::with_capacity(x.len());
        while idx < x.len() {
            if ep_i == 0
                && self.handler.cond.is_second_time()
                // && partial_grad > 100.0
                && x.get_entry_len(idx) > 1
            {
                // Verify endianness.
                let (_, partial_grad_opt) = self.infer_endianness(x, idx, fx);
                if let Some(partial_grad_vec) = partial_grad_opt {
                    idx += partial_grad_vec.len();
                    grad.extend(partial_grad_vec);
                    debug_assert!(idx == grad.len());
                    continue;
                }
            }
            let partial_grad = self.partial_gradient(x, idx, fx);
            grad.push(partial_grad);
            idx += 1;
        }
        Gradient::new(grad)
    }

    /// Return if endianness changed
    ///
    /// There are 3 cases.
    /// - If it is indeed LE, nothing changes, return `(false, None)`
    /// - If it is BE, we change the endianness of the input, return `(true, None)`
    /// - If it is Split, we split the input into bytes, does sign inference and return
    /// all the partial gradients(since we had these information while doing endian
    /// inference anyway.), return `(true, Vec<f64>>)`
    ///
    /// The judging critia is the gradient around this point.
    fn infer_endianness(
        &mut self,
        x: &mut MutInput,
        idx: usize,
        fx: f64,
    ) -> (bool, Option<Vec<f64>>) {
        let len = x.get_entry_len(idx);
        // Prepare sub_x with only one dimension of the original input
        // but we split it into bytes to see the grad change.
        let mut sub_x = x.clone_nth(idx);
        debug!("Before endian split: {:?}", sub_x);
        sub_x.split_meta_w_sign_change(0, |input| {
            input.infer_dyn_sign(|input| self.execute_cond(input));
            input.assign_sign(&mut rand::thread_rng());
            debug!("Done inference new sign: {:?}", input);
        });
        debug_assert!(len == sub_x.len());
        debug!("After endian split: {:?}", sub_x);

        let partial_grad: Vec<f64> = (0..len)
            .map(|idx| self.partial_gradient(&mut sub_x, idx, fx))
            .collect();
        debug!("Partial grad for each byte: {:?}", partial_grad);

        let grad_abs: Vec<f64> = partial_grad.iter().map(|g| g.abs()).collect();
        // Process data points.
        let mut ascend = true;
        let mut descend = true;
        for idx in 0..grad_abs.len() - 1 {
            if grad_abs[idx].greater_than(&grad_abs[idx + 1]) {
                descend = false;
            } else if partial_grad[idx].less_than(&grad_abs[idx + 1]) {
                ascend = false;
            }
        }

        if ascend == descend {
            // No endianness, should split this var into bytes.
            debug!("Split");
            x.split_meta_w_sign_change(idx, |input| {
                let meta = input.get_mut_meta();
                sub_x
                    .take()
                    .1
                    .into_iter()
                    .enumerate()
                    .for_each(|(offset, meta_offset)| meta[offset + idx] = meta_offset);
            });
            (true, Some(partial_grad))
        } else if ascend {
            // Big endian
            debug!("Big Endian");
            x.nth_to_be_w_sign_change(idx, |input| self.execute_cond(input));
            (true, None)
        } else if descend {
            // Little endian
            // But we assumed le, then this must be a large partial gradient.
            debug!("Little Endian");
            (false, None)
        } else {
            unreachable!("Shouldn't be here");
        }
    }

    fn partial_gradient(&mut self, x: &mut MutInput, idx: usize, fx: f64) -> f64 {
        let max_step = 256f64;
        let mut perturbate = |s: &mut Self, mut step: f64| {
            // Take the orig buf out so we can mutate it.
            let orig_buf: Vec<u8> = x.get_slice(idx).iter().cloned().collect();
            let f_new = loop {
                let delta = x.add_nth_(idx, step);
                if delta != step {
                    break f64::INFINITY;
                }

                // Keep looping until a new f value is found...
                let f_new = s.execute_cond(&x);
                if !f_new.equal_to(&fx) {
                    break f_new;
                }

                step *= 2f64;
                if step > max_step {
                    break f64::INFINITY;
                }
            };
            // Apply the original data back.
            x.write_slice(idx, &orig_buf);
            // We take the doubled steps: s, s*2, s*4... s*(2^k)
            // `step.abs()` here is `s*(2^k)`
            // Therefore, all the steps sums up to
            // `s*2^(k+1) - 1 = step.abs() * 2f64 - 1f64`.
            (f_new, step.abs() * 2f64 - 1f64)
        };

        let (add_one_val, add_step) = perturbate(self, 1f64);
        debug!("add_one_val, step: {}, {}", add_one_val, add_step);
        let (sub_one_val, sub_step) = perturbate(self, -1f64);
        debug!("sub_one_val, step: {}, {}", sub_one_val, sub_step);

        // NAN is meant for crashing trials when we first developed
        // this algorithm. But in Angora's framework, unreachable and crash
        // is not distinguished, both case would return `defs::UNREACHABLE`,
        // thus the following code should not be reachable either.
        let ret = if add_one_val.is_nan() || sub_one_val.is_nan() {
            unreachable!("Shouldn't be here");
        // f64::NAN
        } else {
            // debug!("add_one_val={}, sub_one_val={}", add_one_val,sub_one_val);
            match (add_one_val.is_infinite(), sub_one_val.is_infinite()) {
                (true, true) => 0f64,
                (true, false) => (fx - sub_one_val) / sub_step,
                (false, true) => (add_one_val - fx) / sub_step,
                (false, false) => (add_one_val - sub_one_val) / (add_step + sub_step),
            }
        };
        // debug!("ret={}",ret);
        ret
    }

    fn reload_input(&mut self, input_min: &mut MutInput) -> i128 {
        input_min.assign(&self.handler.cond.variables);
        self.execute(&input_min)
    }

    fn is_solved(&self, f_curr: f64) -> bool {
        self.exact && f_curr.abs().equal_to_zero() || !self.exact && f_curr.less_than_zero()
    }

    pub fn run<T: Rng>(&mut self, rng: &mut T) {
        self.exact = self.handler.cond.base.is_strict_equality();
        let mut input = self.handler.get_f_input();
        debug_assert!(
            input.len() > 0,
            "Input length == 0!! {:?}",
            self.handler.cond
        );
        debug!("Init start...");
        let f0 = if self.handler.cond.more_than_twice() {
            self.execute(&input)
        } else {
            self.handler.cond.linear = true;
            self.init_start_point(&mut input)
        };
        debug!("Init start magic done, f0 = {}...", f0);

        // The magic before has done all the work for us.
        if self.handler.cond.is_done() {
            debug!("Cond is solved using initial magic");
            return;
        }
        if f0 == defs::UNREACHABLE {
            warn!("Initial input is unreachable.");
            return;
        }

        // If we decides to do dynamic sign inference.
        if self.handler.cond.is_second_time() {
            debug!("Before dyn sign inference: {:?}", input);
            input.infer_dyn_sign(|input| self.execute_cond(input));
            if self.handler.cond.is_done() {
                debug!("Cond is solved when inferring sign");
                return;
            }
            input.assign_sign(rng);
            debug!("After dyn sign inference: {:?}", input);
        }

        let mut grad;
        let mut f_curr = f0 as f64;
        for ep_i in 0..self.max_epoch {
            if self.handler.is_stopped_or_skip() {
                break;
            }
            debug!(">>> epoch={}, fcurr={}", ep_i, f_curr);
            grad = self.gradient_may_split(&mut input, f_curr, ep_i);
            debug!("input: {:?}", input);
            debug!("grad: {:?}", grad);
            if grad.iter_raw().find(|x| x.is_nan()).is_some() {
                debug!("Encountered NaN. Aborting");
                unreachable!();
            }
            let (f_new, status) = self.descend(grad, &mut input, f_curr);
            match status {
                DescendStatus::SolvedHalfWay => return,
                DescendStatus::StepTooLarge => {
                    f_curr = f_new;
                }
                DescendStatus::LeadsToHigherValue
                | DescendStatus::Unable
                | DescendStatus::ZeroGrad => {
                    if self.num_restart > config::MAX_NUM_MINIMAL_OPTIMA_ROUND {
                        return;
                    } else {
                        self.num_restart += 1;
                        self.repick_start_point(&mut input, f_curr, rng);
                        f_curr = self.execute_cond(&input);
                    }
                }
            }
        }
    }

    fn descend(&mut self, grad: Gradient, x_curr: &mut MutInput, f0: f64) -> (f64, DescendStatus) {
        if grad.iter_raw().find(|x| !x.equal_to_zero()).is_none() {
            return (f0, DescendStatus::ZeroGrad);
        }
        fn get_factor_of_coefficients(ics: &[(usize, f64)]) -> f64 {
            let v = f64::max(ics[ics.len() - 1].1.abs(), 1f64);
            v / ics.iter().fold(0.0, |acc, x| acc + x.1.powi(2))
        }
        fn f64_cmp(a: f64, b: f64) -> std::cmp::Ordering {
            if a.less_than(&b) {
                std::cmp::Ordering::Less
            } else if a.greater_than(&b) {
                std::cmp::Ordering::Greater
            } else {
                std::cmp::Ordering::Equal
            }
        }
        let mut ics_pos = Vec::new();
        let mut ics_neg = Vec::new();
        for (i, v) in grad.iter_raw().enumerate() {
            if v.greater_than_zero() {
                ics_pos.push((i, v));
            } else if v.less_than_zero() {
                ics_neg.push((i, v));
            }
        }
        ics_pos.sort_by(|a, b| f64_cmp(b.1, a.1));
        ics_neg.sort_by(|a, b| f64_cmp(a.1, b.1));
        debug_assert!(!(ics_pos.is_empty() && ics_neg.is_empty()));
        let factor = if ics_neg.is_empty() {
            get_factor_of_coefficients(&ics_pos)
        } else if ics_pos.is_empty() {
            get_factor_of_coefficients(&ics_neg)
        } else {
            get_factor_of_coefficients(&ics_pos).min(get_factor_of_coefficients(&ics_neg))
        };
        debug!("factor={}", factor);

        let mut descend_delta = grad.iter_raw().map(|x| -x * factor).collect::<Vec<_>>();
        let mut ascend_delta = descend_delta.iter().map(|x| -x).collect::<Vec<_>>();
        let mut f_curr = f0;
        let mut i = 0;
        let mut started = false;

        loop {
            debug!("x_curr={:?}, f_curr={}", x_curr, f_curr);

            // let mut x_new = vec![];
            let mut buf_new = vec![];
            let delta_slice = if f_curr.less_than_zero() && self.exact {
                // We should ascend
                &mut ascend_delta
            } else {
                &mut descend_delta
            };

            let mut add_delta_with_coeff_and_push_if_moved = |ics| {
                let (moved, buf) = x_curr.clone_buf_and_do(|x_copy| {
                    x_copy
                        .add_delta_with_coeffecients(delta_slice, ics)
                        .is_some()
                });
                if moved && !x_curr.is_value_identical(&buf) {
                    buf_new.push(buf);
                }
            };
            if ics_neg.is_empty() && !ics_pos.is_empty() {
                add_delta_with_coeff_and_push_if_moved(&ics_pos);
            } else if !ics_neg.is_empty() && ics_pos.is_empty() {
                add_delta_with_coeff_and_push_if_moved(&ics_neg);
            } else if !ics_neg.is_empty() && !ics_pos.is_empty() {
                add_delta_with_coeff_and_push_if_moved(&ics_pos);
                add_delta_with_coeff_and_push_if_moved(&ics_neg);
                if buf_new.len() == 2 {
                    let (moved, buf) = x_curr.clone_buf_and_do(|x_copy| {
                        x_copy.apply_value(buf_new[0].clone());
                        x_copy
                            .add_delta_with_coeffecients(delta_slice, &ics_neg)
                            .is_some()
                    });
                    if moved
                        && !x_curr.is_value_identical(&buf_new[0])
                        && !x_curr.is_value_identical(&buf_new[1])
                    {
                        buf_new.insert(0, buf);
                    }
                }
            } else
            /* ics_neg.is_empty() && ics_pos.is_empty() */
            {
                unreachable!();
            }
            /*
            if ics_neg.is_empty() || ics_pos.is_empty() {
                let mut x_copy = x_curr.clone();
                if ics_neg.is_empty() {
                    if x_copy
                        .add_delta_with_coeffecients(delta_slice, &ics_pos)
                        .is_some()
                        && x_copy != *x_curr
                    {
                        x_new.push(x_copy);
                    }
                } else if x_copy
                    .add_delta_with_coeffecients(delta_slice, &ics_neg)
                    .is_some()
                    && x_copy != *x_curr
                {
                    x_new.push(x_copy);
                }
            } else {
                let mut x_copy = x_curr.clone();
                if x_copy
                    .add_delta_with_coeffecients(delta_slice, &ics_pos)
                    .is_some()
                    && x_copy != *x_curr
                {
                    x_new.push(x_copy);
                }
                let mut x_copy = x_curr.clone();
                if x_copy
                    .add_delta_with_coeffecients(delta_slice, &ics_neg)
                    .is_some()
                    && x_copy != *x_curr
                {
                    x_new.push(x_copy);
                }
                if x_new.len() == 2 {
                    let mut x_copy = x_new[0].clone();
                    if x_copy
                        .add_delta_with_coeffecients(delta_slice, &ics_neg)
                        .is_some()
                        && x_copy != x_new[0]
                        && x_copy != x_new[1]
                    {
                        x_new.insert(0, x_copy);
                    }
                }
            }
            */
            if buf_new.is_empty() && i == 0 {
                let (moved, buf) = x_curr.clone_buf_and_do(|x_copy| {
                    debug!("inc_lsb");
                    x_copy.inc_lsb(&ics_neg)
                });
                if moved {
                    buf_new.push(buf);
                }
                let (moved, buf) = x_curr.clone_buf_and_do(|x_copy| {
                    debug!("dec_lsb");
                    x_copy.dec_lsb(&ics_pos)
                });
                if moved {
                    buf_new.push(buf)
                }
            }
            /*
            if x_new.is_empty() && i == 0 {
                let mut x_copy = x_curr.clone();
                if x_copy.inc_lsb(&ics_neg) {
                    debug!("inc_lsb");
                    x_new.push(x_copy);
                }
                let mut x_copy = x_curr.clone();
                if x_copy.dec_lsb(&ics_pos) {
                    debug!("dec_lsb");
                    x_new.push(x_copy);
                }
            }
            */
            let mut found = false;
            let mut all_inf = true;

            for buf in buf_new.into_iter() {
                let (f_new, buf) = x_curr.replace_buf_and_do(buf, |x_| self.execute_cond(&x_));
                debug!("value={:?}, f_new={}", buf, f_new);
                if f_new.is_infinite() {
                    continue;
                } else if self.is_solved(f_new) {
                    x_curr.apply_value(buf);
                    return (f_new, DescendStatus::SolvedHalfWay);
                } else if f_new.abs() < f_curr.abs() {
                    // Save the input that minimizes absolute value of condition
                    x_curr.apply_value(buf);
                    f_curr = f_new;
                    found = true;
                    break;
                } else {
                    all_inf = false;
                }
            }
            /*
            for x_ in x_new.into_iter() {
                let f_new = self.execute_cond(&x_);
                debug!("x_={:?}, f_new={}", x_, f_new);
                if f_new.is_infinite() {
                    continue;
                } else if self.is_solved(f_new) {
                    *x_curr = x_;
                    return (f_new, DescendStatus::SolvedHalfWay);
                // Why abs? If it is eq constraint, we should change direction.
                } else if f_new.abs() < f_curr.abs() {
                    // Save the input that minimizes absolute value of condition
                    *x_curr = x_;
                    f_curr = f_new;
                    found = true;
                    break;
                } else {
                    all_inf = false;
                }
            }
            */
            if !found {
                let status = if started {
                    debug!(
                        "Cannot make such step(size = {}), maybe step size is too high.",
                        1 << i,
                    );
                    DescendStatus::StepTooLarge
                } else {
                    // Can't start, but the gradient is fresh.
                    if all_inf {
                        // TODO: Gradient is wrong.
                        debug!(                            "Cannot move even if step size is 1. Every step leads to inf, this is a trap.",
                        );
                        DescendStatus::Unable
                    } else {
                        //  We can make steps, it's just that they all lead to higher values.
                        // We are at local minima.
                        debug!(                            "Cannot move even if step size is 1. Every step leads to higher value, this is a local minima.",
                        );
                        DescendStatus::LeadsToHigherValue
                    }
                };
                return (f_curr, status);
            } else {
                started = true;
            }
            for d in &mut ascend_delta {
                *d *= 2.0;
            }
            for d in &mut descend_delta {
                *d *= 2.0;
            }
            i += 1;
        }
    }
    fn init_start_point(&mut self, input_min: &mut MutInput) -> i128 {
        let mut fmin = self.handler.execute_cond_direct();
        let (changed, buf) = input_min.clone_buf_and_do(|input| {
            let mut changed = false;
            input.assign(&self.handler.cond.variables);
            let f1 = self.execute(&input);
            if f1 < fmin {
                fmin = f1;
                changed = true;
            }
            // reverse endian
            if f1 > 1 {
                let mut rev_v = self.handler.cond.variables.clone();
                rev_v.reverse();
                input.assign(&rev_v);
                let f1 = self.execute(&input);
                if f1 < fmin {
                    fmin = f1;
                    changed = true;
                }
            }
            changed
        });
        if changed {
            input_min.apply_value(buf);
        }
        fmin
    }

    fn get_interesting_point(&mut self, input: &mut MutInput) -> bool {
        if !self.handler.cond.more_than_twice() && self.sample_index.0 < input.len() {
            let n = input.get_entry_len(self.sample_index.0);
            if self.sample_index.1 < n {
                let interesting_vals = get_interesting_bytes(n);
                input.set(self.sample_index.0, interesting_vals[self.sample_index.1]);

                self.sample_index.1 += 1;
                if self.sample_index.1 == n {
                    self.sample_index.1 = 0;
                    self.sample_index.0 += 1;
                }
                return true;
            }
        }
        false
    }

    fn repick_start_point<T: Rng>(
        &mut self,
        input_min: &mut MutInput,
        _f0: f64,
        rng: &mut T,
    ) -> f64 {
        let mut fmin = std::u64::MAX as f64;
        let mut input = input_min.clone();

        // for _ in 0..config::MAX_RANDOM_SAMPLE_NUM {
        loop {
            if self.handler.is_stopped_or_skip() {
                break;
            }

            let has_int_p = self.get_interesting_point(&mut input);
            if !has_int_p {
                // input.randomize_all_with_weight(rng, 2);
                input.randomize_all_uniform(rng);
            }

            let f1 = self.execute(&input) as f64;
            if f1 < fmin {
                fmin = f1;
                input_min.set_value_from_input(&input);
                break;
            }

            if has_int_p {
                input = input_min.clone();
            }
        }

        fmin
    }
}
