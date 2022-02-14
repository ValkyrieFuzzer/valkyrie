use super::{forkcli, shm_conds};
use std::ops::DerefMut;

use libc::*;
use std::{slice, sync::Once};

/*
#[ctor]
fn fast_init() {
    START.call_once(|| {
        shm_branches::map_branch_counting_shm();
        forkcli::start_forkcli();
    });
}
*/

#[no_mangle]
pub extern "C" fn __trace_init() {
    forkcli::start_forkcli();
}

#[no_mangle]
pub extern "C" fn __angora_trace_cmp(
    condition: u32,
    cmpid: u32,
    context: u32,
    arg1: u64,
    arg2: u64,
) -> u32 {
    let mut conds = shm_conds::SHM_CONDS.lock().expect("SHM mutex poisoned.");
    match conds.deref_mut() {
        &mut Some(ref mut c) => {
            if c.check_match(cmpid, context) {
                return c.update_cmp(condition, arg1, arg2);
            }
        },
        _ => {},
    }
    condition
}

#[no_mangle]
pub extern "C" fn __angora_trace_switch(cmpid: u32, context: u32, condition: u64) -> u64 {
    let mut conds = shm_conds::SHM_CONDS.lock().expect("SHM mutex poisoned.");
    match conds.deref_mut() {
        &mut Some(ref mut c) => {
            if c.check_match(cmpid, context) {
                return c.update_switch(condition);
            }
        },
        _ => {},
    }
    condition
}

#[no_mangle]
pub extern "C" fn __branch_table_sort_function_map(
    func_ptr_ptr: *mut (*const c_void, isize),
    size: usize,
) {
    let func_ptr = unsafe { slice::from_raw_parts_mut(func_ptr_ptr, size) };

    func_ptr.sort_by_key(|&(func, _)| func);
}

#[no_mangle]
pub extern "C" fn __branch_table_dynamic_resolve_base_ptr(
    base: usize,
    ptr: *const c_void,
    func_ptr_ptr: *const (*const c_void, usize),
    size: usize,
) -> usize {
    let func_ptr = unsafe { slice::from_raw_parts(func_ptr_ptr, size) };

    if let Ok(index) = func_ptr.binary_search_by_key(&ptr, |&(func, _)| func) {
        base + func_ptr[index].1
    } else {
        0
    }
}

#[no_mangle]
pub extern "C" fn __angora_trace_exploit_div(cmpid: u32, context: u32, size: u32, dividend: u64) {
    let mut conds = shm_conds::SHM_CONDS.lock().expect("SHM mutex poisoned.");
    match conds.deref_mut() {
        &mut Some(ref mut c) => {
            let condition = (dividend == 0) as u32;
            if c.check_match(cmpid | (1 << 28), context) {
                let _ = c.update_cmp(condition, dividend, 0);
            }
            let upper = if size < 8 {
                (1 << (8 * size)) - 1
            } else {
                0xffff_ffff
            };
            let output = (dividend - 1) & 0xffff_ffff;
            let condition = (output == upper) as u32;
            if c.check_match(cmpid | (2 << 28), context) {
                let _ = c.update_cmp(condition, output, upper);
            }
        },
        _ => {},
    }
}
#[no_mangle]
pub extern "C" fn __angora_trace_exploit_intflow(
    cmpid: u32,
    context: u32,
    size: u32,
    s_result: i64,
    u_result: u64,
) {
    let bit_size = if size == 8 { 32 } else { size * 8 };
    let mut conds = shm_conds::SHM_CONDS.lock().expect("SHM mutex poisoned.");
    match conds.deref_mut() {
        &mut Some(ref mut c) => {
            // U<bit_size>::MAX
            let upper: u64 = (1 << bit_size) - 1;
            let condition = (u_result > upper) as u32;
            if c.check_match(cmpid | (1 << 28), context) {
                let _ = c.update_cmp(condition, u_result, upper);
            }
            // U<bit_size>::MIN, i.e. 0
            let lower: u64 = 0;
            if c.check_match(cmpid | (2 << 28), context) {
                // Test unsigned less than 0 always fails.
                let _ = c.update_cmp(false as u32, u_result, lower);
            }
            // I<bit_size>::MAX
            let upper: i64 = (1 << (bit_size - 1)) - 1;
            let condition = (s_result > upper) as u32;
            if c.check_match(cmpid | (3 << 28), context) {
                let _ = c.update_cmp(condition, s_result as u64, upper as u64);
            }

            // I<bit_size>::MIN
            let lower = 0xffff_ffff_ffff_ffff << (bit_size - 1) as u64;
            let condition = (s_result < lower as i64) as u32;
            if c.check_match(cmpid | (4 << 28), context) {
                let _ = c.update_cmp(condition, s_result as u64, lower);
            }
        },
        _ => {},
    }
}
#[no_mangle]
pub extern "C" fn __angora_trace_exploit_mem_arg(
    cmpid: u32,
    mut expid: u32,
    context: u32,
    size: u32,
    arg: u64,
) {
    let mut conds = shm_conds::SHM_CONDS.lock().expect("SHM mutex poisoned.");
    match conds.deref_mut() {
        &mut Some(ref mut c) => {
            let upper = if size < 8 {
                (1 << size) - 1
            } else {
                std::u32::MAX as u64 - 1
            };

            expid |= 0b0000;
            let condition = (arg > upper) as u32;
            if c.check_match(cmpid | (expid << 28), context) {
                let _ = c.update_cmp(condition, arg, upper);
            }
            let lower = 0;
            expid |= 0b1000;
            // This is not a typo.
            // Since we are treatting arg as signed, we want `arg < 0`,
            // that would imply arg == 0b1...,
            // i.e (arg as unsigned) > signed::MAX, which is unsigned::MAX >> 1.
            let condition = (arg > (upper >> 1)) as u32;
            if c.check_match(cmpid | (expid << 28), context) {
                let _ = if arg > (upper >> 1) {
                    // As long as this is an insanely large value, we are happy.
                    c.update_cmp(condition, std::u64::MAX, lower);
                } else {
                    c.update_cmp(condition, arg, lower);
                };
            }
        },
        _ => {},
    }
}
