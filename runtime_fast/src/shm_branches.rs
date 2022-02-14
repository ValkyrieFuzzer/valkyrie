// map branch counting shared memory.

use angora_common::{defs::BRANCHES_SHM_ENV_VAR, shm::SharedMemory};
use libc::{c_void, exit, off_t, size_t};
use std::{env, os::unix::io::IntoRawFd};

/* pub type BranchBuf = [u8; BRANCHES_SIZE];
static mut __ANGORA_AREA_INITIAL: BranchBuf = [255; BRANCHES_SIZE]; */

/* #[no_mangle]
pub static mut __angora_area_ptr: *const u8 = unsafe { &__ANGORA_AREA_INITIAL[0] as *const u8 };
 */
extern "C" {
    pub static __fuzz_branch_num: u64;
    pub static __fuzz_branch_count_size: u8;
}

/* pub fn map_branch_counting_shm() {
    let id_val = env::var(BRANCHES_SHM_ENV_VAR);
    match id_val {
        Ok(val) => {
            let shm_id = val.parse::<i32>().expect("Could not parse i32 value.");
            let mem = shm::SHM::<BranchBuf>::from_id(shm_id);
            if mem.is_fail() {
                eprintln!("fail to load shm");
                process::exit(1);
            }
            unsafe {
                __angora_area_ptr = mem.get_ptr() as *const u8;
            }
            return;
        },
        Err(_) => {},
    }
} */

#[no_mangle]
pub unsafe extern "C" fn __alloc_branch_count_table(size: size_t, nmemb: off_t) -> *mut c_void {
    fn abort<T, E: std::error::Error>(error: E) -> T {
        println!("Branch Count: {:?}", error);
        // Normally we should return error status, but this would make config unhappy.
        // autoconfig normally compile a small program and test if it runs, return error
        // would lead to autoconfig conclude that the compiler doesn't work...
        unsafe { exit(0) };
    }

    let shm_addr = env::var(BRANCHES_SHM_ENV_VAR).unwrap_or_else(abort);

    let alloc_size = size as usize * nmemb as usize;

    let shm = SharedMemory::open_with_size(shm_addr.as_str(), alloc_size).unwrap_or_else(abort);

    let ptr = shm.as_ptr() as *mut c_void;

    shm.into_raw_fd();

    ptr
}
