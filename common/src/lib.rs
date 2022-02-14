pub mod cond_stmt_base;
pub mod config;
pub mod defs;
pub mod log_data;
pub mod shm;
pub mod tag;

// void __unfold_branch_fn(uint32_t) {}

#[no_mangle]
pub fn __unfold_branch_fn(_x: u32) {}

#[cfg(debug_assertions)]
use lazy_static::lazy_static;
#[cfg(debug_assertions)]
use parse_int::parse;
#[cfg(debug_assertions)]
lazy_static! {
    // Only show debug information of a certain cmpid if set.
    pub static ref DEBUG_CMPID: Option<u32> = {
        std::env::var("DEBUG_CMPID").ok().and_then(|s| parse::<u32>(&s).ok())
    };
}

#[macro_export]
macro_rules! debug_cmpid {
    ($cmpid: expr, $($arg:tt)*) => {
        #[cfg(debug_assertions)]
        {
            use angora_common::DEBUG_CMPID;
            if let Some(_cmpid) = *DEBUG_CMPID {
                if _cmpid == $cmpid {
                    debug!($($arg)*);
                }
            } else {
                debug!($($arg)*);
            }
        }
        #[cfg(not(debug_assertions))]
        debug!($($arg)*);
    };
}
