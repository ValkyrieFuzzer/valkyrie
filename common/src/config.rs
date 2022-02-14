use once_cell::sync::OnceCell;

// ************ Switches **************
// length
pub const ENABLE_INPUT_LEN_EXPLORATION: bool = true;
pub const ENABLE_RANDOM_LEN: bool = false;
pub const ENABLE_MICRO_RANDOM_LEN: bool = true;

// other
pub const DISABLE_INFER_SHAPE_IF_HAS_AND_OP: bool = true;
pub const PREFER_FAST_COND: bool = true;

// ************ Resources ****************
pub const MAX_INPUT_LEN: usize = 1048576;

// branch.rs
pub const MAP_SIZE_POW2: usize = 20;
pub const BRANCHES_SIZE: usize = 1 << MAP_SIZE_POW2;

// executor.rs:
pub const TMOUT_SKIP: usize = 3;
pub const TIME_LIMIT: u64 = 1;
pub const MEM_LIMIT: u64 = 200; // MB
pub const TIME_LIMIT_TRACK: u64 = 20;
pub const MEM_LIMIT_TRACK: u64 = 0;
/// Fuzz time for one condition
pub const LONG_FUZZ_TIME: usize = 16;
/// Fuzz time in one satte
pub const STATE_FUZZ_TIME: usize = 4;
pub const MAX_INVARIABLE_NUM: usize = 16;
pub const MAX_NUM_MINIMAL_OPTIMA_ALL: usize = 28;
// based the bit bucket: [1], [2], [3], [4, 7], [8, 15], [16, 31], [32, 127], [128, infinity]
pub const MAX_COND_ORDER: u32 = 16;

// ************ Mutation ****************
// SEARCH
pub const ENABLE_DET_MUTATION: bool = true;
pub const MAX_SEARCH_EXEC_NUM: usize = 376;
pub const MAX_EXPLOIT_EXEC_NUM: usize = 66;
pub const MAX_NUM_MINIMAL_OPTIMA_ROUND: usize = 8;
pub const MAX_RANDOM_SAMPLE_NUM: usize = 10;
pub const GD_MOMENTUM_BETA: f64 = 0.0;
pub const GD_ESCAPE_RATIO: f64 = 1.0;
pub const BONUS_EXEC_NUM: usize = 66;

// AFL
pub const MUTATE_ARITH_MAX: u32 = 30;
pub const RANDOM_LEN_NUM: usize = 30;
pub const MAX_HAVOC_FLIP_TIMES: usize = 45; // for all bytes
pub const MAX_SPLICE_TIMES: usize = 45;

#[derive(Debug)]
pub struct FuzzerConfig {
    /// Use AFL as a side help.
    enable_afl: bool,
    /// Solve exploitable conds
    enable_exploitation: bool,
    /// Use dynamic sign information
    enable_dyn_sign: bool,
    /// Give a random change based on known sign information.
    enable_random_sign: bool,
    /// Use dynamic endianness inference.
    enable_dyn_endian: bool,
    /// Assume all inputs starts with big endian
    assume_be: bool,
    /// Use multiple input points.
    enable_multi_pt: bool,
    /// Max priority.
    max_priority: u16,

    belong: bool,
    order: bool,
}

pub static CONFIG: OnceCell<FuzzerConfig> = OnceCell::new();
// Static defined config.
// pub static CONFIG: FuzzerConfig = FuzzerConfig {
// enable_afl: true,
// enable_exploitation: true,
// enable_dyn_sign: true,
// enable_random_sign: false,
// enable_dyn_endian: true,
// assume_be: false,
// enable_multi_pt: true,
// };

impl Default for FuzzerConfig {
    fn default() -> Self {
        Self {
            enable_afl: true,
            enable_exploitation: true,
            enable_dyn_sign: true,
            enable_random_sign: false,
            enable_dyn_endian: true,
            assume_be: false,
            enable_multi_pt: true,
            max_priority: std::u16::MAX,
            belong: false,
            order: true,
        }
    }
}
impl FuzzerConfig {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn get() -> &'static Self {
        CONFIG.get().expect("Config is not initialized")
        // &CONFIG
    }
    pub fn set_enable_afl<'a>(&'a mut self, enable_afl: bool) -> &'a mut Self {
        self.enable_afl = enable_afl;
        self
    }
    pub fn enable_afl(&self) -> bool {
        self.enable_afl
    }
    pub fn set_enable_exploitation<'a>(&'a mut self, enable_exploitation: bool) -> &'a mut Self {
        self.enable_exploitation = enable_exploitation;
        self
    }
    pub fn enable_exploitation(&self) -> bool {
        self.enable_exploitation
    }
    pub fn set_enable_dyn_sign<'a>(&'a mut self, enable_dyn_sign: bool) -> &'a mut Self {
        self.enable_dyn_sign = enable_dyn_sign;
        self
    }
    pub fn enable_dyn_sign(&self) -> bool {
        self.enable_dyn_sign
    }
    pub fn set_enable_random_sign<'a>(&'a mut self, enable_random_sign: bool) -> &'a mut Self {
        self.enable_random_sign = enable_random_sign;
        self
    }
    pub fn enable_random_sign(&self) -> bool {
        self.enable_random_sign
    }
    pub fn set_enable_dyn_endian<'a>(&'a mut self, enable_dyn_endian: bool) -> &'a mut Self {
        self.enable_dyn_endian = enable_dyn_endian;
        self
    }
    pub fn enable_dyn_endian(&self) -> bool {
        self.enable_dyn_endian
    }
    pub fn set_assume_be<'a>(&'a mut self, assume_be: bool) -> &'a mut Self {
        self.assume_be = assume_be;
        self
    }
    pub fn assume_be(&self) -> bool {
        self.assume_be
    }
    pub fn set_enable_multi_pt<'a>(&'a mut self, enable_multi_pt: bool) -> &'a mut Self {
        self.enable_multi_pt = enable_multi_pt;
        self
    }
    pub fn enable_multi_pt(&self) -> bool {
        self.enable_multi_pt
    }
    pub fn set_max_priority<'a>(&'a mut self, max_priority: u16) -> &'a mut Self {
        self.max_priority = max_priority;
        self
    }
    pub fn max_priority(&self) -> u16 {
        self.max_priority
    }
    pub fn set_belong<'a>(&'a mut self, belong: bool) -> &'a mut Self {
        self.belong = belong;
        self
    }
    pub fn belong(&self) -> bool {
        self.belong
    }
    pub fn set_order<'a>(&'a mut self, order: bool) -> &'a mut Self {
        self.order = order;
        self
    }
    pub fn order(&self) -> bool {
        self.order
    }
}
