#[derive(Clone, Copy, Debug)]
pub enum FuzzType {
    ExploreFuzz,
    ExploitIntFuzz,
    ExploitMemFuzz,
    ExploitRandFuzz,
    CmpFnFuzz,
    LenFuzz,
    AFLFuzz,
    OtherFuzz,
}

pub const FUZZ_TYPE_NUM: usize = FuzzType::OtherFuzz as usize + 1;
static FUZZ_TYPE_NAME: [&str; FUZZ_TYPE_NUM] = [
    "Explore", "ExpInt", "ExpMem", "ExpRand", "CmpFn", "Len", "AFL", "Other",
];

impl Default for FuzzType {
    fn default() -> Self {
        FuzzType::OtherFuzz
    }
}

impl FuzzType {
    pub fn index(&self) -> usize {
        *self as usize
    }
}

pub fn get_fuzz_type_name(i: usize) -> String {
    FUZZ_TYPE_NAME[i].to_string()
}
