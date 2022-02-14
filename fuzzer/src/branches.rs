use crate::executor::StatusType;
use angora_common::{config::BRANCHES_SIZE, shm::*};
use sha2::{Digest, Sha256};
#[cfg(feature = "unstable")]
use std::intrinsics::unlikely;
use std::{
    self,
    collections::HashSet,
    ops::{Deref, DerefMut},
    path::Path,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, RwLock,
    },
};

// Map of bit bucket
// [1], [2], [3], [4, 7], [8, 15], [16, 31], [32, 127], [128, infinity]
static COUNT_LOOKUP: [u8; 256] = [
    0, 1, 2, 4, 8, 8, 8, 8, 16, 16, 16, 16, 16, 16, 16, 16, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32,
    32, 32, 32, 32, 32, 32, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
    128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
    128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
    128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
    128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
    128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
    128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
];

type TableEntryType = u16;
const ENTRY_SIZE: usize = std::mem::size_of::<TableEntryType>();

macro_rules! cast {
    ($ptr:expr) => {{
        unsafe { std::mem::transmute($ptr) }
    }};
}

#[derive(Debug, Clone, Hash)]
pub struct Trace {
    inner: Vec<u8>,
    top: Vec<u16>,
}

impl Trace {
    pub fn empty() -> Self {
        Self {
            inner: Vec::new(),
            top: Vec::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn resize(&mut self, new_len: usize) {
        self.inner.resize(new_len, 255_u8);
        self.top.resize(new_len, 255_u16);
    }
}

impl PartialEq for Trace {
    fn eq(&self, other: &Self) -> bool {
        assert_eq!(self.len(), other.len());
        let bucket_stat = self
            .inner
            .iter()
            .zip(other.inner.iter())
            .fold(true, |acc, (x, y)| acc & (*x == (*x | *y)));
        let top_stat = self
            .top
            .iter()
            .zip(other.top.iter())
            .fold(true, |acc, (x, y)| acc & (*x >= *y));
        bucket_stat && top_stat
        // self.inner == other.inner
    }
}

impl Eq for Trace {}

impl Deref for Trace {
    type Target = Vec<u8>;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for Trace {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

#[derive(Hash, Eq, PartialEq, Debug)]
pub struct CrashInfo {
    error: String,
    stack_hash: [u8; 32],
    // summary_hash: u32,
}

impl CrashInfo {
    pub fn from_output_string(s: &str) -> Self {
        let mut san_lines = false;
        let output_lines = s.lines();

        let mut stacks = Vec::new();
        let mut summary = String::new();
        let mut error = String::new();
        for line in output_lines {
            if line.contains("==ERROR: AddressSanitize") {
                san_lines = true;
                let mut word = line.split_whitespace();
                error = word.nth(2).unwrap_or_default().to_string();
            }
            if line.contains("SUMMARY: AddressSanitizer") {
                summary = line.to_string();
            }
            if san_lines && line.starts_with("    #") {
                // stacks.push(san_lines.to_string());
                let words = line.split_whitespace();
                let loc = words.last().unwrap_or_default();
                stacks.push(loc.to_string());
            }
        }
        let mut hasher = Sha256::new();
        for i in &stacks {
            hasher.update(i);
        }
        hasher.update(&summary);
        hasher.update(&error);
        let stack_hash_raw = hasher.finalize();
        let mut stack_hash = [0_u8; 32];
        let mut stack_hash_raw_iter = stack_hash_raw.iter();
        for i in 0..32 {
            stack_hash[i] = stack_hash_raw_iter.nth(i).cloned().unwrap_or_default();
        }
        Self { error, stack_hash }
    }
}

struct Crashes {
    inner: HashSet<CrashInfo>,
}

impl Crashes {
    pub fn new() -> Self {
        Self {
            inner: HashSet::new(),
        }
    }
}

pub struct GlobalBranches {
    virgin_branches: RwLock<Trace>,
    tmouts_branches: RwLock<Trace>,
    crashes_branches: RwLock<Trace>,
    crashes: RwLock<Crashes>,
    density: AtomicUsize,
}

impl GlobalBranches {
    pub fn new() -> Self {
        Self {
            virgin_branches: RwLock::new(Trace::empty()),
            tmouts_branches: RwLock::new(Trace::empty()),
            crashes_branches: RwLock::new(Trace::empty()),
            crashes: RwLock::new(Crashes::new()),
            density: AtomicUsize::new(0),
        }
    }

    pub fn get_density(&self) -> f32 {
        let d = self.density.load(Ordering::Relaxed);
        (d * 10000 / BRANCHES_SIZE) as f32 / 100.0
    }
}

pub struct Branches {
    global: Arc<GlobalBranches>,
    trace: SharedMemory,
}

impl Branches {
    pub fn new<S: AsRef<Path>>(global: Arc<GlobalBranches>, shm_name: S) -> Self {
        let trace = SharedMemory::create_empty(shm_name).expect("Could not open shared memory");
        Self { global, trace }
    }

    pub fn clear_trace(&mut self) {
        self.trace.clear();
    }

    pub fn resize(&mut self) {
        self.trace.resize().unwrap();
        // Since branch counting is using u16 to do hit count,
        // we need to divide the size by 2.
        debug_assert!((self.trace.size() & 1) == 0);
        let new_size = self.trace.size() >> 1;
        // debug!("Resized branch buffer size = {}", new_size);
        if let Ok(mut lock) = self.global.virgin_branches.write() {
            lock.resize(new_size);
        }
        if let Ok(mut lock) = self.global.tmouts_branches.write() {
            lock.resize(new_size);
        }
        if let Ok(mut lock) = self.global.crashes_branches.write() {
            lock.resize(new_size);
        }
    }

    fn get_path(&mut self) -> Vec<(usize, u8)> {
        let mut path = Vec::<(usize, u8)>::new();
        let table = BranchCountTable::new(&mut self.trace);
        // debug!("Branch table = {:?}", &table);
        let buf: &[TableEntryType] = table.branch_table;
        for (i, &v) in buf.iter().enumerate() {
            let c = if v > 255 { 255 } else { v as u8 };
            #[cfg(feature = "unstable")]
            {
                if unsafe { unlikely(c > 0) } {
                    path.push((i, COUNT_LOOKUP[c as usize]));
                }
            }
            #[cfg(not(feature = "unstable"))]
            {
                if c > 0 {
                    path.push((i, COUNT_LOOKUP[c as usize]));
                }
            }
        }

        /* let buf_plus: &[u64] = {cast!(&*table.branch_table)};
        debug!("Bufplus = {:?}", &buf_plus);
        for (i, &v) in buf_plus.iter().enumerate() {
            macro_rules! run_loop {
                () => {{
                    let base = i * ENTRY_SIZE;
                    for j in 0..ENTRY_SIZE {
                        let idx = base + j;
                        let new_val = buf[idx] as u8;
                        if new_val > 0 {
                            path.push((idx, COUNT_LOOKUP[new_val as usize]))
                        }
                    }
                }};
            }
            #[cfg(feature = "unstable")]
            {
                if unsafe { unlikely(v > 0) } {
                    run_loop!()
                }
            }
            #[cfg(not(feature = "unstable"))]
            {
                if v > 0 {
                    run_loop!()
                }
            }
        } */
        // debug!("count branch table: {}", path.len());
        path
    }

    pub fn dedup_crash(&mut self, crash_output: &str) -> (bool, bool, usize) {
        let crash_info = CrashInfo::from_output_string(crash_output);
        let mut new_crash = false;
        // There is a race condition here?!
        match self.global.crashes.read() {
            Ok(lock) => {
                if !lock.inner.contains(&crash_info) {
                    new_crash = true;
                }
            }
            Err(poisoned) => warn!("Lock poisoned! {:?}", poisoned),
        };
        if new_crash {
            match self.global.crashes.write() {
                Ok(mut lock) => {
                    lock.inner.insert(crash_info);
                }
                Err(poisoned) => warn!("Lock poisoned! {:?}", poisoned),
            }
        }
        (new_crash, new_crash, 1)
    }

    pub fn has_new(&mut self, status: StatusType) -> (bool, bool, usize) {
        let path = self.get_path();
        let gb_map = match status {
            StatusType::Normal => &self.global.virgin_branches,
            StatusType::Timeout => &self.global.tmouts_branches,
            StatusType::Crash => &self.global.crashes_branches,
            _ => {
                return (false, false, 0);
            }
        };
        let edge_num = path.len();

        let mut to_write = vec![];
        let mut has_new_edge = false;
        let mut num_new_edge = 0;
        {
            // read only
            let gb_map_read = gb_map.read().unwrap();
            for &br in &path {
                let gb_v = gb_map_read[br.0];

                if gb_v == 255u8 {
                    num_new_edge += 1;
                }

                if (br.1 & gb_v) > 0 {
                    to_write.push((br.0, gb_v & (!br.1)));
                }
            }
        }

        if num_new_edge > 0 {
            if status == StatusType::Normal {
                // only count virgin branches
                self.global
                    .density
                    .fetch_add(num_new_edge, Ordering::Relaxed);
            }
            has_new_edge = true;
        }

        if to_write.is_empty() {
            return (false, false, edge_num);
        }

        {
            // write
            let mut gb_map_write = gb_map.write().unwrap();
            for &br in &to_write {
                gb_map_write[br.0] = br.1;
            }
        }

        (true, has_new_edge, edge_num)
    }
}

impl std::fmt::Debug for Branches {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "")
    }
}
