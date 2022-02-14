// Modify input randomly like AFL.
// All the byte offsets in the input is the input.
// Random pick offsets, then flip, add/sub ..
// And GE algorithm.

use super::*;
use rand::{self, distributions::Uniform, Rng};

static IDX_TO_SIZE: [usize; 4] = [1, 2, 4, 8];

pub struct AFLFuzz<'a> {
    handler: SearchHandler<'a>,
    run_ratio: usize,
}

impl<'a> AFLFuzz<'a> {
    pub fn new(handler: SearchHandler<'a>) -> Self {
        // FIXME:
        let edge_num = handler.cond.base.arg1 as usize;
        let avg_edge_num = handler.executor.local_stats.avg_edge_num.get() as usize;
        let run_ratio = if edge_num * 3 < avg_edge_num {
            2
        } else if edge_num < avg_edge_num {
            3
        } else {
            5
        };

        Self { handler, run_ratio }
    }

    pub fn run(&mut self) {
        if self.handler.cond.is_first_time() {
            self.afl_len();
        }

        self.handler.max_times = (config::MAX_SPLICE_TIMES * self.run_ratio).into();
        loop {
            if self.handler.is_stopped_or_skip() {
                break;
            }
            if !self.splice() {
                break;
            }
        }

        let max_stacking = if self.handler.buf.len() <= 16 {
            64
        } else {
            256
        };
        let max_choice = if config::ENABLE_MICRO_RANDOM_LEN {
            60
        } else {
            60
        };

        let choice_range = Uniform::new(0, max_choice);

        self.handler.max_times += (config::MAX_HAVOC_FLIP_TIMES * self.run_ratio).into();
        self.handler.skip = false;

        loop {
            if self.handler.is_stopped_or_skip() {
                break;
            }
            let mut buf = self.handler.buf.clone();
            self.havoc_flip(&mut buf, max_stacking, choice_range);
            self.handler.execute(&buf);
        }
    }

    fn locate_diffs(buf1: &Vec<u8>, buf2: &Vec<u8>, len: usize) -> (Option<usize>, Option<usize>) {
        let mut first_loc = None;
        let mut last_loc = None;

        for i in 0..len {
            if buf1[i] != buf2[i] {
                if first_loc.is_none() {
                    first_loc = Some(i);
                }
                last_loc = Some(i);
            }
        }

        (first_loc, last_loc)
    }

    fn splice_two_vec(buf1: &Vec<u8>, buf2: &Vec<u8>) -> Option<Vec<u8>> {
        let len = std::cmp::min(buf1.len(), buf2.len());
        if len < 2 {
            return None;
        }
        let (f_loc, l_loc) = Self::locate_diffs(buf1, buf2, len);
        if f_loc.is_none() || l_loc.is_none() {
            return None;
        }
        let f_loc = f_loc.unwrap();
        let l_loc = l_loc.unwrap();
        if f_loc == l_loc {
            return None;
        }

        let split_at = f_loc + rand::random::<usize>() % (l_loc - f_loc);
        Some([&buf1[..split_at], &buf2[split_at..]].concat())
    }

    // GE algorithm
    fn splice(&mut self) -> bool {
        let buf1 = self.handler.buf.clone();
        let buf2 = self.handler.executor.random_input_buf();
        if let Some(new_buf) = Self::splice_two_vec(&buf1, &buf2) {
            self.handler.execute(&new_buf);
            true
        } else {
            false
        }
    }

    fn havoc_flip(&self, buf: &mut Vec<u8>, max_stacking: usize, choice_range: Uniform<u32>) {
        let mut rng = rand::thread_rng();
        let max_len = angora_common::config::MAX_INPUT_LEN as u32;
        let use_stacking = 1 + rng.gen_range(0, max_stacking);

        for _ in 0..use_stacking {
            let byte_len = buf.len() as u32;
            if byte_len == 0 {
                return;
            }
            match rng.sample(choice_range) {
                0..=3 => {
                    // flip bit
                    let byte_idx: u32 = rng.gen_range(0, byte_len);
                    let bit_idx: u32 = rng.gen_range(0, 8);
                    buf[byte_idx as usize] ^= 128 >> bit_idx;
                }
                4..=15 => {
                    // set interesting value
                    let n: u32 = rng.gen_range(0, 3);
                    // Random size
                    let size = IDX_TO_SIZE[n as usize];
                    if byte_len > size as u32 {
                        let byte_idx: u32 = rng.gen_range(0, byte_len - size as u32 + 1);
                        let vals = get_interesting_bytes(size);
                        let wh = rng.gen_range(0, vals.len() as u32);
                        // Random value with that size
                        let mut val = vals[wh as usize];
                        // Random endianness for the value
                        if rng.gen_bool(0.5) {
                            val = mut_input::reverse_endian(val, size)
                        }
                        mut_input::set_val_in_buf(buf, byte_idx as usize, size, val);
                    }
                }
                16..=39 => {
                    // random add or sub
                    let n: u32 = rng.gen_range(0, 3);
                    // Random size
                    let size = IDX_TO_SIZE[n as usize];
                    if byte_len > size as u32 {
                        let byte_idx: u32 = rng.gen_range(0, byte_len - size as u32 + 1);
                        // Random value
                        let v: u32 = rng.gen_range(0, config::MUTATE_ARITH_MAX);
                        // Random add or sub
                        let direction: bool = rng.gen();
                        let swap_endian: bool = rng.gen();
                        mut_input::update_val_in_buf(
                            buf,
                            false,
                            byte_idx as usize,
                            size,
                            direction,
                            swap_endian,
                            v as u64,
                        );
                    }
                }
                40..=43 => {
                    // random byte
                    let byte_idx: u32 = rng.gen_range(0, byte_len);
                    let val: u8 = rng.gen();
                    buf[byte_idx as usize] = val;
                }
                44..=46 => {
                    // Clone bytes.
                    let mut size = self.random_block_len(byte_len);
                    let from_idx: u32 = rng.gen_range(0, byte_len - size + 1);
                    let before_idx: u32 = rng.gen_range(0, byte_len + 1);
                    // clone's gonna extend the buf len, make sure it don't exceed
                    // max input len.
                    if size + byte_len > max_len {
                        size = max_len - byte_len;
                    }

                    mut_input::insert_partial_buf(
                        buf,
                        buf[from_idx as usize..(from_idx + size) as usize]
                            .iter()
                            .cloned()
                            .collect(),
                        before_idx as usize,
                    );
                }
                47 => {
                    let mut size = self.random_block_len(byte_len);
                    let before_idx: u32 = rng.gen_range(0, byte_len + 1);
                    // clone's gonna extend the buf len, make sure it don't exceed
                    // max input len.
                    if size + byte_len > max_len {
                        size = max_len - byte_len;
                    }

                    mut_input::insert_partial_buf(
                        buf,
                        vec![rng.gen(); size as usize],
                        before_idx as usize,
                    );
                }
                48..=50 => {
                    // overwrite bytes.
                    let size = self.random_block_len(byte_len);
                    let from_idx: u32 = rng.gen_range(0, byte_len - size + 1);
                    let to_idx: u32 = rng.gen_range(0, byte_len - size + 1);
                    mut_input::overwrite_partial_buf(
                        buf,
                        from_idx as usize,
                        size as usize,
                        to_idx as usize,
                    );
                }
                51 => {
                    // overwrite bytes with constant
                    let size = self.random_block_len(byte_len) as usize;
                    let to_idx = rng.gen_range(0, byte_len - size as u32 + 1) as usize;
                    buf[to_idx..to_idx + size].copy_from_slice(&vec![rng.gen(); size]);
                }
                52..=59 => {
                    // Delete bytes.
                    let size = self.random_block_len(byte_len) as usize;
                    let from_idx = rng.gen_range(0, byte_len - size as u32 + 1) as usize;
                    let mut new_buf = vec![0; byte_len as usize - size];
                    new_buf[..from_idx].copy_from_slice(&buf[..from_idx]);
                    new_buf[from_idx..].copy_from_slice(&buf[from_idx + size..]);
                    *buf = new_buf;
                }
                _ => {}
            }
        }
    }
    fn random_block_len(&self, limit: u32) -> u32 {
        let mut rng = rand::thread_rng();
        let (mut min, max) = match rng.gen_range(0, 3) {
            0 => (1, 32),
            1 => (32, 128),
            _ => {
                if rng.gen_bool(0.9) {
                    (128, 1500)
                } else {
                    (1500, angora_common::config::MAX_INPUT_LEN as u32)
                }
            }
        };
        if min >= limit {
            min = std::cmp::min(1, limit - 1);
        }
        rng.gen_range(min, std::cmp::min(limit, max))
    }

    fn random_len(&mut self) {
        let len = self.handler.buf.len();
        if len > config::MAX_INPUT_LEN {
            return;
        }

        // let step = std::cmp::max( len / config::INFLATE_MAX_ITER_NUM + 1, 5);
        let orig_len = self.handler.buf.len();
        let mut rng = rand::thread_rng();

        let mut buf = self.handler.buf.clone();
        for _ in 0..config::RANDOM_LEN_NUM {
            let step = rng.gen::<usize>() % orig_len + 1;
            let mut v = vec![0u8; step];
            rng.fill_bytes(&mut v);
            buf.append(&mut v);
            if buf.len() < config::MAX_INPUT_LEN {
                self.handler.execute(&buf);
            } else {
                break;
            }
        }
    }

    fn add_small_len(&mut self) {
        let len = self.handler.buf.len();
        if len > config::MAX_INPUT_LEN {
            return;
        }

        let mut rng = rand::thread_rng();
        let mut buf = self.handler.buf.clone();
        let mut step = 1;
        for _ in 0..4 {
            let mut v = vec![0u8; step];
            rng.fill_bytes(&mut v);
            buf.append(&mut v);
            step = step * 2;
            if buf.len() < config::MAX_INPUT_LEN {
                self.handler.execute(&buf);
            } else {
                break;
            }
        }
    }

    fn afl_len(&mut self) {
        if config::ENABLE_RANDOM_LEN {
            self.random_len();
        } else {
            self.add_small_len();
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_locate_diffs() {
        let buf1: Vec<u8> = vec![1, 2, 3, 4, 5];
        let buf2: Vec<u8> = vec![1, 2, 3, 4, 5];
        let len = std::cmp::min(buf1.len(), buf2.len());
        let (f_loc, l_loc) = AFLFuzz::locate_diffs(&buf1, &buf2, len);
        assert!(f_loc.is_none());
        assert!(l_loc.is_none());
        let buf2: Vec<u8> = vec![0, 2, 3, 4, 5];
        let (f_loc, l_loc) = AFLFuzz::locate_diffs(&buf1, &buf2, len);
        assert_eq!(f_loc, Some(0));
        assert_eq!(l_loc, Some(0));
        let buf2: Vec<u8> = vec![1, 2, 0, 0, 5];
        let (f_loc, l_loc) = AFLFuzz::locate_diffs(&buf1, &buf2, len);
        assert_eq!(f_loc, Some(2));
        assert_eq!(l_loc, Some(3));
        let buf2: Vec<u8> = vec![0, 2, 0, 4, 5];
        let (f_loc, l_loc) = AFLFuzz::locate_diffs(&buf1, &buf2, len);
        assert_eq!(f_loc, Some(0));
        assert_eq!(l_loc, Some(2));
    }

    #[test]
    fn test_splice() {
        let buf1: Vec<u8> = vec![1, 2, 3, 4, 5];
        let buf2: Vec<u8> = vec![1, 2, 2, 2, 5, 6];

        let new_vec = AFLFuzz::splice_two_vec(&buf1, &buf2).unwrap();
        // split at index 2 or 3
        assert!(new_vec == vec![1, 2, 2, 4, 5, 6] || new_vec == vec![1, 2, 2, 2, 5, 6]);
    }
}
