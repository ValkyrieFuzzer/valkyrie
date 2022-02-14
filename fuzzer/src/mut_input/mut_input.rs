use super::*;
use crate::{
    mut_input::sign::{Sign, SignInfo},
    search,
};
use angora_common::config::{self, FuzzerConfig};
use rand::{self, distributions::Uniform, Rng};
use std::{
    cmp,
    fmt::{self, Debug},
    ops::{Add, Range, Sub},
    u16, u32, u64, u8,
};

#[derive(Clone, Debug, PartialEq, Eq, Hash, Copy)]
pub enum Endian {
    BigEndian,
    LittleEndian,
    // Split(Box<InputMeta>),
    Split,
}
impl Default for Endian {
    fn default() -> Self {
        if FuzzerConfig::get().assume_be() {
            Self::BigEndian
        } else {
            Self::LittleEndian
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct InputMeta {
    sign_info: SignInfo,
    sign: bool,
    pub endian: Endian,
    offset: usize,
    size: usize,
}

impl InputMeta {
    fn new(sign: bool, offset: usize, size: usize) -> Self {
        Self {
            sign_info: SignInfo::from_static_sign(sign),
            sign,
            endian: Endian::default(),
            offset,
            size,
        }
    }
    fn update_dyn_sign_info(&mut self, dyn_n: Sign, dyn_s: Sign) {
        self.sign_info.update_dyn_sign(dyn_n, dyn_s);
    }
    fn set_sign(&mut self, sign: bool) {
        self.sign = sign;
    }

    pub fn is_le(&self) -> bool {
        self.endian == Endian::LittleEndian
    }

    pub fn is_be(&self) -> bool {
        self.endian == Endian::BigEndian
    }

    /// Change this metadata from le to be.
    // This function shoudld only be called when it's le.
    pub fn to_be(&mut self) {
        debug_assert!(self.endian == Endian::LittleEndian);
        self.endian = Endian::BigEndian;
    }

    fn start(&self) -> usize {
        self.offset
    }
    fn end(&self) -> usize {
        self.offset + self.size
    }
    fn split(self) -> Vec<InputMeta> {
        self.range()
            .map(|offset| Self {
                sign: self.sign,
                sign_info: self.sign_info,
                // endian: Endian::Split(Box::new(self.clone())),
                endian: Endian::Split,
                offset,
                size: 1,
            })
            .collect()
    }
    fn range(&self) -> Range<usize> {
        self.start()..self.end()
    }
}
impl fmt::Display for InputMeta {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{:?}=>{}",
            self.sign_info,
            if self.sign { "S" } else { "U" }
        )
    }
}

trait InputFrom<T>: Sized {
    fn input_from(t: T) -> Option<Self>;
}
trait InputInto<T: Sized> {
    fn input_into(self) -> Option<T>;
}

impl<T, U> InputFrom<U> for T
where
    U: InputInto<T>,
{
    fn input_from(u: U) -> Option<T> {
        U::input_into(u)
    }
}
/*
impl<T,U> InputInto<U> for T where U: InputFrom<T> {
    fn input_into(self) -> Option<U> {
        InputFrom::input_from(self)
    }
}
*/

macro_rules! impl_input_into_for_f64 {
    ($t:ty) => {
        impl InputInto<$t> for f64 {
            fn input_into(self) -> Option<$t> {
                if self <= <$t>::MAX as f64 && self >= <$t>::MIN as f64 {
                    Some(self as $t)
                } else {
                    None
                }
            }
        }
    };
}

impl_input_into_for_f64!(i8);
impl_input_into_for_f64!(u8);
impl_input_into_for_f64!(i16);
impl_input_into_for_f64!(u16);
impl_input_into_for_f64!(i32);
impl_input_into_for_f64!(u32);
impl_input_into_for_f64!(i64);
impl_input_into_for_f64!(u64);
impl_input_into_for_f64!(f32);
impl InputInto<f64> for f64 {
    fn input_into(self) -> Option<f64> {
        Some(self)
    }
}

trait InputCheckedArith: Sized {
    fn checked_add(self, rhs: Self) -> Option<Self>;
    fn checked_sub(self, rhs: Self) -> Option<Self>;
}

macro_rules! impl_checked_arith_for {
    ($t:ty) => {
        impl InputCheckedArith for $t {
            fn checked_add(self, rhs: Self) -> Option<Self> {
                self.checked_add(rhs)
            }
            fn checked_sub(self, rhs: Self) -> Option<Self> {
                self.checked_sub(rhs)
            }
        }
    };
}

impl_checked_arith_for!(i8);
impl_checked_arith_for!(u8);
impl_checked_arith_for!(i16);
impl_checked_arith_for!(u16);
impl_checked_arith_for!(i32);
impl_checked_arith_for!(u32);
impl_checked_arith_for!(i64);
impl_checked_arith_for!(u64);
pub trait Numerical {
    fn val(&self) -> f64;
    fn max(&self) -> f64;
    fn min(&self) -> f64;
}

macro_rules! impl_numerical_for {
    ($t:ty) => {
        impl Numerical for $t {
            fn val(&self) -> f64 {
                *self as f64
            }
            fn max(&self) -> f64 {
                <$t>::MAX as f64
            }
            fn min(&self) -> f64 {
                <$t>::MIN as f64
            }
        }
    };
}

impl_numerical_for!(i8);
impl_numerical_for!(u8);
impl_numerical_for!(i16);
impl_numerical_for!(u16);
impl_numerical_for!(i32);
impl_numerical_for!(u32);
impl_numerical_for!(i64);
impl_numerical_for!(u64);
impl_numerical_for!(isize);
impl_numerical_for!(usize);
impl_numerical_for!(f32);
impl_numerical_for!(f64);

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Numeral {
    inner: f64,
    upper_bound: f64,
    lower_bound: f64,
}

impl Numeral {
    pub fn new(inner: f64, upper_bound: f64, lower_bound: f64) -> Self {
        Self {
            inner,
            upper_bound,
            lower_bound,
        }
    }

    pub fn from_numerical<N: Numerical>(n: N) -> Self {
        Self {
            inner: n.val(),
            upper_bound: n.max(),
            lower_bound: n.min(),
        }
    }

    pub fn min(&self) -> f64 {
        self.lower_bound
    }

    pub fn set_min(&mut self) {
        self.inner = self.lower_bound
    }

    pub fn max(&self) -> f64 {
        self.upper_bound
    }

    pub fn set_max(&mut self) {
        self.inner = self.upper_bound
    }

    pub fn to_f64(&self) -> f64 {
        self.inner
    }
    pub fn inc(&mut self) -> bool {
        if self.inner + 1.0_f64 > self.upper_bound {
            false
        } else {
            self.inner += 1.0_f64;
            true
        }
    }

    pub fn dec(&mut self) -> bool {
        if self.inner - 1.0_f64 < self.lower_bound {
            false
        } else {
            self.inner -= 1.0_f64;
            true
        }
    }

    fn set(&mut self, v: f64, is_ceil: bool) -> f64 {
        if v > self.max() {
            self.set_max();
            v - self.max()
        } else if v < self.min() {
            self.set_min();
            v - self.min()
        } else {
            let v2 = if is_ceil { v.ceil() } else { v.floor() };
            self.inner = v2;
            v - v2
        }
    }
    fn set_exact(&mut self, v: f64) -> f64 {
        if v > self.max() {
            self.set_max();
            v - self.max()
        } else if v < self.min() {
            self.set_min();
            v - self.min()
        } else {
            self.inner = v;
            0f64
        }
    }
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct MutInput {
    value: Vec<u8>,
    meta: Vec<InputMeta>,
}

impl MutInput {
    pub fn new() -> Self {
        Self {
            value: vec![],
            meta: vec![],
        }
    }
    pub fn get_meta<'a>(&'a self) -> &'a Vec<InputMeta> {
        &self.meta
    }
    pub fn get_mut_meta<'a>(&'a mut self) -> &'a mut Vec<InputMeta> {
        &mut self.meta
    }

    /// Get a input in the form of a slice of bytes.
    pub fn get_slice<'a>(&'a self, idx: usize) -> &'a [u8] {
        &self.value[self.meta[idx].range()]
    }
    pub fn get_mut_slice<'a>(&'a mut self, idx: usize) -> &'a mut [u8] {
        &mut self.value[self.meta[idx].range()]
    }
    pub fn write_slice(&mut self, idx: usize, src: &[u8]) {
        self.get_mut_slice(idx).copy_from_slice(src);
    }
    pub fn take(self) -> (Vec<u8>, Vec<InputMeta>) {
        (self.value, self.meta)
    }

    /// Clone the buffer, do something and return. It's guaranteed
    /// that `self` is not changed.
    ///
    /// As we put more things in the metadata, the overhead of clone
    /// a metadata is higher. We want the reduce the clone of the
    /// metadata.
    ///
    /// This function takes a copy of the buffer, do what you asked
    /// to do, and construct the data structure back.
    ///
    /// TODO: How do we setup API so we can guarantee metadata is not
    /// changed?
    pub fn clone_buf_and_do<F, R>(&mut self, f: F) -> (R, Vec<u8>)
    where
        F: FnOnce(&mut Self) -> R,
    {
        let mut buf = self.value.clone();
        let ret = f(self);
        std::mem::swap(&mut self.value, &mut buf);
        (ret, buf)
    }
    pub fn replace_buf_and_do<F, R>(&mut self, mut buf: Vec<u8>, f: F) -> (R, Vec<u8>)
    where
        F: FnOnce(&mut Self) -> R,
    {
        std::mem::swap(&mut self.value, &mut buf);
        let ret = f(self);
        std::mem::swap(&mut self.value, &mut buf);
        (ret, buf)
    }

    pub fn is_value_identical(&self, other: &Vec<u8>) -> bool {
        self.value == *other
    }

    /// Take n-th input out and construct new `MutInput`.
    /// This shouldn't affect anything else.
    pub fn clone_nth(&self, idx: usize) -> Self {
        MutInput {
            value: self.value.clone(),
            meta: vec![self.meta[idx].clone()],
        }
    }
    pub fn clone_value(&self) -> Vec<u8> {
        self.value.clone()
    }
    pub fn apply_value(&mut self, value: Vec<u8>) {
        debug_assert!(value.len() == self.value.len());
        self.value = value;
    }

    /// Then we have to process it byte-by-byte.
    /// Split meta data @ idx-th place into bytes.
    /// This is used when we decides that n-th input is neither le nor be.
    /// Also give me how do you want to change the `SignInfo` of the newly
    /// splitted Metadata.
    ///
    /// The sign after splitting may not be the same. For example, if we split
    /// an `int` into 4 bytes, only one byte should be signed and other is
    /// unsigned. This is called sign problem.
    ///
    /// We can force the caller to think about new sign problem with the closure
    pub fn split_meta_w_sign_change<F>(&mut self, idx: usize, change_sign: F)
    where
        F: FnOnce(&mut Self),
    {
        let mut meta = self.meta.split_off(idx);
        let after = meta.split_off(1);
        debug_assert!(meta.len() == 1);
        let meta = meta.pop().unwrap().split();
        self.meta.extend(meta);
        self.meta.extend(after);
        change_sign(self);
    }

    /// The length of input. Input is always less than buffer, as
    /// one input can consists of multiple bytes.
    pub fn len(&self) -> usize {
        self.meta.len()
    }

    /// The length of buffer.
    pub fn val_len(&self) -> usize {
        self.value.len()
    }

    pub fn from(offsets: &Vec<TagSeg>, input: &Vec<u8>) -> Self {
        let len = input.len();
        let mut mut_input = MutInput::new();
        for off in offsets {
            let begin = off.begin as usize;
            let end = off.end as usize;
            if begin == end {
                continue;
            }
            if end <= len {
                mut_input.push((input[begin..end]).to_vec(), off.sign);
            } else {
                warn!("Tag set out of the bound of the input, this shouldn't happen.");
                // end > len
                if begin >= len {
                    let r = end - begin;
                    mut_input.push(vec![0u8; r], off.sign);
                } else {
                    // begin < len
                    let mut v = input[begin..len].to_vec();
                    let r = end - len;
                    let mut ext_v = vec![0u8; r];
                    v.append(&mut ext_v);
                    mut_input.push(v, off.sign);
                }
            }
        }

        mut_input
    }

    // ATT: ele will be moved
    fn push(&mut self, mut ele: Vec<u8>, sign: bool) {
        if ele.len() != 1 && ele.len() != 2 && ele.len() != 4 && ele.len() != 8 {
            for _ in 0..ele.len() {
                self.meta.push(InputMeta::new(sign, self.value.len(), 1));
            }
        } else {
            self.meta
                .push(InputMeta::new(sign, self.value.len(), ele.len()));
        }
        self.value.append(&mut ele);
    }

    pub fn update(&mut self, index: usize, direction: bool, delta: u64) {
        let info = &self.meta[index];
        update_val_in_buf(
            &mut self.value,
            info.sign,
            info.offset,
            info.size,
            direction,
            false,
            delta,
        );
    }

    // the return value is unsigned!!
    pub fn get_entry(&self, index: usize) -> u64 {
        let info = &self.meta[index];
        match read_val_from_buf(&self.value, info.offset, info.size) {
            Ok(v) => v,
            Err(_) => {
                panic!("meta: {:?}", self.meta);
            },
        }
    }

    pub fn get_entry_len(&self, index: usize) -> usize {
        self.meta[index].size
    }

    pub fn set(&mut self, index: usize, val: u64) {
        let info = &self.meta[index];
        set_val_in_buf(&mut self.value, info.offset, info.size, val);
    }

    pub fn assign(&mut self, val: &Vec<u8>) {
        let l = cmp::min(val.len(), self.val_len());
        if l > 0 {
            let scope = &mut self.value[0..l];
            scope.clone_from_slice(&val[0..l]);
        }
    }

    pub fn get_value(&self) -> Vec<u8> {
        self.value.clone()
    }

    pub fn set_value_from_input(&mut self, input: &MutInput) {
        self.value = input.get_value();
    }

    pub fn bitflip(&mut self, i: usize) {
        let byte_i = i >> 3;
        let bit_i = i & 7;
        assert!(byte_i < self.val_len());
        self.value[byte_i] ^= 128 >> bit_i;
    }

    pub fn write_to_input(&self, offsets: &Vec<TagSeg>, input: &mut Vec<u8>) {
        // assert_eq!(self.len(), offsets.len());
        if offsets.len() > 0 {
            let ext_len = offsets.last().unwrap().end as usize;
            let orig_len = input.len();
            if ext_len > orig_len {
                let mut v = vec![0u8; ext_len - orig_len];
                input.append(&mut v);
            }
        }
        set_bytes_by_offsets(offsets, &self.value, input);
    }

    pub fn inc_lsb(&mut self, ics: &[(usize, f64)]) -> bool {
        for ic in ics.iter().rev() {
            if self.add_nth_(ic.0, 1.0).abs() > 0.99 {
                return true;
            }
        }
        false
    }
    pub fn dec_lsb(&mut self, ics: &[(usize, f64)]) -> bool {
        for ic in ics.iter().rev() {
            if self.add_nth_(ic.0, -1.0).abs() > 0.99 {
                return true;
            }
        }
        false
    }

    fn nth_val(&self, index: usize) -> Numeral {
        assert!(index < self.meta.len());
        let item = self.meta.get(index).unwrap();
        let len = item.size;
        let signed = item.sign;
        let range = item.range();
        match (len, signed) {
            (1, false) => {
                let val: u8 = self.value[item.offset] as u8;
                Numeral::from_numerical(val)
            },
            (1, true) => {
                let val: i8 = self.value[item.offset] as i8;
                Numeral::from_numerical(val)
            },
            (2, false) => {
                let mut b = [0_u8; 2];
                b.copy_from_slice(&self.value[range]);
                let val: u16 = match item.endian {
                    Endian::LittleEndian => <u16>::from_le_bytes(b),
                    Endian::BigEndian => <u16>::from_be_bytes(b),
                    Endian::Split => panic!("Multi-byte value shouldn't have Endian::Split."),
                };
                Numeral::from_numerical(val)
            },
            (2, true) => {
                let mut b = [0_u8; 2];
                b.copy_from_slice(&self.value[range]);
                let val: i16 = match item.endian {
                    Endian::LittleEndian => <i16>::from_le_bytes(b),
                    Endian::BigEndian => <i16>::from_be_bytes(b),
                    Endian::Split => panic!("Multi-byte value shouldn't have Endian::Split."),
                };
                Numeral::from_numerical(val)
            },
            (4, false) => {
                let mut b = [0_u8; 4];
                b.copy_from_slice(&self.value[range]);
                let val: u32 = match item.endian {
                    Endian::LittleEndian => <u32>::from_le_bytes(b),
                    Endian::BigEndian => <u32>::from_be_bytes(b),
                    Endian::Split => panic!("Multi-byte value shouldn't have Endian::Split."),
                };
                Numeral::from_numerical(val)
            },
            (4, true) => {
                let mut b = [0_u8; 4];
                b.copy_from_slice(&self.value[range]);
                let val: i32 = match item.endian {
                    Endian::LittleEndian => <i32>::from_le_bytes(b),
                    Endian::BigEndian => <i32>::from_be_bytes(b),
                    Endian::Split => panic!("Multi-byte value shouldn't have Endian::Split."),
                };
                Numeral::from_numerical(val)
            },
            (8, false) => {
                let mut b = [0_u8; 8];
                b.copy_from_slice(&self.value[range]);
                let val: u64 = match item.endian {
                    Endian::LittleEndian => <u64>::from_le_bytes(b),
                    Endian::BigEndian => <u64>::from_be_bytes(b),
                    Endian::Split => panic!("Multi-byte value shouldn't have Endian::Split."),
                };
                Numeral::from_numerical(val)
            },
            (8, true) => {
                let mut b = [0_u8; 8];
                b.copy_from_slice(&self.value[range]);
                let val: i64 = match item.endian {
                    Endian::LittleEndian => <i64>::from_le_bytes(b),
                    Endian::BigEndian => <i64>::from_be_bytes(b),
                    Endian::Split => panic!("Multi-byte value shouldn't have Endian::Split."),
                };
                Numeral::from_numerical(val)
            },
            _ => unimplemented!(),
        }
    }
    fn write_nth_val(&mut self, idx: usize, val: i128) {
        assert!(idx < self.meta.len());
        let meta = self.meta.get(idx).unwrap();
        let len = meta.size;
        // Since we are writing back to a buffer, we don't really care about signs.
        match len {
            1 => {
                self.value[meta.offset] = val as u8;
            },
            2 => {
                let val = match meta.endian {
                    Endian::LittleEndian => val as u16,
                    Endian::BigEndian => (val as u16).to_be(),
                    Endian::Split => panic!("Multi-byte value shouldn't have Endian::Split."),
                };
                let ptr = &mut self.value[meta.offset] as *mut u8 as *mut u16;
                unsafe {
                    *ptr = val;
                }
            },
            4 => {
                let val = match meta.endian {
                    Endian::LittleEndian => val as u32,
                    Endian::BigEndian => (val as u32).to_be(),
                    Endian::Split => panic!("Multi-byte value shouldn't have Endian::Split."),
                };
                let ptr = &mut self.value[meta.offset] as *mut u8 as *mut u32;
                unsafe {
                    *ptr = val;
                }
            },
            8 => {
                let val = match meta.endian {
                    Endian::LittleEndian => val as u64,
                    Endian::BigEndian => (val as u64).to_be(),
                    Endian::Split => panic!("Multi-byte value shouldn't have Endian::Split."),
                };
                let ptr = &mut self.value[meta.offset] as *mut u8 as *mut u64;
                unsafe {
                    *ptr = val;
                }
            },
            _ => unimplemented!(),
        }
    }

    fn deref_ptr<T>(raw_pointer: *const u8) -> T
    where
        T: Add<Output = T> + Sub<Output = T> + InputCheckedArith + Copy + Debug + Default,
    {
        unsafe { *(raw_pointer as *const T) }
    }
    fn deref_ptr_and_add<T>(raw_pointer: *const u8, mut delta: f64) -> T
    where
        T: Add<Output = T> + Sub<Output = T> + InputCheckedArith + Copy + Debug + Default,
        f64: InputInto<T>,
    {
        let orig_val = unsafe { *(raw_pointer as *const T) };
        // debug!("orig_val: {:?}", orig_val);
        let sub = delta < 0.0;
        delta = delta.abs();
        // while delta > 0.1 {
        loop {
            if let Some(d) = InputInto::<T>::input_into(delta) {
                if sub {
                    if let Some(val) = orig_val.checked_sub(d) {
                        // debug!("subed value: {:?}", val);
                        return val;
                    }
                } else {
                    if let Some(val) = orig_val.checked_add(d) {
                        // debug!("added value: {:?}", val);
                        return val;
                    }
                }
            }
            delta /= 2.0_f64;
        }
    }

    /// Inplace add `delta` to `nth` where `ptr` is pointed to.
    ///
    /// Return `new_val`
    fn add_inplace_<
        T: Add<Output = T> + Sub<Output = T> + InputCheckedArith + Copy + Debug + Default,
    >(
        &mut self,
        ptr: *mut u8,
        delta: f64,
    ) -> T
    where
        f64: InputInto<T>,
    {
        let new_val: T = Self::deref_ptr_and_add(ptr as *const u8, delta);
        unsafe { *(ptr as *mut T) = new_val };
        new_val
    }

    /// Inplace add `delta` to `nth` where `ptr` is pointed to.
    ///
    /// Return `(new_val, old_val)`
    fn add_inplace<
        T: Add<Output = T> + Sub<Output = T> + InputCheckedArith + Copy + Debug + Default,
    >(
        &mut self,
        ptr: *mut u8,
        delta: f64,
    ) -> (T, T)
    where
        f64: InputInto<T>,
    {
        let old_val: T = Self::deref_ptr(ptr as *const u8);
        let new_val: T = self.add_inplace_(ptr, delta);
        (new_val, old_val)
    }

    /// Add `delta` to the `index` place of the vector.
    /// Return the added value.
    pub fn add_nth(&mut self, index: usize, delta: f64) -> f64 {
        let item = &self.meta[index];
        let len = item.size;
        let sign = item.sign;
        let raw_pointer = &mut self.value[item.offset] as *mut u8;

        match (len, sign) {
            (1, true) => {
                let res = self.add_inplace::<i8>(raw_pointer, delta);
                res.0 as f64 - res.1 as f64
            },
            (2, true) => {
                let res = self.add_inplace::<i16>(raw_pointer, delta);
                res.0 as f64 - res.1 as f64
            },
            (4, true) => {
                let res = self.add_inplace::<i32>(raw_pointer, delta);
                res.0 as f64 - res.1 as f64
            },
            (8, true) => {
                let res = self.add_inplace::<i64>(raw_pointer, delta);
                res.0 as f64 - res.1 as f64
            },
            (1, false) => {
                let res = self.add_inplace::<u8>(raw_pointer, delta);
                res.0 as f64 - res.1 as f64
            },
            (2, false) => {
                let res = self.add_inplace::<u16>(raw_pointer, delta);
                res.0 as f64 - res.1 as f64
            },
            (4, false) => {
                let res = self.add_inplace::<u32>(raw_pointer, delta);
                res.0 as f64 - res.1 as f64
            },
            (8, false) => {
                let res = self.add_inplace::<u64>(raw_pointer, delta);
                res.0 as f64 - res.1 as f64
            },
            _ => unimplemented!(),
        }
    }

    /// Set nth value to `val`. `ceil` decided how do we trim `val`.
    ///
    /// The new value is returned. It is possible that `val` is greater than the upper
    /// bound of the nth, thus returned value is not guaranteed to be `get_nth() + val`.
    pub fn set_nth(&mut self, index: usize, val: f64, ceil: bool) -> f64 {
        let cur_value = self.nth_val(index).to_f64();
        let raw_delta = val - cur_value;
        // log::debug!("cur_value = {}, raw_delta = {}", cur_value, raw_delta);
        let delta = if ceil {
            raw_delta.ceil()
        } else {
            raw_delta.floor()
        };
        // log::debug!("delta = {}", delta);
        self.add_nth(index, delta) + cur_value
    }

    /// Add nth by taking the value first, add it and save back.
    ///
    /// Return added value.
    pub fn add_nth_(&mut self, idx: usize, v: f64) -> f64 {
        let mut old_val = self.nth_val(idx);
        let old_f64 = old_val.inner;
        let new_f64 = old_val.inner + v;
        let _ = old_val.set_exact(new_f64);
        let new_f64 = old_val.inner;
        self.write_nth_val(idx, old_val.inner as i128);
        new_f64 - old_f64
    }
    /// Set nth value to `val`. `ceil` decided how do we trim `val`.
    ///
    ///
    /// s returned value is not guaranteed to be `get_nth() + val`.
    pub fn set_nth_(&mut self, index: usize, v: f64, ceil: bool) -> f64 {
        let mut cur_value = self.nth_val(index);
        let _ = cur_value.set(v, ceil);
        let new_val = cur_value.inner;
        self.write_nth_val(index, new_val as i128);
        new_val
    }

    /// Add delta. Return `None` if the add is not possible.
    pub fn add_delta_with_coeffecients(
        &mut self,
        delta: &[f64],
        ics: &Vec<(usize, f64)>,
    ) -> Option<f64> {
        #[derive(Debug)]
        struct MinMax {
            val: f64,
            min: f64,
            max: f64,
        }
        let mut min_max = Vec::with_capacity(ics.len() - 1);
        let mut min = 0.0;
        let mut max = 0.0;
        for ic in ics.iter().rev() {
            let v = self.nth_val(ic.0);
            // debug!("v={}", v.to_f64());
            let val = v.to_f64() + delta[ic.0];
            min /= ic.1;
            max /= ic.1;
            min_max.push(MinMax { val, min, max });
            min = (v.min() - val + min) * ic.1;
            max = (v.max() - val + max) * ic.1;
        }
        min_max.reverse();
        let this_mm = &min_max[0];
        let this_val = &self.nth_val(ics[0].0);
        if this_mm.val > this_mm.max + this_val.max() || this_mm.val < this_mm.min + this_val.min()
        {
            return None;
        }
        let mut carry = 0.0;
        let last_ics = ics.len() - 1;
        for (i, (ic, mm)) in ics.iter().zip(min_max.iter()).enumerate() {
            carry /= ic.1;
            // log::debug!("carry={}", carry);
            if i == last_ics {
                let attempted = (min_max[i].val + carry).round();
                let actual = self.set_nth_(ic.0, attempted, false);
                carry = attempted - actual;
                /*
                log::trace!(
                    "attempted = {}, actual = {}, final carry={}",
                    attempted,
                    actual,
                    carry
                );
                */
                return Some(carry);
            }
            let attempted = min_max[i].val + carry;
            let actual = self.set_nth_(ic.0, attempted, false);
            carry = attempted - actual;
            // log::debug!("After setting: carry = {}, mm = {:?}", carry, &mm);
            if carry > mm.max {
                let attempted = self.nth_val(ic.0).to_f64() + carry;
                let actual = self.set_nth_(ic.0, attempted, true);
                carry = attempted - actual;

                if carry > mm.max || carry < mm.min {
                    let attempted = self.nth_val(ic.0).to_f64() + carry + 1.0;
                    let actual = self.set_nth_(ic.0, attempted, true);
                    let _carry = attempted - actual;
                }
            }
            carry *= ic.1;
        }
        panic!("Dead code. Should not have reached here.")
    }

    pub fn randomize_all(&mut self) {
        let mut rng = rand::thread_rng();
        self.randomize_all_with_weight(&mut rng, 3);
    }

    pub fn randomize_all_with_weight<T: Rng>(&mut self, rng: &mut T, weight: u32) {
        // 1/weight true
        let coin = rng.gen_bool(1.0 / weight as f64);
        if coin {
            self.randomize_all_uniform(rng);
        } else {
            self.randomize_all_mut_based(rng);
        }
    }

    pub fn randomize_all_uniform<T: Rng>(&mut self, rng: &mut T) {
        rng.fill_bytes(&mut self.value);
    }

    pub fn randomize_all_mut_based<T: Rng>(&mut self, rng: &mut T) {
        let entry_len = self.len() as u32;
        let byte_len = self.val_len() as u32;
        assert!(byte_len > 0 && entry_len > 0);

        let use_stacking = if byte_len <= 4 {
            1 + rng.gen_range(0, 16)
        } else if byte_len <= 20 {
            1 + rng.gen_range(0, 64)
        } else {
            1 + rng.gen_range(0, 256)
        };

        // let choice_range = Range::new(0, 6);
        let choice_range = Uniform::new(0, 6);

        for _ in 0..use_stacking {
            match rng.sample(choice_range) {
                0 | 1 => {
                    // flip bit
                    let byte_idx: u32 = rng.gen_range(0, byte_len);
                    let bit_idx: u32 = rng.gen_range(0, 8);
                    self.value[byte_idx as usize] ^= 128 >> bit_idx;
                },
                2 => {
                    // add
                    let entry_idx: u32 = rng.gen_range(0, entry_len);
                    let v: u32 = rng.gen_range(1, config::MUTATE_ARITH_MAX);
                    self.update(entry_idx as usize, true, v as u64);
                },
                3 => {
                    // sub
                    let entry_idx: u32 = rng.gen_range(0, entry_len);
                    let v: u32 = rng.gen_range(1, config::MUTATE_ARITH_MAX);
                    self.update(entry_idx as usize, false, v as u64);
                },
                4 => {
                    // set interesting value
                    let entry_idx: u32 = rng.gen_range(0, entry_len as u32);
                    let n = self.get_entry_len(entry_idx as usize);
                    let vals = search::get_interesting_bytes(n);
                    let wh = rng.gen_range(0, vals.len() as u32);
                    self.set(entry_idx as usize, vals[wh as usize]);
                },
                5 => {
                    // random byte
                    let byte_idx: u32 = rng.gen_range(0, byte_len);
                    // self.randomize_one_byte(byte_idx as usize);
                    self.value[byte_idx as usize] = rng.gen();
                },
                _ => {},
            }
        }
    }
    pub fn assign_sign<R: Rng>(&mut self, rng: &mut R) {
        self.meta.iter_mut().for_each(|meta| {
            meta.set_sign(
                if FuzzerConfig::get().enable_random_sign() {
                    meta.sign_info.get_random_sign(rng)
                } else {
                    meta.sign_info.get_concensus_sign()
                },
            )
        });
    }

    /// Fill nth buffer with a u8 `fill`. Then trim head and tail accordingly.
    ///
    /// This is used to set a value to a magic value.
    /// head and tail byte dependens on the endianness.
    /// If LE, buffer head is actually value tail; when BE, buffer head is value head.
    ///
    /// It is possible a value has only one byte, then head and tail overlap.
    /// This means that `trim_head` and `trim_tail` may work on the same byte.
    /// Thus it is **guaranteed** that we always `trim_head` first before we `trim_tail`,
    /// regardless the endianess.
    fn set_nth_fill<H, T>(&mut self, idx: usize, fill: u8, mut trim_head: H, mut trim_tail: T)
    where
        H: FnMut(&mut u8),
        T: FnMut(&mut u8),
    {
        let endian = self.meta[idx].endian;
        let buf = self.get_mut_slice(idx);
        let len = buf.len();
        debug_assert!(len != 0);
        for byte in buf.iter_mut() {
            *byte = fill;
        }
        match endian {
            Endian::LittleEndian => {
                trim_head(&mut buf[len - 1]);
                trim_tail(&mut buf[0]);
            },
            Endian::BigEndian => {
                trim_head(&mut buf[0]);
                trim_tail(&mut buf[len - 1]);
            },
            Endian::Split => {
                trim_head(&mut buf[len - 1]);
                trim_tail(&mut buf[0]);
            },
        };
    }
    /// Validate all input segments.
    ///
    /// For all integer input segments,
    /// 1. Set it to the bounds x_b
    /// 2. Step over the bound x_b +- 1
    /// 3. Compare the difference with other values.
    pub fn infer_dyn_sign_idx<F>(&mut self, idx: usize, f: &mut F) -> (Sign, Sign)
    where
        F: FnMut(&Self) -> f64,
    {
        let orig_val = self.nth_val(idx);
        let dyn_n = {
            // binary  : 111...110 | 111...111 || NORTH POLE || 000...000 | 000...001
            // var_name: n_sub_one |   n_sub   ||            ||   n_add   | n_add_one
            // signed  :     -2    |     -1    ||            ||     0     |     1
            // unsigned:  UMAX - 1 |   UMAX    ||            ||     0     |     1
            let f_n_sub_one = {
                self.set_nth_fill(idx, 0xff, |_| {}, |b| *b -= 1);
                (*f)(self)
            };
            let f_n_sub = {
                self.set_nth_fill(idx, 0xff, |_| {}, |_| {});
                (*f)(self)
            };
            let f_n_add = {
                self.set_nth_fill(idx, 0x00, |_| {}, |_| {});
                (*f)(self)
            };
            let f_n_add_one = {
                self.set_nth_fill(idx, 0x00, |_| {}, |b| *b += 1);
                (*f)(self)
            };
            if f_n_add_one.is_infinite()
                || f_n_add.is_infinite()
                || f_n_sub.is_infinite()
                || f_n_sub_one.is_infinite()
            {
                Sign::Unknown
            } else {
                if ((f_n_sub - f_n_sub_one).abs() + (f_n_add - f_n_add_one).abs()) * 10.0
                    < (f_n_sub - f_n_add).abs()
                {
                    Sign::Unsigned
                } else {
                    Sign::Signed
                }
            }
        };
        let dyn_s = {
            // binary  : 100...001 | 100...000 || SOUTH POLE || 011...111 | 011...110
            // var_name: s_add_one |   s_add   ||            ||   s_sub   | s_sub_one
            // signed  :  MIN + 1  |    MIN    ||            ||    MAX    |  MAX - 1
            // unsigned:  MAX + 2  |  MAX + 1  ||            ||    MAX    |  MAX - 1
            let f_s_add_one = {
                self.set_nth_fill(idx, 0x00, |b| *b = 0x80, |b| *b += 1);
                (*f)(self)
            };
            let f_s_add = {
                self.set_nth_fill(idx, 0x00, |b| *b = 0x80, |_| {});
                (*f)(self)
            };
            let f_s_sub = {
                self.set_nth_fill(idx, 0xff, |b| *b = 0x7f, |_| {});
                (*f)(self)
            };
            let f_s_sub_one = {
                self.set_nth_fill(idx, 0xff, |b| *b = 0x7f, |b| *b -= 1);
                (*f)(self)
            };
            if f_s_add_one.is_infinite()
                || f_s_add.is_infinite()
                || f_s_sub.is_infinite()
                || f_s_sub_one.is_infinite()
            {
                Sign::Unknown
            } else {
                if ((f_s_add_one - f_s_add).abs() + (f_s_sub_one - f_s_sub).abs()) * 10.0
                    < (f_s_add - f_s_sub).abs()
                {
                    Sign::Signed
                } else {
                    Sign::Unsigned
                }
            }
        };
        self.write_nth_val(idx, orig_val.inner as i128);
        (dyn_n, dyn_s)
    }
    pub fn infer_dyn_sign<F>(&mut self, mut f: F)
    where
        F: FnMut(&Self) -> f64,
    {
        for idx in 0..self.len() {
            let (dyn_n, dyn_s) = self.infer_dyn_sign_idx(idx, &mut f);
            self.meta[idx].update_dyn_sign_info(dyn_n, dyn_s);
        }
    }

    pub fn nth_to_be_w_sign_change<F>(&mut self, idx: usize, mut f: F)
    where
        F: FnMut(&Self) -> f64,
    {
        self.meta[idx].to_be();
        let (dyn_n, dyn_s) = self.infer_dyn_sign_idx(idx, &mut f);
        self.meta[idx].update_dyn_sign_info(dyn_n, dyn_s);
    }
}

impl fmt::Display for MutInput {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for i in 0..self.len() {
            write!(
                f,
                "{:.0}(0x{:x}) ",
                self.nth_val(i).inner,
                self.get_entry(i),
            )?
        }
        Ok(())
    }
}

impl fmt::Debug for MutInput {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for i in 0..self.len() {
            let hex = self.get_entry(i);
            let hex_endian = if self.meta[i].is_le() {
                hex
            } else {
                hex.to_be() >> (64 - self.meta[i].size * 8)
            };
            write!(
                f,
                // Repeat zeros(`0`) in-front so "cnt"(`cnt$`) space is used to display the hex value(`x`)
                "{:.0}(0x{:0cnt$x}=>0x{:0cnt$x}, {}) ",
                self.nth_val(i).inner,
                hex,
                hex_endian,
                self.meta[i],
                cnt = self.meta[i].size * 2,
            )?
        }
        Ok(())
    }
}

mod test {
    use super::*;
    use angora_common::config::{FuzzerConfig, CONFIG};
    #[test]
    fn test_clone_buf_and_do() {
        CONFIG.set(FuzzerConfig::default()).unwrap();
        let mut input = MutInput::new();
        input.push(vec![4; 4], true);
        input.push(vec![2; 2], true);
        input.push(vec![1; 1], true);
        assert_eq!(input.value, vec![4, 4, 4, 4, 2, 2, 1]);
        let (sum, buf) = input.clone_buf_and_do(|input| {
            let mut sum = 0;
            for v in input.value.iter_mut() {
                *v -= 1;
                sum += *v;
            }
            sum
        });
        assert_eq!(input.value, vec![4, 4, 4, 4, 2, 2, 1]);
        assert_eq!(buf, vec![3, 3, 3, 3, 1, 1, 0]);
        assert_eq!(sum, 14);
    }
}
