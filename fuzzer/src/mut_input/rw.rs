use super::*;

#[allow(dead_code)]
pub fn get_bytes_by_offsets(offsets: &Vec<TagSeg>, buf: &Vec<u8>) -> Vec<u8> {
    let mut bytes = vec![];
    for off in offsets {
        if off.begin < off.end {
            let mut v_bytes = buf[off.begin as usize..off.end as usize].to_vec();
            bytes.append(&mut v_bytes);
        }
    }
    bytes
}

pub fn set_bytes_by_offsets(offsets: &Vec<TagSeg>, bytes: &Vec<u8>, buf: &mut Vec<u8>) {
    let mut cmp_off = (0, 0);
    for off in offsets {
        if off.begin < off.end {
            cmp_off.0 = cmp_off.1;
            cmp_off.1 = cmp_off.0 + (off.end - off.begin) as usize;
            let scope = &mut buf[off.begin as usize..off.end as usize];
            scope.clone_from_slice(&bytes[cmp_off.0..cmp_off.1]);
        }
    }
}

pub fn read_val_from_buf(buf: &Vec<u8>, off: usize, size: usize) -> Result<u64, &str> {
    match size {
        1 => Ok(buf[off] as u64),
        2 => Ok(unsafe { *(&buf[off] as *const u8 as *const u16) as u64 }),
        4 => Ok(unsafe { *(&buf[off] as *const u8 as *const u32) as u64 }),
        8 => Ok(unsafe { *(&buf[off] as *const u8 as *const u64) }),
        _ => Err("strange arg off and size"),
    }
}

pub fn set_val_in_buf(buf: &mut Vec<u8>, off: usize, size: usize, val: u64) {
    // `off` is in bytes, alignment issue?
    match size {
        1 => {
            let v = &mut buf[off];
            *v = val as u8;
        }
        2 => {
            let v = unsafe { &mut *(&mut buf[off] as *mut u8 as *mut u16) };
            *v = val as u16;
        }
        4 => {
            let v = unsafe { &mut *(&mut buf[off] as *mut u8 as *mut u32) };
            *v = val as u32;
        }
        8 => {
            let v = unsafe { &mut *(&mut buf[off] as *mut u8 as *mut u64) };
            *v = val as u64;
        }
        _ => {
            panic!("strange arg off and size: {}, {}", off, size);
        }
    };
}

pub fn get_val_in_buf(buf: &mut Vec<u8>, off: usize, size: usize) -> u64 {
    match size {
        1 => buf[off] as u64,
        2 => *unsafe { &mut *(&mut buf[off] as *mut u8 as *mut u16) } as u64,
        4 => *unsafe { &mut *(&mut buf[off] as *mut u8 as *mut u32) } as u64,
        8 => *unsafe { &mut *(&mut buf[off] as *mut u8 as *mut u64) } as u64,
        _ => {
            panic!("strange arg off and size: {}, {}", off, size);
        }
    }
}
pub fn reverse_endian(val: u64, size: usize) -> u64 {
    match size {
        1 => val,
        2 => (val as u16).swap_bytes() as u64,
        4 => (val as u32).swap_bytes() as u64,
        8 => (val as u64).swap_bytes() as u64,
        _ => {
            panic!("strange arg size and val: {}, {}", size, val);
        }
    }
}

// Optional:
// saturating_add
// overflowing_add
pub fn update_val_in_buf(
    buf: &mut Vec<u8>,
    sign: bool,
    off: usize,
    size: usize,
    direction: bool,
    swap_endian: bool,
    delta: u64,
) {
    let mut val = get_val_in_buf(buf, off, size);
    if swap_endian {
        val = reverse_endian(val, size);
    }
    match size {
        1 => {
            val = match (sign, direction) {
                (true, true) => (val as i8).wrapping_add(delta as i8) as u8,
                (true, false) => (val as i8).wrapping_sub(delta as i8) as u8,
                (false, true) => (val as u8).wrapping_add(delta as u8) as u8,
                (false, false) => (val as u8).wrapping_sub(delta as u8) as u8,
            } as u64;
        }
        2 => {
            val = match (sign, direction) {
                (true, true) => (val as i16).wrapping_add(delta as i16) as u16,
                (true, false) => (val as i16).wrapping_sub(delta as i16) as u16,
                (false, true) => (val as u16).wrapping_add(delta as u16) as u16,
                (false, false) => (val as u16).wrapping_sub(delta as u16) as u16,
            } as u64;
        }
        4 => {
            val = match (sign, direction) {
                (true, true) => (val as i32).wrapping_add(delta as i32) as u32,
                (true, false) => (val as i32).wrapping_sub(delta as i32) as u32,
                (false, true) => (val as u32).wrapping_add(delta as u32) as u32,
                (false, false) => (val as u32).wrapping_sub(delta as u32) as u32,
            } as u64;
        }
        8 => {
            val = match (sign, direction) {
                (true, true) => (val as i64).wrapping_add(delta as i64) as u64,
                (true, false) => (val as i64).wrapping_sub(delta as i64) as u64,
                (false, true) => (val as u64).wrapping_add(delta as u64) as u64,
                (false, false) => (val as u64).wrapping_sub(delta as u64) as u64,
            } as u64;
        }
        _ => {
            panic!("strange arg off and size: {}, {}", off, size);
        }
    };
    if swap_endian {
        val = reverse_endian(val, size);
    }
    set_val_in_buf(buf, off, size, val);
}

pub fn insert_partial_buf(buf: &mut Vec<u8>, to_insert: Vec<u8>, to: usize) {
    let mut new_buf = vec![];
    new_buf.extend(buf[..to].iter().cloned());
    new_buf.extend(to_insert);
    new_buf.extend(buf[to..].iter().cloned());
    *buf = new_buf;
}
pub fn overwrite_partial_buf(buf: &mut Vec<u8>, from: usize, size: usize, to: usize) {
    buf[..].copy_within(from..(from + size), to);
}

mod test {

    use super::*;
    #[test]
    fn test_buf_funcs() {
        let mut buf = vec![
            0x1c, 0x2d, 0x33, 0x34, 0x22, 0x77, 0xbe, 0xaf, 0x96, 0x10, 0x01, 0xff,
        ];
        let buf_ref = &mut buf;

        let mut val = get_val_in_buf(buf_ref, 0, 4);
        assert_eq!(val, 0x34332d1c);
        val = reverse_endian(val, 4);
        assert_eq!(val, 0x1c2d3334);

        assert_eq!(get_val_in_buf(buf_ref, 5, 1), 0x77);

        let mut val = get_val_in_buf(buf_ref, 7, 2);
        assert_eq!(val, 0x96af);
        val = reverse_endian(val, 2);
        assert_eq!(val, 0xaf96);

        update_val_in_buf(buf_ref, false, 4, 4, true, true, 1);
        let mut val = get_val_in_buf(buf_ref, 4, 4);
        val = reverse_endian(val, 4);
        assert_eq!(val, 0x2277beb0);

        update_val_in_buf(buf_ref, false, 0, 2, false, true, 0xffff);
        let val = get_val_in_buf(buf_ref, 0, 2);
        assert_eq!(val, 0x2e1c);

        update_val_in_buf(buf_ref, false, 8, 4, false, false, 0x30);
        let val = get_val_in_buf(buf_ref, 8, 4);
        assert_eq!(val, 0xff011066);
    }

    #[test]
    fn test_partial_buf_funcs() {
        let mut buf = vec![0x12, 0x34, 0x56, 0x78];
        let buf_ref = &mut buf;

        overwrite_partial_buf(buf_ref, 0, 2, 1);
        assert_eq!(*buf_ref, vec![0x12, 0x12, 0x34, 0x78]);
    }
}
