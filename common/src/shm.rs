use libc::{self, c_void, off_t};
use nix::{
    fcntl::OFlag,
    sys::{
        mman::{mmap, munmap, shm_open, MapFlags, ProtFlags},
        stat::Mode,
    },
    unistd::ftruncate,
    Error,
};
use std::{
    self,
    fs::File,
    ops::{Deref, DerefMut},
    os::unix::io::{AsRawFd, FromRawFd, IntoRawFd, RawFd},
    path::Path,
    ptr,
    ptr::null_mut,
    slice,
};

// T must be fixed size
pub struct SHM<T: Sized> {
    id: i32,
    size: usize,
    ptr: *mut T,
}

impl<T> SHM<T> {
    pub fn new() -> Self {
        let size = std::mem::size_of::<T>() as usize;
        let id = unsafe {
            libc::shmget(
                libc::IPC_PRIVATE,
                size,
                libc::IPC_CREAT | libc::IPC_EXCL | 0o600,
            )
        };
        let ptr = unsafe { libc::shmat(id, std::ptr::null(), 0) as *mut T };

        SHM::<T> {
            id: id as i32,
            size,
            ptr,
        }
    }

    pub fn from_id(id: i32) -> Self {
        let size = std::mem::size_of::<T>() as usize;
        let ptr = unsafe { libc::shmat(id as libc::c_int, std::ptr::null(), 0) as *mut T };
        SHM::<T> { id, size, ptr }
    }

    pub fn clear(&mut self) {
        unsafe { libc::memset(self.ptr as *mut libc::c_void, 0, self.size) };
    }

    pub fn get_id(&self) -> i32 {
        self.id
    }

    pub fn get_ptr(&self) -> *mut T {
        self.ptr
    }

    pub fn is_fail(&self) -> bool {
        -1 == self.ptr as isize
    }
}

impl<T> Deref for SHM<T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        unsafe { &*self.ptr }
    }
}

impl<T> DerefMut for SHM<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { &mut *self.ptr }
    }
}

impl<T> std::fmt::Debug for SHM<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}, {}, {:p}", self.id, self.size, self.ptr)
    }
}

impl<T> Drop for SHM<T> {
    fn drop(&mut self) {
        unsafe { libc::shmctl(self.id, libc::IPC_RMID, std::ptr::null_mut()) };
    }
}

#[derive(Debug)]
pub struct SharedMemory {
    shm_file: File,
    mmap_ptr: *mut (),
    mmap_size: usize,
}

impl SharedMemory {
    pub unsafe fn new(shm_file: File, mmap_ptr: *mut (), mmap_size: usize) -> SharedMemory {
        SharedMemory {
            shm_file,
            mmap_ptr,
            mmap_size,
        }
    }

    pub fn open_with_size<P: AsRef<Path>>(
        file_name: P,
        size: usize,
    ) -> Result<SharedMemory, Error> {
        let shm_file = shm_open(
            file_name.as_ref(),
            OFlag::O_RDWR | OFlag::O_TRUNC,
            Mode::from_bits(0o000).unwrap(),
        )?;

        ftruncate(shm_file, size as off_t)?;

        let branch_table_ptr = unsafe {
            mmap(
                ptr::null_mut(),
                size as usize,
                ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                MapFlags::MAP_SHARED,
                shm_file,
                0,
            )
        }? as *mut ();

        Ok(unsafe { SharedMemory::new(File::from_raw_fd(shm_file), branch_table_ptr, size) })
    }

    pub fn create_empty<P: AsRef<Path>>(file_name: P) -> Result<SharedMemory, failure::Error> {
        let shm_file = shm_open(
            file_name.as_ref(),
            OFlag::O_CREAT | OFlag::O_RDWR,
            Mode::from_bits(0o600).unwrap(),
        )?;

        Ok(unsafe { SharedMemory::new(File::from_raw_fd(shm_file), null_mut(), 0) })
    }

    pub fn resize(&mut self) -> Result<(), failure::Error> {
        let mmap_size = self.shm_file.metadata()?.len() as usize;

        if mmap_size != self.mmap_size {
            if self.mmap_size > 0 {
                unsafe { munmap(self.mmap_ptr as *mut c_void, self.mmap_size)? };
            }

            self.mmap_ptr = unsafe {
                mmap(
                    ptr::null_mut(),
                    mmap_size as usize,
                    ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                    MapFlags::MAP_SHARED,
                    self.as_raw_fd(),
                    0,
                )
            }? as *mut ();

            self.mmap_size = mmap_size;
        }

        Ok(())
    }

    pub fn clear(&mut self) {
        unsafe { libc::memset(self.mmap_ptr as *mut libc::c_void, 0, self.mmap_size) };
    }

    pub unsafe fn as_ptr(&self) -> *const () {
        self.mmap_ptr as *const ()
    }

    pub unsafe fn as_mut_ptr(&mut self) -> *mut () {
        self.mmap_ptr
    }

    pub fn size(&self) -> usize {
        self.mmap_size
    }
}

impl AsRawFd for SharedMemory {
    fn as_raw_fd(&self) -> RawFd {
        self.shm_file.as_raw_fd()
    }
}

impl IntoRawFd for SharedMemory {
    fn into_raw_fd(self) -> RawFd {
        self.shm_file.into_raw_fd()
    }
}

#[derive(Debug)]
pub struct BranchCountTable<'a> {
    pub branch_table: &'a mut [u16],
}

impl<'a> BranchCountTable<'a> {
    pub fn new(shared_memory: &'a mut SharedMemory) -> BranchCountTable<'a> {
        let branch_table = unsafe {
            slice::from_raw_parts_mut(
                shared_memory.as_ptr() as *mut u16,
                shared_memory.size() / std::mem::size_of::<u16>(),
            )
        };

        BranchCountTable { branch_table }
    }

    pub fn set_zero(&mut self) {
        for i in self.branch_table.iter_mut() {
            *i = 0_u16;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_u8() {
        let mut one = SHM::<u8>::new();
        *one = 1;
        assert_eq!(1, *one);
    }

    #[test]
    fn test_array() {
        let mut arr = SHM::<[u8; 10]>::new();
        arr.clear();
        let sl = &mut arr;
        assert_eq!(0, sl[4]);
        sl[4] = 33;
        assert_eq!(33, sl[4]);
    }

    #[test]
    fn test_shm_fail() {
        let arr = SHM::<[u8; 10]>::from_id(88888888);
        assert!(arr.is_fail());

        let arr = SHM::<[u8; 10]>::new();
        assert!(!arr.is_fail());
        let arr2 = SHM::<[u8; 10]>::from_id(arr.get_id());
        assert!(!arr2.is_fail());
    }
}
