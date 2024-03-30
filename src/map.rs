// Axel '0vercl0k' Souchet - July 18 2023
//! This module implements the logic that allows to memory map a file on both
//! Unix and Windows (cf [`memory_map_file`] / [`unmap_memory_mapped_file`]).
use std::{convert, fs, io, path, ptr, slice};

/// A cursor over a slice of bytes. This is used to seek / read from the
/// mapping.
pub type Cursor<'a> = io::Cursor<&'a [u8]>;

/// A memory mapped is basically either a slice over a memory mapping or a
/// regular slice. The main difference is that the former needs special handling
/// when dropped ([`unmap_memory_mapped_file`]). This means that the type
/// actually owns the memory mapped region although it's not obvious from its
/// definition.
#[derive(Debug)]
pub enum MappedFile<'a> {
    /// This means the underlying slice is over a memory mapping that needs
    /// special handling to be dropped. It is owned by this type.
    Mmaped(&'a [u8]),
    /// This gives users flexibility when they don't want to necessarily memory
    /// map a file and want to parse directly from a vector, or a string. It
    /// could also be because they already have mapped a file themselves in
    /// which case it wouldn't make sense to map it again.
    Slice(&'a [u8]),
}

impl<'a> MappedFile<'a> {
    /// Create a new [`MappedFile`] from a path. This memory maps the file and
    /// as a result, the instance will known that mapping.
    pub fn new<P>(path: P) -> io::Result<MappedFile<'a>>
    where
        P: convert::AsRef<path::Path>,
    {
        // Open the file..
        let file = fs::File::open(path)?;

        // ..and memory map it using the underlying OS-provided APIs.
        memory_map_file(file)
    }

    /// Create a [`io::Cursor`] over the underlying byte slice. This is used
    /// extensively to parse the minidump like it is reading / seeking from a
    /// file.
    pub fn cursor(&self) -> Cursor<'a> {
        // Grab the slice off of it.
        let slice = match self {
            Self::Mmaped(mmaped) => mmaped,
            Self::Slice(slice_) => slice_,
        };

        // Create the cursor over the slice.
        io::Cursor::new(slice)
    }
}

/// Convert a byte slice reference into a [`MappedFile`]. This is useful for
/// users that want to create a [`MappedFile`] instance from a slice that came
/// from somewhere and that isn't owned by the instance. You can imagine this
/// slice coming from a [`Vec<u8>`] or a [`String`] or another mapped file
/// maybe.
impl<'a> From<&'a [u8]> for MappedFile<'a> {
    fn from(value: &'a [u8]) -> Self {
        Self::Slice(value)
    }
}

/// Drop the [`MappedFile`]. In the case we memory mapped the file, we need to
/// drop the mapping using OS-provided APIs. Otherwise, we have nothing to do!
impl<'a> Drop for MappedFile<'a> {
    fn drop(&mut self) {
        match self {
            Self::Mmaped(mmap) => unmap_memory_mapped_file(mmap).expect("failed to unmap"),
            Self::Slice(_) => {}
        }
    }
}

#[cfg(windows)]
#[allow(non_camel_case_types, clippy::upper_case_acronyms)]
/// Module that implements memory mapping on Windows using CreateFileMappingA /
/// MapViewOfFile.
mod windows {
    use std::os::windows::prelude::AsRawHandle;
    use std::os::windows::raw::HANDLE;

    use super::*;

    const PAGE_READONLY: DWORD = 2;
    const FILE_MAP_READ: DWORD = 4;

    type DWORD = u32;
    type BOOL = u32;
    type SIZE_T = usize;
    type LPCSTR = *mut u8;
    type LPVOID = *const u8;

    extern "system" {
        /// Creates or opens a named or unnamed file mapping object for a
        /// specified file.
        ///
        /// <https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createfilemappinga>
        fn CreateFileMappingA(
            h: HANDLE,
            file_mapping_attrs: *const u8,
            protect: DWORD,
            max_size_high: DWORD,
            max_size_low: DWORD,
            name: LPCSTR,
        ) -> HANDLE;

        /// Maps a view of a file mapping into the address space of a calling
        /// process.
        ///
        /// <https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-mapviewoffile>
        fn MapViewOfFile(
            file_mapping_object: HANDLE,
            desired_access: DWORD,
            file_offset_high: DWORD,
            file_offset_low: DWORD,
            number_of_bytes_to_map: SIZE_T,
        ) -> LPVOID;

        /// Closes an open object handle.
        ///
        /// <https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-closehandle>
        fn CloseHandle(h: HANDLE) -> BOOL;

        /// Unmaps a mapped view of a file from the calling process's address
        /// space.
        ///
        /// <https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-unmapviewoffile>
        fn UnmapViewOfFile(base_address: LPVOID) -> BOOL;
    }

    /// Memory map a file into memory.
    pub fn memory_map_file<'a>(file: fs::File) -> Result<MappedFile<'a>, io::Error> {
        // Grab the underlying HANDLE.
        let file_handle = file.as_raw_handle();

        // Create the mapping.
        let mapping_handle = unsafe {
            CreateFileMappingA(
                file_handle,
                ptr::null_mut(),
                PAGE_READONLY,
                0,
                0,
                ptr::null_mut(),
            )
        };

        // If the mapping is NULL, it failed so let's bail.
        if mapping_handle.is_null() {
            return Err(io::Error::last_os_error());
        }

        // Grab the size of the underlying file, this will be the size of the
        // view.
        let size = file.metadata()?.len().try_into().unwrap();

        // Map the view in the address space.
        let base = unsafe { MapViewOfFile(mapping_handle, FILE_MAP_READ, 0, 0, size) };

        // If the base address is NULL, it failed so let's bail.
        if base.is_null() {
            // Don't forget to close the HANDLE we created for the mapping.
            unsafe {
                CloseHandle(mapping_handle);
            }
            return Err(io::Error::last_os_error());
        }

        // Now we materialized a view in the address space, we can get rid of
        // the mapping handle.
        unsafe {
            CloseHandle(mapping_handle);
        }

        // Make sure the size is not bigger than what [`slice::from_raw_parts`] wants.
        if size > isize::MAX.try_into().unwrap() {
            panic!("slice is too large");
        }

        // Create the slice over the mapping.
        // SAFETY: This is safe because:
        //   - It is a byte slice, so we don't need to care about the alignment.
        //   - The base is not NULL as we've verified that it is the case above.
        //   - The underlying is owned by the type and the lifetime.
        //   - We asked the OS to map `size` bytes, so we have a guarantee that there's
        //     `size` consecutive bytes.
        //   - We never give a mutable reference to this slice, so it can't get mutated.
        //   - The total len of the slice is guaranteed to be smaller than
        //     [`isize::MAX`].
        //   - The underlying mapping, the type and the slice have the same lifetime
        //     which guarantees that we can't access the underlying once it has been
        //     unmapped (use-after-unmap).
        Ok(MappedFile::Mmaped(unsafe {
            slice::from_raw_parts(base, size)
        }))
    }

    /// Unmap the memory mapped file.
    pub fn unmap_memory_mapped_file(data: &[u8]) -> Result<(), io::Error> {
        match unsafe { UnmapViewOfFile(data.as_ptr()) } {
            0 => Err(io::Error::last_os_error()),
            _ => Ok(()),
        }
    }
}

#[cfg(windows)]
use windows::*;

#[cfg(unix)]
/// Module that implements memory mapping on Unix using the mmap syscall.
mod unix {
    use std::os::fd::AsRawFd;

    use super::*;

    const PROT_READ: i32 = 1;
    const MAP_SHARED: i32 = 1;
    const MAP_FAILED: *const u8 = usize::MAX as _;

    extern "system" {
        fn mmap(
            addr: *const u8,
            length: usize,
            prot: i32,
            flags: i32,
            fd: i32,
            offset: i32,
        ) -> *const u8;

        fn munmap(addr: *const u8, length: usize) -> i32;
    }

    pub fn memory_map_file<'a>(file: fs::File) -> Result<MappedFile<'a>, io::Error> {
        // Grab the underlying file descriptor.
        let file_fd = file.as_raw_fd();

        // Grab the size of the underlying file. This will be the size of the
        // memory mapped region.
        let size = file.metadata()?.len().try_into().unwrap();

        // Mmap the file.
        let ret = unsafe { mmap(ptr::null_mut(), size, PROT_READ, MAP_SHARED, file_fd, 0) };

        // If the system call failed, bail.
        if ret == MAP_FAILED {
            return Err(io::Error::last_os_error());
        }

        // Make sure the size is not bigger than what [`slice::from_raw_parts`] wants.
        if size > isize::MAX.try_into().unwrap() {
            panic!("slice is too large");
        }

        // Create the slice over the mapping.
        // SAFETY: This is safe because:
        //   - It is a byte slice, so we don't need to care about the alignment.
        //   - The base is not NULL as we've verified that it is the case above.
        //   - The underlying is owned by the type and the lifetime.
        //   - We asked the OS to map `size` bytes, so we have a guarantee that there's
        //     `size` consecutive bytes.
        //   - We never give a mutable reference to this slice, so it can't get mutated.
        //   - The total len of the slice is guaranteed to be smaller than
        //     [`isize::MAX`].
        //   - The underlying mapping, the type and the slice have the same lifetime
        //     which guarantees that we can't access the underlying once it has been
        //     unmapped (use-after-unmap).
        Ok(MappedFile::Mmaped(unsafe {
            slice::from_raw_parts(ret, size)
        }))
    }

    // Unmap a memory mapped file.
    pub fn unmap_memory_mapped_file(data: &[u8]) -> Result<(), io::Error> {
        match unsafe { munmap(data.as_ptr(), data.len()) } {
            0 => Ok(()),
            _ => Err(io::Error::last_os_error()),
        }
    }
}

#[cfg(unix)]
use unix::*;

#[cfg(not(any(windows, unix)))]
/// Your system hasn't been implemented; if you do it, send a PR!
fn unimplemented() -> u32 {}
