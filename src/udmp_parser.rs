// Axel '0vercl0k' Souchet - July 29 2023
//! This module is where the parsing logic is implemented. The
//! [`UserDumpParser`] can memory map a file by default but users can also build
//! an instance from a slice they got from somewhere else.
use std::io::{Read, Seek};
use std::{collections, fmt, io, mem, ops, path, slice, vec};

use crate::map::{Cursor, MappedFile};
use crate::structs::*;

/// Disables all access to the committed region of pages. An attempt to read
/// from, write to, or execute the committed region results in an access
/// violation.
pub const PAGE_NOACCESS: u32 = 1;
/// Enables read-only access to the committed region of pages. An attempt to
/// write to the committed region results in an access violation. If Data
/// Execution Prevention is enabled, an attempt to execute code in the committed
/// region results in an access violation.
pub const PAGE_READONLY: u32 = 2;
/// Enables read-only or read/write access to the committed region of pages. If
/// Data Execution Prevention is enabled, attempting to execute code in the
/// committed region results in an access violation.
pub const PAGE_READWRITE: u32 = 4;
/// Enables read-only or copy-on-write access to a mapped view of a file mapping
/// object. An attempt to write to a committed copy-on-write page results in a
/// private copy of the page being made for the process. The private page is
/// marked as PAGE_READWRITE, and the change is written to the new page. If Data
/// Execution Prevention is enabled, attempting to execute code in the committed
/// region results in an access violation.
pub const PAGE_WRITECOPY: u32 = 8;
/// Enables execute access to the committed region of pages. An attempt to write
/// to the committed region results in an access violation.
pub const PAGE_EXECUTE: u32 = 16;
/// Enables execute or read-only access to the committed region of pages. An
/// attempt to write to the committed region results in an access violation.
pub const PAGE_EXECUTE_READ: u32 = 32;
/// Enables execute, read-only, or read/write access to the committed region of
/// pages.
pub const PAGE_EXECUTE_READWRITE: u32 = 64;
/// Enables execute, read-only, or copy-on-write access to a mapped view of a
/// file mapping object. An attempt to write to a committed copy-on-write page
/// results in a private copy of the page being made for the process. The
/// private page is marked as PAGE_EXECUTE_READWRITE, and the change is written
/// to the new page.
pub const PAGE_EXECUTE_WRITECOPY: u32 = 128;
/// Pages in the region become guard pages. Any attempt to access a guard page
/// causes the system to raise a STATUS_GUARD_PAGE_VIOLATION exception and turn
/// off the guard page status. Guard pages thus act as a one-time access alarm.
pub const PAGE_GUARD: u32 = 0x1_00;
/// Sets all pages to be non-cachable. Applications should not use this
/// attribute except when explicitly required for a device. Using the
/// interlocked functions with memory that is mapped with SEC_NOCACHE can result
/// in an EXCEPTION_ILLEGAL_INSTRUCTION exception.
pub const PAGE_NOCACHE: u32 = 0x2_00;
/// Sets all pages to be write-combined. Applications should not use this
/// attribute except when explicitly required for a device. Using the
/// interlocked functions with memory that is mapped as write-combined can
/// result in an EXCEPTION_ILLEGAL_INSTRUCTION exception.
pub const PAGE_WRITECOMBINE: u32 = 0x4_00;

/// The memory rights constants on Windows make it annoying to know if the page
/// is readable / writable / executable, so we have to create our own masks.
/// A page is readable if it is protected with any of the below rights.
const READABLE: u32 = PAGE_READONLY
    | PAGE_READWRITE
    | PAGE_EXECUTE_READ
    | PAGE_EXECUTE_READWRITE
    | PAGE_EXECUTE_WRITECOPY
    | PAGE_WRITECOPY;

/// A page is writable if it is protected with any of the below rights.
const WRITABLE: u32 = PAGE_READWRITE | PAGE_EXECUTE_READWRITE | PAGE_WRITECOPY;
/// A page is executable if it is protected with any of the below rights.
const EXECUTABLE: u32 =
    PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;

/// A DLL loaded in the virtual address space.
#[allow(clippy::len_without_is_empty)]
#[derive(Default, Debug)]
pub struct Module<'a> {
    /// The range of where the module is loaded in memory at.
    pub range: ops::Range<u64>,
    /// PE checksum of the module.
    pub checksum: u32,
    /// Timestamp.
    pub time_date_stamp: u32,
    /// The module path on the file system.
    pub path: path::PathBuf,
    pub version_info: FixedFileInfo,
    pub cv_record: &'a [u8],
    pub misc_record: &'a [u8],
}

impl<'a> Module<'a> {
    /// Build a new [`Module`] instance.
    fn new(
        entry: ModuleEntry,
        module_name: String,
        cv_record: &'a [u8],
        misc_record: &'a [u8],
    ) -> Self {
        let start = entry.base_of_image;
        let end = entry.base_of_image + entry.size_of_image as u64;
        let range = ops::Range { start, end };
        if range.is_empty() {
            panic!("range is malformed");
        }

        Self {
            range,
            checksum: entry.checksum,
            time_date_stamp: entry.time_date_stamp,
            path: module_name.into(),
            version_info: entry.version_info,
            cv_record,
            misc_record,
        }
    }

    /// Get the file name of the module. This returns [`None`] if the file name
    /// can't be converted to a Rust string.
    pub fn file_name(&self) -> Option<&str> {
        self.path.file_name().unwrap().to_str()
    }

    /// Get the address of where the module was loaded at.
    pub fn start_addr(&self) -> u64 {
        self.range.start
    }

    /// Get the address of where the last byte of the module was loaded at.
    pub fn end_addr(&self) -> u64 {
        self.range.end - 1
    }

    /// Get the length of the range of memory the module was loaded at.
    pub fn len(&self) -> u64 {
        self.range.end - self.range.start
    }
}

/// A [`ThreadContext`] stores the thread contexts for the architecture that are
/// supported by the library.
#[derive(Debug)]
pub enum ThreadContext {
    /// The Intel x86 thread context.
    X86(Box<ThreadContextX86>),
    /// The Intel x64 thread context.
    X64(Box<ThreadContextX64>),
}

/// Display the [`ThreadContext`] like WinDbg would.
impl fmt::Display for ThreadContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::X86(ctx) => ctx.fmt(f),
            Self::X64(ctx) => ctx.fmt(f),
        }
    }
}

/// A thread that was running when the dump was generated.
#[derive(Debug)]
pub struct Thread {
    /// The thread ID.
    pub id: u32,
    /// The suspend count counter cf [Freezing and Suspending Threads](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/controlling-processes-and-threads).
    pub suspend_count: u32,
    /// The priority class cf [Priority Class](https://learn.microsoft.com/en-us/windows/win32/procthread/scheduling-priorities).
    pub priority_class: u32,
    /// Thread priority cf [Priority level](https://learn.microsoft.com/en-us/windows/win32/procthread/scheduling-priorities).
    pub priority: u32,
    /// The thread environment block address.
    pub teb: u64,
    /// The thread context.
    context: ThreadContext,
}

impl Thread {
    /// Build a new [`Thread`] instance.
    fn new(entry: ThreadEntry, context: ThreadContext) -> Self {
        Self {
            id: entry.thread_id,
            suspend_count: entry.suspend_count,
            priority_class: entry.priority_class,
            priority: entry.priority,
            teb: entry.teb,
            context,
        }
    }

    /// Get a reference to the [`ThreadContext`].
    pub fn context(&self) -> &ThreadContext {
        &self.context
    }
}

/// A block of memory in the address space that isn't a [`Module`]. [`MemBlock`]
/// can have `data` associated with it but isn't a guarantee (think about a
/// memory region that is mapped as `PAGE_NOACCESS`).
#[derive(Default, Debug)]
#[allow(clippy::len_without_is_empty)]
pub struct MemBlock<'a> {
    /// Range over the start/end address of the memory region.
    pub range: ops::Range<u64>,
    /// The base of the allocation that gave life to this memory region.
    pub allocation_base: u64,
    /// The page protection used at allocation time.
    pub allocation_protect: u32,
    /// The state of the memory region. See [State](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-memory_basic_information).
    pub state: u32,
    /// The page protection currently applied to the memory region.
    pub protect: u32,
    /// The type of memory region. See [Type](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-memory_basic_information).
    pub type_: u32,
    /// The [`MemBlock`]'s data.
    pub data: &'a [u8],
}

impl<'a> MemBlock<'a> {
    /// Is the memory region readable?
    pub fn is_readable(&self) -> bool {
        (self.protect & READABLE) != 0
    }

    /// Is the memory region writable?
    pub fn is_writable(&self) -> bool {
        (self.protect & WRITABLE) != 0
    }

    /// Is the memory region executable?
    pub fn is_executable(&self) -> bool {
        (self.protect & EXECUTABLE) != 0
    }

    /// Stringify the memory region state.
    pub fn state_as_str(&self) -> &str {
        match self.state {
            0x10_00 => "MEM_COMMIT",
            0x20_00 => "MEM_RESERVE",
            0x1_00_00 => "MEM_FREE",
            _ => "UNKNOWN",
        }
    }

    /// Stringify the memory region type.
    pub fn type_as_str(&self) -> &str {
        if self.state == 0x1_00_00 {
            return "";
        }

        match self.type_ {
            0x2_00_00 => "MEM_PRIVATE",
            0x4_00_00 => "MEM_MAPPED",
            0x1_00_00_00 => "MEM_IMAGE",
            _ => "UNKNOWN",
        }
    }

    /// Stringify the memory region protection.
    pub fn protect_as_str(&self) -> String {
        if self.protect == 0 {
            return "".into();
        }

        // Those bits are the only ones that can be combined with the page
        // protections from below. So strip those first off `protect`.
        let bits = collections::HashMap::from([
            (PAGE_GUARD, "PAGE_GUARD"),
            (PAGE_NOCACHE, "PAGE_NOCACHE"),
            (PAGE_WRITECOMBINE, "PAGE_WRITECOMBINE"),
        ]);

        // This is where the parts of the stringified mask are stored in.
        let mut parts = vec::Vec::new();
        let mut protect = self.protect;

        // Walk through the bits to check if turned on.
        for (mask, str) in bits.iter() {
            // If the current bit isn't set, skip.
            if (protect & mask) == 0 {
                continue;
            }

            // If it is set, strip it off from `protect` and push its
            // stringified value in the vector.
            protect &= !mask;
            parts.push(*str);
        }

        // Now we can handle the 'normal' page properties.
        parts.push(match protect {
            PAGE_NOACCESS => "PAGE_NOACCESS",
            PAGE_READONLY => "PAGE_READONLY",
            PAGE_READWRITE => "PAGE_READWRITE",
            PAGE_WRITECOPY => "PAGE_WRITECOPY",
            PAGE_EXECUTE => "PAGE_EXECUTE",
            PAGE_EXECUTE_READ => "PAGE_EXECUTE_READ",
            PAGE_EXECUTE_READWRITE => "PAGE_EXECUTE_READWRITE",
            PAGE_EXECUTE_WRITECOPY => "PAGE_EXECUTE_WRITECOPY",
            _ => "UNKNOWN",
        });

        parts.join(" | ")
    }

    /// Get a slice over the [`MemBlock`]'s data from its absolute address.
    ///
    /// If the dump had a memory block of size 4 bytes starting at address
    /// 0xdead then calling `data_from(0xdead+1)` returns a slice over the
    /// last 3 bytes of the memory block. This is useful when you don't need
    /// to reason about offsets.
    pub fn data_from(&self, addr: u64) -> Option<&[u8]> {
        // If the memory block is empty return `None`. Also bail if this
        // `MemBlock` doesn't contain the address.
        if self.data.is_empty() || !self.range.contains(&addr) {
            return None;
        }

        // `addr` is contained in the range, so this is safe.
        let offset = addr - self.range.start;

        // Return the slice to the user.
        Some(&self.data[offset.try_into().unwrap()..])
    }

    /// Get the address of where this [`MemBlock`] was at in memory.
    pub fn start_addr(&self) -> u64 {
        self.range.start
    }

    /// Get the end address of where this [`MemBlock`] was at in memory.
    ///
    /// Note that the underlying range is not inclusive, so this address is
    /// pointing right after the last byte's address.
    pub fn end_addr(&self) -> u64 {
        self.range.end
    }

    /// Get the size of the [`MemBlock`].
    ///
    /// Note that a region of memory can exists without having any `data`
    /// associated with it. This method returns the range len, not `data`'s len.
    ///
    /// An example is a memory region mapped as `PAGE_NOACCESS`; it exists in
    /// the address space but has no content.
    pub fn len(&self) -> u64 {
        self.range.end - self.range.start
    }
}

/// Convert a [`MemoryInfo`] into a [`MemBlock`].
impl<'a> From<MemoryInfo> for MemBlock<'a> {
    fn from(value: MemoryInfo) -> Self {
        Self {
            range: value.base_address..(value.base_address + value.region_size),
            allocation_base: value.allocation_base,
            allocation_protect: value.allocation_protect,
            state: value.state,
            protect: value.protect,
            type_: value.type_,
            ..Default::default()
        }
    }
}

/// Map a base address to a [`MemBlock`].
pub type MemBlocks<'a> = collections::BTreeMap<u64, MemBlock<'a>>;

/// Map a thread id to a [`Thread`].
pub type Threads = collections::BTreeMap<u32, Thread>;

/// Map a base address to a [`Module`].
pub type Modules<'a> = collections::BTreeMap<u64, Module<'a>>;

/// Architectures supported by the library.
#[derive(Debug, Clone, Copy)]
pub enum Arch {
    /// Intel x86.
    X86,
    /// Intel x64.
    X64,
}

/// This stores  useful information fished out of of Windows minidump file:
/// thread contexts and memory blocks.
#[derive(Debug)]
pub struct UserDumpParser<'a> {
    /// The thread id of the foreground thread.
    pub foreground_tid: Option<u32>,
    /// The architecture of the dumped process.
    arch: Arch,
    /// A map of [`MemBlock`]s.
    mem_blocks: MemBlocks<'a>,
    /// A map of [`Module`].
    modules: Modules<'a>,
    /// A map of [`Thread`].
    threads: Threads,
    /// This is where we hold the backing data. Either it is a memory mapped
    /// file, or a slice that needs to live as long as this.
    _mapped_file: MappedFile<'a>,
}

impl<'a> UserDumpParser<'a> {
    /// Create an instance from a filepath. This memory maps the file and parses
    /// it.
    pub fn new<S: AsRef<path::Path>>(path: S) -> io::Result<UserDumpParser<'a>> {
        let mapped_file = MappedFile::new(path)?;
        Self::with_file(mapped_file)
    }

    /// Create an instance from something that dereference to a slice of bytes.
    pub fn with_slice(
        slice: &'a impl std::ops::Deref<Target = [u8]>,
    ) -> io::Result<UserDumpParser<'a>> {
        Self::with_file(MappedFile::from(slice.deref()))
    }

    /// Is the architeture X64?
    pub fn is_arch_x64(&self) -> bool {
        matches!(self.arch, Arch::X64)
    }

    /// Is the architecture X86?
    pub fn is_arch_x86(&self) -> bool {
        matches!(self.arch, Arch::X86)
    }

    /// Get a reference to the base address -> [`Module`] map.
    pub fn modules(&self) -> &Modules {
        &self.modules
    }

    /// Find a [`Module`] that includes `address` in its range.
    pub fn get_module(&self, address: u64) -> Option<&Module> {
        self.modules
            .values()
            .find(|module| module.range.contains(&address))
    }

    /// Get a reference to the TID -> [`Thread`] map.
    pub fn threads(&self) -> &Threads {
        &self.threads
    }

    /// Find a [`Thread`] with a specific TID.
    pub fn get_thread(&self, id: u32) -> Option<&Thread> {
        self.threads.values().find(|thread| thread.id == id)
    }

    /// Get a reference to the base address -> [`MemBlock`] map.
    pub fn mem_blocks(&self) -> &MemBlocks {
        &self.mem_blocks
    }

    /// Find a [`MemBlock`] that includes `address` in its range.
    pub fn get_mem_block(&self, address: u64) -> Option<&MemBlock> {
        self.mem_blocks
            .values()
            .find(|block| block.range.contains(&address))
    }

    /// Utility to get a slice from a [`LocationDescriptor32`] safely.
    fn slice_from_location_descriptor(
        reader: &Cursor,
        location: LocationDescriptor32,
    ) -> io::Result<&'a [u8]> {
        // Grab the offset and the wanted len.
        let offset = location.rva.try_into().unwrap();
        let len = location.data_size.try_into().unwrap();

        // Grab a reference on the underlying slice.
        let slice_ref = reader.get_ref();

        // Split the slice in two. We only care about the tail.
        let (_, tail) = slice_ref.split_at(offset);

        // Make sure the tail slice is big enough.
        if tail.len() < len {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "not enough data for slicing",
            ));
        }

        // Make sure we hold `from_raw_parts`'s contract.
        if len > isize::MAX.try_into().unwrap() {
            panic!("len > isize::MAX");
        }

        // Build the slice!
        Ok(unsafe { slice::from_raw_parts(tail.as_ptr(), len) })
    }

    /// Parse the system info stream to know which architecture is used.
    fn parse_system_info(cursor: &mut Cursor) -> io::Result<Arch> {
        // Read the stream info.
        let system_info = read_struct::<SystemInfoStream>(cursor)?;

        // Build the value of the enum safely.
        Ok(match system_info.processor_arch {
            ARCH_X86 => Arch::X86,
            ARCH_X64 => Arch::X64,
            _ => panic!("Unsupported architecture {:x}", system_info.processor_arch),
        })
    }

    /// Parse the exception stream to know figure out if there's a foreground
    /// TID.
    fn parse_exception(cursor: &mut Cursor) -> io::Result<u32> {
        // Read the exception stream.
        let exception = read_struct::<ExceptionStream>(cursor)?;

        // Return the TID.
        Ok(exception.thread_id)
    }

    /// Parse the memory info list stream to build the [`MemBlocks`] map.
    fn parse_mem_info_list(cursor: &mut Cursor) -> io::Result<MemBlocks<'a>> {
        // Create storage for the memory blocks.
        let mut mem_blocks = MemBlocks::new();

        // Read the memory info list stream.
        let mem_info_list = read_struct::<MemoryInfoListStream>(cursor)?;

        // Ensure that each entry is at least as big as what we expected.
        let mem_info_size = mem::size_of::<MemoryInfo>() as u32;
        let size_of_entry = mem_info_list.size_of_entry;
        if size_of_entry < mem_info_size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "MemoryInfo's size ({}) doesn't match the dump ({})",
                    mem_info_size, mem_info_list.size_of_entry
                ),
            ));
        }

        // Iterate through every entries.
        for _ in 0..mem_info_list.number_of_entries {
            // Read the memory info structure.
            let mem_info = peek_struct::<MemoryInfo>(cursor)?;

            // The key in the map is the base address.
            let key = mem_info.base_address;

            // If we already inserted this address, there's something wrong so
            // bail.
            let previous_val = mem_blocks.insert(key, mem_info.into());
            if previous_val.is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Address {} already in the mem map", key),
                ));
            }

            // Move on to the next entry.
            cursor.seek(io::SeekFrom::Current(size_of_entry.into()))?;
        }

        // We're done.
        Ok(mem_blocks)
    }

    /// Parse the memory64 list stream to associate data to the MemBlock we
    /// parsed from the memory info list stream. That's why we parse the memory
    /// info list stream first.
    fn parse_mem64_list(cursor: &mut Cursor, mem_blocks: &mut MemBlocks<'a>) -> io::Result<()> {
        // Read the memory64 list stream.
        let mem_list = read_struct::<Memory64ListStream>(cursor)?;

        // Grab the starting offset.
        let mut data_offset = mem_list.base_rva;

        // Iterate through every entries.
        for _ in 0..mem_list.number_of_memory_ranges {
            // Read a descriptor.
            let descriptor = read_struct::<MemoryDescriptor64>(cursor)?;

            // Get a reference to the associated MemBlock off `mem_blocks`.
            let entry = mem_blocks
                .get_mut(&descriptor.start_of_memory_range)
                .ok_or(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "Address {} in Memory64ListStream but not in MemoryInfoListStream",
                        descriptor.start_of_memory_range
                    ),
                ))?;

            // Read the slice of bytes and associate it to the MemBlock instance.
            entry.data = Self::slice_from_location_descriptor(cursor, LocationDescriptor32 {
                rva: data_offset.try_into().unwrap(),
                data_size: descriptor.data_size.try_into().unwrap(),
            })?;

            // Bump the offset by the size of this region to find where the next
            // data slice is at.
            data_offset = data_offset.checked_add(descriptor.data_size).unwrap();
        }

        // We're done!
        Ok(())
    }

    /// Parse the tread list and extract their contexts.
    fn parse_thread_list(cursor: &mut Cursor, arch: Arch) -> io::Result<Threads> {
        // Create the map of threads.
        let mut threads = Threads::new();

        // Read the thread list.
        let thread_list = read_struct::<ThreadList>(cursor)?;

        // Iterate through every entries.
        for _ in 0..thread_list.number_of_threads {
            // Read the entry.
            let thread = read_struct::<ThreadEntry>(cursor)?;

            // Save the current position.
            let pos = cursor.stream_position()?;

            // Grab the slice of its context.
            let thread_context_slice =
                Self::slice_from_location_descriptor(cursor, thread.thread_context)?;

            // Let's make sense of this slice based on what architectcure it is.
            let thread_context = match arch {
                // Read a ThreadContextX86 context if the slice is big enough.
                Arch::X86 => {
                    if thread_context_slice.len() < mem::size_of::<ThreadContextX86>() {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!(
                                "The X86 thread context for TID {} has an unexpected size",
                                thread.thread_id
                            ),
                        ));
                    }

                    // Build a reference to a ThreadContextX86 at this address.
                    let ptr = thread_context_slice.as_ptr() as *const _;
                    ThreadContext::X86(unsafe { std::ptr::read_unaligned(ptr) })
                }
                // Read a ThreadContextX86 context if the slice is big enough.
                Arch::X64 => {
                    if thread_context_slice.len() < mem::size_of::<ThreadContextX64>() {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!(
                                "The X64 thread context for TID {} has an unexpected size",
                                thread.thread_id
                            ),
                        ));
                    }

                    // Build a reference to a ThreadContextX64 at this address.
                    let ptr = thread_context_slice.as_ptr() as *const _;
                    ThreadContext::X64(unsafe { std::ptr::read_unaligned(ptr) })
                }
            };

            // The key in the map is the thread id.
            let key = thread.thread_id;

            // Create a Thread from its context and the descriptor.
            let thread = Thread::new(thread, thread_context);

            // If we've already encountered a thread with this id, then let's
            // bail.
            let previous_val = threads.insert(key, thread);
            if previous_val.is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Thread {} already in the map", key),
                ));
            }

            // Restore the position to get ready to parse the next entry.
            cursor.seek(io::SeekFrom::Start(pos))?;
        }

        Ok(threads)
    }

    /// Parse the module list.
    fn parse_module_list(cursor: &mut Cursor) -> io::Result<Modules<'a>> {
        // Build the map of modules.
        let mut modules = Modules::new();

        // Read the module list.
        let module_list = read_struct::<ModuleList>(cursor)?;

        // Iterate through every entries.
        for _ in 0..module_list.number_of_modules {
            // Read the module entry.
            let module = read_struct::<ModuleEntry>(cursor)?;

            // Save the position.
            let pos = cursor.stream_position()?;

            // Grab the CV / misc record slices.
            let cv_record = Self::slice_from_location_descriptor(cursor, module.cv_record)?;
            let misc_record = Self::slice_from_location_descriptor(cursor, module.misc_record)?;

            // Travel to where the module name is stored at.
            cursor.seek(io::SeekFrom::Start(module.module_name_rva.into()))?;

            // Read its length.
            let module_name_length = read_struct::<u32>(cursor)?.try_into().unwrap();

            // Allocate a backing buffer.
            let mut module_name = vec![0; module_name_length];

            // Read the module name off the slice into the buffer.
            cursor.read_exact(module_name.as_mut_slice())?;

            // Convert the module name into a Rust string.
            let module_name = utf16_string_from_slice(&module_name).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Module name is incorrect utf8: {e}"),
                )
            })?;

            // Create a module from its descriptor / name / records.
            let module = Module::new(module, module_name, cv_record, misc_record);

            // If there's already a module at this address, something is wrong
            // so we bail.
            let previous_val = modules.insert(module.range.start, module);
            if let Some(previous_val) = previous_val {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Module {} already in the map", previous_val.path.display()),
                ));
            }

            // Restore the saved cursor.
            cursor.seek(io::SeekFrom::Start(pos))?;
        }

        // We're done!
        Ok(modules)
    }

    pub fn with_file(_mapped_file: MappedFile<'a>) -> io::Result<UserDumpParser<'a>> {
        // Grab a cursor to start parsing the bits.
        let mut cursor = _mapped_file.cursor();

        // Read the header.
        let hdr = read_struct::<Header>(&mut cursor)?;

        // If we don't see the expected signature, bail.
        if hdr.signature != EXPECTED_DUMP_SIGNATURE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Header signature {:x} is unexpected", hdr.signature),
            ));
        }

        // Check if the flags make sense.
        if (hdr.flags & VALID_DUMP_FLAGS) != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Header signature {:x} is unexpected", hdr.signature),
            ));
        }

        // Move to the stream directory.
        cursor.seek(io::SeekFrom::Start(hdr.stream_directory_rva.into()))?;

        // Create a map to store where directories are stored at.
        let mut directory_locations = collections::HashMap::new();

        // Iterate through every entries.
        for _ in 0..hdr.number_of_streams {
            // Read the directory..
            let directory = read_struct::<Directory>(&mut cursor)?;

            // ..if we hit the `STREAM_TYPE_UNUSED`, we'll stop there.
            if directory.stream_type == STREAM_TYPE_UNUSED {
                break;
            }

            // Keep track of this directory.
            directory_locations.insert(directory.stream_type, directory.location);
        }

        // Parsing directories in a certain orders make things easier, and below
        // is the order we want.
        let required = true;
        let not_required = false;
        let directory_parsing_order = [
            // We need the architecture to decode threads.
            (STREAM_TYPE_SYSTEM_INFO, required),
            (STREAM_TYPE_EXCEPTION, not_required),
            // We parse this stream to build MemBlock w/o any data.
            (STREAM_TYPE_MEMORY_INFO_LIST, required),
            // We associate the data when parsing that stream.
            (STREAM_TYPE_MEMORY64_LIST, required),
            (STREAM_TYPE_THREAD_LIST, not_required),
            (STREAM_TYPE_MODULE_LIST, not_required),
        ];

        // Declare a bunch of state.
        let mut arch = None;
        let mut foreground_tid = None;
        let mut mem_blocks = MemBlocks::new();
        let mut modules = Modules::new();
        let mut threads = Threads::new();

        // Iterate through the directories in order.
        for (directory_type, required) in directory_parsing_order {
            // Check if we've encountered this stream directory
            let directory_location = directory_locations.get(&directory_type);

            // If we haven't, and that this directory is required, we bail.
            // Otherwise we just go to the next.
            let Some(directory_location) = directory_location else {
                if required {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("The directory {directory_type} is required but not present"),
                    ));
                }

                continue;
            };

            // Move to where the stream is at.
            cursor.seek(io::SeekFrom::Start(directory_location.rva.into()))?;

            // Parse the streams we support.
            match directory_type {
                STREAM_TYPE_SYSTEM_INFO => arch = Some(Self::parse_system_info(&mut cursor)?),
                STREAM_TYPE_EXCEPTION => foreground_tid = Some(Self::parse_exception(&mut cursor)?),
                STREAM_TYPE_MEMORY_INFO_LIST => {
                    mem_blocks = Self::parse_mem_info_list(&mut cursor)?
                }
                STREAM_TYPE_MEMORY64_LIST => Self::parse_mem64_list(&mut cursor, &mut mem_blocks)?,
                STREAM_TYPE_THREAD_LIST => {
                    threads = Self::parse_thread_list(&mut cursor, arch.unwrap())?
                }
                STREAM_TYPE_MODULE_LIST => modules = Self::parse_module_list(&mut cursor)?,
                _ => unreachable!("Only parsing stream types we know about"),
            };
        }

        // The system info stream is required to be parsed so we know we have a
        // value in arch.
        let arch = arch.unwrap();

        // Phew, we have everything needed to build an instance!
        Ok(UserDumpParser {
            _mapped_file,
            arch,
            foreground_tid,
            mem_blocks,
            modules,
            threads,
        })
    }
}

/// Peek for a `T` from the cursor.
fn peek_struct<T>(cursor: &mut Cursor) -> io::Result<T> {
    let mut s = mem::MaybeUninit::uninit();
    let size_of_s = mem::size_of_val(&s);
    let slice_over_s = unsafe { slice::from_raw_parts_mut(s.as_mut_ptr() as *mut u8, size_of_s) };

    let pos = cursor.position();
    cursor.read_exact(slice_over_s)?;
    cursor.seek(io::SeekFrom::Start(pos))?;

    Ok(unsafe { s.assume_init() })
}

/// Read a `T` from the cursor.
fn read_struct<T>(cursor: &mut Cursor) -> io::Result<T> {
    let s = peek_struct(cursor)?;
    let size_of_s = mem::size_of_val(&s);

    cursor.seek(io::SeekFrom::Current(size_of_s.try_into().unwrap()))?;

    Ok(s)
}

/// Convert a slice of byte into an UTF16 Rust string.
fn utf16_string_from_slice(slice: &[u8]) -> io::Result<String> {
    // Every code point is 2 bytes, so we expect the length to be a multiple of
    // 2.
    if (slice.len() % 2) != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Slice length needs to be % 2",
        ));
    }

    // Iterate over chunks of 2 bytes to yield u16's.
    let iter = slice.chunks(2).map(|c| u16::from_le_bytes([c[0], c[1]]));

    // Decode the u16's into a String. If one of the u16 can't be decoded into a
    // valid code point, then it fails. Otherwise they all get collected into a
    // String.
    char::decode_utf16(iter)
        .collect::<Result<_, _>>()
        .or(Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Module name is not UTF16",
        )))
}

#[cfg(test)]
mod tests {
    use core::fmt::Debug;

    use crate::UserDumpParser;

    #[test]
    fn assert_traits() {
        fn assert_traits_<T: Send + Sync + Debug>() {}
        assert_traits_::<UserDumpParser>();
    }
}
