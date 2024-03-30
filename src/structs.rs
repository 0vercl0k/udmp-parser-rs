// Axel '0vercl0k' Souchet - July 29 2023
//! This is where all the raw Windows user-dump structures are stored in.
use std::fmt;

pub const STREAM_TYPE_UNUSED: u32 = 0;
pub const STREAM_TYPE_THREAD_LIST: u32 = 3;
pub const STREAM_TYPE_MODULE_LIST: u32 = 4;
pub const STREAM_TYPE_EXCEPTION: u32 = 6;
pub const STREAM_TYPE_SYSTEM_INFO: u32 = 7;
pub const STREAM_TYPE_MEMORY64_LIST: u32 = 9;
pub const STREAM_TYPE_MEMORY_INFO_LIST: u32 = 16;

pub const EXCEPTION_MAXIMUM_PARAMETERS: usize = 15;

pub const EXPECTED_DUMP_SIGNATURE: u32 = 0x504d_444d;

pub const VALID_DUMP_FLAGS: u32 = 0x001f_ffff;

pub const WOW64_MAXIMUM_SUPPORTED_EXTENSION: usize = 512;

pub const WOW64_SIZE_OF_80387_REGISTERS: usize = 80;

pub const ARCH_X86: u16 = 0;
pub const ARCH_X64: u16 = 9;

#[derive(Debug, Default)]
#[repr(C)]
pub struct Header {
    pub signature: u32,
    pub version: u16,
    pub implementation_version: u16,
    pub number_of_streams: u32,
    pub stream_directory_rva: u32,
    pub checksum: u32,
    pub reserved: u32,
    pub timedatestamp: u32,
    pub flags: u32,
}

#[derive(Debug, Default, Clone, Copy)]
#[repr(C)]
pub struct LocationDescriptor32 {
    pub data_size: u32,
    pub rva: u32,
}

#[derive(Debug, Default)]
#[repr(C)]
pub struct Directory {
    pub stream_type: u32,
    pub location: LocationDescriptor32,
}

#[derive(Debug, Default)]
#[repr(C)]
pub struct SystemInfoStream {
    pub processor_arch: u16,
    pub processor_level: u16,
    pub processor_revision: u16,
    pub number_of_processors: u8,
    pub product_type: u8,
    pub major_version: u32,
    pub minor_version: u32,
    pub build_number: u32,
    pub platform_id: u32,
    pub csd_version_rva: u32,
    pub suite_mask: u16,
    pub reserverd2: u16,
}

#[derive(Default, Debug)]
#[repr(C)]
pub struct ExceptionRecord {
    pub exception_code: u32,
    pub exception_flags: u32,
    pub exception_record: u64,
    pub exception_address: u64,
    pub number_parameters: u32,
    pub unused_alignment: u32,
    pub exception_information: [u64; EXCEPTION_MAXIMUM_PARAMETERS],
}

#[derive(Default, Debug)]
#[repr(C)]
pub struct ExceptionStream {
    pub thread_id: u32,
    pub alignment: u32,
    pub exception_record: ExceptionRecord,
    pub thread_context: LocationDescriptor32,
}

#[derive(Default, Debug)]
#[repr(C)]
pub struct MemoryInfo {
    pub base_address: u64,
    pub allocation_base: u64,
    pub allocation_protect: u32,
    pub alignment1: u32,
    pub region_size: u64,
    pub state: u32,
    pub protect: u32,
    pub type_: u32,
    pub alignment2: u32,
}

#[derive(Default, Debug)]
#[repr(C)]
pub struct MemoryInfoListStream {
    pub size_of_header: u32,
    pub size_of_entry: u32,
    pub number_of_entries: u64,
}

#[derive(Default, Debug)]
#[repr(C)]
pub struct Memory64ListStream {
    pub number_of_memory_ranges: u64,
    pub base_rva: u64,
}

#[derive(Default, Debug)]
#[repr(C)]
pub struct MemoryDescriptor64 {
    pub start_of_memory_range: u64,
    pub data_size: u64,
}

#[derive(Default, Debug)]
#[repr(C)]
pub struct ThreadList {
    pub number_of_threads: u32,
}

#[derive(Default, Debug)]
#[repr(C)]
pub struct MemoryDescriptor {
    pub start_of_memory_range: u64,
    pub memory: LocationDescriptor32,
}

#[derive(Default, Debug)]
#[repr(C)]
pub struct ThreadEntry {
    pub thread_id: u32,
    pub suspend_count: u32,
    pub priority_class: u32,
    pub priority: u32,
    pub teb: u64,
    pub stack: MemoryDescriptor,
    pub thread_context: LocationDescriptor32,
}

#[derive(Default, Debug)]
#[repr(C)]
pub struct ModuleList {
    pub number_of_modules: u32,
}

#[derive(Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct FixedFileInfo {
    pub signature: u32,
    pub struc_version: u32,
    pub file_version_ms: u32,
    pub file_version_ls: u32,
    pub product_version_ms: u32,
    pub product_version_ls: u32,
    pub file_flags_mask: u32,
    pub file_flags: u32,
    pub file_os: u32,
    pub file_type: u32,
    pub file_subtype: u32,
    pub file_date_ms: u32,
    pub file_date_ls: u32,
}

#[derive(Default, Debug)]
#[repr(packed(1))]
pub struct ModuleEntry {
    pub base_of_image: u64,
    pub size_of_image: u32,
    pub checksum: u32,
    pub time_date_stamp: u32,
    pub module_name_rva: u32,
    pub version_info: FixedFileInfo,
    pub cv_record: LocationDescriptor32,
    pub misc_record: LocationDescriptor32,
    _reserved0: u64,
    _reserved1: u64,
}

#[derive(Debug, PartialEq)]
#[repr(C)]
pub struct FloatingSaveArea32 {
    pub control_word: u32,
    pub status_word: u32,
    pub tag_word: u32,
    pub error_offset: u32,
    pub error_selector: u32,
    pub data_offset: u32,
    pub data_selector: u32,
    pub register_area: [u8; WOW64_SIZE_OF_80387_REGISTERS],
    pub cr0_npx_state: u32,
}

impl Default for FloatingSaveArea32 {
    fn default() -> Self {
        // SAFETY: All zero values are fine for every types used by
        // [`FloatingSaveArea32`].
        unsafe { std::mem::zeroed() }
    }
}

/// The context of an Intel X86 thread.
#[derive(Debug)]
#[repr(C)]
pub struct ThreadContextX86 {
    pub context_flags: u32,
    pub dr0: u32,
    pub dr1: u32,
    pub dr2: u32,
    pub dr3: u32,
    pub dr6: u32,
    pub dr7: u32,
    pub float_save: FloatingSaveArea32,
    pub seg_gs: u32,
    pub seg_fs: u32,
    pub seg_es: u32,
    pub seg_ds: u32,
    pub edi: u32,
    pub esi: u32,
    pub ebx: u32,
    pub edx: u32,
    pub ecx: u32,
    pub eax: u32,
    pub ebp: u32,
    pub eip: u32,
    pub seg_cs: u32,
    pub eflags: u32,
    pub esp: u32,
    pub seg_ss: u32,
    pub extended_registers: [u8; WOW64_MAXIMUM_SUPPORTED_EXTENSION],
}

impl fmt::Display for ThreadContextX86 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "eax={:08x} ebx={:08x} ecx={:08x} edx={:08x} esi={:08x} edi={:08x}",
            self.eax, self.ebx, self.ecx, self.edx, self.esi, self.edi
        )?;
        writeln!(
            f,
            "eip={:08x} esp={:08x} ebp={:08x}",
            self.eip, self.esp, self.ebp
        )?;
        write!(
            f,
            "cs={:04x}  ss={:04x}  ds={:04x}  es={:04x}  fs={:04x} gs={:04x}              efl={:08x}",
            self.seg_cs,
            self.seg_ss,
            self.seg_ds,
            self.seg_es,
            self.seg_fs,
            self.seg_gs,
            self.eflags
        )
    }
}

impl Default for ThreadContextX86 {
    fn default() -> Self {
        // SAFETY: All zero values are fine for every types used by
        // [`ThreadContextX86`].
        unsafe { std::mem::zeroed() }
    }
}

/// The context of an Intel X64 thread.
#[derive(Debug)]
#[repr(C)]
pub struct ThreadContextX64 {
    pub p1_home: u64,
    pub p2_home: u64,
    pub p3_home: u64,
    pub p4_home: u64,
    pub p5_home: u64,
    pub p6_home: u64,
    pub context_flags: u32,
    pub mxcsr: u32,
    pub seg_cs: u16,
    pub seg_ds: u16,
    pub seg_es: u16,
    pub seg_fs: u16,
    pub seg_gs: u16,
    pub seg_ss: u16,
    pub eflags: u32,
    pub dr0: u64,
    pub dr1: u64,
    pub dr2: u64,
    pub dr3: u64,
    pub dr6: u64,
    pub dr7: u64,
    pub rax: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rbx: u64,
    pub rsp: u64,
    pub rbp: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
    pub control_word: u16,
    pub status_word: u16,
    pub tag_word: u8,
    pub reserved1: u8,
    pub error_opcode: u16,
    pub error_offset: u32,
    pub error_selector: u16,
    pub reserved2: u16,
    pub data_offset: u32,
    pub data_selector: u16,
    pub reserved3: u16,
    pub mxcsr2: u32,
    pub mxcsr_mask: u32,
    pub float_registers: [u128; 8],
    pub xmm0: u128,
    pub xmm1: u128,
    pub xmm2: u128,
    pub xmm3: u128,
    pub xmm4: u128,
    pub xmm5: u128,
    pub xmm6: u128,
    pub xmm7: u128,
    pub xmm8: u128,
    pub xmm9: u128,
    pub xmm10: u128,
    pub xmm11: u128,
    pub xmm12: u128,
    pub xmm13: u128,
    pub xmm14: u128,
    pub xmm15: u128,
    pub padding: [u8; 0x60],
    pub vector_registers: [u128; 26],
    pub vector_control: u64,
    pub debug_control: u64,
    pub last_branch_to_rip: u64,
    pub last_branch_from_rip: u64,
    pub last_exception_to_rip: u64,
    pub last_exception_from_rip: u64,
}

impl fmt::Display for ThreadContextX64 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "rax={:016x} rbx={:016x} rcx={:016x}",
            self.rax, self.rbx, self.rcx
        )?;
        writeln!(
            f,
            "rdx={:016x} rsi={:016x} rdi={:016x}",
            self.rdx, self.rsi, self.rdi
        )?;
        writeln!(
            f,
            "rip={:016x} rsp={:016x} rbp={:016x}",
            self.rip, self.rsp, self.rbp
        )?;
        writeln!(
            f,
            " r8={:016x}  r9={:016x} r10={:016x}",
            self.r8, self.r9, self.r10
        )?;
        writeln!(
            f,
            "r11={:016x} r12={:016x} r13={:016x}",
            self.r11, self.r12, self.r13
        )?;
        writeln!(f, "r14={:016x} r15={:016x}", self.r14, self.r15)?;
        writeln!(f, "cs={:04x}  ss={:04x}  ds={:04x}  es={:04x}  fs={:04x} gs={:04x}              efl={:08x}",
        self.seg_cs, self.seg_ss, self.seg_ds, self.seg_es, self.seg_fs, self.seg_gs,
        self.eflags)?;
        writeln!(
            f,
            "fpcw={:04x}    fpsw={:04x}    fptw={:04x}",
            self.control_word, self.status_word, self.tag_word
        )?;
        writeln!(
            f,
            "  st0={:032x}       st1={:032x}",
            self.float_registers[0], self.float_registers[1]
        )?;
        writeln!(
            f,
            "  st2={:032x}       st3={:032x}",
            self.float_registers[2], self.float_registers[3]
        )?;
        writeln!(
            f,
            "  st4={:032x}       st5={:032x}",
            self.float_registers[4], self.float_registers[5]
        )?;
        writeln!(
            f,
            "  st6={:032x}       st7={:032x}",
            self.float_registers[6], self.float_registers[7]
        )?;
        writeln!(f, " xmm0={:032x}      xmm1={:032x}", self.xmm0, self.xmm1)?;
        writeln!(f, " xmm2={:032x}      xmm3={:032x}", self.xmm2, self.xmm3)?;
        writeln!(f, " xmm4={:032x}      xmm5={:032x}", self.xmm4, self.xmm5)?;
        writeln!(f, " xmm6={:032x}      xmm7={:032x}", self.xmm6, self.xmm7)?;
        writeln!(f, " xmm8={:032x}      xmm9={:032x}", self.xmm8, self.xmm9)?;
        writeln!(f, "xmm10={:032x}     xmm11={:032x}", self.xmm10, self.xmm11)?;
        writeln!(f, "xmm12={:032x}     xmm13={:032x}", self.xmm12, self.xmm13)?;
        write!(f, "xmm14={:032x}     xmm15={:032x}", self.xmm14, self.xmm15)
    }
}

impl Default for ThreadContextX64 {
    fn default() -> Self {
        // SAFETY: All zero values are fine for every types used by
        // [`ThreadContextX64`].
        unsafe { std::mem::zeroed() }
    }
}

#[cfg(test)]
mod tests {
    use std::mem;

    use super::*;

    /// Ensure that the sizes of key structures are right.
    #[test]
    fn sizeofs() {
        assert_eq!(mem::size_of::<FloatingSaveArea32>(), 0x70);
        assert_eq!(mem::size_of::<ThreadContextX86>(), 0x2cc);
        // assert_eq!(mem::offset_of!(ThreadContextX64, Xmm0), 0x1a0);
        // assert_eq!(mem::offset_of!(ThreadContextX64, VectorRegister), 0x300);
        assert_eq!(mem::size_of::<ThreadContextX64>(), 0x4d0);
        assert_eq!(mem::size_of::<Header>(), 0x20);
        assert_eq!(mem::size_of::<LocationDescriptor32>(), 0x8);
        assert_eq!(mem::size_of::<Directory>(), 0xC);
        assert_eq!(mem::size_of::<Memory64ListStream>(), 0x10);
        assert_eq!(mem::size_of::<MemoryDescriptor64>(), 0x10);
        assert_eq!(mem::size_of::<FixedFileInfo>(), 0x34);
        assert_eq!(mem::size_of::<ModuleEntry>(), 0x6c);
        assert_eq!(mem::size_of::<MemoryInfoListStream>(), 0x10);
        assert_eq!(mem::size_of::<MemoryInfo>(), 0x30);
        assert_eq!(mem::size_of::<MemoryDescriptor>(), 0x10);
        assert_eq!(mem::size_of::<ThreadEntry>(), 0x30);
        assert_eq!(mem::size_of::<SystemInfoStream>(), 32);
        assert_eq!(mem::size_of::<ExceptionRecord>(), 0x98);
        assert_eq!(mem::size_of::<ExceptionStream>(), 0xa8);
    }
}
