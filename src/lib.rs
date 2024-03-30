// Axel '0vercl0k' Souchet - July 29 2023
#![doc = include_str!("../README.md")]
mod udmp_parser;
pub use udmp_parser::{
    PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY, PAGE_GUARD,
    PAGE_NOACCESS, PAGE_NOCACHE, PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOMBINE, PAGE_WRITECOPY,
    *,
};

mod map;

mod structs;
pub use structs::{FloatingSaveArea32, ThreadContextX64, ThreadContextX86};
