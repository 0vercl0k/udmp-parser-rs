# udmp-parser: A Rust crate for parsing Windows user minidumps
[![Crates.io](https://img.shields.io/crates/v/udmp-parser.svg)](https://crates.io/crates/udmp-parser)
[![Documentation](https://docs.rs/udmp-parser/badge.svg)](https://docs.rs/udmp-parser/)
![Build status](https://github.com/0vercl0k/udmp-parser-rs/workflows/Builds/badge.svg)

This is a cross-platform crate that parses Windows user [minidump](https://docs.microsoft.com/en-us/windows/win32/debug/minidump-files) dumps that you can generate via WinDbg or via right-click **Create memory dump file** in the Windows task manager.

![parser](https://github.com/0vercl0k/udmp-parser-rs/raw/main/pics/parser.gif)

The library supports Intel 32-bit / 64-bit dumps and provides read access to things like:

- The thread list and their context records,
- The virtual memory,
- The loaded modules.

Compiled binaries are available in the [releases](https://github.com/0vercl0k/udmp-parser-rs/releases) section.

## Parser
The [parser](src/examples/parser.rs) application is a small utility to show-case how to use the library and demonstrate its features. You can use it to dump memory, list the loaded modules, dump thread contexts, dump a memory map various, etc.

![parser-usage](https://github.com/0vercl0k/udmp-parser-rs/raw/main/pics/parser-usage.gif)

Here are the options supported:
```text
parser.exe [-a] [-mods] [-mem] [-t [<TID>|main]] [-dump <addr>] <dump path>

Examples:
  Show all:
    parser.exe -a user.dmp
  Show loaded modules:
    parser.exe -mods user.dmp
  Show memory map:
    parser.exe -mem user.dmp
  Show all threads:
    parser.exe -t user.dmp
  Show thread w/ specific TID:
    parser.exe -t 1337 user.dmp
  Show foreground thread:
    parser.exe -t main user.dmp
  Show a memory page at a specific address:
    parser.exe -dump 0x7ff00 user.dmp
```

# Authors

* Axel '[@0vercl0k](https://twitter.com/0vercl0k)' Souchet

# Contributors

[ ![contributors-img](https://contrib.rocks/image?repo=0vercl0k/udmp-parser-rs) ](https://github.com/0vercl0k/udmp-parser-rs/graphs/contributors)
