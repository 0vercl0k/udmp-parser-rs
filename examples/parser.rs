// Axel '0vercl0k' Souchet - July 20 2023
use std::env;
use std::result::Result;
use udmp_parser_rs::UserDumpParser;

/// Command line argument.
struct Cli {
    dump_path: String,
    show_all: bool,
    show_mods: bool,
    show_memmap: bool,
    show_threads: bool,
    show_foreground_thread: bool,
    thread: Option<u32>,
    address: Option<u64>,
}

/// Convert an hexadecimal string to a `u64`.
fn string_to_hex(s: &str) -> Result<u64, String> {
    u64::from_str_radix(s.trim_start_matches("0x"), 16).map_err(|e| e.to_string())
}

/// Parse the command line arguments.
fn parse_args() -> Result<Cli, String> {
    let mut dump_path = None;
    let mut show_all = false;
    let mut show_mods = false;
    let mut show_memmap = false;
    let mut show_threads = false;
    let mut show_foreground_thread = false;
    let mut thread = None;
    let mut address = None;

    let args = env::args().collect::<Vec<_>>();
    let mut idx = 1;
    while idx < args.len() {
        let cur = &args[idx];
        let is_final = (idx + 1) >= args.len();
        if is_final {
            dump_path = Some(cur.clone());
            break;
        }

        let next = if is_final { None } else { Some(&args[idx + 1]) };
        match cur.as_str() {
            "-a" => {
                show_all = true;
            }
            "-mods" => {
                show_mods = true;
            }
            "-mem" => {
                show_memmap = true;
            }
            "-t" => {
                show_threads = true;
                let Some(next) = next else {
                    break;
                };

                if next == "main" {
                    show_foreground_thread = true;
                } else {
                    thread = next.parse().map(Some).unwrap_or(None);
                }

                if show_foreground_thread || thread.is_some() {
                    idx += 1;
                }
            }
            "-dump" => {
                let Some(next) = next else {
                    return Err("-dump needs to be followed by an address".into());
                };

                address = Some(string_to_hex(next)?);
                idx += 1;
            }
            rest => {
                return Err(format!("{} is not a valid option", rest));
            }
        };

        idx += 1;
    }

    let Some(dump_path) = dump_path else {
        return Err("You didn't specify a dump path".into());
    };

    Ok(Cli {
        dump_path,
        show_all,
        show_mods,
        show_memmap,
        show_threads,
        show_foreground_thread,
        thread,
        address,
    })
}

/// Print a hexdump of data that started at `address`.
fn hexdump(address: u64, mut data_iter: impl ExactSizeIterator<Item = u8>) {
    let len = data_iter.len();
    for i in (0..len).step_by(16) {
        print!("{:016x}: ", address + (i as u64 * 16));
        let mut row = [None; 16];
        for item in row.iter_mut() {
            if let Some(c) = data_iter.next() {
                *item = Some(c);
                print!("{:02x}", c);
            } else {
                print!(" ");
            }
        }
        print!(" |");
        for item in &row {
            if let Some(c) = item {
                let c = char::from(*c);
                print!("{}", if c.is_ascii_graphic() { c } else { '.' });
            } else {
                print!(" ");
            }
        }
        println!("|");
    }
}

/// Display help.
fn help() {
    println!("parser.exe [-a] [-mods] [-mem] [-t [<TID|main>]] [-dump <addr>] <dump path>");
    println!();
    println!("Examples:");
    println!("  Show all:");
    println!("    parser.exe -a user.dmp");
    println!("  Show loaded modules:");
    println!("    parser.exe -mods user.dmp");
    println!("  Show memory map:");
    println!("    parser.exe -mem user.dmp");
    println!("  Show all threads:");
    println!("    parser.exe -t user.dmp");
    println!("  Show thread w/ specific TID:");
    println!("    parser.exe -t 1337 user.dmp");
    println!("  Show foreground thread:");
    println!("    parser.exe -t main user.dmp");
    println!("  Dump a memory page at a specific address:");
    println!("    parser.exe -dump 0x7ff00 user.dmp");
}

fn main() -> Result<(), String> {
    // If we don't have any arguments, display the help.
    if env::args().len() == 1 {
        help();
        return Ok(());
    }

    // Parse the command line arguments.
    let cli = parse_args()?;

    // Let's try to parse the dump file specified by the user.
    let dump = UserDumpParser::new(cli.dump_path).map_err(|e| e.to_string())?;

    // Do we want to display modules?
    if cli.show_mods || cli.show_all {
        println!("Loaded modules:");

        // Iterate through the module and display their base address and path.
        for (base, module) in dump.modules() {
            println!("{:016x}: {}", base, module.path.display());
        }
    }

    // Do we want the memory map?
    if cli.show_memmap || cli.show_all {
        println!("Memory map:");

        // Iterate over the memory blocks.
        for block in dump.mem_blocks().values() {
            // Grab the string representation about its state, type, protection.
            let state = block.state_as_str();
            let type_ = block.type_as_str();
            let protect = block.protect_as_str();

            // Print it all out.
            print!(
                "{:016x} {:016x} {:016x} {:11} {:11} {:22}",
                block.range.start,
                block.range.end,
                block.len(),
                type_,
                state,
                protect
            );

            // Do we have a module that exists at this address?
            let module = dump.get_module(block.range.start);

            // If we do, then display its name / path.
            if let Some(module) = module {
                print!(
                    " [{}; \"{}\"]",
                    module.file_name().unwrap(),
                    module.path.display()
                );
            }

            // Do we have data with this block? If so display the first few
            // bytes.
            if block.data.len() >= 4 {
                print!(
                    " {:02x} {:02x} {:02x} {:02x}...",
                    block.data[0], block.data[1], block.data[2], block.data[3]
                );
            }

            println!();
        }
    }

    // Do we want threads?
    if cli.show_threads || cli.show_all {
        println!("Threads:");

        // Grab the foreground tid.
        let foreground_tid = dump.foreground_tid;

        // Iterate through all the threads.
        for (tid, thread) in dump.threads() {
            // If the user specified a pid..
            if let Some(wanted_tid) = cli.thread {
                // .. skip an threads that don't match what the user wants..
                if *tid != wanted_tid {
                    continue;
                }

                // Otherwise we keep going.
            }

            // If the user only wants the main thread, and we haven't found it,
            // skip this thread until we find it.
            if cli.show_foreground_thread
                && *tid != foreground_tid.expect("no foreground thread id in dump")
            {
                continue;
            }

            // Print out the thread info.
            println!("TID {}, TEB {:016x}", tid, thread.teb);
            println!("Context:");
            println!("{}", thread.context());
        }
    }

    // Do we want to dump memory?
    if let Some(address) = cli.address {
        println!("Memory:");

        // Try to find a block that contains `address`.
        let block = dump.get_mem_block(address);

        // If we have one..
        if let Some(block) = block {
            // .. and it has data, dump it..
            if let Some(data) = block.data_from(address) {
                println!("{:016x} -> {:016x}", address, block.end_addr());
                hexdump(address, data.iter().take(0x1_00).copied());
            }
            // .. otherwise, inform the user..
            else {
                println!(
                    "The memory at {:016x} (from block {:016x} -> {:016x}) has no backing data",
                    address, block.range.start, block.range.end
                );
            }
        }
        // .. otherwise, inform he user.
        else {
            println!("No memory block were found for {:016x}", address);
        }
    }

    // All right, enough for today.
    Ok(())
}
