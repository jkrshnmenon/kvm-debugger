use std::fs::File;
use std::io::{BufRead, BufReader};
use std::process;

// Function to find the address of the BSS section for a given PID.
pub fn bss_addr(child: i32) -> Option<usize> {
    let fname = format!("/proc/{}/maps", child);
    let file = File::open(&fname).unwrap_or_else(|err| {
        eprintln!("Failed to open file: {}", err);
        process::exit(1);
    });

    let reader = BufReader::new(file);

    for line in reader.lines() {
        let line = line.unwrap();

        let mut parts = line.split_whitespace();
        let address = parts.next().unwrap_or("");
        let perms = parts.next().unwrap_or("");

        if perms == "rw-p" {
            let addr_range = address.split('-').next().unwrap_or("");
            if let Ok(addr) = usize::from_str_radix(addr_range, 16) {
                return Some(addr + 0x300);
            }
        }
    }

    None
}