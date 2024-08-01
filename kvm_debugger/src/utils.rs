use std::fs::File;
use std::io::{BufRead, BufReader};
use std::process;
use libc;

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

pub fn syscall_name(sys_no: i64) -> String{
    let name = match sys_no {
        libc::SYS_read => "read",
        libc::SYS_write => "write",
        libc::SYS_open => "open",
        libc::SYS_close => "close",
        libc::SYS_stat => "stat",
        libc::SYS_fstat => "fstat",
        libc::SYS_lstat => "lstat",
        libc::SYS_poll => "poll",
        libc::SYS_lseek => "lseek",
        libc::SYS_mmap => "mmap",
        libc::SYS_mprotect => "mprotect",
        libc::SYS_munmap => "munmap",
        libc::SYS_brk => "brk",
        libc::SYS_rt_sigaction => "rt_sigaction",
        libc::SYS_rt_sigprocmask => "rt_sigprocmask",
        libc::SYS_rt_sigreturn => "rt_sigreturn",
        libc::SYS_ioctl => "ioctl",
        libc::SYS_pread64 => "pread64",
        libc::SYS_pwrite64 => "pwrite64",
        libc::SYS_readv => "readv",
        libc::SYS_writev => "writev",
        libc::SYS_access => "access",
        libc::SYS_pipe => "pipe",
        libc::SYS_select => "select",
        libc::SYS_sched_yield => "sched_yield",
        libc::SYS_mremap => "mremap",
        libc::SYS_msync => "msync",
        libc::SYS_mincore => "mincore",
        libc::SYS_madvise => "madvise",
        libc::SYS_shmget => "shmget",
        libc::SYS_shmat => "shmat",
        libc::SYS_shmctl => "shmctl",
        libc::SYS_dup => "dup",
        libc::SYS_dup2 => "dup2",
        libc::SYS_pause => "pause",
        libc::SYS_nanosleep => "nanosleep",
        libc::SYS_getitimer => "getitimer",
        libc::SYS_alarm => "alarm",
        libc::SYS_setitimer => "setitimer",
        libc::SYS_getpid => "getpid",
        libc::SYS_sendfile => "sendfile",
        libc::SYS_socket => "socket",
        libc::SYS_connect => "connect",
        libc::SYS_accept => "accept",
        libc::SYS_sendto => "sendto",
        libc::SYS_recvfrom => "recvfrom",
        libc::SYS_openat => "openat",
        libc::SYS_newfstatat => "newfstatat",
        libc::SYS_arch_prctl => "arch_prctl",
        libc::SYS_set_tid_address => "set_tid_address",
        libc::SYS_prlimit64 => "prlimit64",
        _ => "unknown",
    };
    name.to_string()
}