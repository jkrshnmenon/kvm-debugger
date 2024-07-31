use libc;
use std::{ptr, process};

const PRE_SYSCALL: u32 = 0;
const POST_SYSCALL: u32 = 1;

static mut CUR_STATE: u32 = POST_SYSCALL;

pub fn default_regs() -> libc::user_regs_struct {
    libc::user_regs_struct {
        r15: 0,
        r14: 0,
        r13: 0,
        r12: 0,
        rbp: 0,
        rbx: 0,
        r11: 0,
        r10: 0,
        r9: 0,
        r8: 0,
        rax: 0,
        rcx: 0,
        rdx: 0,
        rsi: 0,
        rdi: 0,
        orig_rax: 0,
        rip: 0,
        cs: 0,
        eflags: 0,
        rsp: 0,
        ss: 0,
        fs_base: 0,
        gs_base: 0,
        ds: 0,
        es: 0,
        fs: 0,
        gs: 0,
    }
}

pub fn enable_tracing() {
    unsafe {
        if libc::ptrace(
            libc::PTRACE_TRACEME, 
            0, 
            ptr::null_mut::<libc::c_void>(), 
            ptr::null_mut::<libc::c_void>()) < 0 {
                eprintln!("ptrace(PTRACE_TRACEME) failed!");
                process::exit(1);
            }
    }
    println!("Enabled PTRACE_TRACEME");
}


pub fn set_tracesysgood(pid: i32) {
    unsafe {
        if libc::ptrace(
            libc::PTRACE_SETOPTIONS,
            pid,
            0,
            libc::PTRACE_O_TRACESYSGOOD) < 0 {
                eprintln!("ptrace(PTRACE_SETOPTIONS) failed!");
                process::exit(1);
            }
    }
    println!("Set PTRACE_SETOPTIONS: PTRACE_O_TRACESYSGOOD");
}


pub fn trace_one_syscall(pid: i32) -> libc::user_regs_struct {
    unsafe {
        if CUR_STATE != POST_SYSCALL {
            eprintln!("Unexpected state!");
            process::exit(1);
        }
    }
    unsafe {
        if libc::ptrace(
            libc::PTRACE_SYSCALL,
            pid,
            ptr::null_mut::<libc::c_void>(),
            ptr::null_mut::<libc::c_void>()) < 0 {
                eprintln!("ptrace(PTRACE_SYSCALL) failed!");
                process::exit(1);
            }
    }

    let mut status: i32 = 0;
    unsafe {
        let _ = libc::waitpid(pid, &mut status, 0);
    }

    if status != 0 {
        eprintln!("waitpid failed!");
        process::exit(1);
    }

    unsafe {
        CUR_STATE = PRE_SYSCALL;
    }

    let mut regs: libc::user_regs_struct = default_regs();
    unsafe {
        libc::ptrace(
            libc::PTRACE_GETREGS,
            pid,
            ptr::null_mut::<libc::c_void>(),
            &mut regs as *mut libc::user_regs_struct);
    }
    regs
}