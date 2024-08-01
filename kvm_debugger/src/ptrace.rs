#![allow(unused_assignments)]
use libc::{
    ptrace, 
    waitpid, 
    user_regs_struct, 
    c_void,
    WIFEXITED, 
    SYS_ioctl,
    PTRACE_SYSCALL, 
    PTRACE_TRACEME, 
    PTRACE_SETOPTIONS, 
    PTRACE_O_TRACESYSGOOD, 
    PTRACE_GETREGS, 
    PTRACE_SETREGS, 
    PTRACE_PEEKDATA, 
    PTRACE_POKEDATA};
use std::{process, ptr};
use log::{info, debug, error};
use errno::errno;

const PRE_SYSCALL: u32 = 0;
const POST_SYSCALL: u32 = 1;

static mut CUR_STATE: u32 = POST_SYSCALL;

pub fn default_regs() -> user_regs_struct {
    user_regs_struct {
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
        if ptrace(
            PTRACE_TRACEME, 
            0, 
            ptr::null_mut::<c_void>(), 
            ptr::null_mut::<c_void>()) < 0 {
                eprintln!("ptrace(PTRACE_TRACEME) failed!");
                process::exit(1);
            }
    }
    info!("Enabled PTRACE_TRACEME");
}


pub fn set_tracesysgood(pid: i32) {
    unsafe {
        ptrace(
            PTRACE_SETOPTIONS,
            pid,
            0,
            PTRACE_O_TRACESYSGOOD);
    }
    info!("Set PTRACE_SETOPTIONS: PTRACE_O_TRACESYSGOOD: {}", pid);
}


pub fn trace_one_syscall(pid: i32) -> user_regs_struct {
    info!("Tracing one syscall for : {}", pid);
    unsafe {
        if CUR_STATE != POST_SYSCALL {
            eprintln!("Unexpected state!");
            process::exit(1);
        }
    }
    debug!("Calling ptrace(PTRACE_SYSCALL)");
    unsafe {
        if ptrace(
            PTRACE_SYSCALL,
            pid,
            ptr::null_mut::<c_void>(),
            ptr::null_mut::<c_void>()) < 0 {
                let err = errno();
                error!(
                "ptrace(PTRACE_SYSCALL) failed: {} (errno: {})",
                err,
                err.0
            );
            process::exit(1);
            }
    }

    debug!("Going to waitpid");
    let mut status: i32 = 0;
    unsafe {
        if waitpid(pid, &mut status, 0) == -1 {
            error!("waitpid failed");
        }
        if WIFEXITED(status) {
            error!("Child exited normally with status: {}", WIFEXITED(status));
            process::exit(1);
        }
    }

    unsafe {
        CUR_STATE = PRE_SYSCALL;
    }

    debug!("Getting registers");
    let mut regs: user_regs_struct = default_regs();
    unsafe {
        if ptrace(
            PTRACE_GETREGS,
            pid,
            ptr::null_mut::<c_void>(),
            &mut regs as *mut user_regs_struct) < 0 {
                error!("ptrace(PTRACE_GETREGS) failed!");
                process::exit(1);
            }
    }
    regs
}

pub fn finish_syscall(pid: i32) -> user_regs_struct {
    info!("Finishing syscall");
    unsafe {
        if CUR_STATE != PRE_SYSCALL {
            eprintln!("Unexpected state!");
            process::exit(1);
        }
    }
    debug!("Calling ptrace(PTRACE_SYSCALL)");
    unsafe {
        if ptrace(
            PTRACE_SYSCALL,
            pid,
            ptr::null_mut::<c_void>(),
            ptr::null_mut::<c_void>()) < 0 {
                error!("ptrace(PTRACE_SYSCALL) failed!");
                process::exit(1);
            }
    }

    debug!("Going to waitpid");
    let mut status: i32 = 0;
    unsafe {
        if waitpid(pid, &mut status, 0) == -1 {
            error!("waitpid failed");
        }
        if WIFEXITED(status) {
            error!("Child exited normally with status: {}", WIFEXITED(status));
            process::exit(1);
        }
    }

    unsafe {
        CUR_STATE = POST_SYSCALL;
    }

    debug!("Getting registers");
    let mut regs: user_regs_struct = default_regs();
    unsafe {
        if ptrace(
            PTRACE_GETREGS,
            pid,
            ptr::null_mut::<c_void>(),
            &mut regs as *mut user_regs_struct) < 0 {
                error!("ptrace(PTRACE_GETREGS) failed!");
                process::exit(1);
            }
    }
    regs
}


pub fn read_proc_memory(pid: i32, addr: u64, len: usize) -> Vec<u8> {
    debug!("Reading process memory: pid: {}, addr: {:#016x}, len: {}", pid, addr, len);
    let mut content = Vec::<u8>::with_capacity(len);
    for x in (0..len).step_by(8) {
        let mut data: u64 = 0;
        // PEEKDATA reads a long value from the address
        debug!("Reading from address: {:#016x}", addr + x as u64);
        unsafe {
            data = ptrace(
                PTRACE_PEEKDATA,
                pid,
                addr + x as u64,
                std::ptr::null_mut::<c_void>()) as u64;
        }
        debug!("Got data: {:#016x}", data);
        let min = std::cmp::min(8, len - x);
        for j in 0..min {
            content.push(((data >> (j * 8)) & 0xff) as u8);
        }
    }
    debug!("Got content: {:?}", content);
   content 
}


pub fn write_proc_memory(pid: i32, addr: u64, content: &[u8]) {
    for x in (0..content.len()).step_by(8) {
        let mut data: u64 = 0;
        for j in 0..std::cmp::min(8, content.len() - x) {
            data |= (content[x + j] as u64) << (j * 8);
        }
        // POKEDATA writes a long value to the address
        unsafe {
            ptrace(
                PTRACE_POKEDATA,
                pid,
                addr + x as u64,
                data as *mut u64 as *mut c_void);
        }
    }
}


pub fn set_regs(pid: i32, regs: &user_regs_struct) {
    debug!("Setting registers");
    unsafe {
        if ptrace(
            PTRACE_SETREGS,
            pid,
            ptr::null_mut::<c_void>(),
            regs as *const user_regs_struct as *mut user_regs_struct) < 0 {
                let err = errno();
                error!(
                    "ptrace(PTRACE_SETREGS) failed: {} (errno: {})",
                    err,
                    err.0
                );
            }
    }
}


pub fn execute_ioctl(
    syscall_ins_addr: u64, 
    pid: i32, 
    arg1: u64, 
    arg2: u64, 
    arg3: u64, 
    regs: &mut user_regs_struct) -> u64 {
    debug!("Executing ioctl: arg1={:#016x}, arg2={:#016x}, arg3={:#016x}", arg1, arg2, arg3);

    regs.rip = syscall_ins_addr;

    let foo: Vec<u8> = read_proc_memory(pid, syscall_ins_addr, 2);
    debug!("Sanity check: {:#016x} = {:?}", syscall_ins_addr, foo);
    assert_eq!(foo, vec![0x0f, 0x05]);

    set_regs(pid, regs);

    let mut new_regs = trace_one_syscall(pid);

    new_regs.orig_rax = SYS_ioctl as u64;
    new_regs.rdi = arg1;
    new_regs.rsi = arg2;
    new_regs.rdx = arg3;
    set_regs(pid, &new_regs);

    let result_regs = finish_syscall(pid);
    assert_eq!(result_regs.rax, 0);
    result_regs.rax
}