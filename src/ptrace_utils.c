#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <unistd.h>
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include "ptrace_utils.h"
#include "utils.h"

#define PRE_SYSCALL 0
#define POST_SYSCALL 1

int cur_state = POST_SYSCALL;

int trace_one_syscall(pid_t child, struct user_regs_struct *regs) {
    log_debug(stderr, "Entering trace_one_syscall\n");
    if ( cur_state != POST_SYSCALL) {
        log_error(stderr, "Invalid cur_state: %d\n", cur_state);
	exit(EXIT_FAILURE);
    }
    int status;
    ptrace(PTRACE_SYSCALL, child, 0, 0);
    waitpid(child, &status, 0);

    if (WIFEXITED(status))
        return 1;

    cur_state = PRE_SYSCALL;
    ptrace(PTRACE_GETREGS, child, 0, regs);
    log_debug(stderr, "Current syscall num = %llu\n", regs->orig_rax);
    return 0;
}

int finish_syscall(pid_t child, struct user_regs_struct *regs) {
    log_debug(stderr, "Entering finish_syscall\n");
    if ( cur_state != PRE_SYSCALL) {
        // This should only happen in the KVM_SET_GUEST_DEBUG case
        log_error(stderr, "Invalid cur_state: %d\n", cur_state);
	// exit(EXIT_FAILURE);
    }
    int status;
    ptrace(PTRACE_SYSCALL, child, 0, 0);
    waitpid(child, &status, 0);

    if (WIFEXITED(status))
        return 1;

    cur_state = POST_SYSCALL;
    ptrace(PTRACE_GETREGS, child, 0, regs);
    log_debug(stderr, "Syscall(%lld) return value: 0x%llx\n", regs->orig_rax, regs->rax);
    return 0;
}

int execute_ioctl(size_t syscall_ins_addr, pid_t child, size_t arg1, size_t arg2, size_t arg3, struct user_regs_struct *regs) {
    // Set the RIP to point to the syscall instruction
    regs->rip = syscall_ins_addr;
    unsigned char *foo = read_proc_memory(child, (void *)regs->rip, 2);
    // syscall instruction is 0x0f05
    assert(foo[0] == 0x0f);
    assert(foo[1] == 0x05);

    set_regs(child, regs);

    if (trace_one_syscall(child, regs) == 1) {
        log_error(stderr, "trace_one_syscall failed\n");
        perror("trace_one_syscall");
        exit(EXIT_FAILURE);
    }

    // Set the new register values
    regs->rdx = arg3;
    regs->rsi = arg2;
    regs->rdi = arg1;
    regs->orig_rax = SYS_ioctl;
    set_regs(child, regs);

    // Do the syscall
    if (finish_syscall(child, regs) == 1 ) {
        log_error(stderr, "finish_syscall failed\n");
        perror("finish_syscall");
        exit(EXIT_FAILURE);
    }
    if ( (long)regs->rax < 0 ) {
        log_error(stderr, "ioctl failed");
        exit(EXIT_FAILURE);
    }
    return regs->rax;
}

int trace_one_instruction(pid_t child, struct user_regs_struct *regs) {
    ptrace(PTRACE_SINGLESTEP, child, 0, 0);
    ptrace(PTRACE_GETREGS, child, 0, regs);
    return 0;
}


int set_regs(pid_t child, struct user_regs_struct *regs) {
    ptrace(PTRACE_SETREGS, child, 0, regs);
    return 0;
}


unsigned char *read_proc_memory(pid_t child, void *addr, size_t len) {
    log_debug(stderr, "Reading process(pid=%d) memory at %p : %lu\n", child, addr, len);
    unsigned char *content = calloc(len, 1);
    size_t data = 0;
    int i = 0, j = 0;
    int min;
    log_debug(stderr, "Value: ");
    for ( i = 0; i < len; i += 8) {
        data = ptrace(PTRACE_PEEKDATA, child, addr + i, NULL);
        if (data == -1) {
            perror("ptrace PEEKDATA");
            return NULL;
        }
	log_debug(stderr, "0x%lx ", data);
        min = len - i < 8 ? len - i : 8;
        for ( j = 0; j < min; j++) {
            content[i + j] = data >> j * 8;
        }
    }
    log_debug(stderr, "\n");
    return content;
}


size_t write_proc_memory(pid_t child, void *addr, char *data, size_t len) {
    size_t i = 0;
    long word;
    for ( i = 0; i < len; i += 8) {
        memcpy(&word, data + i, sizeof(word));
        ptrace(PTRACE_POKEDATA, child, addr + i, word);
    }
    return i;
}
