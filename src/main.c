#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <linux/kvm.h>
#include <assert.h>
#include "kvm_utils.h"
#include "ptrace_utils.h"
#include "utils.h"

extern char **environ;
extern struct kvm_guest_debug dbg;
int enabled = 0;


int start_vm(char *vm_path, char **vm_args) {
    pid_t child = fork();
    int stdin_fd[2];
    int stdout_fd[2];
    int stderr_fd[2];
    pipe(stdin_fd);
    pipe(stdout_fd);
    pipe(stderr_fd);
    if (child == -1) {
        log_error(stderr, "Fork failed\n");
        perror("fork");
        exit(EXIT_FAILURE);
    }

    if (child == 0) {
        // Make the child process write to the pipes
        dup2(stdin_fd[1], STDIN_FILENO);
        dup2(stdout_fd[1], STDOUT_FILENO);
        dup2(stderr_fd[1], STDERR_FILENO);
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        execve(vm_path, vm_args, environ);
        log_error(stderr, "Execve failed\n");
        perror("execve");
        exit(EXIT_FAILURE);
    }
    ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_TRACESYSGOOD);
    return child;
}

void trace_vm(char *vm_path, char **vm_args) {
    char *kvm_run;
    long exit_reason;
    int status, vcpu_fd;
    void *exit_reason_offset;
    struct user_regs_struct regs;

    pid_t child = start_vm(vm_path, vm_args);
    waitpid(child, &status, 0);

    while (trace_one_syscall(child, &regs) == 0) {
#ifdef __x86_64__
        if (regs.orig_rax == SYS_ioctl) {
            switch (regs.rsi) {
                case KVM_CREATE_VCPU:
                    if ( finish_syscall(child, &regs) == 1) {
                        log_error(stderr, "finish_syscall failed\n");
                        perror("finish_syscall");
                        exit(EXIT_FAILURE);
                    }
                    vcpu_fd = regs.rax;
                    append_vcpu(vcpu_fd);
                    break;
                case KVM_GET_SREGS:
                // case KVM_SET_SREGS:
                // case KVM_GET_REGS:
                // case KVM_SET_REGS:
                    if ( enabled == 0 ){

                        // Save the old registers
                        long vcpu_fd = regs.rdi;
                        struct user_regs_struct saved_regs_ptr;
                        if (finish_syscall(child, &regs) == 1 ) {
                            log_error(stderr, "finish_syscall failed\n");
                            perror("finish_syscall");
                            exit(EXIT_FAILURE);
                        }
                        assert(regs.rax >= 0);
                        log_debug(stderr, "KVM_GET_SREGS success: %llx\n", regs.rax);
                        memcpy(&saved_regs_ptr, &regs, sizeof(struct user_regs_struct));
			
                        // Write the debug structure into the process memory
                        memset(&dbg, 0, sizeof(dbg));
                        dbg.control = KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_SINGLESTEP | KVM_GUESTDBG_USE_SW_BP;

                        void *addr = bss_addr(child);
                        if ( write_proc_memory(child, addr, (char *)&dbg, sizeof(dbg)) != sizeof(dbg)) {
                            log_error(stderr, "write_proc_memory failed\n");
                            perror("write_proc_memory");
                            exit(EXIT_FAILURE);
                        }

                        // Reset RIP to syscall instruction
                        regs.rip = regs.rip - 2;
                        unsigned char *foo = read_proc_memory(child, (void *)regs.rip, 2);
                        // syscall instruction is 0x0f05
                        assert(foo[0] == 0x0f);
                        assert(foo[1] == 0x05);

                        set_syscall_regs(child, &regs);
                        if (trace_one_syscall(child, &regs) == 1) {
                            log_error(stderr, "trace_one_syscall failed\n");
                            perror("trace_one_syscall");
                            exit(EXIT_FAILURE);
                        }

                        // Set the new register values
                        regs.rdx = (unsigned long) addr;
                        regs.rsi = KVM_SET_GUEST_DEBUG;
                        regs.rdi = vcpu_fd;
                        regs.orig_rax = SYS_ioctl;
                        set_syscall_regs(child, &regs);

                        // Do the syscall
                        if (finish_syscall(child, &regs) == 1 ) {
                            log_error(stderr, "finish_syscall failed\n");
                            perror("finish_syscall");
                            exit(EXIT_FAILURE);
                        }
                        if ( (long)regs.rax < 0 ) {
                            log_error(stderr, "ioctl KVM_SET_GUESTDBG failed");
                            exit(EXIT_FAILURE);
                        }
                        log_debug(stderr, "KVM_SET_GUESTDBG ioctl successful: %llx\n", regs.rax);

                        // Reset the registers to the old state
                        set_syscall_regs(child, &saved_regs_ptr);
                        enabled = 1;
                        break;
                    }
                case KVM_RUN:
                    vcpu_fd = regs.rdi;
                    if (finish_syscall(child, &regs) == 1) {
                        log_error(stderr, "finish_syscall failed\n");
                        perror("fiinsh_syscall");
                        exit(EXIT_FAILURE);
                    }
                    kvm_run = get_vcpu_run(vcpu_fd);
                    exit_reason_offset = (void *)exit_reason_ptr(kvm_run);
                    exit_reason = *(long *)read_proc_memory(child, exit_reason_offset, sizeof(long));
                    handle_kvm_exit(exit_reason);
                    break;
                default:
                    if (finish_syscall(child, &regs) == 1) {
                        log_error(stderr, "finish_syscall failed\n");
                        perror("finish_syscall");
                        exit(EXIT_FAILURE);
                    }
                    break;
            }
        } else if (regs.orig_rax == SYS_mmap) {
            int fd = regs.r8;
            if ((fd != -1) && check_vcpu_fd(fd)) {
                if ( finish_syscall(child, &regs) == 1) {
                    log_error(stderr, "finish_syscall failed\n");
                    perror("finish_syscall");
                    exit(EXIT_FAILURE);
                }
                char *kvm_run = (char *)regs.rax;
                update_vcpu_run(fd, kvm_run);
            } else {
                if ( finish_syscall(child, &regs) == 1) {
                    log_error(stderr, "finish_syscall failed\n");
                    perror("finish_syscall");
                    exit(EXIT_FAILURE);
	        }
	    }
        } else {
            if ( finish_syscall(child, &regs) == 1) {
                log_error(stderr, "finish_syscall failed\n");
                perror("finish_syscall");
                exit(EXIT_FAILURE);
            }
	}
#endif
    }
    log_info(stderr, "Done");
}


int main(int argc, char **argv) {
    if (argc < 2) {
        log_error(stderr, "Usage: %s <vm> [vm_args]\n", argv[0]);
        return 1;
    }
    char *vm_path = argv[1];
    char **vm_args = &argv[1];
    log_info(stderr, "Running %s\n", vm_path);
    trace_vm(vm_path, vm_args);
}
