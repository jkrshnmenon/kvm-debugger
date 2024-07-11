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
#include "kvm_utils.h"
#include "ptrace_utils.h"

extern char **environ;
extern struct kvm_guest_debug dbg;
int enabled = 0;


int start_vm(char *vm_path, char **vm_args) {
    pid_t child = fork();
    if (child == -1) {
        perror("fork");
        exit(EXIT_FAILURE);
    }

    if (child == 0) {
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        execve(vm_path, vm_args, environ);
        perror("execve");
        exit(EXIT_FAILURE);
    }
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

    ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_TRACESYSGOOD);

    while (trace_one_syscall(child, &regs) == 0) {
#ifdef __x86_64__
        if (regs.orig_rax == SYS_ioctl) {
            switch (regs.rsi) {
                case KVM_CREATE_VCPU:
                    if ( trace_one_syscall(child, &regs) == 1) {
                        perror("trace_one_syscall");
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
                        struct user_regs_struct saved_regs_ptr;
                        memcpy(&saved_regs_ptr, &regs, sizeof(struct user_regs_struct));

                        // Write the debug structure into the process memory
                        memset(&dbg, 0, sizeof(dbg));
                        dbg.control = KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_SINGLESTEP | KVM_GUESTDBG_USE_SW_BP;

                        // TODO: Find the address in the bss dynamically
                        if ( write_proc_memory(child, (void *)0x404300, (char *)&dbg, sizeof(dbg)) != sizeof(dbg)) {
                            perror("write_proc_memory");
                            exit(EXIT_FAILURE);
                        }

                        // Set the new register values
                        // printf("[*] Before rsi = %llx, rdx = %llx\n", regs.rsi, regs.rdx);
                        regs.rdx = 0x404300;
                        regs.rsi = KVM_SET_GUEST_DEBUG;
                        set_syscall_regs(child, &regs);

                        // printf("[*] After rsi = %llx, rdx = %llx\n", regs.rsi, regs.rdx);
                        // Do the syscall
                        if (trace_one_syscall(child, &regs) == 1 ) {
                            perror("trace_one_syscall");
                            exit(EXIT_FAILURE);
                        }
                        if ( regs.rax == -1 ) {
                            perror("ioctl KVM_SET_GUESTDBG");
                            exit(EXIT_FAILURE);
                        }
                        puts("KVM_SET_GUESTDBG ioctl successful");

                        // Reset the registers to the old state
                        // set_syscall_regs(child, &saved_regs_ptr);
                        // printf("[*] Finally rsi = %llx, rdx = %llx\n", saved_regs_ptr.rsi, saved_regs_ptr.rdx);
                        enabled = 1;
                        break;
                    }
                case KVM_RUN:
                    vcpu_fd = regs.rdi;
                    if (trace_one_syscall(child, &regs) == 1) {
                        perror("trace_one_syscall");
                        exit(EXIT_FAILURE);
                    }
                    kvm_run = get_vcpu_run(vcpu_fd);
                    exit_reason_offset = (void *)exit_reason_ptr(kvm_run);
                    exit_reason = *(long *)read_proc_memory(child, exit_reason_offset, sizeof(long));
                    handle_kvm_exit(exit_reason);
                    break;
                default:
                    break;
            }
        } else if (regs.orig_rax == SYS_mmap) {
            int fd = regs.r8;
            if ((fd != -1) && check_vcpu_fd(fd)) {
                if ( trace_one_syscall(child, &regs) == 1) {
                    perror("trace_one_syscall");
                    exit(EXIT_FAILURE);
                }
                char *kvm_run = (char *)regs.rax;
                update_vcpu_run(fd, kvm_run);
            }
        }
#endif
    }
    puts("[*] Done");
}


int main(int argc, char **argv) {
    if (argc < 2) {
        printf("Usage: %s <vm> [vm_args]\n", argv[0]);
        return 1;
    }
    char *vm_path = argv[1];
    char **vm_args = &argv[1];
    printf("Running %s\n", vm_path);
    trace_vm(vm_path, vm_args);
}
