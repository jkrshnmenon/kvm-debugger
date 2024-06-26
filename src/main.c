#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <linux/kvm.h>

extern char **environ;


int start_vm(char *vm_path) {
    pid_t child = fork();
    if (child == -1) {
        perror("fork");
        exit(EXIT_FAILURE);
    }

    if (child == 0) {
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        char *args[2] = {vm_path, NULL};
        execve(args[0], args, environ);
        perror("execve");
        exit(EXIT_FAILURE);
    }
    return child;
}

void trace_vm(char *vm_path) {
    pid_t child = start_vm(vm_path);
    int status;
    waitpid(child, &status, 0);

    ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_TRACESYSGOOD);

    while (1) {
        ptrace(PTRACE_SYSCALL, child, 0, 0);
        waitpid(child, &status, 0);

        if (WIFEXITED(status))
            break;

        if (WIFSTOPPED(status) && WSTOPSIG(status) & 0x80) {
            struct user_regs_struct regs;
            ptrace(PTRACE_GETREGS, child, 0, &regs);

#ifdef __x86_64__
            if (regs.orig_rax == SYS_ioctl) {
                switch (regs.rsi) {
                    case KVM_CREATE_VCPU:
                        // I sincerely hope that the value of KVM_CREATE_VCPU isn't used by another ioctl in the same binary
                        ptrace(PTRACE_SYSCALL, child, 0, 0);
                        waitpid(child, &status, 0);
                        ptrace(PTRACE_GETREGS, child, 0, &regs);
                        append_vcpu(regs.rax);
                        break;
                    case KVM_RUN:
                        int vcpu_fd = regs.rdi;
                        ptrace(PTRACE_SYSCALL, child, 0, 0);
                        waitpid(child, &status, 0);
                        ptrace(PTRACE_GETREGS, child, 0, &regs);
                        char *kvm_run = get_vcpu_run(vcpu_fd);
                        long data;
                        data = ptrace(PTRACE_PEEKDATA, child, kvm_run, NULL);
                        if (data == -1) {
                            perror("ptrace PEEKDATA");
                        } else {
                            printf("Data at mmap address: %lx\n", data);
                        }
                        handle_kvm_exit(data);
                        break;
                    default:
                        break;
                }
            } else if (regs.orig_rax == SYS_mmap) {
                int fd = regs.r8;
                if ((fd != -1) && check_vcpu_fd(child, &regs, fd)) {
                    ptrace(PTRACE_SYSCALL, child, 0, 0);
                    waitpid(child, &status, 0);
                    ptrace(PTRACE_GETREGS, child, 0, &regs);
                    char *kvm_run = regs.rax;
                    update_vcpu_run(fd, kvm_run);
                }
            }
#endif
        }
    }
}


int main(int argc, char **argv) {
    if (argc < 2) {
        printf("Usage: %s <vm>\n", argv[0]);
        return 1;
    }
    char *vm_path = argv[1];
    printf("Running %s\n", vm_path);
    trace_vm(vm_path);
}