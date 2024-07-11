#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include "ptrace_utils.h"

int trace_one_syscall(pid_t child, struct user_regs_struct *regs) {
    int status;
    ptrace(PTRACE_SYSCALL, child, 0, 0);
    waitpid(child, &status, 0);

    if (WIFEXITED(status))
        return 1;

    if (WIFSTOPPED(status) && WSTOPSIG(status) & 0x80) {
        ptrace(PTRACE_GETREGS, child, 0, regs);
        return 0;
    }
    return 1;
}


int set_syscall_regs(pid_t child, struct user_regs_struct *regs) {
    ptrace(PTRACE_SETREGS, child, 0, regs);
    return 0;
}


unsigned char *read_proc_memory(pid_t child, void *addr, size_t len) {
    unsigned char *content = malloc(len);
    size_t data;
    int i = 0, j = 0;
    int min;
    for ( i = 0; i < len; i += 8) {
        data = ptrace(PTRACE_PEEKDATA, child, addr + i, NULL);
        if (data == -1) {
            perror("ptrace PEEKDATA");
            return NULL;
        }
        min = len - i < 8 ? len - i : 8;
        for ( j = 0; j < min; j++) {
            content[i + j] = data >> j * 8;
        }
    }
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
