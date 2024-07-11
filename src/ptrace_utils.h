#include <unistd.h>
#include <stdio.h>

int trace_one_syscall(pid_t child, struct user_regs_struct *regs);

int finish_syscall(pid_t child, struct user_regs_struct *regs);

int trace_one_instruction(pid_t child, struct user_regs_struct *regs);

int set_syscall_regs(pid_t child, struct user_regs_struct *regs);

unsigned char *read_proc_memory(pid_t child, void *addr, size_t len);

size_t write_proc_memory(pid_t child, void *addr, char *data, size_t len);
