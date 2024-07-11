#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>
#include <linux/kvm.h>
#include <sys/user.h>
#include "kvm_utils.h"

// A table of vcpu's
struct vcpu *vcpu_table = NULL;
size_t vcpu_table_size = 0;
struct kvm_guest_debug dbg;

// A function to add a new entry into the vcpu_table with the given fd and kvm_run pointer set to NULL
int append_vcpu(int fd) {
    // printf("Appending new vcpu with fd: %d\n", fd);
    struct vcpu *new_table = realloc(vcpu_table, sizeof(struct vcpu) * (vcpu_table_size + 1));
    if (new_table == NULL) {
        return -1;
    }
    vcpu_table = new_table;
    vcpu_table[vcpu_table_size].fd = fd;
    vcpu_table[vcpu_table_size].kvm_run = NULL;
    vcpu_table_size++;
    return 0;
}


// A function to check if a given fd is in the vcpu_table
int check_vcpu_fd(int fd) {
    for (size_t i = 0; i < vcpu_table_size; i++) {
        if (vcpu_table[i].fd == fd) {
            // printf("Found vcpu with fd: %d\n", fd);
            return 1;
        }
    }
    return 0;
}


// A function to update the KVM_RUN pointer of a vcpu given the fd
int update_vcpu_run(int fd, char *kvm_run) {
    // printf("Updating vcpu with fd: %d with kvm_run pointer: %p\n", fd, kvm_run);
    for (size_t i = 0; i < vcpu_table_size; i++) {
        if (vcpu_table[i].fd == fd) {
            vcpu_table[i].kvm_run = kvm_run;
            return 0;
        }
    }
    return -1;
}


// A function to return the KVM_RUN pointer given a vcpu fd
char *get_vcpu_run(int fd) {
    for (size_t i = 0; i < vcpu_table_size; i++) {
        if (vcpu_table[i].fd == fd) {
            // printf("Found kvm_run pointer: %p for vcpu with fd: %d\n", vcpu_table[i].kvm_run, fd);
            return vcpu_table[i].kvm_run;
        }
    }
    return NULL;
}


char *exit_reason_ptr(char *kvm_run) {
    return kvm_run + offsetof(struct kvm_run, exit_reason);
}


// A function handle the KVM_EXIT conditions
void handle_kvm_exit(int exit_condition) {
	// printf("Checking exit_condition: %d\n", exit_condition);
    switch (exit_condition) {
        case KVM_EXIT_DEBUG:
            printf("KVM_EXIT_DEBUG MOTHERFUCKER\n");
            break;
        case KVM_EXIT_HLT:
            // printf("KVM_EXIT_HLT\n");
            break;
        case KVM_EXIT_IO:
            // printf("KVM_EXIT_IO\n");
            break;
        default:
            // printf("Some other KVM_EXIT\n");
            break;
    }
}
