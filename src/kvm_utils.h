#include <stdio.h>
#include <stdlib.h>

// A struct to hold the details of a KVM vcpu such as fd and pointer to KVM_RUN structure.
struct vcpu {
    int fd;
    char *kvm_run;
};

// A function to add a new entry into the vcpu_table with the given fd and kvm_run pointer set to NULL
int append_vcpu(int fd);

// A function to check if a given fd is in the vcpu_table
int check_vcpu_fd(int fd);

// A function to update the KVM_RUN pointer of a vcpu given the fd
int update_vcpu_run(int fd, char *kvm_run);

// A function to return the KVM_RUN pointer given a vcpu fd
char *get_vcpu_run(int fd);

// A function handle the KVM_EXIT conditions
void handle_kvm_exit(int vcpu_fd);
