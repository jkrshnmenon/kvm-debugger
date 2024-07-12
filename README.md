<!-- Your comment goes here -->
## Motivation

I've found a few CTF challenges that have some code running inside a KVM-based hypervisor which contains a vulnerability.

In situations where the source code of the hypervisor isn't available, it might be pretty hard to debug what goes on inside the VM.

So I decided to make this thing that basically creates a GDB interface for the VM using `KVM_EXIT_DEBUG`.

~~The only assumption is that the VM has enabled debug mode `ioctl(vcpu, KVM_SET_GUEST_DEBUG, {KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_SW_BP})`~~


## Implementation

The idea is to trap the `KVM_RUN` ioctl and replace it with a wrapper that catches `KVM_EXIT_DEBUG`

If the VM exit code is `KVM_EXIT_DEBUG`, we use the KVM functions to get the registers and send those to GDB.

If the VM exit code isn't `KVM_EXIT_DEBUG`, we return the actual exit code back up the call stack and it gets handled like it should be.


## Status

- [x] Implement the wrapper function for KVM_RUN ioctl

- [x] Handle KVM_EXIT_DEBUG exit code in the wrapper function

- [x] Retrieve registers from the VM using KVM functions

- [ ] Send registers to GDB for debugging

- [ ] Handle other VM exit codes appropriately

- [ ] Test the debugger with different scenarios


## Progress

- [x] Use PTRACE to track the ioctl and mmap calls

- [x] Identify the VCPU fd and KVM_RUN pointers

- [x] Trap the KVM_RUN ioctl and read the exit reason from KVM_RUN pointer

- [x] Automatically find a location in the process BSS to inject data into

- [x] Inject the `kvm_guest_debug` structure into the process memory

- [x] Modify the arguments for one syscall to KVM_SET_GUEST_DEBUG

- [x] Fix the process so that it runs the original syscall

- [x] Figure out a better way to execute arbitrary ioctl in process
