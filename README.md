<!-- Your comment goes here -->
## Motivation

I've found a few CTF challenges that have some code running inside a KVM-based hypervisor which contains a vulnerability.

In situations where the source code of the hypervisor isn't available, it might be pretty hard to debug what goes on inside the VM.

So I decided to make this thing that basically creates a GDB interface for the VM using `KVM_EXIT_DEBUG`.

The only assumption is that the VM has enabled debug mode `ioctl(vcpu, KVM_SET_GUEST_DEBUG, {KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_SW_BP})`


## Implementation

The idea is to trap the `KVM_RUN` ioctl and replace it with a wrapper that catches `KVM_EXIT_DEBUG`

If the VM exit code is `KVM_EXIT_DEBUG`, we use the KVM functions to get the registers and send those to GDB.

If the VM exit code isn't `KVM_EXIT_DEBUG`, we return the actual exit code back up the call stack and it gets handled like it should be.


## Status

<input disabled="" type="checkbox"> Implement the wrapper function for KVM_RUN ioctl
<input disabled="" type="checkbox"> Handle KVM_EXIT_DEBUG exit code in the wrapper function
<input disabled="" type="checkbox"> Retrieve registers from the VM using KVM functions
<input disabled="" type="checkbox"> Send registers to GDB for debugging
<input disabled="" type="checkbox"> Handle other VM exit codes appropriately
<input disabled="" type="checkbox"> Test the debugger with different scenarios


## Progress

<input disabled="" type="checkbox"> Use PTRACE to track the ioctl and mmap calls
<input disabled="" type="checkbox"> Identify the VCPU fd and KVM_RUN pointers
<input disabled="" type="checkbox"> Trap the KVM_RUN ioctl and read the exit reason from KVM_RUN pointer
<input disabled="" type="checkbox"> Automatically find a location in the process BSS to inject data into
<input disabled="" type="checkbox"> Inject the `kvm_guest_debug` structure into the process memory
<input disabled="" type="checkbox"> Modify the arguments for one syscall to KVM_SET_GUEST_DEBUG
<input disabled="" type="checkbox"> Fix the process so that it runs the original syscall
<input disabled="" type="checkbox"> Figure out a better way to execute arbitrary ioctl in process

