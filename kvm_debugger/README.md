# Compiling

`cargo build`

# Running

`cargo run -- <path_to_vm> -- <extra args for vm>`

# Testing

`RUST_LOG=info cargo run -- ../tests/kvm-hello-world/kvm-hello-world -- "-s"`

You should see some output like this:
```
 --------------------------------------------------------------------------------
                     KVM Debugger
 --------------------------------------------------------------------------------
 -------------------------------------------------------------------------------- registers
 $rax   : 0x65
 $rbx   : 0x0
 $rcx   : 0x0
 $rdx   : 0x34
 $rsp   : 0x0
 $rbp   : 0x0
 $rsi   : 0x0
 $rdi   : 0x0
 $rip   : 0x10
 $r8    : 0x0
 $r9    : 0x0
 $r10   : 0x0
 $r11   : 0x0
 $r12   : 0x0
 $r13   : 0x0
 $r14   : 0x0
 $r15   : 0x0
 -------------------------------------------------------------------------------- stack
 0x00000000000000|+0x00: 0xffffffffffffffff
 0x00000000000008|+0x08: 0xffffffffffffffff
 0x00000000000010|+0x10: 0xffffffffffffffff
 0x00000000000018|+0x18: 0xffffffffffffffff
 0x00000000000020|+0x20: 0xffffffffffffffff
 0x00000000000028|+0x28: 0xffffffffffffffff
 0x00000000000030|+0x30: 0xffffffffffffffff
 0x00000000000038|+0x38: 0xffffffffffffffff
 -------------------------------------------------------------------------------- code
 -> 0x00000000000010: 
 --------------------------------------------------------------------------------
                     KVM Debugger
 --------------------------------------------------------------------------------
 -------------------------------------------------------------------------------- I/O
 Direction: 1
 Port: e9
 Data: [101]

```

And the relevant code that's being executed is:
```
00000000 <_start>:
   0:   ba 00 00 00 00          mov    edx,0x0
   5:   b8 48 00 00 00          mov    eax,0x48
   a:   8d b6 00 00 00 00       lea    esi,[esi+0x0]
  10:   e6 e9                   out    0xe9,al
  12:   0f b6 42 01             movzx  eax,BYTE PTR [edx+0x1]
  16:   83 c2 01                add    edx,0x1
  19:   84 c0                   test   al,al
  1b:   75 f3                   jne    10 <_start+0x10>
  1d:   c7 05 00 04 00 00 2a    mov    DWORD PTR ds:0x400,0x2a
  24:   00 00 00 
  27:   b8 2a 00 00 00          mov    eax,0x2a
  2c:   8d 74 26 00             lea    esi,[esi+eiz*1+0x0]
  30:   f4                      hlt
```

Or the C equivalent:

```
_start(void) {
	const char *p;

	for (p = "Hello, world!\n"; *p; ++p)
		outb(0xE9, *p);

	*(long *) 0x400 = 42;

	for (;;)
		asm("hlt" : /* empty */ : "a" (42) : "memory");
}
```