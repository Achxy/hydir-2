/* RDTSC is a real Ghidra CALLOTHER user operation, not a pure value op. */
.section .text
.globl hydir_rdtsc
.type hydir_rdtsc,@function
hydir_rdtsc:
  rdtsc
  shl $32, %rdx
  or %rdx, %rax
  ret
.size hydir_rdtsc, .-hydir_rdtsc

.globl _start
.type _start,@function
_start:
  call hydir_rdtsc
  mov $60, %rax
  xor %rdi, %rdi
  syscall
.size _start, .-_start
.section .note.GNU-stack,"",@progbits
