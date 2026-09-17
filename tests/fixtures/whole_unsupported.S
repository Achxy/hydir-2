.section .rodata
sentinel:
  .byte 0
.section .text
.globl _start
.type _start,@function
_start:
  push %rbp
  mov $60, %rax
  xor %rdi, %rdi
  syscall
.size _start, .-_start
.section .note.GNU-stack,"",@progbits
