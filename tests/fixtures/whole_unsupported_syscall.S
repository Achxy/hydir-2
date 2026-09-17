.section .rodata
sentinel:
  .byte 0
.section .text
.globl _start
.type _start,@function
_start:
  mov $39, %rax
  xor %rdi, %rdi
  xor %rsi, %rsi
  xor %rdx, %rdx
  syscall
  mov $60, %rax
  xor %rdi, %rdi
  xor %rsi, %rsi
  xor %rdx, %rdx
  syscall
.size _start, .-_start
.section .note.GNU-stack,"",@progbits
