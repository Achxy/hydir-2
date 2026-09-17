.section .rodata
readonly_word:
  .quad 0
.section .text
.globl _start
.type _start,@function
_start:
  mov $1, %rax
  mov %rax, readonly_word(%rip)
  mov $60, %rax
  xor %rdi, %rdi
  xor %rsi, %rsi
  xor %rdx, %rdx
  syscall
.size _start, .-_start
.section .note.GNU-stack,"",@progbits
