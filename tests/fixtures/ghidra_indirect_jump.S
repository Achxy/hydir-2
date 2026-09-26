.section .text
.globl hydir_indirect_jump
.type hydir_indirect_jump,@function
hydir_indirect_jump:
  test %rdi, %rdi
  je .Ltarget
  jmp *%rax
.Ltarget:
  mov $7, %rax
  ret
.size hydir_indirect_jump, .-hydir_indirect_jump

.globl _start
.type _start,@function
_start:
  lea .Ltarget(%rip), %rax
  mov $1, %rdi
  call hydir_indirect_jump
  mov $60, %rax
  xor %rdi, %rdi
  syscall
.size _start, .-_start
.section .note.GNU-stack,"",@progbits
