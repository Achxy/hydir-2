/* Linked fixture: a decoded external CALL targets an unnamed interior byte. */
.text
.globl _start
.type _start,@function
_start:
  mov $1, %rdi
  mov $2, %rsi
  call hydir_outer+3
  mov $60, %rax
  xor %rdi, %rdi
  syscall
.size _start, .-_start

.globl hydir_outer
.type hydir_outer,@function
hydir_outer:
  mov %rdi, %rax
  add %rsi, %rax
  ret
.size hydir_outer, .-hydir_outer
