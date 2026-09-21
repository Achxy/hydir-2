/* Linked fixture: a second ELF text symbol starts inside hydir_outer. */
.text
.globl _start
.type _start,@function
_start:
  mov $60, %rax
  xor %rdi, %rdi
  syscall
.size _start, .-_start

.globl hydir_outer
.type hydir_outer,@function
hydir_outer:
  mov %rdi, %rax
.globl hydir_inner
.type hydir_inner,@function
hydir_inner:
  add %rsi, %rax
  ret
.size hydir_inner, .-hydir_inner
.size hydir_outer, .-hydir_outer
