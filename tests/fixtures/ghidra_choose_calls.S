.section .text
.globl hydir_choose
.type hydir_choose,@function
hydir_choose:
  test %rdi, %rdi
  je .Lleft
  call hydir_right
  ret
.Lleft:
  call hydir_left
  ret
.size hydir_choose, .-hydir_choose

.globl hydir_right
.type hydir_right,@function
hydir_right:
  mov $2, %rax
  ret
.size hydir_right, .-hydir_right

.globl hydir_left
.type hydir_left,@function
hydir_left:
  mov $1, %rax
  ret
.size hydir_left, .-hydir_left

.globl _start
.type _start,@function
_start:
  xor %rdi, %rdi
  call hydir_choose
  mov $60, %rax
  xor %rdi, %rdi
  syscall
.size _start, .-_start
.section .note.GNU-stack,"",@progbits
