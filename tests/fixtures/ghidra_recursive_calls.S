.section .text
.globl hydir_recursive_sum
.type hydir_recursive_sum,@function
hydir_recursive_sum:
  test %rdi, %rdi
  je .Lbase
  push %rdi
  lea -1(%rdi), %rdi
  call hydir_recursive_sum
  pop %rdx
  add %rdx, %rax
  ret
.Lbase:
  xor %eax, %eax
  ret
.size hydir_recursive_sum, .-hydir_recursive_sum

.globl _start
.type _start,@function
_start:
  mov $3, %rdi
  call hydir_recursive_sum
  mov %rax, %rdi
  mov $60, %eax
  syscall
.size _start, .-_start
.section .note.GNU-stack,"",@progbits
