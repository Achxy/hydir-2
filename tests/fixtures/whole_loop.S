.section .data
shared_count:
  .quad 0

.section .rodata
good_message:
  .ascii "THREE\n"
bad_message:
  .ascii "BAD\n"

.section .text
.globl increment_count
.type increment_count,@function
increment_count:
  mov shared_count(%rip), %rax
  add $1, %rax
  mov %rax, shared_count(%rip)
  ret
.size increment_count, .-increment_count

.globl write_result
.type write_result,@function
write_result:
  mov shared_count(%rip), %rax
  cmp $3, %rax
  jne wrong_count
  mov $1, %rax
  mov $1, %rdi
  lea good_message(%rip), %rsi
  mov $6, %rdx
  syscall
  ret
wrong_count:
  mov $1, %rax
  mov $1, %rdi
  lea bad_message(%rip), %rsi
  mov $4, %rdx
  syscall
  ret
.size write_result, .-write_result

.globl _start
.type _start,@function
_start:
  mov $3, %rcx
count_loop:
  call increment_count
  sub $1, %rcx
  jne count_loop
  call write_result
  mov $60, %rax
  xor %rdi, %rdi
  xor %rsi, %rsi
  xor %rdx, %rdx
  syscall
.size _start, .-_start

.section .note.GNU-stack,"",@progbits
