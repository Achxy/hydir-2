.section .rodata
hello_message:
  .ascii "HydIR\n"

.section .text
.globl write_hello
.type write_hello,@function
write_hello:
  mov $1, %rax
  mov $1, %rdi
  lea hello_message(%rip), %rsi
  mov $6, %rdx
  syscall
  ret
.size write_hello, .-write_hello

.globl _start
.type _start,@function
_start:
  movzbq hello_message(%rip), %rax
  cmp $72, %rax
  jne hello_done
  call write_hello
hello_done:
  mov $60, %rax
  xor %rdi, %rdi
  xor %rsi, %rsi
  xor %rdx, %rdx
  syscall
.size _start, .-_start

.section .note.GNU-stack,"",@progbits
