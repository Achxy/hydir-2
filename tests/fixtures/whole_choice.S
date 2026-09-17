.section .rodata
chosen_a:
  .ascii "A\n"
chosen_b:
  .ascii "B\n"

.section .data
data_anchor:
  .byte 0
.section .bss
choice_byte:
  .zero 1

.section .text
.globl write_a
.type write_a,@function
write_a:
  mov $1, %rax
  mov $1, %rdi
  lea chosen_a(%rip), %rsi
  mov $2, %rdx
  syscall
  ret
.size write_a, .-write_a

.globl write_b
.type write_b,@function
write_b:
  mov $1, %rax
  mov $1, %rdi
  lea chosen_b(%rip), %rsi
  mov $2, %rdx
  syscall
  ret
.size write_b, .-write_b

.globl _start
.type _start,@function
_start:
  mov $0, %rax
  mov $0, %rdi
  lea choice_byte(%rip), %rsi
  mov $1, %rdx
  syscall
  movzbq choice_byte(%rip), %rax
  cmp $65, %rax
  jne choice_b
  call write_a
  jmp choice_done
choice_b:
  call write_b
choice_done:
  mov $60, %rax
  xor %rdi, %rdi
  xor %rsi, %rsi
  xor %rdx, %rdx
  syscall
.size _start, .-_start

.section .note.GNU-stack,"",@progbits
