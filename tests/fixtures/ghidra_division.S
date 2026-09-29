/* Keep quotient in range: x86 DIV faults on quotient overflow, which the
   Ghidra raw P-code instruction does not model. The 32-bit DIV/IDIV SLEIGH
   definitions use 64-bit INT_DIV/INT_REM and INT_SDIV/INT_SREM respectively. */
.section .text
.globl hydir_udiv32
.type hydir_udiv32,@function
hydir_udiv32:
  divl %ecx
  ret
.size hydir_udiv32, .-hydir_udiv32

.globl hydir_sdiv32
.type hydir_sdiv32,@function
hydir_sdiv32:
  idivl %ecx
  ret
.size hydir_sdiv32, .-hydir_sdiv32

.globl _start
.type _start,@function
_start:
  mov $11, %eax
  xor %edx, %edx
  mov $3, %ecx
  call hydir_udiv32
  mov $-11, %eax
  cdq
  mov $3, %ecx
  call hydir_sdiv32
  mov $60, %eax
  xor %edi, %edi
  syscall
.size _start, .-_start
.section .note.GNU-stack,"",@progbits
