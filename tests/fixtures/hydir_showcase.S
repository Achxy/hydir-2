# HydIR showcase crackme: a tiny trusted freestanding ELF.
#
# The secret is HYDR.  This is intentionally not a hostile sample: it is a
# deterministic fixture designed to exercise HydIR's current contracts.

.section .rodata
banner:
  .ascii "HYDIR VM-STYLE CRACKME\n"
banner_end:
granted:
  .ascii "ACCESS GRANTED\n"
granted_end:
denied:
  .ascii "ACCESS DENIED\n"
denied_end:

.section .bss
.balign 8
input:
  .zero 4

.section .text
.globl hydir_max2
.type hydir_max2,@function
hydir_max2:
  movq %rdi, %rax
  cmpq %rsi, %rdi
  jae .Lmax_done
  movq %rsi, %rax
.Lmax_done:
  ret
.size hydir_max2, .-hydir_max2

.globl write_banner
.type write_banner,@function
write_banner:
  mov $1, %rax
  mov $1, %rdi
  lea banner(%rip), %rsi
  mov $(banner_end-banner), %rdx
  syscall
  ret
.size write_banner, .-write_banner

.globl write_granted
.type write_granted,@function
write_granted:
  mov $1, %rax
  mov $1, %rdi
  lea granted(%rip), %rsi
  mov $(granted_end-granted), %rdx
  syscall
  ret
.size write_granted, .-write_granted

.globl write_denied
.type write_denied,@function
write_denied:
  mov $1, %rax
  mov $1, %rdi
  lea denied(%rip), %rsi
  mov $(denied_end-denied), %rdx
  syscall
  ret
.size write_denied, .-write_denied

.globl _start
.type _start,@function
_start:
  call write_banner

  mov $0, %rax
  mov $0, %rdi
  lea input(%rip), %rsi
  mov $4, %rdx
  syscall

  # Use the liftable scalar function as a small score/lower-bound check.
  movzbq input(%rip), %rdi
  mov $72, %rsi
  call hydir_max2
  cmp $72, %rax
  jne .Ldenied

  movzbq input(%rip), %rax
  cmp $72, %rax
  jne .Ldenied
  movzbq input+1(%rip), %rax
  cmp $89, %rax
  jne .Ldenied
  movzbq input+2(%rip), %rax
  cmp $68, %rax
  jne .Ldenied
  movzbq input+3(%rip), %rax
  cmp $82, %rax
  jne .Ldenied

  call write_granted
  jmp .Lexit
.Ldenied:
  call write_denied
.Lexit:
  mov $60, %rax
  xor %rdi, %rdi
  xor %rsi, %rsi
  xor %rdx, %rdx
  syscall
.size _start, .-_start

.section .note.GNU-stack,"",@progbits
