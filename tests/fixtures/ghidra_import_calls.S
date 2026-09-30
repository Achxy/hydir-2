.section .rodata
hydir_message:
  .asciz "hydir"

.section .text
.globl hydir_import_strlen
.type hydir_import_strlen,@function
hydir_import_strlen:
  lea hydir_message(%rip), %rdi
  call strlen@PLT
  ret
.size hydir_import_strlen, .-hydir_import_strlen

.globl hydir_import_memcmp
.type hydir_import_memcmp,@function
hydir_import_memcmp:
  lea hydir_message(%rip), %rdi
  lea hydir_message(%rip), %rsi
  mov $5, %edx
  call memcmp@PLT
  ret
.size hydir_import_memcmp, .-hydir_import_memcmp

.section .note.GNU-stack,"",@progbits
