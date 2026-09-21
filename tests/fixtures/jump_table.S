.intel_syntax noprefix

.section .text
.global table_dispatch
.type table_dispatch, @function
table_dispatch:
  .cfi_startproc
  cmp edi, 2
  ja .Ldefault
  jmp qword ptr [rdi * 8 + jump_targets]
.Lcase0:
  mov eax, 10
  ret
.Lcase1:
  mov eax, 20
  ret
.Lcase2:
  mov eax, 30
  ret
.Ldefault:
  xor eax, eax
  ret
  .cfi_endproc
.size table_dispatch, .-table_dispatch

.section .rodata
.p2align 3
jump_targets:
  .quad .Lcase0
  .quad .Lcase1
  .quad .Lcase2

.section .note.GNU-stack,"",@progbits
