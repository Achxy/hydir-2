.intel_syntax noprefix
.text
go_text_start:

.globl go_first
.type go_first,@function
go_first:
  lea rax, [rdi + 1]
  ret
.size go_first, .-go_first

.globl go_second
.type go_second,@function
go_second:
  lea rax, [rdi + 2]
  ret
.size go_second, .-go_second
go_text_end:

.section .gopclntab,"a",@progbits
.p2align 3
go_pclntab:
  .long 0xfffffff1
  .byte 0, 0, 1, 8
  .quad 2
  .quad 0
  .quad 0
  .quad go_funcnames - go_pclntab
  .quad go_funcnames - go_pclntab
  .quad go_funcnames - go_pclntab
  .quad go_funcnames - go_pclntab
  .quad go_functab - go_pclntab

go_funcnames:
  .asciz "main.first"
  .asciz "main.second"

.p2align 2
go_functab:
  .long go_first - go_text_start
  .long go_func0 - go_functab
  .long go_second - go_text_start
  .long go_func1 - go_functab
  .long go_text_end - go_text_start

go_func0:
  .long go_first - go_text_start
  .long 0
go_func1:
  .long go_second - go_text_start
  .long 11

.section .note.GNU-stack,"",@progbits
