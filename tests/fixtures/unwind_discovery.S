.text

.hidden unwind_only_a
.type unwind_only_a,@function
unwind_only_a:
  .cfi_startproc
  leaq 1(%rdi), %rax
  retq
  .cfi_endproc
.size unwind_only_a, .-unwind_only_a

.hidden unwind_only_b
.type unwind_only_b,@function
unwind_only_b:
  .cfi_startproc
  xorl %eax, %eax
  retq
  .cfi_endproc
.size unwind_only_b, .-unwind_only_b

.section .note.GNU-stack,"",@progbits
