.text

.globl exported_fn
.type exported_fn,@function
exported_fn:
  .cfi_startproc
  pushq %rbp
  .cfi_def_cfa_offset 16
  .cfi_offset %rbp, -16
  movq %rsp, %rbp
  .cfi_def_cfa_register %rbp
  callq external_hook@PLT
  leaq 1(%rdi), %rax
  popq %rbp
  .cfi_def_cfa %rsp, 8
  retq
  .cfi_endproc
.size exported_fn, .-exported_fn

.type init_fn,@function
init_fn:
  retq
.size init_fn, .-init_fn

.type fini_fn,@function
fini_fn:
  retq
.size fini_fn, .-fini_fn

.section .init_array,"aw",@init_array
.p2align 3
.quad init_fn

.section .fini_array,"aw",@fini_array
.p2align 3
.quad fini_fn

.section .tdata,"awT",@progbits
.p2align 3
.globl hydir_tls_value
.type hydir_tls_value,@object
hydir_tls_value:
  .quad 0x1122334455667788
.size hydir_tls_value, 8

.section .note.GNU-stack,"",@progbits
