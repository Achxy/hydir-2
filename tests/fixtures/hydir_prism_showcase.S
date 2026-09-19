# HydIR PRISM: one trusted ELF designed to make the native pipeline visible.
#
# Each `hydir_stage_*` symbol has one presentation job: structured control
# flow, stack state, direct-call summaries, bounded loops, mapped memory, or
# reversible trampoline patching. The program accepts exactly `HYDR`.

.section .rodata
prism_banner:
  .ascii "\n"
  .ascii "  +----------------------------------------------------------+\n"
  .ascii "  |  HYDIR // PRISM                                         |\n"
  .ascii "  |  MACHINE BYTES -> REGION IR -> C -> PATCHED ELF         |\n"
  .ascii "  +----------------------------------------------------------+\n"
  .ascii "  live demo: CFG | physical state | calls | patch trampoline\n\n"
prism_banner_end:
prism_prompt:
  .ascii "  Enter the four-byte signal: "
prism_prompt_end:
prism_granted:
  .ascii "\n  [ VERIFIED ] signal accepted // HYDIR OWNS THE BINARY\n"
prism_granted_end:
prism_denied:
  .ascii "\n  [ REFUSED  ] signal rejected // uncertainty stayed explicit\n"
prism_denied_end:

.section .data
.balign 8
.globl hydir_prism_counter
.type hydir_prism_counter,@object
hydir_prism_counter:
  .quad 0
.size hydir_prism_counter, .-hydir_prism_counter

.section .bss
.balign 8
prism_input:
  .zero 8

.section .text

# Hero 1: a compact diamond that becomes deterministic structured C.
.globl hydir_stage_decision
.type hydir_stage_decision,@function
hydir_stage_decision:
  mov %rdi, %rax
  cmp %rsi, %rdi
  jae .Ldecision_done
  mov %rsi, %rax
.Ldecision_done:
  ret
.size hydir_stage_decision, .-hydir_stage_decision

# Hero 2: five bytes on purpose. A larger PatchLang replacement forces the
# reversible entry-trampoline / appended RX-segment placement path.
.globl hydir_stage_patch_portal
.type hydir_stage_patch_portal,@function
hydir_stage_patch_portal:
  nop
  mov %rdi, %rax
  ret
.size hydir_stage_patch_portal, .-hydir_stage_patch_portal

# Hero 3: explicit frame state and a typed stack-local round trip.
.globl hydir_stage_stack_mix
.type hydir_stage_stack_mix,@function
hydir_stage_stack_mix:
  push %rbp
  mov %rsp, %rbp
  sub $16, %rsp
  mov %rdi, -8(%rbp)
  mov -8(%rbp), %rax
  add %rsi, %rax
  leave
  ret
.size hydir_stage_stack_mix, .-hydir_stage_stack_mix

# Hero 4: a direct callee with a resolved SysV return contract.
.globl hydir_stage_leaf_add
.type hydir_stage_leaf_add,@function
hydir_stage_leaf_add:
  mov %rdi, %rax
  add %rsi, %rax
  ret
.size hydir_stage_leaf_add, .-hydir_stage_leaf_add

.globl hydir_stage_call_chain
.type hydir_stage_call_chain,@function
hydir_stage_call_chain:
  sub $8, %rsp
  call hydir_stage_leaf_add
  add $8, %rsp
  ret
.size hydir_stage_call_chain, .-hydir_stage_call_chain

# Hero 5: a bounded back-edge for loop and flag recovery.
.globl hydir_stage_loop_sum
.type hydir_stage_loop_sum,@function
hydir_stage_loop_sum:
  mov $0, %rax
  mov $3, %rcx
.Lloop_sum:
  add %rdi, %rax
  sub $1, %rcx
  jne .Lloop_sum
  ret
.size hydir_stage_loop_sum, .-hydir_stage_loop_sum

# Hero 6: TEST-defined flags feeding a visible decision.
.globl hydir_stage_bit_gate
.type hydir_stage_bit_gate,@function
hydir_stage_bit_gate:
  mov $0, %rax
  test %rsi, %rdi
  je .Lbit_gate_done
  mov $1, %rax
.Lbit_gate_done:
  ret
.size hydir_stage_bit_gate, .-hydir_stage_bit_gate

# Hero 7: mapped global state for conservative cross-function effect analysis.
.globl hydir_stage_record
.type hydir_stage_record,@function
hydir_stage_record:
  mov $7, %rax
  mov %rax, hydir_prism_counter(%rip)
  ret
.size hydir_stage_record, .-hydir_stage_record

.globl hydir_stage_record_parent
.type hydir_stage_record_parent,@function
hydir_stage_record_parent:
  sub $8, %rsp
  call hydir_stage_record
  add $8, %rsp
  ret
.size hydir_stage_record_parent, .-hydir_stage_record_parent

.globl prism_write_banner
.type prism_write_banner,@function
prism_write_banner:
  mov $1, %rax
  mov $1, %rdi
  lea prism_banner(%rip), %rsi
  mov $(prism_banner_end-prism_banner), %rdx
  syscall
  ret
.size prism_write_banner, .-prism_write_banner

.globl prism_write_granted
.type prism_write_granted,@function
prism_write_granted:
  mov $1, %rax
  mov $1, %rdi
  lea prism_granted(%rip), %rsi
  mov $(prism_granted_end-prism_granted), %rdx
  syscall
  ret
.size prism_write_granted, .-prism_write_granted

.globl prism_write_denied
.type prism_write_denied,@function
prism_write_denied:
  mov $1, %rax
  mov $1, %rdi
  lea prism_denied(%rip), %rsi
  mov $(prism_denied_end-prism_denied), %rdx
  syscall
  ret
.size prism_write_denied, .-prism_write_denied

.globl _start
.type _start,@function
_start:
  call prism_write_banner

  mov $1, %rax
  mov $1, %rdi
  lea prism_prompt(%rip), %rsi
  mov $(prism_prompt_end-prism_prompt), %rdx
  syscall

  mov $0, %rax
  mov $0, %rdi
  lea prism_input(%rip), %rsi
  mov $4, %rdx
  syscall
  cmp $4, %rax
  jne .Lprism_denied

  call hydir_stage_record_parent

  movzbq prism_input(%rip), %rdi
  mov $72, %rsi
  call hydir_stage_decision
  cmp $72, %rax
  jne .Lprism_denied

  # Patching identity to subtraction changes 72 to 71 and flips this route.
  movzbq prism_input(%rip), %rdi
  mov $1, %rsi
  call hydir_stage_patch_portal
  cmp $72, %rax
  jne .Lprism_denied

  mov $40, %rdi
  mov $2, %rsi
  call hydir_stage_stack_mix
  cmp $42, %rax
  jne .Lprism_denied

  mov $20, %rdi
  mov $22, %rsi
  call hydir_stage_call_chain
  cmp $42, %rax
  jne .Lprism_denied

  mov $14, %rdi
  xor %rsi, %rsi
  call hydir_stage_loop_sum
  cmp $42, %rax
  jne .Lprism_denied

  mov $0x48, %rdi
  mov $0x08, %rsi
  call hydir_stage_bit_gate
  cmp $1, %rax
  jne .Lprism_denied

  movzbq prism_input(%rip), %rax
  cmp $72, %rax
  jne .Lprism_denied
  movzbq prism_input+1(%rip), %rax
  cmp $89, %rax
  jne .Lprism_denied
  movzbq prism_input+2(%rip), %rax
  cmp $68, %rax
  jne .Lprism_denied
  movzbq prism_input+3(%rip), %rax
  cmp $82, %rax
  jne .Lprism_denied

  call prism_write_granted
  jmp .Lprism_exit

.Lprism_denied:
  call prism_write_denied

.Lprism_exit:
  mov $60, %rax
  xor %rdi, %rdi
  xor %rsi, %rsi
  xor %rdx, %rdx
  syscall
.size _start, .-_start

.section .note.GNU-stack,"",@progbits
