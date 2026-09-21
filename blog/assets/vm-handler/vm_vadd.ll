; Hand-derived semantic implementation of tests/fixtures/vm_vadd.S.
; This is an analyst model, not output from HydIR's scalar lifter.
; Layout: { vreg[4], stack[16], sp, vpc }; all fields are i64.
%VMState = type { [4 x i64], [16 x i64], i64, i64 }

define void @vm_vadd_ir(ptr %state) {
entry:
  %sp.ptr = getelementptr %VMState, ptr %state, i32 0, i32 2
  %sp = load i64, ptr %sp.ptr, align 8
  %lo = sub i64 %sp, 2
  %hi = sub i64 %sp, 1
  %lo.ptr = getelementptr %VMState, ptr %state, i32 0, i32 1, i64 %lo
  %hi.ptr = getelementptr %VMState, ptr %state, i32 0, i32 1, i64 %hi
  %a = load i64, ptr %lo.ptr, align 8
  %b = load i64, ptr %hi.ptr, align 8
  %sum = add i64 %a, %b
  store i64 %sum, ptr %lo.ptr, align 8
  store i64 %hi, ptr %sp.ptr, align 8
  %vpc.ptr = getelementptr %VMState, ptr %state, i32 0, i32 3
  %vpc = load i64, ptr %vpc.ptr, align 8
  %next = add i64 %vpc, 1
  store i64 %next, ptr %vpc.ptr, align 8
  ret void
}
