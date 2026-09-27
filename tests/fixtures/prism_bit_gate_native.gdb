set pagination off
set confirm off
set auto-load off
python
import gdb
import json
import os

snapshot = json.load(open(os.environ["HYDIR_NATIVE_SNAPSHOT"], encoding="utf-8"))
instructions = {
    int(row["address"]["offset"], 16): bytes.fromhex(row["parsed_bytes"])
    for row in snapshot["selected_function"]["instructions"]
}
entry = int(snapshot["selected_function"]["entry"]["offset"], 16)
ret_address = int(os.environ["HYDIR_NATIVE_RETURN"], 16)
ret_instruction = next(
    int(row["address"]["offset"], 16)
    for row in snapshot["selected_function"]["instructions"]
    if row["mnemonic"] == "RET"
)
observed_instruction = (
    int(os.environ["HYDIR_NATIVE_OBSERVE_INSTRUCTION"], 16)
    if "HYDIR_NATIVE_OBSERVE_INSTRUCTION" in os.environ else None
)
observed_flags = None

# The kernel maps this exact ELF before starti stops, including when GDB
# initially stops in its dynamic loader. Install a valid SysV call frame on
# the inferior's stack, then enter the fixture function directly.
gdb.execute("starti", to_string=True)
gdb.execute("set $rsp = $rsp - 8")
entry_rsp = int(gdb.parse_and_eval("$rsp"))
gdb.selected_inferior().write_memory(entry_rsp, ret_address.to_bytes(8, "little"))
gdb.execute("set $rip = 0x%x" % entry)
if "HYDIR_NATIVE_INPUT_HEX" in os.environ:
    input_bytes = bytes.fromhex(os.environ["HYDIR_NATIVE_INPUT_HEX"])
    if not input_bytes or len(input_bytes) > 128:
        raise RuntimeError("native input must contain 1..128 bytes")
    input_address = entry_rsp - 0x100
    gdb.selected_inferior().write_memory(input_address, input_bytes)
    gdb.execute("set $rdi = 0x%x" % input_address)
else:
    gdb.execute("set $rdi = %s" % os.environ["HYDIR_NATIVE_RDI"])
gdb.execute("set $rsi = %s" % os.environ["HYDIR_NATIVE_RSI"])
if "HYDIR_NATIVE_RAX" in os.environ:
    gdb.execute("set $rax = %s" % os.environ["HYDIR_NATIVE_RAX"])

visits = []
max_visits = int(os.environ.get("HYDIR_NATIVE_MAX_VISITS", str(len(instructions) + 1)))
for _ in range(max_visits):
    pc = int(gdb.parse_and_eval("$rip"))
    if pc == ret_address and visits and visits[-1] == ret_instruction:
        break
    if pc not in instructions:
        raise RuntimeError("native execution left selected function at 0x%x" % pc)
    expected = instructions[pc]
    actual = bytes(gdb.selected_inferior().read_memory(pc, len(expected)))
    if actual != expected:
        raise RuntimeError("native bytes at 0x%x differ from Ghidra snapshot" % pc)
    visits.append(pc)
    gdb.execute("si", to_string=True)
    if pc == observed_instruction:
        observed_eflags = int(gdb.parse_and_eval("$eflags"))
        observed_flags = {
            "cf": observed_eflags & 1,
            "of": (observed_eflags >> 11) & 1,
        }
else:
    raise RuntimeError("native execution exceeded selected-function instruction budget")

flags = int(gdb.parse_and_eval("$eflags"))
result = {
    "instruction_visits": ["0x%x" % pc for pc in visits],
    "return_pc": "0x%x" % int(gdb.parse_and_eval("$rip")),
    "stack_delta": int(gdb.parse_and_eval("$rsp")) - entry_rsp,
    "registers": {
        name: int(gdb.parse_and_eval("$" + name)) & ((1 << 64) - 1)
        for name in ("rax", "rdi", "rsi")
    },
    "flags": {name: (flags >> bit) & 1 for name, bit in
              (("cf", 0), ("zf", 6), ("sf", 7), ("of", 11))},
}
if observed_instruction is not None:
    if observed_flags is None:
        raise RuntimeError("requested native instruction was not visited")
    result["observed_flags"] = observed_flags
print("HYDIR_NATIVE_RESULT=" + json.dumps(result, sort_keys=True))
end
