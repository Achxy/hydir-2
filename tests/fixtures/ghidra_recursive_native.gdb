set pagination off
set confirm off
set auto-load off
python
import gdb
import json
import os

snapshot = json.load(open(os.environ["HYDIR_RECURSIVE_SNAPSHOT"], encoding="utf-8"))
instructions = {
    int(row["address"]["offset"], 16): bytes.fromhex(row["parsed_bytes"])
    for row in snapshot["selected_function"]["instructions"]
}
entry = int(snapshot["selected_function"]["entry"]["offset"], 16)
return_address = int(os.environ["HYDIR_RECURSIVE_RETURN"], 16)
value = int(os.environ["HYDIR_RECURSIVE_ARG"])
mask = (1 << 64) - 1

gdb.execute("starti", to_string=True)
gdb.execute("set $rsp = $rsp - 8")
entry_rsp = int(gdb.parse_and_eval("$rsp"))
gdb.selected_inferior().write_memory(entry_rsp, return_address.to_bytes(8, "little"))
gdb.execute("set $rip = 0x%x" % entry)
gdb.execute("set $rdi = %d" % value)
gdb.execute("set $rax = 0")

steps = []
for _ in range(256):
    pc = int(gdb.parse_and_eval("$rip"))
    if pc == return_address and steps:
        break
    if pc not in instructions:
        raise RuntimeError("recursive native path left selected function at 0x%x" % pc)
    expected = instructions[pc]
    actual = bytes(gdb.selected_inferior().read_memory(pc, len(expected)))
    if actual != expected:
        raise RuntimeError("native bytes disagree with Ghidra at 0x%x" % pc)
    gdb.execute("si", to_string=True)
    steps.append({
        "address": "0x%x" % pc,
        "rax": int(gdb.parse_and_eval("$rax")) & mask,
        "rsp_delta": int(gdb.parse_and_eval("$rsp")) - entry_rsp,
        "return_slot": int.from_bytes(
            bytes(gdb.selected_inferior().read_memory(entry_rsp, 8)), "little"),
    })
else:
    raise RuntimeError("recursive native path exceeded instruction budget")

print("HYDIR_NATIVE_RESULT=" + json.dumps({
    "entry_rsp": entry_rsp,
    "steps": steps,
    "return_pc": "0x%x" % int(gdb.parse_and_eval("$rip")),
    "rax": int(gdb.parse_and_eval("$rax")) & mask,
    "rsp_delta": int(gdb.parse_and_eval("$rsp")) - entry_rsp,
}, sort_keys=True))
end
