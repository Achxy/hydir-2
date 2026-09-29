set pagination off
set confirm off
set auto-load off
python
import gdb
import json
import os

caller = json.load(open(os.environ["HYDIR_NATIVE_CALLER"], encoding="utf-8"))
callee = json.load(open(os.environ["HYDIR_NATIVE_CALLEE"], encoding="utf-8"))
instructions = {}
for snapshot in (caller, callee):
    for row in snapshot["selected_function"]["instructions"]:
        address = int(row["address"]["offset"], 16)
        if address in instructions:
            raise RuntimeError("overlapping selected-function instruction")
        instructions[address] = bytes.fromhex(row["parsed_bytes"])

entry = int(caller["selected_function"]["entry"]["offset"], 16)
leaf = int(callee["selected_function"]["entry"]["offset"], 16)
ret_address = int(os.environ["HYDIR_NATIVE_RETURN"], 16)
caller_ret = next(int(row["address"]["offset"], 16)
                  for row in caller["selected_function"]["instructions"]
                  if row["mnemonic"] == "RET")

gdb.execute("starti", to_string=True)
gdb.execute("set $rsp = $rsp - 8")
entry_rsp = int(gdb.parse_and_eval("$rsp"))
gdb.selected_inferior().write_memory(entry_rsp, ret_address.to_bytes(8, "little"))
gdb.execute("set $rip = 0x%x" % entry)
gdb.execute("set $rax = 0x%x" % leaf)

visits = []
for _ in range(16):
    pc = int(gdb.parse_and_eval("$rip"))
    if pc == ret_address and visits and visits[-1] == caller_ret:
        break
    if pc not in instructions:
        raise RuntimeError("native execution left selected caller/callee at 0x%x" % pc)
    expected = instructions[pc]
    actual = bytes(gdb.selected_inferior().read_memory(pc, len(expected)))
    if actual != expected:
        raise RuntimeError("native bytes at 0x%x differ from Ghidra snapshots" % pc)
    visits.append(pc)
    gdb.execute("si", to_string=True)
else:
    raise RuntimeError("native call path exceeded instruction budget")

result = {
    "instruction_visits": ["0x%x" % pc for pc in visits],
    "return_pc": "0x%x" % int(gdb.parse_and_eval("$rip")),
    "stack_delta": int(gdb.parse_and_eval("$rsp")) - entry_rsp,
    "rax": int(gdb.parse_and_eval("$rax")) & ((1 << 64) - 1),
}
print("HYDIR_NATIVE_RESULT=" + json.dumps(result, sort_keys=True))
end
