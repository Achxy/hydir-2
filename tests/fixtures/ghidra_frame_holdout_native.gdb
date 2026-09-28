set pagination off
set confirm off
set auto-load off
python
import gdb
import json
import os

root = json.load(open(os.environ["HYDIR_NATIVE_SNAPSHOT"], encoding="utf-8"))
step = json.load(open(os.environ["HYDIR_NATIVE_CALLEE_SNAPSHOT"], encoding="utf-8"))
frame = bytes.fromhex(os.environ["HYDIR_NATIVE_FRAME_HEX"])
entry = int(root["selected_function"]["entry"]["offset"], 16)
gdb.execute("starti", to_string=True)
inferior = gdb.selected_inferior()
for snapshot in (root, step):
    for row in snapshot["selected_function"]["instructions"]:
        address = int(row["address"]["offset"], 16)
        expected = bytes.fromhex(row["parsed_bytes"])
        if bytes(inferior.read_memory(address, len(expected))) != expected:
            raise RuntimeError("native instruction differs from Ghidra at 0x%x" % address)

base = int(gdb.parse_and_eval("$rsp")) - 0x1000
inferior.write_memory(base, frame)
expression = "((unsigned int (*)(unsigned long long,unsigned long long))0x%x)(0x%x,%u)" % (
    entry, base, len(frame))
result = int(gdb.parse_and_eval(expression))
print("HYDIR_NATIVE_RESULT=" + json.dumps({
    "result": result,
    "verified_instructions": sum(
        len(snapshot["selected_function"]["instructions"])
        for snapshot in (root, step)),
}, sort_keys=True))
end
