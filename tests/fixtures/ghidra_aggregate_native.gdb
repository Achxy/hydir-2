set pagination off
set confirm off
set auto-load off
python
import gdb
import json
import os
import struct

snapshot = json.load(open(os.environ["HYDIR_NATIVE_SNAPSHOT"], encoding="utf-8"))
entry = int(snapshot["selected_function"]["entry"]["offset"], 16)
nodes = json.loads(os.environ["HYDIR_NATIVE_NODES"])
scale = int(os.environ["HYDIR_NATIVE_SCALE"])
gdb.execute("starti", to_string=True)
inferior = gdb.selected_inferior()
instructions = snapshot["selected_function"]["instructions"]
for row in instructions:
    address = int(row["address"]["offset"], 16)
    expected = bytes.fromhex(row["parsed_bytes"])
    if bytes(inferior.read_memory(address, len(expected))) != expected:
        raise RuntimeError("native bytes differ from snapshot at 0x%x" % address)

base = int(gdb.parse_and_eval("$rsp")) - 0x1000
for index, value in enumerate(nodes):
    next_address = base + (index + 1) * 0x20 if index + 1 < len(nodes) else 0
    inferior.write_memory(base + index * 0x20,
                          struct.pack("<i4xQ", value, next_address))
pointer = base if nodes else 0
expression = "((unsigned int (*)(unsigned long long,unsigned long long))0x%x)(0x%x,0x%x)" % (
    entry, pointer, scale)
result = int(gdb.parse_and_eval(expression))
print("HYDIR_NATIVE_RESULT=" + json.dumps({
    "result": result,
    "verified_instruction_bytes": len(instructions),
}, sort_keys=True))
end
