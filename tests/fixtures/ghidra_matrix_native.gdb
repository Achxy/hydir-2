set pagination off
set confirm off
set auto-load off
python
import gdb
import json
import os

snapshot = json.load(open(os.environ["HYDIR_NATIVE_SNAPSHOT"], encoding="utf-8"))
entry = int(snapshot["selected_function"]["entry"]["offset"], 16)
kind = os.environ["HYDIR_MATRIX_KIND"]

# Start the exact generated ELF and verify the code bytes before invoking a
# selected function through GDB's inferior-call mechanism.
gdb.execute("starti", to_string=True)
inferior = gdb.selected_inferior()
instructions = snapshot["selected_function"]["instructions"]
for row in instructions:
    address = int(row["address"]["offset"], 16)
    expected = bytes.fromhex(row["parsed_bytes"])
    actual = bytes(inferior.read_memory(address, len(expected)))
    if actual != expected:
        raise RuntimeError("native bytes differ from snapshot at 0x%x" % address)

if kind == "add2":
    arg0 = int(os.environ["HYDIR_MATRIX_ARG0"], 16)
    arg1 = int(os.environ["HYDIR_MATRIX_ARG1"], 16)
    result_type = "unsigned long long"
elif kind == "equals":
    candidate = bytes.fromhex(os.environ["HYDIR_MATRIX_INPUT_HEX"])
    if len(candidate) != 12:
        raise RuntimeError("comparison input must contain 12 bytes")
    arg0 = int(gdb.parse_and_eval("$rsp")) - 0x1000
    inferior.write_memory(arg0, candidate)
    arg1 = int(os.environ["HYDIR_MATRIX_ARG1"], 16)
    result_type = "unsigned int"
else:
    raise RuntimeError("unknown native matrix function")

expression = "((%s (*)(unsigned long long,unsigned long long))0x%x)(0x%x,0x%x)" % (
    result_type, entry, arg0, arg1)
value = int(gdb.parse_and_eval(expression))
print("HYDIR_NATIVE_RESULT=" + json.dumps({
    "result": value,
    "verified_instruction_bytes": len(instructions),
}, sort_keys=True))
end
