// Bounded, independent Ghidra P-code emulator oracle for exact fixture checks.
// Run after analysis with:
// -postScript HydIROracle.java <output.json> <binary> <entry-hex> <max-steps>
//   <register-seeds> <memory-seeds> <register-watches> <memory-watches> [start-hex]

import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.PcodeOp;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class HydIROracle extends GhidraScript {
    private static final int MAX_STEPS = 256;
    private static final int MAX_ITEMS = 64;
    private static final int MAX_MEMORY_WIDTH = 8;
    private static final int MAX_OUTPUT_BYTES = 1024 * 1024;

    private record MemoryItem(Address address, int size) {}

    private static long parseHex(String text) {
        if (!text.matches("0x[0-9a-fA-F]{1,16}")) {
            throw new IllegalArgumentException("expected bounded 0x-prefixed hexadecimal value: " + text);
        }
        return Long.parseUnsignedLong(text.substring(2), 16);
    }

    private static String hex(long value) {
        return "0x" + Long.toUnsignedString(value, 16);
    }

    private static String hex(BigInteger value) {
        return "0x" + value.toString(16);
    }

    // HeadlessAnalyzer tokenizes punctuation in post-script arguments (including
    // '=', ';', and ','). Hex-encoded UTF-8 keeps each bounded list in one token.
    private static String decodeArg(String token) {
        if (!token.matches("h(?:[0-9a-fA-F]{2}){0,4096}")) {
            throw new IllegalArgumentException("oracle list argument must be h-prefixed UTF-8 hex");
        }
        return new String(java.util.HexFormat.of().parseHex(token.substring(1)), StandardCharsets.UTF_8);
    }

    private static String sha256(Path path) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (InputStream input = Files.newInputStream(path)) {
            byte[] buffer = new byte[64 * 1024];
            int count;
            while ((count = input.read(buffer)) != -1) digest.update(buffer, 0, count);
        }
        return java.util.HexFormat.of().formatHex(digest.digest());
    }

    private static void quoted(StringBuilder json, String value) {
        json.append('"');
        for (int i = 0; i < value.length(); i++) {
            char ch = value.charAt(i);
            if (ch == '"' || ch == '\\') json.append('\\').append(ch);
            else if (ch < 0x20 || ch >= 0x7f) json.append(String.format("\\u%04x", (int) ch));
            else json.append(ch);
        }
        json.append('"');
    }

    private static void addressJson(StringBuilder json, Address address) {
        json.append("{\"space\":");
        quoted(json, address.getAddressSpace().getName());
        json.append(",\"offset\":");
        quoted(json, hex(address.getOffset()));
        json.append('}');
    }

    private Register register(String name) {
        if (!name.matches("[A-Za-z][A-Za-z0-9_]{0,31}")) {
            throw new IllegalArgumentException("invalid register name");
        }
        Register register = currentProgram.getLanguage().getRegister(name);
        if (register == null || register.getBitLength() > 64 || register.getBitLength() == 0) {
            throw new IllegalArgumentException("unsupported register: " + name);
        }
        return register;
    }

    private Address ram(String value) {
        return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(parseHex(value));
    }

    private List<MemoryItem> memoryItems(String spec) {
        List<MemoryItem> items = new ArrayList<>();
        if (spec.isEmpty()) return items;
        for (String item : spec.split(";", -1)) {
            if (items.size() >= MAX_ITEMS) throw new IllegalArgumentException("too many memory items");
            String[] fields = item.split(":", -1);
            if (fields.length != 2) throw new IllegalArgumentException("memory watch format: address:size");
            int size = Integer.parseInt(fields[1]);
            if (size < 1 || size > MAX_MEMORY_WIDTH) throw new IllegalArgumentException("memory width exceeds 8");
            Address address = ram(fields[0]);
            if (Long.compareUnsigned(address.getOffset(), -1L - (size - 1)) > 0) {
                throw new IllegalArgumentException("memory watch overflows address space");
            }
            items.add(new MemoryItem(address, size));
        }
        return items;
    }

    private void seedRegisters(EmulatorHelper emulator, String spec) {
        if (spec.isEmpty()) return;
        Set<String> names = new HashSet<>();
        int count = 0;
        for (String item : spec.split(";", -1)) {
            if (++count > MAX_ITEMS) throw new IllegalArgumentException("too many register seeds");
            String[] fields = item.split("=", -1);
            if (fields.length != 2) throw new IllegalArgumentException("register seed format: NAME=0xVALUE");
            Register register = register(fields[0]);
            if (!names.add(register.getName())) throw new IllegalArgumentException("duplicate register seed");
            BigInteger value = new BigInteger(Long.toUnsignedString(parseHex(fields[1])));
            if (value.bitLength() > register.getBitLength()) {
                throw new IllegalArgumentException("register seed exceeds width: " + fields[0]);
            }
            emulator.writeRegister(register, value);
        }
    }

    private void seedMemory(EmulatorHelper emulator, String spec) {
        if (spec.isEmpty()) return;
        Set<Long> bytes = new HashSet<>();
        int count = 0;
        for (String item : spec.split(";", -1)) {
            if (++count > MAX_ITEMS) throw new IllegalArgumentException("too many memory seeds");
            String[] fields = item.split(":", -1);
            if (fields.length != 3) throw new IllegalArgumentException("memory seed format: address:size:value");
            MemoryItem memory = memoryItems(fields[0] + ":" + fields[1]).get(0);
            long value = parseHex(fields[2]);
            if (memory.size < 8 && (value >>> (memory.size * 8)) != 0) {
                throw new IllegalArgumentException("memory seed exceeds width");
            }
            byte[] littleEndian = new byte[memory.size];
            for (int i = 0; i < littleEndian.length; i++) {
                if (!bytes.add(memory.address.getOffset() + i)) {
                    throw new IllegalArgumentException("overlapping memory seeds");
                }
                littleEndian[i] = (byte) (value >>> (i * 8));
            }
            emulator.writeMemory(memory.address, littleEndian);
        }
    }

    private static long littleEndian(byte[] bytes) {
        long value = 0;
        for (int i = 0; i < bytes.length; i++) value |= (long) (bytes[i] & 0xff) << (8 * i);
        return value;
    }

    private static void writeAtomically(Path output, byte[] bytes) throws Exception {
        if (bytes.length > MAX_OUTPUT_BYTES) throw new IllegalStateException("oracle output too large");
        Path absolute = output.toAbsolutePath();
        Path parent = absolute.getParent();
        if (parent == null || !Files.isDirectory(parent)) throw new IllegalArgumentException("oracle output parent missing");
        Path temporary = Files.createTempFile(parent, ".hydir-oracle-", ".json");
        try {
            Files.write(temporary, bytes);
            try {
                Files.move(temporary, absolute, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            } catch (java.nio.file.AtomicMoveNotSupportedException unsupported) {
                Files.move(temporary, absolute, StandardCopyOption.REPLACE_EXISTING);
            }
        } finally {
            Files.deleteIfExists(temporary);
        }
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 8 && args.length != 9) {
            throw new IllegalArgumentException("Usage: HydIROracle.java <output.json> <binary> <entry-hex> <max-steps> <register-seeds> <memory-seeds> <register-watches> <memory-watches> [start-hex]");
        }
        Path binary = Path.of(args[1]);
        Path output = Path.of(args[0]);
        if (!Files.isRegularFile(binary) || (Files.exists(output) && Files.isSameFile(binary, output))) {
            throw new IllegalArgumentException("invalid original binary or oracle output path");
        }
        String digest = sha256(binary);
        if (!digest.equalsIgnoreCase(currentProgram.getExecutableSHA256())) {
            throw new IllegalStateException("original binary SHA-256 disagrees with Ghidra project");
        }
        if (!currentProgram.getLanguageID().getIdAsString().equals("x86:LE:64:default")) {
            throw new IllegalArgumentException("oracle currently requires x86:LE:64:default");
        }
        int maxSteps = Integer.parseInt(args[3]);
        if (maxSteps < 1 || maxSteps > MAX_STEPS) throw new IllegalArgumentException("step limit must be 1..256");
        Address entry = ram(args[2]);
        Function function = currentProgram.getFunctionManager().getFunctionAt(entry);
        if (function == null) throw new IllegalArgumentException("function entry not found in analyzed Ghidra program");
        Address start = args.length == 9 ? ram(args[8]) : entry;
        if (!function.getBody().contains(start) || currentProgram.getListing().getInstructionAt(start) == null) {
            throw new IllegalArgumentException("start must be an analyzed instruction in selected function");
        }
        String registerSeeds = decodeArg(args[4]);
        String memorySeeds = decodeArg(args[5]);
        String registerWatches = decodeArg(args[6]);
        String memoryWatches = decodeArg(args[7]);
        List<Register> watchedRegisters = new ArrayList<>();
        if (!registerWatches.isEmpty()) {
            for (String name : registerWatches.split(",", -1)) {
                if (watchedRegisters.size() >= MAX_ITEMS) throw new IllegalArgumentException("too many register watches");
                watchedRegisters.add(register(name));
            }
        }
        List<MemoryItem> watchedMemory = memoryItems(memoryWatches);
        StringBuilder json = new StringBuilder();
        json.append("{\"schema_version\":1,\"oracle\":\"ghidra_emulator_helper\",\"binary_sha256\":");
        quoted(json, digest);
        json.append(",\"language_id\":");
        quoted(json, currentProgram.getLanguageID().getIdAsString());
        json.append(",\"entry\":");
        addressJson(json, entry);
        json.append(",\"start\":");
        addressJson(json, start);
        json.append(",\"steps\":[");
        String stop = "step_budget";
        String reason = "bounded instruction step budget reached";
        EmulatorHelper emulator = new EmulatorHelper(currentProgram);
        try {
            seedRegisters(emulator, registerSeeds);
            seedMemory(emulator, memorySeeds);
            emulator.getEmulator().setExecuteAddress(start.getAddressableWordOffset());
            for (int step = 0; step < maxSteps; step++) {
                monitor.checkCancelled();
                Address pc = emulator.getExecutionAddress();
                if (pc == null || !function.getBody().contains(pc)) {
                    stop = "left_function";
                    reason = "next instruction is outside selected function";
                    break;
                }
                Instruction instruction = currentProgram.getListing().getInstructionAt(pc);
                if (instruction == null) {
                    stop = "undecoded_instruction";
                    reason = "Ghidra has no instruction at execution address";
                    break;
                }
                boolean unsupported = instruction.getFlowType().isCall();
                boolean returns = false;
                for (PcodeOp op : instruction.getPcode()) {
                    if (op.getOpcode() == PcodeOp.CALL || op.getOpcode() == PcodeOp.CALLIND || op.getOpcode() == PcodeOp.CALLOTHER) unsupported = true;
                    if (op.getOpcode() == PcodeOp.RETURN) returns = true;
                }
                if (unsupported) {
                    stop = "unsupported_effect";
                    reason = "call or CALLOTHER requires an external effect model";
                    break;
                }
                if (!emulator.step(monitor)) {
                    stop = "emulation_error";
                    reason = emulator.getLastError();
                    if (reason == null) reason = "Ghidra emulator step failed";
                    break;
                }
                if (step != 0) json.append(',');
                json.append("{\"address\":");
                addressJson(json, pc);
                json.append(",\"mnemonic\":");
                quoted(json, instruction.getMnemonicString());
                json.append(",\"next_address\":");
                addressJson(json, emulator.getExecutionAddress());
                json.append(",\"register_values\":[");
                for (int i = 0; i < watchedRegisters.size(); i++) {
                    if (i != 0) json.append(',');
                    BigInteger value = emulator.readRegister(watchedRegisters.get(i));
                    if (value == null) json.append("null"); else quoted(json, hex(value));
                }
                json.append("],\"memory_values\":[");
                for (int i = 0; i < watchedMemory.size(); i++) {
                    if (i != 0) json.append(',');
                    MemoryItem item = watchedMemory.get(i);
                    byte[] bytes = emulator.readMemory(item.address, item.size);
                    if (bytes == null || bytes.length != item.size) json.append("null");
                    else quoted(json, hex(littleEndian(bytes)));
                }
                json.append(']');
                json.append('}');
                if (returns) {
                    stop = "return";
                    reason = "RETURN P-code instruction executed";
                    break;
                }
                if (instruction.getFlowType().isTerminal()) {
                    stop = "terminal";
                    reason = "terminal instruction executed without RETURN P-code";
                    break;
                }
            }
            json.append("],\"stop\":{\"kind\":");
            quoted(json, stop);
            json.append(",\"reason\":");
            quoted(json, reason);
            json.append("},\"registers\":[");
            for (int i = 0; i < watchedRegisters.size(); i++) {
                if (i != 0) json.append(',');
                Register register = watchedRegisters.get(i);
                BigInteger value = emulator.readRegister(register);
                json.append("{\"name\":");
                quoted(json, register.getName());
                json.append(",\"offset\":");
                quoted(json, hex(register.getAddress().getOffset()));
                json.append(",\"size\":").append(register.getNumBytes());
                json.append(",\"value\":");
                if (value == null) json.append("null"); else quoted(json, hex(value));
                json.append('}');
            }
            json.append("],\"memory\":[");
            for (int i = 0; i < watchedMemory.size(); i++) {
                if (i != 0) json.append(',');
                MemoryItem item = watchedMemory.get(i);
                byte[] bytes = emulator.readMemory(item.address, item.size);
                json.append("{\"address\":");
                addressJson(json, item.address);
                json.append(",\"size\":").append(item.size);
                json.append(",\"value\":");
                if (bytes == null || bytes.length != item.size) json.append("null");
                else quoted(json, hex(littleEndian(bytes)));
                json.append('}');
            }
            json.append("]}");
        } finally {
            emulator.dispose();
        }
        writeAtomically(output, json.toString().getBytes(StandardCharsets.UTF_8));
    }
}
