// Apply a byte-verified, bounded observed call or jump worklist in a disposable project.
// Run before HydIRSnapshot.java with: -postScript HydIRRediscover.java <worklist> <binary>

import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.List;

public class HydIRRediscover extends GhidraScript {
    private static final int MAX_TARGETS = 256;
    private static final int MAX_WORKLIST_BYTES = 64 * 1024;
    private static final char[] HEX = "0123456789abcdef".toCharArray();

    private static String hex(byte[] bytes) {
        char[] chars = new char[bytes.length * 2];
        for (int i = 0; i < bytes.length; i++) {
            int value = bytes[i] & 0xff;
            chars[i * 2] = HEX[value >>> 4];
            chars[i * 2 + 1] = HEX[value & 0xf];
        }
        return new String(chars);
    }

    private static String sha256(Path path) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (InputStream input = Files.newInputStream(path)) {
            byte[] buffer = new byte[64 * 1024];
            int count;
            while ((count = input.read(buffer)) != -1) digest.update(buffer, 0, count);
        }
        return hex(digest.digest());
    }

    private static Address address(AddressSpace ram, String text) {
        if (!text.matches("0x[0-9a-f]{1,16}")) {
            throw new IllegalArgumentException("Invalid observed control address: " + text);
        }
        return ram.getAddress(Long.parseUnsignedLong(text.substring(2), 16));
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 2) {
            throw new IllegalArgumentException("Usage: HydIRRediscover.java <worklist> <binary>");
        }
        Path worklist = Path.of(args[0]);
        Path binary = Path.of(args[1]);
        if (!Files.isRegularFile(worklist) || Files.size(worklist) > MAX_WORKLIST_BYTES
                || !Files.isRegularFile(binary)) {
            throw new IllegalArgumentException("Observed worklist or binary is unavailable or oversized");
        }
        String digest = sha256(binary);
        if (!digest.equalsIgnoreCase(currentProgram.getExecutableSHA256())) {
            throw new IllegalStateException("Observed binary does not match Ghidra project");
        }
        List<String> lines = Files.readAllLines(worklist, StandardCharsets.US_ASCII);
        if (lines.isEmpty()) throw new IllegalArgumentException("Observed worklist is empty");
        String[] header = lines.get(0).split("\\t", -1);
        boolean calls = header.length == 4 && header[0].equals("hydir-observed-calls-v1");
        boolean jumps = header.length == 4 && header[0].equals("hydir-observed-jumps-v1");
        if ((!calls && !jumps)
                || !header[1].equals(digest)
                || !header[3].matches("[1-9][0-9]{0,2}")) {
            throw new IllegalArgumentException("Observed worklist header is invalid");
        }
        int count = Integer.parseInt(header[3]);
        if (count > MAX_TARGETS || lines.size() != count + 1) {
            throw new IllegalArgumentException("Observed worklist exceeds target limit");
        }
        AddressSpace ram = currentProgram.getAddressFactory().getAddressSpace("ram");
        if (ram == null) throw new IllegalStateException("Ghidra project lacks ram space");
        Address selected = address(ram, header[2]);
        if (currentProgram.getFunctionManager().getFunctionAt(selected) == null) {
            throw new IllegalStateException("Selected observed function is absent");
        }
        AddressSet changed = new AddressSet();
        for (int index = 1; index < lines.size(); index++) {
            monitor.checkCancelled();
            String[] fields = lines.get(index).split("\\t", -1);
            if (fields.length != 4 || !fields[2].matches("(?:[0-9a-f]{2}){1,16}")
                    || !fields[3].matches("(?:[0-9a-f]{2}){1,16}")) {
                throw new IllegalArgumentException("Malformed observed entry " + index);
            }
            Address source = address(ram, fields[0]);
            Address target = address(ram, fields[1]);
            Instruction instruction = currentProgram.getListing().getInstructionAt(source);
            if (instruction == null || !(calls ? instruction.getFlowType().isCall()
                                             : instruction.getFlowType().isJump())
                    || !instruction.getFlowType().isComputed()
                    || !currentProgram.getFunctionManager().getFunctionAt(selected).getBody().contains(source)) {
                throw new IllegalStateException("Observed source is no longer a computed flow in selected function: " + source);
            }
            String parsed = hex(instruction.getParsedBytes());
            if (instruction.getLength() * 2 != fields[2].length() || !parsed.equals(fields[2])) {
                throw new IllegalStateException("Observed source bytes disagree with Ghidra: " + source);
            }
            MemoryBlock block = currentProgram.getMemory().getBlock(target);
            if (block == null || !block.isExecute() || !block.isInitialized()) {
                throw new IllegalStateException("Observed target is not executable Ghidra memory: " + target);
            }
            if (jumps && !currentProgram.getFunctionManager().getFunctionAt(selected).getBody().contains(target)) {
                throw new IllegalStateException("Observed jump target leaves selected function: " + target);
            }
            byte[] targetWitness = new byte[fields[3].length() / 2];
            if (currentProgram.getMemory().getBytes(target, targetWitness) != targetWitness.length
                    || !hex(targetWitness).equals(fields[3])) {
                throw new IllegalStateException("Observed target bytes disagree with Ghidra: " + target);
            }
            Address[] existing = instruction.getFlows();
            if (existing != null && Arrays.asList(existing).contains(target)) {
                throw new IllegalStateException("Observed target is already a static flow: " + source);
            }
            for (Reference reference : instruction.getMnemonicReferences()) {
                if (!reference.isMemoryReference()) {
                    throw new IllegalStateException("Cannot preserve mnemonic reference at " + source);
                }
            }
            currentProgram.getReferenceManager().addMemoryReference(
                source, target, calls ? RefType.COMPUTED_CALL : RefType.COMPUTED_JUMP,
                SourceType.USER_DEFINED, CodeUnit.MNEMONIC);
            changed.add(source);
            changed.add(target);
        }
        AutoAnalysisManager manager = AutoAnalysisManager.getAnalysisManager(currentProgram);
        manager.setIgnoreChanges(false);
        manager.reAnalyzeAll(changed);
        analyzeChanges(currentProgram);
        println("HydIR reanalyzed " + count + (calls ? " observed computed-call targets" : " observed computed-jump targets"));
    }
}
