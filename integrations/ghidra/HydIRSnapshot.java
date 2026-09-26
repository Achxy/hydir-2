// Hydir's thin Ghidra front end. All P-code validation and lifting lives in Rust.
// Run after analysis with: -postScript HydIRSnapshot.java <output.json> <binary> [entry-hex]

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.framework.Application;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.AbstractFloatDataType;
import ghidra.program.model.data.AbstractIntegerDataType;
import ghidra.program.model.data.Array;
import ghidra.program.model.data.BooleanDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.data.Union;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.pcode.VarnodeAST;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SourceType;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.Iterator;

public class HydIRSnapshot extends GhidraScript {
    // A snapshot is one function plus the program index. Exceeding a cap fails the
    // export; it never produces a plausible-looking partial analysis.
    private static final int MAX_FUNCTIONS = 65_536;
    private static final int MAX_ADDRESS_SPACES = 256;
    private static final int MAX_MEMORY_BLOCKS = 4_096;
    private static final int MAX_SYMBOLS = 65_536;
    private static final int MAX_PROTOTYPE_PARAMETERS = 256;
    private static final int MAX_PROTOTYPE_TEXT_BYTES = 4_096;
    private static final int MAX_PROTOTYPE_TYPE_DEPTH = 4;
    private static final int MAX_INSTRUCTIONS = 16_384;
    private static final int MAX_PCODE_OPS = 262_144;
    private static final int MAX_HIGH_PCODE_OPS = 16_384;
    private static final int MAX_HIGH_JSON_CHARS = 4 * 1024 * 1024;
    private static final int HIGH_DECOMPILE_TIMEOUT_SECONDS = 30;
    private static final int MAX_OPS_PER_INSTRUCTION = 256;
    private static final int MAX_INPUTS_PER_OP = 256;
    private static final int MAX_FLOW_TARGETS_PER_INSTRUCTION = 256;
    private static final int MAX_FLOW_EDGES = 262_144;
    private static final int MAX_INSTRUCTION_BYTES = 32;
    private static final int MAX_JSON_CHARS = 16 * 1024 * 1024;
    private static final int MAX_JSON_BYTES = 16 * 1024 * 1024;
    private static final char[] HEX = "0123456789abcdef".toCharArray();

    private static final class Json {
        private final StringBuilder value = new StringBuilder();

        Json raw(String text) {
            if (text.length() > MAX_JSON_CHARS - value.length()) {
                throw new IllegalStateException("HydIR snapshot exceeds JSON character limit");
            }
            value.append(text);
            return this;
        }

        Json quoted(String text) {
            if (text == null) {
                throw new IllegalArgumentException("Ghidra returned a null metadata string");
            }
            raw("\"");
            for (int i = 0; i < text.length(); i++) {
                char ch = text.charAt(i);
                switch (ch) {
                    case '\"': raw("\\\""); break;
                    case '\\': raw("\\\\"); break;
                    case '\b': raw("\\b"); break;
                    case '\f': raw("\\f"); break;
                    case '\n': raw("\\n"); break;
                    case '\r': raw("\\r"); break;
                    case '\t': raw("\\t"); break;
                    default:
                        // Escape all UTF-16 surrogate code units, including malformed
                        // unpaired ones, so the output remains valid ASCII JSON.
                        if (ch < 0x20 || ch >= 0x7f) {
                            raw(String.format("\\u%04x", (int) ch));
                        } else {
                            raw(String.valueOf(ch));
                        }
                }
            }
            return raw("\"");
        }

        Json address(Address address) {
            if (address == null) {
                throw new IllegalArgumentException("Ghidra returned a null address");
            }
            raw("{\"space\":").quoted(address.getAddressSpace().getName());
            raw(",\"offset\":").quoted(hex(address.getOffset()));
            return raw("}");
        }

        Json varnode(Varnode node) {
            if (node == null) {
                return raw("null");
            }
            if (node.getSize() <= 0) {
                throw new IllegalStateException("Ghidra returned a nonpositive varnode size");
            }
            raw("{\"space\":").quoted(node.getAddress().getAddressSpace().getName());
            raw(",\"offset\":").quoted(hex(node.getOffset()));
            return raw(",\"size\":" + node.getSize() + "}");
        }

        byte[] bytes() {
            byte[] bytes = value.toString().getBytes(StandardCharsets.UTF_8);
            if (bytes.length > MAX_JSON_BYTES) {
                throw new IllegalStateException("HydIR snapshot exceeds JSON byte limit");
            }
            return bytes;
        }
    }

    private static final class FlowEdge {
        final Address source;
        final Address target;
        final String kind;
        final boolean conditional;
        final boolean computed;

        FlowEdge(Address source, Address target, String kind, boolean conditional, boolean computed) {
            this.source = source;
            this.target = target;
            this.kind = kind;
            this.conditional = conditional;
            this.computed = computed;
        }

        void write(Json json) {
            json.raw("{\"source\":").address(source);
            json.raw(",\"target\":");
            if (target == null) json.raw("null");
            else json.address(target);
            json.raw(",\"kind\":").quoted(kind);
            json.raw(",\"conditional\":" + conditional);
            json.raw(",\"computed\":" + computed + "}");
        }
    }

    private static final class CallTarget {
        final Address source;
        final Address target;
        final boolean conditional;
        final boolean computed;

        CallTarget(Address source, Address target, boolean conditional, boolean computed) {
            this.source = source;
            this.target = target;
            this.conditional = conditional;
            this.computed = computed;
        }

        void write(Json json) {
            json.raw("{\"call_site\":").address(source);
            json.raw(",\"target\":");
            if (target == null) json.raw("null");
            else json.address(target);
            json.raw(",\"conditional\":" + conditional);
            json.raw(",\"computed\":" + computed + "}");
        }
    }

    private static void addFlow(List<FlowEdge> edges, Address source, Address target,
            String kind, boolean conditional, boolean computed) {
        if (edges.size() >= MAX_FLOW_EDGES) {
            throw new IllegalStateException("HydIR snapshot exceeds flow edge limit " + MAX_FLOW_EDGES);
        }
        edges.add(new FlowEdge(source, target, kind, conditional, computed));
    }

    private static void addCall(List<CallTarget> calls, Address source, Address target,
            boolean conditional, boolean computed) {
        if (calls.size() >= MAX_FLOW_EDGES) {
            throw new IllegalStateException("HydIR snapshot exceeds call target limit " + MAX_FLOW_EDGES);
        }
        calls.add(new CallTarget(source, target, conditional, computed));
    }

    private static String hex(long value) {
        return "0x" + Long.toUnsignedString(value, 16);
    }

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
            while ((count = input.read(buffer)) != -1) {
                digest.update(buffer, 0, count);
            }
        }
        return hex(digest.digest());
    }

    private static long functionSizeBytes(Function function) {
        long addresses = function.getBody().getNumAddresses();
        int unit = function.getEntryPoint().getAddressSpace().getAddressableUnitSize();
        if (unit <= 0 || addresses > Long.MAX_VALUE / unit) {
            throw new IllegalStateException("Function size overflow at " + function.getEntryPoint());
        }
        return addresses * unit;
    }

    private static String namespace(Symbol symbol) {
        Namespace parent = symbol.getParentNamespace();
        return parent == null ? "" : parent.getName(true);
    }

    private static String prototypeText(String text, String field) {
        if (text == null || text.isEmpty()
                || text.getBytes(StandardCharsets.UTF_8).length > MAX_PROTOTYPE_TEXT_BYTES) {
            throw new IllegalStateException("Ghidra " + field + " is missing or exceeds "
                + MAX_PROTOTYPE_TEXT_BYTES + " UTF-8 bytes");
        }
        for (int i = 0; i < text.length(); i++) {
            if (Character.isISOControl(text.charAt(i))) {
                throw new IllegalStateException("Ghidra " + field + " contains control characters");
            }
        }
        return text;
    }

    private static String typeKind(DataType dataType) {
        if (dataType instanceof Pointer) return "pointer";
        if (dataType instanceof Array) return "array";
        if (dataType instanceof Structure) return "struct";
        if (dataType instanceof Union) return "union";
        if (dataType instanceof ghidra.program.model.data.Enum) return "enum";
        if (dataType instanceof TypeDef) return "typedef";
        if (dataType instanceof AbstractIntegerDataType
                || dataType instanceof AbstractFloatDataType
                || dataType instanceof BooleanDataType
                || dataType instanceof VoidDataType) return "primitive";
        return "unknown";
    }

    private static void writeDataType(Json json, DataType dataType) {
        writeDataType(json, dataType, 0);
    }

    private static void writeDataType(Json json, DataType dataType, int depth) {
        if (dataType == null) {
            throw new IllegalStateException("Ghidra returned a null prototype data type");
        }
        int length = dataType.getLength();
        if (length < -1) {
            throw new IllegalStateException("Ghidra returned an invalid prototype data type size");
        }
        json.raw("{\"display_name\":")
            .quoted(prototypeText(dataType.getDisplayName(), "type display name"));
        json.raw(",\"path\":")
            .quoted(prototypeText(dataType.getPathName(), "type path"));
        json.raw(",\"size_bytes\":");
        if (length < 0) json.raw("null");
        else json.raw(Integer.toString(length));
        json.raw(",\"kind\":").quoted(typeKind(dataType));
        DataType target = null;
        if (dataType instanceof Pointer) target = ((Pointer) dataType).getDataType();
        else if (dataType instanceof Array) target = ((Array) dataType).getDataType();
        else if (dataType instanceof TypeDef) target = ((TypeDef) dataType).getDataType();
        boolean truncated = target != null && depth + 1 >= MAX_PROTOTYPE_TYPE_DEPTH;
        json.raw(",\"target_type\":");
        if (target == null || truncated) json.raw("null");
        else writeDataType(json, target, depth + 1);
        json.raw(",\"element_count\":");
        if (dataType instanceof Array) {
            int count = ((Array) dataType).getNumElements();
            if (count < 0) {
                throw new IllegalStateException("Ghidra returned a negative array element count");
            }
            json.raw(Integer.toString(count));
        } else {
            json.raw("null");
        }
        json.raw(",\"detail_truncated\":" + truncated);
        json.raw("}");
    }

    private static void writePrototype(Json json, Function function) {
        SourceType signatureSource = function.getSignatureSource();
        Parameter returned = function.getReturn();
        Parameter[] parameters = function.getParameters();
        if (signatureSource == null || returned == null || parameters == null) {
            throw new IllegalStateException("Ghidra returned an incomplete function signature");
        }
        if (parameters.length > MAX_PROTOTYPE_PARAMETERS) {
            throw new IllegalStateException("HydIR snapshot exceeds prototype parameter limit "
                + MAX_PROTOTYPE_PARAMETERS);
        }
        boolean sourced = signatureSource != SourceType.DEFAULT
            || returned.getSource() != SourceType.DEFAULT || function.hasVarArgs();
        for (Parameter parameter : parameters) {
            if (parameter.getSource() != SourceType.DEFAULT) sourced = true;
        }
        if (!sourced) return;

        json.raw(",\"prototype\":{\"signature_source\":")
            .quoted(signatureSource.name());
        json.raw(",\"calling_convention\":");
        String convention = function.getCallingConventionName();
        if (convention == null || convention.isEmpty()) json.raw("null");
        else json.quoted(prototypeText(convention, "calling convention"));
        json.raw(",\"has_varargs\":" + function.hasVarArgs());
        json.raw(",\"return_type\":");
        writeDataType(json, function.getReturnType());
        json.raw(",\"return_source\":").quoted(returned.getSource().name());
        json.raw(",\"parameters\":[");
        for (int i = 0; i < parameters.length; i++) {
            Parameter parameter = parameters[i];
            if (i != 0) json.raw(",");
            json.raw("{\"name\":").quoted(prototypeText(parameter.getName(), "parameter name"));
            json.raw(",\"data_type\":");
            writeDataType(json, parameter.getFormalDataType());
            json.raw(",\"source_type\":").quoted(parameter.getSource().name());
            json.raw(",\"auto_parameter\":" + parameter.isAutoParameter() + "}");
        }
        json.raw("]}");
    }

    // Decompiler P-code is analysis evidence: it may merge, remove, or create
    // operations and must never replace the instruction P-code above.
    private static void writeHighVarnode(Json json, Varnode node) {
        if (!(node instanceof VarnodeAST)) {
            throw new IllegalStateException("Decompiler returned a non-SSA varnode");
        }
        VarnodeAST ast = (VarnodeAST) node;
        json.raw("{\"varnode\":").varnode(node);
        json.raw(",\"ssa_id\":" + ast.getUniqueId());
        json.raw(",\"is_input\":" + ast.isInput());
        HighVariable high = ast.getHigh();
        json.raw(",\"high_name\":");
        if (high == null || high.getName() == null || high.getName().isEmpty()) {
            json.raw("null");
        } else {
            json.quoted(prototypeText(high.getName(), "high variable name"));
        }
        json.raw(",\"high_type\":");
        if (high == null || high.getDataType() == null) json.raw("null");
        else writeDataType(json, high.getDataType());
        json.raw("}");
    }

    private static String highPcodeStatus(String status, String detail) {
        Json result = new Json();
        result.raw("{\"source\":\"ghidra_decompiler\",\"simplification_style\":\"decompile\"");
        result.raw(",\"status\":").quoted(status);
        result.raw(",\"detail\":").quoted(detail);
        result.raw(",\"operations\":[]}");
        return result.value.toString();
    }

    private String writeHighPcode(Function function) throws Exception {
        DecompInterface decompiler = new DecompInterface();
        try {
            decompiler.toggleCCode(false);
            decompiler.setSimplificationStyle("decompile");
            if (!decompiler.openProgram(currentProgram)) {
                return highPcodeStatus("unavailable", "decompiler could not open program");
            }
            DecompileResults result = decompiler.decompileFunction(
                function, HIGH_DECOMPILE_TIMEOUT_SECONDS, monitor);
            monitor.checkCancelled();
            if (!result.decompileCompleted() || result.getHighFunction() == null) {
                return highPcodeStatus("unavailable", "decompilation did not complete");
            }
            HighFunction high = result.getHighFunction();
            Json evidence = new Json();
            evidence.raw("{\"source\":\"ghidra_decompiler\","
                + "\"simplification_style\":\"decompile\",\"status\":\"complete\","
                + "\"detail\":\"\",\"operations\":[");
            Iterator<PcodeOpAST> ops = high.getPcodeOps();
            int count = 0;
            while (ops.hasNext()) {
                monitor.checkCancelled();
                if (count >= MAX_HIGH_PCODE_OPS) {
                    return highPcodeStatus("omitted_limit", "high P-code operation limit exceeded");
                }
                PcodeOpAST op = ops.next();
                if (op.getNumInputs() > MAX_INPUTS_PER_OP) {
                    return highPcodeStatus("omitted_limit", "high P-code input limit exceeded");
                }
                if (count != 0) evidence.raw(",");
                evidence.raw("{\"index\":" + count);
                evidence.raw(",\"mnemonic\":").quoted(op.getMnemonic());
                evidence.raw(",\"opcode\":" + op.getOpcode());
                evidence.raw(",\"sequence_time\":" + op.getSeqnum().getTime());
                evidence.raw(",\"source_address\":").address(op.getSeqnum().getTarget());
                evidence.raw(",\"is_dead\":" + op.isDead());
                evidence.raw(",\"output\":");
                if (op.getOutput() == null) evidence.raw("null");
                else writeHighVarnode(evidence, op.getOutput());
                evidence.raw(",\"inputs\":[");
                for (int input = 0; input < op.getNumInputs(); input++) {
                    if (input != 0) evidence.raw(",");
                    writeHighVarnode(evidence, op.getInput(input));
                }
                evidence.raw("]}");
                count++;
                if (evidence.value.length() > MAX_HIGH_JSON_CHARS) {
                    return highPcodeStatus("omitted_limit", "high P-code JSON limit exceeded");
                }
            }
            evidence.raw("]}");
            return evidence.value.toString();
        } catch (RuntimeException invalid) {
            // A malformed decompiler hint must not prevent exporting raw semantics.
            return highPcodeStatus("unavailable", "decompiler evidence could not be serialized");
        } finally {
            decompiler.dispose();
        }
    }

    private Function selectFunction(List<Function> functions, String[] args) {
        if (args.length == 2) {
            for (Function function : functions) {
                if (function.getBody().getNumAddresses() > 0) {
                    return function;
                }
            }
            throw new IllegalStateException("No function with an analyzed body is available");
        }
        if (!args[2].matches("0[xX][0-9a-fA-F]{1,16}")) {
            throw new IllegalArgumentException("Function entry must be a 0x-prefixed hexadecimal offset");
        }
        long offset = Long.parseUnsignedLong(args[2].substring(2), 16);
        Function selected = null;
        for (Function function : functions) {
            if (function.getEntryPoint().getOffset() == offset) {
                if (selected != null) {
                    throw new IllegalArgumentException("Function entry is ambiguous across address spaces: " + args[2]);
                }
                selected = function;
            }
        }
        if (selected == null) {
            throw new IllegalArgumentException("Function entry not found: " + args[2]);
        }
        return selected;
    }

    private static void writeAtomically(Path output, byte[] bytes) throws Exception {
        Path absolute = output.toAbsolutePath();
        Path parent = absolute.getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }
        Path temporary = Files.createTempFile(parent, ".hydir-snapshot-", ".json.tmp");
        try {
            Files.write(temporary, bytes);
            try {
                Files.move(temporary, absolute, StandardCopyOption.ATOMIC_MOVE,
                    StandardCopyOption.REPLACE_EXISTING);
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
        if (args.length != 2 && args.length != 3) {
            throw new IllegalArgumentException(
                "Usage: HydIRSnapshot.java <output.json> <original-binary-path> [function-entry-hex]");
        }
        Path binary = Path.of(args[1]);
        if (!Files.isRegularFile(binary)) {
            throw new IllegalArgumentException("Original binary is not a regular file: " + binary);
        }
        Path output = Path.of(args[0]);
        if (Files.exists(output) && Files.isSameFile(output, binary)) {
            throw new IllegalArgumentException("Snapshot output must not replace the original binary");
        }
        String digest = sha256(binary);
        String importedDigest = currentProgram.getExecutableSHA256();
        if (importedDigest == null || importedDigest.isBlank()) {
            throw new IllegalStateException("Ghidra project has no recorded original binary SHA-256");
        }
        if (!importedDigest.equalsIgnoreCase(digest)) {
            throw new IllegalStateException("Original binary SHA-256 does not match the Ghidra project");
        }

        List<Function> functions = new ArrayList<>();
        FunctionIterator iterator = currentProgram.getFunctionManager().getFunctions(true);
        while (iterator.hasNext()) {
            monitor.checkCancelled();
            if (functions.size() >= MAX_FUNCTIONS) {
                throw new IllegalStateException("HydIR snapshot exceeds function limit " + MAX_FUNCTIONS);
            }
            functions.add(iterator.next());
        }
        functions.sort(Comparator.comparing(Function::getEntryPoint));
        if (functions.isEmpty()) {
            throw new IllegalStateException("Ghidra found no functions; run analysis before exporting");
        }
        Function selected = selectFunction(functions, args);

        Json json = new Json();
        json.raw("{\"schema_version\":2,\"source\":\"ghidra\","
            + "\"flow_overrides_applied\":true,\"binary_sha256\":")
            .quoted(digest);
        json.raw(",\"program\":{\"name\":").quoted(currentProgram.getName());
        json.raw(",\"ghidra_version\":").quoted(Application.getApplicationVersion());
        json.raw(",\"language_id\":").quoted(currentProgram.getLanguageID().toString());
        json.raw(",\"compiler_spec_id\":")
            .quoted(currentProgram.getCompilerSpec().getCompilerSpecID().toString());
        json.raw(",\"image_base\":").address(currentProgram.getImageBase());
        json.raw("},\"address_spaces\":[");
        AddressSpace[] spaces = currentProgram.getAddressFactory().getAllAddressSpaces();
        if (spaces.length > MAX_ADDRESS_SPACES) {
            throw new IllegalStateException("HydIR snapshot exceeds address-space limit "
                + MAX_ADDRESS_SPACES);
        }
        Arrays.sort(spaces, Comparator.comparing(AddressSpace::getName)
            .thenComparingInt(AddressSpace::getSpaceID));
        for (int i = 0; i < spaces.length; i++) {
            AddressSpace space = spaces[i];
            if (i != 0) json.raw(",");
            json.raw("{\"name\":").quoted(space.getName());
            json.raw(",\"id\":" + space.getSpaceID());
            json.raw(",\"type\":" + space.getType());
            json.raw(",\"addressable_unit_size\":" + space.getAddressableUnitSize());
            json.raw(",\"pointer_size\":" + space.getPointerSize() + "}");
        }
        json.raw("],\"memory_blocks\":[");
        MemoryBlock[] blocks = currentProgram.getMemory().getBlocks();
        if (blocks.length > MAX_MEMORY_BLOCKS) {
            throw new IllegalStateException("HydIR snapshot exceeds memory block limit "
                + MAX_MEMORY_BLOCKS);
        }
        Arrays.sort(blocks, Comparator
            .comparing((MemoryBlock block) -> block.getStart().getAddressSpace().getName())
            .thenComparing((left, right) -> Long.compareUnsigned(
                left.getStart().getOffset(), right.getStart().getOffset()))
            .thenComparing(MemoryBlock::getName));
        for (int i = 0; i < blocks.length; i++) {
            monitor.checkCancelled();
            MemoryBlock block = blocks[i];
            if (i != 0) json.raw(",");
            json.raw("{\"name\":").quoted(block.getName());
            json.raw(",\"start\":").address(block.getStart());
            json.raw(",\"end\":").address(block.getEnd());
            json.raw(",\"size\":" + block.getSize());
            json.raw(",\"read\":" + block.isRead());
            json.raw(",\"write\":" + block.isWrite());
            json.raw(",\"execute\":" + block.isExecute());
            json.raw(",\"initialized\":" + block.isInitialized());
            json.raw(",\"loaded\":" + block.isLoaded());
            json.raw(",\"overlay\":" + block.isOverlay());
            json.raw(",\"block_type\":").quoted(block.getType().toString());
            json.raw("}");
        }
        json.raw("],\"symbols\":[");
        List<Symbol> symbols = new ArrayList<>();
        SymbolIterator symbolIterator = currentProgram.getSymbolTable().getDefinedSymbols();
        while (symbolIterator.hasNext()) {
            monitor.checkCancelled();
            Symbol symbol = symbolIterator.next();
            Address address = symbol.getAddress();
            // Local-variable and namespace placeholders have no program memory
            // address. The snapshot covers program and external symbols only.
            if (address == null || (!address.isMemoryAddress() && !address.isExternalAddress())) {
                continue;
            }
            if (symbols.size() >= MAX_SYMBOLS) {
                throw new IllegalStateException("HydIR snapshot exceeds symbol limit " + MAX_SYMBOLS);
            }
            symbols.add(symbol);
        }
        symbols.sort(Comparator
            .comparing((Symbol symbol) -> symbol.getAddress().getAddressSpace().getName())
            .thenComparing((left, right) -> Long.compareUnsigned(
                left.getAddress().getOffset(), right.getAddress().getOffset()))
            .thenComparing(HydIRSnapshot::namespace)
            .thenComparing(symbol -> symbol.getName())
            .thenComparing(symbol -> symbol.getSymbolType().toString())
            .thenComparing(symbol -> symbol.getSource().name())
            .thenComparing(Symbol::isPrimary)
            .thenComparing(Symbol::isExternal));
        for (int i = 0; i < symbols.size(); i++) {
            monitor.checkCancelled();
            Symbol symbol = symbols.get(i);
            if (i != 0) json.raw(",");
            json.raw("{\"address\":").address(symbol.getAddress());
            json.raw(",\"name\":").quoted(symbol.getName());
            json.raw(",\"namespace\":").quoted(namespace(symbol));
            json.raw(",\"symbol_type\":").quoted(symbol.getSymbolType().toString());
            json.raw(",\"source_type\":").quoted(symbol.getSource().name());
            json.raw(",\"primary\":" + symbol.isPrimary());
            json.raw(",\"external\":" + symbol.isExternal());
            json.raw("}");
        }
        json.raw("],\"functions\":[");
        for (int i = 0; i < functions.size(); i++) {
            monitor.checkCancelled();
            Function function = functions.get(i);
            if (i != 0) json.raw(",");
            json.raw("{\"entry\":").address(function.getEntryPoint());
            json.raw(",\"name\":").quoted(function.getName());
            json.raw(",\"size\":" + functionSizeBytes(function));
            writePrototype(json, function);
            json.raw("}");
        }
        json.raw("],\"selected_function\":{\"entry\":").address(selected.getEntryPoint());
        json.raw(",\"instructions\":[");

        InstructionIterator instructions = currentProgram.getListing().getInstructions(selected.getBody(), true);
        int instructionCount = 0;
        int totalOps = 0;
        List<FlowEdge> flowEdges = new ArrayList<>();
        List<CallTarget> callTargets = new ArrayList<>();
        while (instructions.hasNext()) {
            monitor.checkCancelled();
            if (instructionCount >= MAX_INSTRUCTIONS) {
                throw new IllegalStateException("HydIR snapshot exceeds instruction limit " + MAX_INSTRUCTIONS);
            }
            Instruction instruction = instructions.next();
            // Raw instruction P-code with Ghidra's analyzed flow overrides.
            // This is distinct from decompiler high P-code.
            PcodeOp[] ops = instruction.getPcode(true);
            if (ops == null) {
                throw new IllegalStateException("Ghidra returned null P-code at " + instruction.getAddress());
            }
            if (ops.length > MAX_OPS_PER_INSTRUCTION) {
                throw new IllegalStateException("Instruction exceeds P-code op limit at "
                    + instruction.getAddress());
            }
            if (ops.length > MAX_PCODE_OPS - totalOps) {
                throw new IllegalStateException("HydIR snapshot exceeds P-code op limit " + MAX_PCODE_OPS);
            }
            byte[] bytes = instruction.getBytes();
            byte[] parsedBytes = instruction.getParsedBytes();
            if (bytes.length == 0 || bytes.length > MAX_INSTRUCTION_BYTES
                    || parsedBytes.length == 0 || parsedBytes.length > MAX_INSTRUCTION_BYTES) {
                throw new IllegalStateException("Instruction byte length is outside HydIR limits at "
                    + instruction.getAddress());
            }
            if (instructionCount++ != 0) json.raw(",");
            json.raw("{\"address\":").address(instruction.getAddress());
            json.raw(",\"bytes\":").quoted(hex(bytes));
            json.raw(",\"parsed_bytes\":").quoted(hex(parsedBytes));
            json.raw(",\"mnemonic\":").quoted(instruction.getMnemonicString());
            json.raw(",\"pcode\":[");
            for (int i = 0; i < ops.length; i++) {
                PcodeOp op = ops[i];
                if (i != 0) json.raw(",");
                json.raw("{\"mnemonic\":").quoted(op.getMnemonic());
                json.raw(",\"opcode\":" + op.getOpcode());
                json.raw(",\"sequence_index\":" + i);
                json.raw(",\"sequence_time\":" + op.getSeqnum().getTime());
                json.raw(",\"source_address\":").address(op.getSeqnum().getTarget());
                String useropName = null;
                if (op.getOpcode() == PcodeOp.CALLOTHER && op.getNumInputs() > 0) {
                    Varnode id = op.getInput(0);
                    if (id != null && id.isConstant()
                            && Long.compareUnsigned(id.getOffset(), Integer.MAX_VALUE) <= 0) {
                        useropName = currentProgram.getLanguage()
                            .getUserDefinedOpName((int) id.getOffset());
                    }
                }
                json.raw(",\"userop_name\":");
                if (useropName == null) json.raw("null");
                else json.quoted(useropName);
                json.raw(",\"output\":").varnode(op.getOutput());
                json.raw(",\"inputs\":[");
                if (op.getNumInputs() > MAX_INPUTS_PER_OP) {
                    throw new IllegalStateException("P-code op exceeds input limit at "
                        + instruction.getAddress());
                }
                for (int j = 0; j < op.getNumInputs(); j++) {
                    if (j != 0) json.raw(",");
                    Varnode input = op.getInput(j);
                    if (input == null) {
                        throw new IllegalStateException("Null P-code input at " + instruction.getAddress());
                    }
                    json.varnode(input);
                }
                json.raw("]}");
            }
            json.raw("]}");
            totalOps += ops.length;

            // Ghidra's analyzed instruction flow includes flow overrides and
            // references. Keep unresolved computed flows even when it also
            // reports candidate targets; the candidate list need not be complete.
            Address source = instruction.getAddress();
            Address fallthrough = instruction.getFallThrough();
            if (fallthrough != null) {
                addFlow(flowEdges, source,
                    Address.NO_ADDRESS.equals(fallthrough) ? null : fallthrough,
                    "fallthrough", false, false);
            }
            FlowType flowType = instruction.getFlowType();
            String flowKind = flowType.isCall() ? "call" : flowType.isJump() ? "branch" : "other";
            Address[] rawFlows = instruction.getFlows();
            if (rawFlows == null) rawFlows = new Address[0];
            if (rawFlows.length > MAX_FLOW_TARGETS_PER_INSTRUCTION) {
                throw new IllegalStateException("Instruction exceeds flow target limit at " + source);
            }
            List<Address> flows = new ArrayList<>();
            boolean unresolved = flowType.isComputed();
            for (Address target : rawFlows) {
                if (target == null || Address.NO_ADDRESS.equals(target)) {
                    unresolved = true;
                } else if (!flows.contains(target)) {
                    flows.add(target);
                }
            }
            flows.sort(Comparator.comparing(Address::toString));
            for (Address target : flows) {
                addFlow(flowEdges, source, target, flowKind,
                    flowType.isConditional(), flowType.isComputed());
                if (flowType.isCall()) {
                    addCall(callTargets, source, target,
                        flowType.isConditional(), flowType.isComputed());
                }
            }
            if (flows.isEmpty() && (flowType.isCall() || flowType.isJump())) {
                unresolved = true;
            }
            if (unresolved) {
                addFlow(flowEdges, source, null, flowKind,
                    flowType.isConditional(), flowType.isComputed());
                if (flowType.isCall()) {
                    addCall(callTargets, source, null,
                        flowType.isConditional(), flowType.isComputed());
                }
            }
        }
        if (instructionCount == 0) {
            throw new IllegalStateException("Selected function has no analyzed instructions: "
                + selected.getEntryPoint());
        }
        json.raw("],\"flow_edges\":[");
        for (int i = 0; i < flowEdges.size(); i++) {
            if (i != 0) json.raw(",");
            flowEdges.get(i).write(json);
        }
        json.raw("],\"call_targets\":[");
        for (int i = 0; i < callTargets.size(); i++) {
            if (i != 0) json.raw(",");
            callTargets.get(i).write(json);
        }
        json.raw("]");
        String highEvidence = writeHighPcode(selected);
        if (json.value.length() + highEvidence.length() + 19 <= MAX_JSON_CHARS) {
            json.raw(",\"high_pcode\":").raw(highEvidence);
        }
        json.raw("}}\n");
        writeAtomically(output, json.bytes());
        println("HydIR snapshot written to " + output.toAbsolutePath()
            + " (" + instructionCount + " instructions, " + totalOps + " raw P-code ops, "
            + flowEdges.size() + " flow edges, " + callTargets.size() + " call targets)");
    }
}
