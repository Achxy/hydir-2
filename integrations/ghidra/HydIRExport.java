// HydIR Ghidra bridge: export bounded function, CFG, and call-graph facts.
//
// Run this as a Ghidra postScript or from the Script Manager. The first script
// argument is the output JSON path. The output is deliberately a small,
// versioned interchange format; it does not copy Ghidra project state.

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.block.CodeBlockReference;
import ghidra.program.model.block.CodeBlockReferenceIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import java.io.File;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class HydIRExport extends GhidraScript {
    private static String json(String value) {
        return "\"" + value.replace("\\", "\\\\")
            .replace("\"", "\\\"")
            .replace("\r", "\\r")
            .replace("\n", "\\n") + "\"";
    }

    private static String address(Address address) {
        return String.format("0x%016x", address.getOffset());
    }

    private static String comma(boolean first) {
        return first ? "" : ",";
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 1) {
            println("Usage: HydIRExport.java <output.json>");
            return;
        }

        FunctionIterator iterator = currentProgram.getFunctionManager().getFunctions(true);
        List<Function> functions = new ArrayList<>();
        while (iterator.hasNext()) {
            functions.add(iterator.next());
        }
        functions.sort(Comparator.comparing(function -> function.getEntryPoint().getOffset()));

        BasicBlockModel blocks = new BasicBlockModel(currentProgram);
        Set<String> cfgEdges = new HashSet<>();
        StringBuilder output = new StringBuilder();
        output.append("{\n");
        output.append("  \"schema_version\": 1,\n");
        output.append("  \"source\": \"ghidra\",\n");
        output.append("  \"program\": ").append(json(currentProgram.getName())).append(",\n");
        output.append("  \"functions\": [\n");

        boolean firstFunction = true;
        for (Function function : functions) {
            if (!firstFunction) output.append(",\n");
            firstFunction = false;
            output.append("    {\n");
            output.append("      \"name\": ").append(json(function.getName())).append(",\n");
            output.append("      \"entry\": ").append(json(address(function.getEntryPoint()))).append(",\n");
            output.append("      \"size\": ").append(function.getBody().getNumAddresses()).append(",\n");
            output.append("      \"blocks\": [\n");

            List<CodeBlock> functionBlocks = new ArrayList<>();
            CodeBlockIterator blockIterator = blocks.getCodeBlocks(function.getBody(), monitor);
            while (blockIterator.hasNext()) {
                functionBlocks.add(blockIterator.next());
            }
            functionBlocks.sort(Comparator.comparing(block -> block.getMinAddress().getOffset()));

            boolean firstBlock = true;
            for (CodeBlock block : functionBlocks) {
                if (!firstBlock) output.append(",\n");
                firstBlock = false;
                output.append("        {\n");
                output.append("          \"address\": ").append(json(address(block.getMinAddress()))).append(",\n");
                InstructionIterator instructions = currentProgram.getListing().getInstructions(block, true);
                String mnemonic = "<empty>";
                if (instructions.hasNext()) {
                    Instruction instruction = instructions.next();
                    mnemonic = instruction.getMnemonicString();
                }
                output.append("          \"mnemonic\": ").append(json(mnemonic)).append("\n");
                output.append("        }");

                CodeBlockReferenceIterator destinations = block.getDestinations(monitor);
                while (destinations.hasNext()) {
                    CodeBlockReference reference = destinations.next();
                    String edge = address(block.getMinAddress()) + "\u0000" + address(reference.getDestinationAddress());
                    cfgEdges.add(edge);
                }
            }
            output.append("\n      ],\n");
            output.append("      \"calls\": [");
            boolean firstCall = true;
            for (Function callee : function.getCalledFunctions(monitor)) {
                if (!firstCall) output.append(",");
                firstCall = false;
                output.append("{\"target\": ").append(json(address(callee.getEntryPoint()))).append("}");
            }
            output.append("]\n");
            output.append("    }");
        }
        output.append("\n  ],\n");
        output.append("  \"cfg_edges\": [\n");
        boolean firstEdge = true;
        for (String edge : cfgEdges) {
            String[] parts = edge.split("\\u0000", 2);
            if (!firstEdge) output.append(",\n");
            firstEdge = false;
            output.append("    {\"source\": ").append(json(parts[0]))
                .append(", \"target\": ").append(json(parts[1])).append("}");
        }
        output.append("\n  ],\n");
        output.append("  \"call_edges\": [\n");
        boolean firstCallEdge = true;
        for (Function function : functions) {
            for (Function callee : function.getCalledFunctions(monitor)) {
                if (!firstCallEdge) output.append(",\n");
                firstCallEdge = false;
                output.append("    {\"source\": ").append(json(address(function.getEntryPoint())))
                    .append(", \"target\": ").append(json(address(callee.getEntryPoint()))).append("}");
            }
        }
        output.append("\n  ]\n}\n");

        File destination = new File(args[0]);
        File parent = destination.getAbsoluteFile().getParentFile();
        if (parent != null) parent.mkdirs();
        try (PrintWriter writer = new PrintWriter(destination, "UTF-8")) {
            writer.print(output.toString());
        }
        println("HydIR graph export written to " + destination.getAbsolutePath());
    }
}
