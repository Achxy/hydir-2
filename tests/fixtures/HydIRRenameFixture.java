// Reproduce the analyst edit in ghidra_userop_rdtsc_project.zip.
// Run with -postScript HydIRRenameFixture.java 0x201174 hydir_analyst_rdtsc.

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;

public class HydIRRenameFixture extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 2) {
            throw new IllegalArgumentException("expected function entry and analyst name");
        }
        Function function = getFunctionAt(toAddr(args[0]));
        if (function == null) {
            throw new IllegalStateException("fixture function is missing");
        }
        function.setName(args[1], SourceType.USER_DEFINED);
    }
}
