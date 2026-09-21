package hydir.ghidra;

import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Function;
import ghidra.program.util.ProgramLocation;

@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = "HydIR",
    category = PluginCategoryNames.ANALYSIS,
    shortDescription = "HydIR region decompilation and patching",
    description = "HydIR v2 region decompilation, PatchLang preview, verification, and apply workflow")
public final class HydIRPlugin extends ProgramPlugin {
    private final HydIRProvider provider;

    public HydIRPlugin(PluginTool tool) {
        super(tool);
        provider = new HydIRProvider(this, tool);
        provider.addToTool();
    }

    @Override
    protected void locationChanged(ProgramLocation location) {
        Function function = null;
        if (currentProgram != null && location != null) {
            function = currentProgram.getFunctionManager()
                .getFunctionContaining(location.getAddress());
        }
        provider.setFunction(function);
    }

    @Override
    protected void programClosed(ghidra.program.model.listing.Program program) {
        provider.setFunction(null);
        super.programClosed(program);
    }

    @Override
    protected void dispose() {
        provider.removeFromTool();
        super.dispose();
    }
}
