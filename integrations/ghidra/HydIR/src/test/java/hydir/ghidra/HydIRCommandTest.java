package hydir.ghidra;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.nio.file.Path;
import org.junit.Test;

public class HydIRCommandTest {
    @Test
    public void commandsAreArgumentSeparatedAndVersioned() {
        var settings = new HydIRCommand.Settings("hydirctl", "project-1", 7);
        var command = HydIRCommand.preview(
            settings, Path.of("patch file.json"), Path.of("bundle file.json"));
        assertEquals("patch-preview", command.get(2));
        assertEquals("project-1", command.get(3));
        assertEquals("7", command.get(4));
        assertTrue(command.get(5).endsWith("patch file.json"));
    }

    @Test
    public void patchDocumentEscapesSourceAndRoundTripsProjectDigest() {
        var digest = "a".repeat(64);
        var document = HydIRCommand.patchDocument(
            digest, "symbol\\\"name", "u64 x = arg0;\nreturn x;");
        assertTrue(document.contains("symbol\\\\\\\"name"));
        assertTrue(document.contains("u64 x = arg0;\\nreturn x;"));
        assertEquals(digest, HydIRCommand.binarySha256("{\"binary_sha256\":\"" + digest + "\"}"));
    }
}
