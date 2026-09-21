package hydir.ghidra;

import java.nio.file.Path;
import java.util.List;

final class HydIRCommand {
    record Settings(String executable, String projectId, long revision) {
        Settings {
            if (executable == null || executable.isBlank()) {
                throw new IllegalArgumentException("hydirctl executable is required");
            }
            if (projectId == null || projectId.isBlank()) {
                throw new IllegalArgumentException("project ID is required");
            }
            if (revision < 0) {
                throw new IllegalArgumentException("revision cannot be negative");
            }
        }
    }

    private HydIRCommand() {
    }

    static List<String> project(Settings settings) {
        return List.of(settings.executable(), "remote", "project", settings.projectId());
    }

    static List<String> decompile(Settings settings, String symbol, Path output) {
        return List.of(
            settings.executable(), "remote", "decompile", settings.projectId(),
            Long.toUnsignedString(settings.revision()), symbol, "--assume-u64x2", "--output",
            output.toAbsolutePath().toString());
    }

    static List<String> preview(Settings settings, Path patch, Path bundle) {
        return List.of(
            settings.executable(), "remote", "patch-preview", settings.projectId(),
            Long.toUnsignedString(settings.revision()), patch.toAbsolutePath().toString(),
            "--trusted-fixture", "--assume-u64x2", "--assume-entry-only", "--output",
            bundle.toAbsolutePath().toString());
    }

    static List<String> apply(
            Settings settings, Path patch, String idempotencyKey, Path output) {
        return List.of(
            settings.executable(), "remote", "patch", settings.projectId(),
            Long.toUnsignedString(settings.revision()), patch.toAbsolutePath().toString(),
            idempotencyKey, "--trusted-fixture", "--assume-u64x2", "--assume-entry-only",
            "--output", output.toAbsolutePath().toString());
    }

    static String patchDocument(String binarySha256, String symbol, String replacement) {
        if (binarySha256 == null || !binarySha256.matches("[0-9a-f]{64}")) {
            throw new IllegalArgumentException("project binary SHA-256 is invalid");
        }
        return "{\n"
            + "  \"schema_version\": 1,\n"
            + "  \"binary_sha256\": \"" + binarySha256 + "\",\n"
            + "  \"function_symbol\": \"" + json(symbol) + "\",\n"
            + "  \"prototype\": \"u64(u64,u64)\",\n"
            + "  \"replacement\": \"" + json(replacement) + "\"\n"
            + "}\n";
    }

    static String binarySha256(String projectJson) {
        var matcher = java.util.regex.Pattern
            .compile("\\\"binary_sha256\\\"\\s*:\\s*\\\"([0-9a-f]{64})\\\"")
            .matcher(projectJson);
        if (!matcher.find()) {
            throw new IllegalArgumentException("project reply has no valid binary_sha256");
        }
        return matcher.group(1);
    }

    private static String json(String value) {
        if (value == null) {
            throw new IllegalArgumentException("JSON value is required");
        }
        var escaped = new StringBuilder();
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            switch (character) {
                case '\\' -> escaped.append("\\\\");
                case '"' -> escaped.append("\\\"");
                case '\n' -> escaped.append("\\n");
                case '\r' -> escaped.append("\\r");
                case '\t' -> escaped.append("\\t");
                default -> {
                    if (character < 0x20) {
                        escaped.append(String.format("\\u%04x", (int) character));
                    }
                    else {
                        escaped.append(character);
                    }
                }
            }
        }
        return escaped.toString();
    }
}
