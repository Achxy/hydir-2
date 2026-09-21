package hydir.ghidra;

import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Function;
import ghidra.util.Msg;
import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.GridLayout;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComponent;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;

final class HydIRProvider extends ComponentProviderAdapter {
    private static final int MAX_PROCESS_OUTPUT = 2 * 1024 * 1024;
    private static final Duration PROCESS_TIMEOUT = Duration.ofSeconds(60);

    private final JPanel panel = new JPanel(new BorderLayout(8, 8));
    private final JTextField executable = new JTextField("hydirctl");
    private final JTextField endpoint = new JTextField("http://127.0.0.1:50051");
    private final JTextField tokenFile = new JTextField();
    private final JTextField projectId = new JTextField();
    private final JTextField revision = new JTextField("1");
    private final JLabel functionLabel = new JLabel("No function selected");
    private final JLabel status = new JLabel("Configure a HydIR project and select a function");
    private final JTextArea decompilation = area(false);
    private final JTextArea patchSource = area(true);
    private final JTextArea patchPreview = area(false);
    private final JCheckBox trustedFixture =
        new JCheckBox("I am using a trusted fixture with u64(u64,u64) ABI");
    private final JCheckBox entryOnly =
        new JCheckBox("I assert no control flow enters the selected function interior");
    private final JButton decompileButton = new JButton("Decompile region");
    private final JButton previewButton = new JButton("Compile & verify preview");
    private final JButton applyButton = new JButton("Apply verified patch to copy");
    private volatile Function function;
    private volatile boolean previewCurrent;
    private volatile boolean running;

    HydIRProvider(HydIRPlugin plugin, PluginTool tool) {
        super(tool, "HydIR Region Workbench", plugin.getName());
        setTitle("HydIR Region Workbench");
        patchSource.setText("return arg0 - arg1;\n");
        buildUi();
        decompileButton.addActionListener(event -> decompile());
        previewButton.addActionListener(event -> preview());
        applyButton.addActionListener(event -> apply());
        trustedFixture.addActionListener(event -> refreshButtons());
        entryOnly.addActionListener(event -> refreshButtons());
        var invalidatesPreview = new SimpleDocumentListener(this::invalidatePreview);
        patchSource.getDocument().addDocumentListener(invalidatesPreview);
        executable.getDocument().addDocumentListener(invalidatesPreview);
        endpoint.getDocument().addDocumentListener(invalidatesPreview);
        tokenFile.getDocument().addDocumentListener(invalidatesPreview);
        projectId.getDocument().addDocumentListener(invalidatesPreview);
        revision.getDocument().addDocumentListener(invalidatesPreview);
        refreshButtons();
    }

    private static JTextArea area(boolean editable) {
        var result = new JTextArea();
        result.setEditable(editable);
        result.setLineWrap(false);
        result.setTabSize(4);
        return result;
    }

    private void buildUi() {
        var connection = new JPanel(new GridLayout(5, 2, 6, 4));
        connection.setBorder(BorderFactory.createTitledBorder("HydIR v2 connection"));
        connection.add(new JLabel("hydirctl"));
        connection.add(executable);
        connection.add(new JLabel("Local/TLS endpoint"));
        connection.add(endpoint);
        connection.add(new JLabel("Private token file"));
        connection.add(tokenFile);
        connection.add(new JLabel("Project ID"));
        connection.add(projectId);
        connection.add(new JLabel("Expected revision"));
        connection.add(revision);

        var top = new JPanel(new BorderLayout(6, 6));
        top.add(connection, BorderLayout.CENTER);
        var selection = new JPanel(new FlowLayout(FlowLayout.LEFT));
        selection.add(new JLabel("Selected function:"));
        selection.add(functionLabel);
        selection.add(decompileButton);
        top.add(selection, BorderLayout.SOUTH);
        panel.add(top, BorderLayout.NORTH);

        var patchControls = new JPanel(new GridLayout(0, 1, 4, 4));
        patchControls.add(trustedFixture);
        patchControls.add(entryOnly);
        var buttons = new JPanel(new FlowLayout(FlowLayout.LEFT));
        buttons.add(previewButton);
        buttons.add(applyButton);
        patchControls.add(buttons);

        var patchPanel = new JPanel(new BorderLayout(6, 6));
        patchPanel.add(patchControls, BorderLayout.NORTH);
        var patchSplit = new JSplitPane(
            JSplitPane.VERTICAL_SPLIT,
            new JScrollPane(patchSource),
            new JScrollPane(patchPreview));
        patchSplit.setResizeWeight(0.4);
        patchPanel.add(patchSplit, BorderLayout.CENTER);

        var tabs = new JTabbedPane();
        tabs.addTab("Decompiled C", new JScrollPane(decompilation));
        tabs.addTab("PatchLang / PatchBundle", patchPanel);
        panel.add(tabs, BorderLayout.CENTER);

        status.setBorder(BorderFactory.createEmptyBorder(4, 4, 4, 4));
        panel.add(status, BorderLayout.SOUTH);
    }

    @Override
    public JComponent getComponent() {
        return panel;
    }

    void setFunction(Function selected) {
        function = selected;
        previewCurrent = false;
        SwingUtilities.invokeLater(() -> {
            functionLabel.setText(selected == null
                ? "No function selected"
                : selected.getName() + " @ " + selected.getEntryPoint());
            refreshButtons();
        });
    }

    private ClientContext clientContext() {
        long expectedRevision;
        try {
            expectedRevision = Long.parseUnsignedLong(revision.getText().trim());
        }
        catch (NumberFormatException exception) {
            throw new IllegalArgumentException("Expected revision must be an unsigned integer");
        }
        var endpointValue = endpoint.getText().trim();
        var tokenFileValue = tokenFile.getText().trim();
        if (endpointValue.isBlank() || tokenFileValue.isBlank()) {
            throw new IllegalArgumentException("Endpoint and private token file are required");
        }
        return new ClientContext(
            new HydIRCommand.Settings(
                executable.getText().trim(), projectId.getText().trim(), expectedRevision),
            endpointValue,
            tokenFileValue);
    }

    private String symbol() {
        var selected = function;
        if (selected == null) {
            throw new IllegalArgumentException("Select an address inside a function");
        }
        return selected.getName();
    }

    private void decompile() {
        final ClientContext context;
        final String selected;
        try {
            context = clientContext();
            selected = symbol();
        }
        catch (IllegalArgumentException exception) {
            showError(exception.getMessage());
            return;
        }
        submit("Decompiling selected region", () -> {
            var output = Files.createTempFile("hydir-decompile-", ".c");
            try {
                run(context, HydIRCommand.decompile(context.settings(), selected, output));
                return Files.readString(output, StandardCharsets.UTF_8);
            }
            finally {
                Files.deleteIfExists(output);
            }
        }, decompilation::setText, false);
    }

    private void preview() {
        final ClientContext context;
        final String selected;
        final String source;
        try {
            requirePatchAssertions();
            context = clientContext();
            selected = symbol();
            source = patchSource.getText();
        }
        catch (IllegalArgumentException exception) {
            showError(exception.getMessage());
            return;
        }
        submit("Compiling and verifying PatchLang", () -> {
            var patch = Files.createTempFile("hydir-patch-", ".json");
            var bundle = Files.createTempFile("hydir-bundle-", ".json");
            Files.deleteIfExists(bundle);
            try {
                var project = run(context, HydIRCommand.project(context.settings()));
                var digest = HydIRCommand.binarySha256(project);
                Files.writeString(
                    patch,
                    HydIRCommand.patchDocument(digest, selected, source),
                    StandardCharsets.UTF_8);
                var verification =
                    run(context, HydIRCommand.preview(context.settings(), patch, bundle));
                var bundleJson = Files.readString(bundle, StandardCharsets.UTF_8);
                return verification + "\n\n" + bundleJson;
            }
            finally {
                Files.deleteIfExists(patch);
                Files.deleteIfExists(bundle);
            }
        }, text -> {
            patchPreview.setText(text);
            previewCurrent = true;
        }, true);
    }

    private void apply() {
        final ClientContext context;
        final String selected;
        final String source;
        final long nextRevision;
        try {
            requirePatchAssertions();
            context = clientContext();
            selected = symbol();
            source = patchSource.getText();
            nextRevision = Math.addExact(context.settings().revision(), 1);
        }
        catch (IllegalArgumentException | ArithmeticException exception) {
            showError(exception.getMessage());
            return;
        }
        if (!previewCurrent) {
            showError("Compile and verify the current PatchLang source before applying it");
            return;
        }
        var chooser = new JFileChooser();
        chooser.setDialogTitle("Write patched ELF to a new file");
        if (chooser.showSaveDialog(panel) != JFileChooser.APPROVE_OPTION) {
            return;
        }
        var destination = chooser.getSelectedFile().toPath().toAbsolutePath();
        submit("Applying verified patch", () -> {
            if (Files.exists(destination)) {
                throw new IllegalArgumentException("Output exists; HydIR never overwrites an ELF");
            }
            var patch = Files.createTempFile("hydir-patch-", ".json");
            try {
                var project = run(context, HydIRCommand.project(context.settings()));
                var digest = HydIRCommand.binarySha256(project);
                Files.writeString(
                    patch,
                    HydIRCommand.patchDocument(digest, selected, source),
                    StandardCharsets.UTF_8);
                return run(context, HydIRCommand.apply(
                    context.settings(), patch, UUID.randomUUID().toString(), destination));
            }
            finally {
                Files.deleteIfExists(patch);
            }
        }, text -> {
            patchPreview.setText(text + "\n\nSaved: " + destination);
            revision.setText(Long.toUnsignedString(nextRevision));
            previewCurrent = false;
        }, true);
    }

    private void requirePatchAssertions() {
        if (!trustedFixture.isSelected() || !entryOnly.isSelected()) {
            throw new IllegalArgumentException(
                "Trusted-fixture, u64 ABI, and entry-only assertions are required");
        }
    }

    private ProcessResult execute(ClientContext context, List<String> command) throws Exception {
        var builder = new ProcessBuilder(command);
        builder.environment().put("HYDIR_ENDPOINT", context.endpoint());
        builder.environment().put("HYDIR_TOKEN_FILE", context.tokenFile());
        builder.redirectErrorStream(true);
        var process = builder.start();
        var output = CompletableFuture.supplyAsync(() -> drain(process));
        if (!process.waitFor(PROCESS_TIMEOUT.toSeconds(), TimeUnit.SECONDS)) {
            process.destroyForcibly();
            throw new IOException("hydirctl exceeded the 60-second operation limit");
        }
        var bytes = output.get(5, TimeUnit.SECONDS);
        return new ProcessResult(process.exitValue(), new String(bytes, StandardCharsets.UTF_8));
    }

    private static byte[] drain(Process process) {
        try (var input = process.getInputStream(); var output = new ByteArrayOutputStream()) {
            var buffer = new byte[8192];
            long total = 0;
            for (int count; (count = input.read(buffer)) >= 0;) {
                if (total < MAX_PROCESS_OUTPUT) {
                    int retained = (int) Math.min(count, MAX_PROCESS_OUTPUT - total);
                    output.write(buffer, 0, retained);
                }
                total += count;
            }
            if (total > MAX_PROCESS_OUTPUT) {
                throw new IOException("hydirctl output exceeded 2 MiB");
            }
            return output.toByteArray();
        }
        catch (IOException exception) {
            throw new RuntimeException(exception);
        }
    }

    private String run(ClientContext context, List<String> command) throws Exception {
        var result = execute(context, command);
        if (result.exitCode() != 0) {
            throw new IOException(result.output().trim());
        }
        return result.output();
    }

    private void submit(
            String activity,
            CheckedSupplier action,
            Consumer<String> success,
            boolean invalidatesPreview) {
        if (running) {
            return;
        }
        running = true;
        status.setText(activity + "…");
        refreshButtons();
        Thread.ofVirtual().name("hydir-ghidra-operation").start(() -> {
            try {
                var result = action.get();
                SwingUtilities.invokeLater(() -> {
                    success.accept(result);
                    status.setText(activity + " completed");
                    running = false;
                    refreshButtons();
                });
            }
            catch (Exception exception) {
                SwingUtilities.invokeLater(() -> {
                    if (invalidatesPreview) {
                        previewCurrent = false;
                    }
                    running = false;
                    refreshButtons();
                    showError(exception.getMessage());
                });
            }
        });
    }

    private void refreshButtons() {
        boolean selected = function != null && !running;
        boolean assertions = trustedFixture.isSelected() && entryOnly.isSelected();
        decompileButton.setEnabled(selected);
        previewButton.setEnabled(selected && assertions);
        applyButton.setEnabled(selected && assertions && previewCurrent);
    }

    private void invalidatePreview() {
        previewCurrent = false;
        refreshButtons();
    }

    private void showError(String message) {
        var detail = message == null || message.isBlank() ? "HydIR operation failed" : message;
        status.setText(detail);
        Msg.showError(this, panel, "HydIR", detail);
    }

    private record ProcessResult(int exitCode, String output) {
    }

    private record ClientContext(
            HydIRCommand.Settings settings, String endpoint, String tokenFile) {
    }

    @FunctionalInterface
    private interface CheckedSupplier {
        String get() throws Exception;
    }
}
