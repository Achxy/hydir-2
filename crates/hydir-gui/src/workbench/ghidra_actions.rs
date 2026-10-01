//! Existing Ghidra analysis actions, grouped by the active workbench view.
use super::ghidra::{FridaPane, GhidraPane, LlvmPane, TracePane};
use super::*;

impl AnalystApp {
    pub(super) fn ghidra_action_view(&mut self, ui: &mut egui::Ui) {
        let Some(snapshot) = &self.ghidra_snapshot else {
            return;
        };
        let address_map = self
            .spec
            .as_ref()
            .and_then(|spec| GhidraAddressMap::new(snapshot, spec));
        let pane = self.shell.ghidra.pane;
        let mut requested = None;
        let mut path_trace_task = None;
        if pane == GhidraPane::Metadata {
            ui.label(
                RichText::new(format!(
                    "Ghidra {} · {} · {}",
                    snapshot.program.ghidra_version,
                    snapshot.program.language_id,
                    snapshot.program.compiler_spec_id
                ))
                .strong(),
            );
            ui.label(
                RichText::new(format!("SHA-256 {}", snapshot.binary_sha256))
                    .monospace()
                    .size(11.0)
                    .color(MUTED),
            );
            ui.separator();
            if !snapshot.memory_blocks.is_empty() {
                egui::CollapsingHeader::new(format!(
                    "Ghidra memory map ({})",
                    snapshot.memory_blocks.len()
                ))
                .id_salt("ghidra_memory_blocks")
                .default_open(true)
                .show(ui, |ui| {
                    ui.label(
                        RichText::new(
                            "Analyzed Ghidra ranges and permissions; these are project evidence.",
                        )
                        .size(11.0)
                        .color(MUTED),
                    );
                    egui::ScrollArea::vertical()
                        .id_salt("ghidra_memory_block_rows")
                        .max_height(160.0)
                        .show_rows(ui, 26.0, snapshot.memory_blocks.len(), |ui, range| {
                            for row in range {
                                let block = &snapshot.memory_blocks[row];
                                let address = address_map.as_ref().and_then(|map| {
                                    map.to_linked(&block.start.space, &block.start.offset)
                                });
                                let label = format!(
                                    "{} {}:{}..{} · {} bytes · {}{}{} · {}",
                                    block.name,
                                    block.start.space,
                                    block.start.offset,
                                    block.end.offset,
                                    block.size,
                                    if block.read { "r" } else { "-" },
                                    if block.write { "w" } else { "-" },
                                    if block.execute { "x" } else { "-" },
                                    if block.initialized {
                                        "initialized"
                                    } else {
                                        "uninitialized"
                                    }
                                );
                                if ui
                                    .add_enabled(
                                        address.is_some(),
                                        egui::Button::selectable(
                                            address.is_some() && self.selected_address == address,
                                            RichText::new(label).monospace().size(11.0),
                                        ),
                                    )
                                    .clicked()
                                {
                                    self.selected_address = address;
                                }
                            }
                        });
                });
            }
            if !snapshot.symbols.is_empty() {
                egui::CollapsingHeader::new(format!("Ghidra symbols ({})", snapshot.symbols.len()))
                    .id_salt("ghidra_symbols")
                    .default_open(true)
                    .show(ui, |ui| {
                        ui.label(
                            RichText::new(
                                "Defined program and external symbols with Ghidra source evidence.",
                            )
                            .size(11.0)
                            .color(MUTED),
                        );
                        egui::ScrollArea::vertical()
                            .id_salt("ghidra_symbol_rows")
                            .max_height(160.0)
                            .show_rows(ui, 26.0, snapshot.symbols.len(), |ui, range| {
                                for row in range {
                                    let symbol = &snapshot.symbols[row];
                                    let address = address_map.as_ref().and_then(|map| {
                                        map.to_linked(&symbol.address.space, &symbol.address.offset)
                                    });
                                    let label = format!(
                                        "{}:{} {}::{} · {} · {}",
                                        symbol.address.space,
                                        symbol.address.offset,
                                        symbol.namespace,
                                        symbol.name,
                                        symbol.symbol_type,
                                        symbol.source_type
                                    );
                                    if ui
                                        .add_enabled(
                                            address.is_some(),
                                            egui::Button::selectable(
                                                address.is_some()
                                                    && self.selected_address == address,
                                                RichText::new(label).monospace().size(11.0),
                                            ),
                                        )
                                        .clicked()
                                    {
                                        self.selected_address = address;
                                    }
                                }
                            });
                    });
            }
        }
        if pane == GhidraPane::Coverage {
            if let Some(report) = &self.ghidra_capability {
                egui::CollapsingHeader::new(format!(
                "Function capability: {} operations · {} conditions/stops",
                report.operations,
                report.stop_sites.len() + report.omitted_stop_sites
            ))
            .id_salt("ghidra_pcode_capability")
            .default_open(true)
            .show(ui, |ui| {
                ui.label(RichText::new("Static capability estimate; execution needs a concrete state. Function equivalence is unverified.")
                    .size(11.0).color(MUTED));
                ui.label(RichText::new(format!(
                    "Discovery: {} instruction nodes, {} known edges, {} unresolved nodes · complete: {}",
                    report.discovery.instruction_nodes, report.discovery.known_edges,
                    report.discovery.unresolved_nodes, report.discovery.complete
                )).monospace().size(11.0));
                ui.label(RichText::new(format!(
                    "Execution: {} exact values, {} conditional memory, {} conditional control, {} stopping operations",
                    report.execution.exact_value_operations,
                    report.execution.conditional_memory_operations,
                    report.execution.conditional_control_operations,
                    report.execution.stopping_operations
                )).monospace().size(11.0));
                ui.label(RichText::new(format!(
                    "Memory: {} reads, {} writes ({} / {} conditional) · calls: {} direct targets, {} unresolved",
                    report.memory.reads, report.memory.writes,
                    report.memory.conditional_reads, report.memory.conditional_writes,
                    report.calls.direct_targets, report.calls.unresolved_targets
                )).monospace().size(11.0));
                egui::ScrollArea::vertical().id_salt("ghidra_capability_stop_sites")
                    .max_height(160.0)
                    .show_rows(ui, 18.0, report.stop_sites.len(), |ui, range| {
                        for row in range {
                            let site = &report.stop_sites[row];
                            let address = address_map.as_ref().and_then(|map| {
                                map.to_linked(&site.address.space, &site.address.offset)
                            });
                            let sequence = site.sequence_index.map_or(String::new(), |index| format!(" #{index}"));
                            let label = format!("{}{} {}: {}", site.address.offset,
                                sequence, site.mnemonic, site.reason);
                            if ui.selectable_label(address.is_some() && self.selected_address == address,
                                RichText::new(label).monospace().size(11.0)).clicked() {
                                    if address.is_some() { self.selected_address = address; }
                            }
                        }
                    });
                if report.omitted_stop_sites > 0 {
                    ui.label(RichText::new(format!("{} more sites omitted", report.omitted_stop_sites))
                        .size(11.0).color(MUTED));
                }
            });
            }
            if let Some(report) = &self.ghidra_coverage {
                egui::CollapsingHeader::new(format!(
                "P-code coverage: {} exact assignments / {} operations",
                report.exact_assignments, report.operations
            ))
            .id_salt("ghidra_pcode_coverage")
            .default_open(true)
            .show(ui, |ui| {
                ui.label(RichText::new("Counts describe Hydir's P-code value lowering. They are not a machine-code equivalence claim.")
                    .size(11.0).color(MUTED));
                for row in &report.by_opcode {
                    ui.label(RichText::new(format!(
                        "{:>3} {:<18} {:>5} total · {:>5} exact · {:>5} opaque",
                        row.opcode, row.mnemonic, row.operations,
                        row.exact_assignments, row.opaque_effects
                    )).monospace().size(11.0));
                }
                if report.omitted_opaque_sites > 0 {
                    ui.label(RichText::new(format!("{} additional opaque sites omitted from this view", report.omitted_opaque_sites))
                        .size(11.0).color(MUTED));
                }
                egui::ScrollArea::vertical().id_salt("ghidra_coverage_opaque_sites")
                    .max_height(140.0)
                    .show_rows(ui, 18.0, report.opaque_sites.len(), |ui, range| {
                        for row in range {
                            let site = &report.opaque_sites[row];
                            let address = address_map.as_ref().and_then(|map| {
                                map.to_linked(&site.address.space, &site.address.offset)
                            });
                            let label = format!("{} #{} {}: {}", site.address.offset,
                                site.sequence_index, site.mnemonic, site.reason);
                            if ui.selectable_label(address.is_some() && self.selected_address == address,
                                RichText::new(label).monospace().size(11.0)).clicked() {
                                    if address.is_some() { self.selected_address = address; }
                                }
                        }
                    });
            });
            }
            if let Some(semantics) = &self.ghidra_semantics {
                let exact = semantics
                    .instructions
                    .iter()
                    .flat_map(|instruction| &instruction.operations)
                    .filter(|operation| matches!(operation.effect, PcodeEffect::Assign { .. }))
                    .count();
                let opaque = semantics.diagnostics.len();
                ui.label(
                RichText::new(format!(
                    "Rust semantic pass: {exact} exact operations · {opaque} opaque operations · function equivalence unverified"
                ))
                .size(11.0)
                .color(if opaque == 0 { GOOD } else { ACCENT }),
            );
                if opaque > 0 {
                    egui::CollapsingHeader::new(format!("Opaque effect diagnostics ({opaque})"))
                        .id_salt("ghidra_semantic_diagnostics")
                        .default_open(true)
                        .show(ui, |ui| {
                            for diagnostic in semantics.diagnostics.iter().take(30) {
                                ui.label(
                                    RichText::new(format!(
                                        "{}:{} #{} · {}",
                                        diagnostic.source_address.space,
                                        diagnostic.source_address.offset,
                                        diagnostic.sequence_index,
                                        diagnostic.message
                                    ))
                                    .monospace()
                                    .size(11.0)
                                    .color(BAD),
                                );
                            }
                            if opaque > 30 {
                                ui.label(
                                    RichText::new(format!(
                                        "{} more; all are marked in the Raw P-code view",
                                        opaque - 30
                                    ))
                                    .size(11.0)
                                    .color(MUTED),
                                );
                            }
                        });
                }
            }
        }
        if pane == GhidraPane::Llvm && self.shell.ghidra.llvm == LlvmPane::Operations {
            let mut selected_exact = None;
            egui::CollapsingHeader::new(format!("LLVM for exact operations ({})", self.ghidra_exact_operations.len()))
            .id_salt("ghidra_exact_llvm")
            .default_open(true)
            .show(ui, |ui| {
                ui.label(RichText::new("Each selection emits one P-code value operation. This is not a whole-function lift.")
                    .size(11.0).color(MUTED));
                egui::ScrollArea::vertical().id_salt("ghidra_exact_llvm_rows")
                    .max_height(120.0)
                    .show_rows(ui, 18.0, self.ghidra_exact_operations.len(), |ui, range| {
                        for row in range {
                            let (instruction_index, operation_index, address) = self.ghidra_exact_operations[row];
                            if let Some(semantic) = self.ghidra_semantics.as_ref()
                                && let Some(instruction) = semantic.instructions.get(instruction_index)
                                && let Some(operation) = instruction.operations.get(operation_index) {
                                let label = format!("{}:{}  #{} {}", instruction.address.space,
                                    instruction.address.offset, operation_index, operation.source.mnemonic);
                                let linked = address.and_then(|value| address_map.as_ref()
                                    .and_then(|map| map.to_linked_raw(value)));
                                if ui.selectable_label(linked.is_some() && self.selected_address == linked,
                                    RichText::new(label).monospace().size(11.0)).clicked() {
                                    selected_exact = Some((instruction_index, operation_index, linked));
                                }
                            }
                        }
                    });
                if let Some(llvm) = &self.ghidra_llvm_operation {
                    if ui.button("Copy LLVM operation").clicked() {
                        ui.ctx().copy_text(llvm.clone());
                    }
                    egui::ScrollArea::both().id_salt("ghidra_exact_llvm_source")
                        .max_height(180.0).show(ui, |ui| {
                            ui.label(RichText::new(llvm).monospace().size(11.0));
                        });
                }
            });
            if let Some((instruction_index, operation_index, address)) = selected_exact {
                self.selected_address = address;
                self.ghidra_llvm_operation = self
                    .ghidra_semantics
                    .as_ref()
                    .and_then(|semantic| semantic.instructions.get(instruction_index))
                    .and_then(|instruction| instruction.operations.get(operation_index))
                    .map(|operation| {
                        emit_pcode_exact_operation_llvm(operation)
                            .unwrap_or_else(|error| format!("LLVM emission failed: {error}"))
                    });
            }
        }
        if pane == GhidraPane::Trace && self.shell.ghidra.trace == TracePane::Path {
            egui::CollapsingHeader::new("Concrete path trace")
            .id_salt("ghidra_concrete_path")
            .default_open(true)
            .show(ui, |ui| {
                ui.label(RichText::new("Seed known register or RAM bytes, then follow one bounded path. Unknown values and unsupported effects stop explicitly; the trace is not a whole-function proof.")
                    .size(11.0).color(MUTED));
                if self.ghidra_trace_memory_mode == "readonly"
                    && self.current_local_path.is_some()
                    && PcodeReadOnlyElfImage::has_eligible_blocks(snapshot)
                {
                    ui.label(RichText::new("File-backed read-only ELF bytes are loaded automatically; seed input and mutable RAM bytes.")
                        .size(11.0).color(MUTED));
                }
                ui.horizontal(|ui| {
                    ui.label("Start instruction");
                    if ui.text_edit_singleline(&mut self.ghidra_trace_start).changed() {
                        self.ghidra_path_trace = None;
                        self.frida_path_comparison = None;
                        self.ghidra_path_lines.clear();
                        self.ghidra_llvm_cfg = None;
                        self.ghidra_llvm_image_cfg = None;
                        self.ghidra_llvm_simplified = None;
                    }
                    if let Some(address) = selected_ghidra_trace_address(
                        snapshot,
                        address_map.as_ref(),
                        self.selected_address,
                    ) && ui.button("Use selected").clicked() {
                            self.ghidra_trace_start = format!("0x{address:x}");
                            self.ghidra_path_trace = None;
                            self.frida_path_comparison = None;
                            self.ghidra_path_lines.clear();
                            self.ghidra_llvm_cfg = None;
                            self.ghidra_llvm_image_cfg = None;
                            self.ghidra_llvm_simplified = None;
                        }
                });
                ui.label(RichText::new("Seed JSON · offsets and values use 0x hexadecimal")
                    .size(11.0).color(MUTED));
                    if ui.add(egui::TextEdit::multiline(&mut self.ghidra_trace_seed_json)
                    .code_editor().desired_rows(8).desired_width(f32::INFINITY)).changed() {
                        self.ghidra_path_trace = None;
                        self.frida_path_comparison = None;
                        self.ghidra_path_lines.clear();
                        self.ghidra_call_trace = None;
                        self.ghidra_call_lines.clear();
                        self.ghidra_assessment = None;
                        self.ghidra_call_llvm = None;
                        if let Some(task) = &self.ghidra_call_llvm_task {
                            task.cancel.store(true, Ordering::Release);
                        }
                    }
                let prior_memory_mode = self.ghidra_trace_memory_mode.clone();
                egui::ComboBox::from_label("Memory")
                    .selected_text(self.ghidra_trace_memory_mode.as_str())
                    .show_ui(ui, |ui| {
                        ui.selectable_value(&mut self.ghidra_trace_memory_mode,
                            "readonly".to_owned(), "Read-only ELF + seed");
                        ui.selectable_value(&mut self.ghidra_trace_memory_mode,
                            "process".to_owned(), "ELF writable data + .bss + seed");
                        ui.selectable_value(&mut self.ghidra_trace_memory_mode,
                            "allocated".to_owned(), "ELF + declared stack/heap");
                        ui.selectable_value(&mut self.ghidra_trace_memory_mode,
                            "seed".to_owned(), "Seed only");
                    });
                if self.ghidra_trace_memory_mode != prior_memory_mode {
                    self.ghidra_path_trace = None;
                    self.ghidra_path_lines.clear();
                    self.frida_path_comparison = None;
                    self.ghidra_llvm_image_cfg = None;
                }
                if self.ghidra_trace_memory_mode == "allocated" {
                    ui.label(RichText::new("Allocation declaration v1 · at most one stack and one heap range. Seed bytes give initial values; declaring a range alone does not make bytes known.")
                        .size(11.0).color(MUTED));
                    if ui.add(egui::TextEdit::multiline(&mut self.ghidra_allocation_json)
                        .code_editor().desired_rows(4).desired_width(f32::INFINITY)).changed() {
                        self.ghidra_path_trace = None;
                        self.ghidra_path_lines.clear();
                        self.frida_path_comparison = None;
                        self.ghidra_llvm_image_cfg = None;
                    }
                    if self.ghidra_allocation_json.len() > MAX_PCODE_PROCESS_ALLOCATIONS_JSON_BYTES {
                        ui.label(RichText::new("Allocation JSON exceeds the 4 KiB limit.")
                            .size(11.0).color(BAD));
                    }
                }
                if ui.add_enabled(!self.busy && !self.ghidra_busy, egui::Button::new("Trace path")).clicked() {
                    self.ghidra_path_trace = None;
                    self.frida_path_comparison = None;
                    self.ghidra_path_lines.clear();
                    path_trace_task = Some(Task::TraceGhidraPath {
                        snapshot: Box::new(snapshot.clone()),
                        seed_json: self.ghidra_trace_seed_json.clone(),
                        start_text: self.ghidra_trace_start.clone(),
                        memory_mode: self.ghidra_trace_memory_mode.clone(),
                        allocation_json: self.ghidra_allocation_json.clone(),
                    });
                }
                match &self.ghidra_path_trace {
                    Some(Ok(trace)) => {
                        let stop = serde_json::to_value(&trace.stop).unwrap_or_default();
                        let kind = stop.get("kind").and_then(serde_json::Value::as_str)
                            .unwrap_or("unknown");
                        ui.label(RichText::new(format!("{} instruction visits · {} events · stop: {kind}",
                            trace.instruction_visits.len(), trace.events.len()))
                            .size(11.0).color(ACCENT));
                        if ui.button("Copy trace JSON").clicked()
                            && let Ok(json) = serde_json::to_string_pretty(trace) {
                                ui.ctx().copy_text(json);
                            }
                        egui::CollapsingHeader::new("Stop detail")
                            .id_salt("ghidra_trace_stop_detail")
                            .default_open(true)
                            .show(ui, |ui| {
                                ui.label(RichText::new(stop.to_string()).monospace().size(11.0));
                            });
                        egui::ScrollArea::vertical().id_salt("ghidra_trace_events")
                            .max_height(180.0)
                            .show_rows(ui, 18.0, self.ghidra_path_lines.len(), |ui, range| {
                                for row in range {
                                    let (address, line) = &self.ghidra_path_lines[row];
                                    let linked = address.and_then(|value| address_map.as_ref()
                                        .and_then(|map| map.to_linked_raw(value)));
                                    if ui.selectable_label(linked.is_some() && self.selected_address == linked,
                                        RichText::new(line).monospace().size(11.0)).clicked() {
                                            if linked.is_some() { self.selected_address = linked; }
                                        }
                                }
                            });
                    }
                    Some(Err(error)) => {
                        ui.label(RichText::new(error).size(11.0).color(BAD));
                    }
                    None => {}
                }
            });
        }
        if pane == GhidraPane::Trace && self.shell.ghidra.trace == TracePane::Calls {
            egui::CollapsingHeader::new("Call trace")
            .id_salt("ghidra_direct_call_trace")
            .default_open(true)
            .show(ui, |ui| {
                ui.label(RichText::new("Use the seed configured in Trace > Path to follow direct calls and concrete indirect targets through automatically analyzed functions. Unknown targets, missing callees, recursion, and budget limits stop explicitly.")
                    .size(11.0).color(MUTED));
                let can_trace = !self.ghidra_busy
                    && !self.ghidra_call_busy
                    && !self.ghidra_call_llvm_busy
                    && self.current_local_path.is_some();
                if ui.add_enabled(can_trace, egui::Button::new("Trace calls")).clicked() {
                    let result = parse_pcode_seed(
                        self.ghidra_trace_seed_json.as_bytes(), snapshot,
                    );
                    match result {
                        Err(error) => {
                            self.ghidra_call_trace = Some(Err(error));
                            self.ghidra_call_lines.clear();
                        }
                        Ok(_) => {
                            let cancel = Arc::new(AtomicBool::new(false));
                            let timeout = ghidra_task_timeout(
                                self.ghidra_runtime_status.as_ref().map(|status| status.mode),
                                true,
                            );
                            let task = Task::TraceGhidraCalls {
                                binary: self.current_local_path.clone().expect("checked above"),
                                binary_sha256: snapshot.binary_sha256.clone(),
                                function: snapshot.selected_function.entry.offset.clone(),
                                seed_json: self.ghidra_trace_seed_json.clone(),
                                allocation_json: (self.ghidra_trace_memory_mode == "allocated")
                                    .then(|| self.ghidra_allocation_json.clone()),
                                cancel: Arc::clone(&cancel),
                                timeout,
                            };
                            match self.tasks.try_send(task) {
                                Ok(()) => {
                                    self.ghidra_call_busy = true;
                                    self.ghidra_call_task = Some(ActiveGhidraTask {
                                        cancel,
                                        started: Instant::now(),
                                        timeout,
                                    });
                                    self.ghidra_call_trace = None;
                                    self.ghidra_call_lines.clear();
                                    self.status = "Collecting Ghidra callees and tracing…".to_owned();
                                }
                                Err(_) => {
                                    self.ghidra_call_trace = Some(Err(
                                        "Analysis queue is full. Retry the call trace.".to_owned(),
                                    ));
                                }
                            }
                        }
                    }
                }
                if self.ghidra_call_busy {
                    if let Some(task) = &self.ghidra_call_task {
                        ghidra_progress(ui, task, "Analyzing callees");
                        if ui
                            .add_enabled(
                                !task.cancel.load(Ordering::Acquire),
                                egui::Button::new("Cancel call trace"),
                            )
                            .clicked()
                        {
                            task.cancel.store(true, Ordering::Release);
                            self.status = "Stopping Ghidra call trace…".to_owned();
                        }
                    }
                }
                match &self.ghidra_call_trace {
                    Some(Ok(trace)) => {
                        let stop = serde_json::to_value(&trace.stop).unwrap_or_default();
                        let kind = stop.get("kind")
                            .and_then(serde_json::Value::as_str)
                            .unwrap_or("unknown");
                        ui.label(RichText::new(format!(
                            "Trace v{} · {} calls · {} function segments · {} visits · stop: {kind}",
                            trace.schema_version, trace.calls.len(), trace.segments.len(), trace.instruction_visits
                        )).size(11.0).color(ACCENT));
                        if let Some(binding) = &trace.process_binding {
                            ui.label(RichText::new(format!(
                                "Shared ELF process {} · {} declared allocations",
                                binding.process_memory_sha256,
                                binding.allocations.regions().len(),
                            )).monospace().size(11.0).color(MUTED));
                        }
                        if ui.button("Copy call trace JSON").clicked()
                            && let Ok(json) = serde_json::to_string_pretty(trace) {
                                ui.ctx().copy_text(json);
                            }
                        for diagnostic in &trace.snapshot_diagnostics {
                            ui.label(RichText::new(diagnostic).size(11.0).color(BAD));
                        }
                        egui::CollapsingHeader::new("Stop detail")
                            .id_salt("ghidra_call_stop_detail")
                            .default_open(true)
                            .show(ui, |ui| {
                                ui.label(RichText::new(stop.to_string()).monospace().size(11.0));
                            });
                        egui::ScrollArea::vertical().id_salt("ghidra_call_events")
                            .max_height(220.0)
                            .show_rows(ui, 18.0, self.ghidra_call_lines.len(), |ui, range| {
                                for row in range {
                                    let (address, line) = &self.ghidra_call_lines[row];
                                    let linked = address.and_then(|value| address_map.as_ref()
                                        .and_then(|map| map.to_linked_raw(value)));
                                    if ui.selectable_label(
                                        linked.is_some() && self.selected_address == linked,
                                        RichText::new(line).monospace().size(11.0),
                                    ).clicked() && linked.is_some() {
                                        self.selected_address = linked;
                                    }
                                }
                            });
                    }
                    Some(Err(error)) => {
                        ui.label(RichText::new(error).size(11.0).color(BAD));
                    }
                    None => {}
                }
            });
        }
        if pane == GhidraPane::Trace && self.shell.ghidra.trace == TracePane::Assessment {
            egui::CollapsingHeader::new("Seeded lift assessment")
            .id_salt("ghidra_function_assessment")
            .default_open(true)
            .show(ui, |ui| {
                ui.label(RichText::new("Checks the supplied seed against reached memory effects and available callees. LLVM emission is reported separately; equivalence has not been verified.")
                    .size(11.0).color(MUTED));
                let can_assess = !self.ghidra_busy
                    && !self.ghidra_call_busy
                    && !self.ghidra_call_llvm_busy
                    && self.current_local_path.is_some();
                if ui.add_enabled(can_assess, egui::Button::new("Assess seeded lift")).clicked() {
                    match parse_pcode_seed(self.ghidra_trace_seed_json.as_bytes(), snapshot) {
                        Err(error) => self.ghidra_assessment = Some(Err(error)),
                        Ok(_) => {
                            let cancel = Arc::new(AtomicBool::new(false));
                            let timeout = ghidra_task_timeout(
                                self.ghidra_runtime_status.as_ref().map(|status| status.mode),
                                true,
                            );
                            let task = Task::AssessGhidra {
                                binary: self.current_local_path.clone().expect("checked above"),
                                binary_sha256: snapshot.binary_sha256.clone(),
                                function: snapshot.selected_function.entry.offset.clone(),
                                seed_json: self.ghidra_trace_seed_json.clone(),
                                cancel: Arc::clone(&cancel),
                                timeout,
                            };
                            match self.tasks.try_send(task) {
                                Ok(()) => {
                                    self.ghidra_call_busy = true;
                                    self.ghidra_call_task = Some(ActiveGhidraTask {
                                        cancel,
                                        started: Instant::now(),
                                        timeout,
                                    });
                                    self.ghidra_assessment = None;
                                    self.status = "Assessing seeded Ghidra lift…".to_owned();
                                }
                                Err(_) => self.ghidra_assessment = Some(Err(
                                    "Analysis queue is full. Retry the assessment.".to_owned(),
                                )),
                            }
                        }
                    }
                }
                match &self.ghidra_assessment {
                    Some(Ok(assessment)) => {
                        let stop = serde_json::to_value(&assessment.trace.stop).unwrap_or_default();
                        let kind = stop.get("kind").and_then(serde_json::Value::as_str)
                            .unwrap_or("unknown");
                        ui.label(RichText::new(format!(
                            "{} reached calls · {} reached memory effects · stop: {kind}",
                            assessment.calls.iter().filter(|call| call.reached).count(),
                            assessment.memory_witnesses.len() + assessment.omitted_memory_witnesses,
                        )).size(11.0).color(ACCENT));
                        ui.label(RichText::new(if assessment.llvm.emitted {
                            "LLVM module emitted; execution and equivalence unverified".to_owned()
                        } else {
                            format!("LLVM emission stopped: {}",
                                assessment.llvm.error.as_deref().unwrap_or("unknown reason"))
                        }).size(11.0).color(MUTED));
                        if ui.button("Copy assessment JSON").clicked()
                            && let Ok(json) = serde_json::to_string_pretty(assessment) {
                                ui.ctx().copy_text(json);
                            }
                        for call in assessment.calls.iter().take(32) {
                            let linked = parse_ghidra_offset(&call.call_site.offset)
                                .and_then(|address| address_map.as_ref()
                                    .and_then(|map| map.to_linked_raw(address)));
                            let label = format!("{} → {} · {}{}",
                                call.call_site.offset,
                                call.target.as_ref().map_or("unknown", |target| target.offset.as_str()),
                                if call.snapshot_loaded { "callee loaded" } else { "callee missing" },
                                if call.reached { " · reached" } else { "" });
                            if ui.selectable_label(linked.is_some() && self.selected_address == linked,
                                RichText::new(label).monospace().size(11.0)).clicked()
                                && linked.is_some() {
                                self.selected_address = linked;
                            }
                        }
                        for witness in assessment.memory_witnesses.iter().take(32) {
                            let linked = parse_ghidra_offset(&witness.source.offset)
                                .and_then(|address| address_map.as_ref()
                                    .and_then(|map| map.to_linked_raw(address)));
                            let label = format!("{} · {:?} {}:0x{:x} ({} bytes)",
                                witness.source.offset, witness.access.kind,
                                witness.access.space, witness.access.byte_offset,
                                witness.access.width_bytes);
                            if ui.selectable_label(linked.is_some() && self.selected_address == linked,
                                RichText::new(label).monospace().size(11.0)).clicked()
                                && linked.is_some() {
                                self.selected_address = linked;
                            }
                        }
                    }
                    Some(Err(error)) => { ui.label(RichText::new(error).size(11.0).color(BAD)); }
                    None => {}
                }
            });
        }
        if pane == GhidraPane::Llvm && self.shell.ghidra.llvm == LlvmPane::Calls {
            egui::CollapsingHeader::new("LLVM across analyzed calls")
            .id_salt("ghidra_call_llvm")
            .default_open(true)
            .show(ui, |ui| {
                ui.label(RichText::new("Uses the seed configured in Trace > Path to collect reached callees, then emits a bounded LLVM CFG across those functions. Unknown calls, unsupported effects, recursion, and budget limits remain explicit stops. Binary equivalence is unverified.")
                    .size(11.0).color(MUTED));
                let can_generate = !self.ghidra_busy
                    && !self.ghidra_call_busy
                    && !self.ghidra_call_llvm_busy
                    && self.current_local_path.is_some();
                let generate = ui.add_enabled(can_generate, egui::Button::new("Generate call CFG LLVM")).clicked();
                let generate_imports = ui.add_enabled(
                    can_generate && self.ghidra_trace_memory_mode == "allocated",
                    egui::Button::new("Generate LLVM with import contracts"),
                ).clicked();
                if generate || generate_imports {
                    match parse_pcode_seed(self.ghidra_trace_seed_json.as_bytes(), snapshot) {
                        Err(error) => self.ghidra_call_llvm = Some(Err(error)),
                        Ok(_) => {
                            let cancel = Arc::new(AtomicBool::new(false));
                            let timeout = ghidra_task_timeout(
                                self.ghidra_runtime_status.as_ref().map(|status| status.mode),
                                true,
                            );
                            let task = Task::EmitGhidraCallLlvm {
                                binary: self.current_local_path.clone().expect("checked above"),
                                binary_sha256: snapshot.binary_sha256.clone(),
                                function: snapshot.selected_function.entry.offset.clone(),
                                seed_json: self.ghidra_trace_seed_json.clone(),
                                allocation_json: (self.ghidra_trace_memory_mode == "allocated")
                                    .then(|| self.ghidra_allocation_json.clone()),
                                assume_import_contracts: generate_imports,
                                cancel: Arc::clone(&cancel),
                                timeout,
                            };
                            match self.tasks.try_send(task) {
                                Ok(()) => {
                                    self.ghidra_call_llvm_busy = true;
                                    self.ghidra_call_llvm_task = Some(ActiveGhidraTask {
                                        cancel,
                                        started: Instant::now(),
                                        timeout,
                                    });
                                    self.ghidra_call_llvm = None;
                                    self.status = "Collecting Ghidra callees and generating LLVM…".to_owned();
                                }
                                Err(_) => self.ghidra_call_llvm = Some(Err(
                                    "Analysis queue is full. Retry call CFG LLVM generation.".to_owned(),
                                )),
                            }
                        }
                    }
                }
                if self.ghidra_call_llvm_busy
                    && let Some(task) = &self.ghidra_call_llvm_task {
                        ghidra_progress(ui, task, "Generating call CFG LLVM");
                        if ui.add_enabled(
                            !task.cancel.load(Ordering::Acquire),
                            egui::Button::new("Cancel call CFG LLVM"),
                        ).clicked() {
                            task.cancel.store(true, Ordering::Release);
                            self.status = "Stopping Ghidra call LLVM generation…".to_owned();
                        }
                    }
                match &self.ghidra_call_llvm {
                    Some(Ok(artifact)) => {
                        ui.label(RichText::new(format!(
                            "Call CFG v{} / LLVM v{} · {} loaded functions · {} source operations · {} static stop sites · max call depth {} · fidelity: {:?} · verification: {:?}",
                            artifact.schema_version,
                            artifact.llvm.schema_version,
                            artifact.function_entries.len(),
                            artifact.llvm.source_operations.len(),
                            artifact.llvm.stop_sites.len(),
                            artifact.max_call_depth,
                            artifact.semantic_fidelity,
                            artifact.verification,
                        )).size(11.0).color(ACCENT));
                        if let Some(allocations) = &artifact.llvm.allocations {
                            ui.label(RichText::new(format!(
                                "Shared ELF process and {} declared allocations",
                                allocations.regions().len(),
                            )).size(11.0).color(MUTED));
                        }
                        if artifact.schema_version == 3 {
                            ui.label(RichText::new("ELF JUMP_SLOT names assume a conforming runtime binding; this LLVM module is not an equivalence proof.")
                                .size(11.0).color(MUTED));
                            for call in &artifact.import_calls {
                                let address = address_map.as_ref().and_then(|map|
                                    map.to_linked(&call.call_site.space, &call.call_site.offset));
                                if ui.selectable_label(
                                    address.is_some() && self.selected_address == address,
                                    RichText::new(format!("{} → {} (assumed binding)",
                                        call.call_site.offset, call.name)).monospace().size(11.0),
                                ).clicked() && address.is_some() {
                                    self.selected_address = address;
                                }
                            }
                        }
                        ui.label(RichText::new("Runnable path module; execution can stop at the listed boundaries. The generated code has not been verified against the binary.")
                            .size(11.0).color(MUTED));
                        for diagnostic in &artifact.snapshot_diagnostics {
                            ui.label(RichText::new(diagnostic).size(11.0).color(BAD));
                        }
                        egui::CollapsingHeader::new(format!("Loaded functions ({})", artifact.function_entries.len()))
                            .id_salt("ghidra_call_llvm_functions")
                            .default_open(true)
                            .show(ui, |ui| {
                                for entry in &artifact.function_entries {
                                    let address = address_map.as_ref().and_then(|map|
                                        map.to_linked(&entry.space, &entry.offset));
                                    if ui.selectable_label(address.is_some() && self.selected_address == address,
                                        RichText::new(&entry.offset).monospace().size(11.0)).clicked()
                                        && address.is_some() {
                                            self.selected_address = address;
                                        }
                                }
                            });
                        ui.horizontal(|ui| {
                            if ui.button("Copy call CFG artifact JSON").clicked()
                                && let Ok(json) = serde_json::to_string_pretty(artifact) {
                                    ui.ctx().copy_text(json);
                                }
                            if ui.button("Copy call CFG LLVM").clicked() {
                                ui.ctx().copy_text(artifact.llvm.llvm_ir.clone());
                            }
                        });
                        egui::CollapsingHeader::new(format!("Linked source operations ({})", artifact.llvm.source_operations.len()))
                            .id_salt("ghidra_call_llvm_operations")
                            .default_open(true)
                            .show(ui, |ui| {
                                egui::ScrollArea::vertical().max_height(180.0)
                                    .id_salt("ghidra_call_llvm_operation_rows")
                                    .show_rows(ui, 18.0, artifact.llvm.source_operations.len(), |ui, range| {
                                        for row in range {
                                            let operation = &artifact.llvm.source_operations[row];
                                            let address = address_map.as_ref().and_then(|map|
                                                map.to_linked(&operation.address.space, &operation.address.offset));
                                            let label = format!("{} #{}:{} {}{}", operation.address.offset,
                                                operation.instruction_index, operation.operation_index, operation.mnemonic,
                                                operation.userop_name.as_ref().map(|name| format!(" ({name})")).unwrap_or_default());
                                            if ui.selectable_label(address.is_some() && self.selected_address == address,
                                                RichText::new(label).monospace().size(11.0)).clicked()
                                                && address.is_some() {
                                                    self.selected_address = address;
                                                }
                                        }
                                    });
                            });
                        egui::CollapsingHeader::new(format!("Linked stop sites ({})", artifact.llvm.stop_sites.len()))
                            .id_salt("ghidra_call_llvm_stops")
                            .default_open(true)
                            .show(ui, |ui| {
                                egui::ScrollArea::vertical().max_height(180.0)
                                    .id_salt("ghidra_call_llvm_stop_rows")
                                    .show_rows(ui, 18.0, artifact.llvm.stop_sites.len(), |ui, range| {
                                        for row in range {
                                            let site = &artifact.llvm.stop_sites[row];
                                            let address = address_map.as_ref().and_then(|map|
                                                map.to_linked(&site.address.space, &site.address.offset));
                                            let label = format!("{} {:?}: {}", site.address.offset, site.status, site.reason);
                                            if ui.selectable_label(address.is_some() && self.selected_address == address,
                                                RichText::new(label).monospace().size(11.0)).clicked()
                                                && address.is_some() {
                                                    self.selected_address = address;
                                                }
                                        }
                                    });
                            });
                        egui::ScrollArea::both().id_salt("ghidra_call_llvm_source")
                            .max_height(220.0).show(ui, |ui| {
                                ui.label(RichText::new(&artifact.llvm.llvm_ir).monospace().size(11.0));
                            });
                    }
                    Some(Err(error)) => {
                        ui.label(RichText::new(error).size(11.0).color(BAD));
                    }
                    None => {}
                }
            });
        }
        if pane == GhidraPane::Llvm && self.shell.ghidra.llvm == LlvmPane::Simplified {
            egui::CollapsingHeader::new("Checked P-code simplification")
            .id_salt("ghidra_checked_simplification")
            .default_open(true)
            .show(ui, |ui| {
                ui.label(RichText::new("Rewrites exact add-zero value operations in raw P-code. Each rule has local bitvector preconditions; equivalence with the original binary has not been established.")
                    .size(11.0).color(MUTED));
                if ui.button("Analyze selected function").clicked() {
                    self.ghidra_simplification = Some(snapshot.pcode_function_ir()
                        .and_then(|raw| raw.simplify_checked()));
                }
                match &self.ghidra_simplification {
                    Some(Ok(artifact)) => {
                        ui.label(RichText::new(format!("{} local rewrites · binary verification: {:?}",
                            artifact.rewrites.len(), artifact.verification))
                            .size(11.0).color(ACCENT));
                        if ui.button("Copy rewrite artifact JSON").clicked()
                            && let Ok(json) = serde_json::to_string_pretty(artifact) {
                                ui.ctx().copy_text(json);
                            }
                        egui::ScrollArea::vertical().id_salt("ghidra_checked_rewrites")
                            .max_height(180.0)
                            .show(ui, |ui| {
                                for rewrite in &artifact.rewrites {
                                    let linked = address_map.as_ref().and_then(|map| {
                                        map.to_linked(&rewrite.source_address.space,
                                            &rewrite.source_address.offset)
                                    });
                                    let label = format!("{} op {}: {} → {} · {:?}",
                                        rewrite.source_address.offset, rewrite.sequence_index,
                                        rewrite.before.mnemonic, rewrite.after.mnemonic, rewrite.rule);
                                    if ui.selectable_label(linked.is_some() && self.selected_address == linked,
                                        RichText::new(label).monospace().size(11.0)).clicked()
                                        && linked.is_some() {
                                            self.selected_address = linked;
                                        }
                                    ui.label(RichText::new(&rewrite.reason).size(11.0).color(MUTED));
                                }
                            });
                    }
                    Some(Err(error)) => {
                        ui.label(RichText::new(error).size(11.0).color(BAD));
                    }
                    None => {}
                }
            });
        }
        if pane == GhidraPane::Llvm && self.shell.ghidra.llvm == LlvmPane::Prefix {
            egui::CollapsingHeader::new("LLVM exact prefix")
            .id_salt("ghidra_llvm_prefix")
            .default_open(true)
            .show(ui, |ui| {
                ui.label(RichText::new("A bounded runnable state transition fragment. It stops at the first opaque effect or uncertain flow; the artifact maps Ghidra varnode bytes into a compact state buffer.")
                    .size(11.0).color(MUTED));
                if self.ghidra_llvm_prefix.is_none() && ui.button("Generate runnable LLVM prefix").clicked() {
                    self.ghidra_llvm_prefix = Some(emit_pcode_standalone_prefix_llvm(snapshot));
                }
                match &self.ghidra_llvm_prefix {
                    Some(Ok(prefix)) => {
                        ui.label(RichText::new(format!("{} exact operations · {} state bytes · stop: {}", prefix.emitted_operations, prefix.state_bytes, prefix.stop_reason))
                            .size(11.0).color(ACCENT));
                        if ui.button("Copy LLVM prefix").clicked() {
                            ui.ctx().copy_text(prefix.llvm_ir.clone());
                        }
                        egui::ScrollArea::both().id_salt("ghidra_llvm_prefix_source")
                            .max_height(200.0).show(ui, |ui| {
                                ui.label(RichText::new(&prefix.llvm_ir).monospace().size(11.0));
                            });
                    }
                    Some(Err(error)) => {
                        ui.label(RichText::new(error).size(11.0).color(BAD));
                    }
                    None => {}
                }
            });
        }
        if pane == GhidraPane::Llvm && self.shell.ghidra.llvm == LlvmPane::Cfg {
            egui::CollapsingHeader::new("LLVM CFG path")
            .id_salt("ghidra_llvm_cfg")
            .default_open(true)
            .show(ui, |ui| {
                ui.label(RichText::new("A bounded runnable LLVM path from the selected instruction. Stops retain source addresses; memory, calls, and unsupported effects remain explicit boundaries.")
                    .size(11.0).color(MUTED));
                if ui.button("Generate CFG LLVM").clicked() {
                    self.ghidra_llvm_cfg = Some(ghidra_trace_start(snapshot, &self.ghidra_trace_start)
                        .and_then(|start| emit_pcode_cfg_llvm(snapshot, Some(&start))));
                }
                match &self.ghidra_llvm_cfg {
                    Some(Ok(artifact)) => {
                        ui.label(RichText::new(format!("{} source operations · {} state bytes · {} static stop sites · fidelity: {:?}",
                            artifact.source_operations.len(), artifact.state_bytes,
                            artifact.stop_sites.len(), artifact.semantic_fidelity))
                            .size(11.0).color(ACCENT));
                        egui::ScrollArea::vertical().id_salt("ghidra_llvm_cfg_stops")
                            .max_height(130.0)
                            .show_rows(ui, 18.0, artifact.stop_sites.len(), |ui, range| {
                                for row in range {
                                    let site = &artifact.stop_sites[row];
                                    let address = address_map.as_ref().and_then(|map| {
                                        map.to_linked(&site.address.space, &site.address.offset)
                                    });
                                    let label = format!("{} {:?}: {}", site.address.offset, site.status, site.reason);
                                    if ui.selectable_label(address.is_some() && self.selected_address == address,
                                        RichText::new(label).monospace().size(11.0)).clicked() {
                                            if address.is_some() { self.selected_address = address; }
                                        }
                                }
                            });
                        if ui.button("Copy CFG LLVM").clicked() {
                            ui.ctx().copy_text(artifact.llvm_ir.clone());
                        }
                        egui::ScrollArea::both().id_salt("ghidra_llvm_cfg_source")
                            .max_height(200.0).show(ui, |ui| {
                                ui.label(RichText::new(&artifact.llvm_ir).monospace().size(11.0));
                            });
                    }
                    Some(Err(error)) => {
                        ui.label(RichText::new(error).size(11.0).color(BAD));
                    }
                    None => {}
                }
                if let Some(path) = self.current_local_path.as_ref() {
                    ui.separator();
                    ui.label(RichText::new("Embed validated ELF bytes in LLVM. The v4 process view includes writable globals and zero-filled tails; unknown relocations and unsupported effects stop explicitly.")
                        .size(11.0).color(MUTED));
                    if ui.button("Generate image-backed CFG LLVM").clicked() {
                        self.ghidra_llvm_image_cfg = Some(emit_ghidra_image_cfg_llvm(
                            snapshot,
                            &self.ghidra_trace_start,
                            path,
                        ));
                    }
                    if ui.button("Generate process-backed CFG LLVM").clicked() {
                        self.ghidra_llvm_image_cfg = Some(emit_ghidra_process_cfg_llvm(
                            snapshot,
                            &self.ghidra_trace_start,
                            path,
                        ));
                    }
                    if ui.button("Generate allocated CFG LLVM").clicked() {
                        self.ghidra_llvm_image_cfg = Some(emit_ghidra_allocated_cfg_llvm(
                            snapshot,
                            &self.ghidra_trace_start,
                            path,
                            &self.ghidra_allocation_json,
                        ));
                    }
                    match &self.ghidra_llvm_image_cfg {
                        Some(Ok(artifact)) => {
                            ui.label(RichText::new(format!(
                                "LLVM v{} · {} source operations · {} static stop sites · fidelity: {:?}",
                                artifact.schema_version,
                                artifact.source_operations.len(),
                                artifact.stop_sites.len(),
                                artifact.semantic_fidelity,
                            )).size(11.0).color(ACCENT));
                            ui.label(RichText::new(format!("Binary SHA-256: {}", artifact.binary_sha256))
                                .monospace().size(11.0).color(MUTED));
                            if let Some(image) = &artifact.read_only_image {
                                ui.label(RichText::new(format!(
                                    "Read-only ELF image: {} 0x{:x} · {} byte window · {} known bytes · contents SHA-256 {}",
                                    image.space, image.base, image.byte_len,
                                    image.known_byte_count, image.contents_sha256,
                                )).monospace().size(11.0).color(MUTED));
                            }
                            if let Some(memory) = &artifact.process_memory {
                                ui.label(RichText::new(format!(
                                    "ELF process memory: {} 0x{:x} · {} byte window · {} known · {} mapped · {} writable · {} unresolved relocation bytes · contents SHA-256 {}",
                                    memory.space, memory.base, memory.byte_len,
                                    memory.known_byte_count, memory.mapped_byte_count,
                                    memory.writable_byte_count,
                                    memory.unresolved_relocation_bytes,
                                    memory.contents_sha256,
                                )).monospace().size(11.0).color(MUTED));
                            }
                            if let Some(allocations) = &artifact.allocations {
                                ui.label(RichText::new(format!(
                                    "Declared allocations: {} ranges; initial bytes stay unknown until seeded",
                                    allocations.regions().len(),
                                )).monospace().size(11.0).color(MUTED));
                                for region in allocations.regions() {
                                    ui.label(RichText::new(format!(
                                        "{:?}: {} 0x{:x} + {} bytes",
                                        region.kind, region.space, region.base, region.byte_len,
                                    )).monospace().size(11.0).color(MUTED));
                                }
                            }
                            egui::ScrollArea::vertical().id_salt("ghidra_llvm_image_cfg_stops")
                                .max_height(130.0)
                                .show_rows(ui, 18.0, artifact.stop_sites.len(), |ui, range| {
                                    for row in range {
                                        let site = &artifact.stop_sites[row];
                                        let address = address_map.as_ref().and_then(|map| {
                                            map.to_linked(&site.address.space, &site.address.offset)
                                        });
                                        let label = format!("{} {:?}: {}", site.address.offset, site.status, site.reason);
                                        if ui.selectable_label(address.is_some() && self.selected_address == address,
                                            RichText::new(label).monospace().size(11.0)).clicked()
                                            && address.is_some() {
                                            self.selected_address = address;
                                        }
                                    }
                                });
                            if ui.button("Copy image-backed CFG LLVM").clicked() {
                                ui.ctx().copy_text(artifact.llvm_ir.clone());
                            }
                            if ui.button("Copy image-backed CFG artifact JSON").clicked()
                                && let Ok(json) = serde_json::to_string_pretty(artifact) {
                                ui.ctx().copy_text(json);
                            }
                            egui::ScrollArea::both().id_salt("ghidra_llvm_image_cfg_source")
                                .max_height(200.0).show(ui, |ui| {
                                    ui.label(RichText::new(&artifact.llvm_ir).monospace().size(11.0));
                                });
                        }
                        Some(Err(error)) => {
                            ui.label(RichText::new(format!("Image-backed CFG LLVM failed: {error}"))
                                .size(11.0).color(BAD));
                        }
                        None => {}
                    }
                }
            });
        }
        if pane == GhidraPane::Llvm && self.shell.ghidra.llvm == LlvmPane::Simplified {
            egui::CollapsingHeader::new("LLVM after checked P-code simplification")
            .id_salt("ghidra_llvm_simplified")
            .default_open(true)
            .show(ui, |ui| {
                ui.label(RichText::new("Hydir applies the listed local identities to raw P-code and emits a bounded CFG path module. Binary equivalence is unverified.")
                    .size(11.0).color(MUTED));
                if ui.button("Generate simplified CFG LLVM").clicked() {
                    self.ghidra_llvm_simplified = Some(
                        ghidra_trace_start(snapshot, &self.ghidra_trace_start)
                            .and_then(|start| emit_pcode_simplified_cfg_llvm(snapshot, Some(&start)))
                    );
                }
                match &self.ghidra_llvm_simplified {
                    Some(Ok(artifact)) => {
                        ui.label(RichText::new(format!("{} rewrites · {} static stop sites · verification: {:?}",
                            artifact.simplification.rewrites.len(),
                            artifact.llvm.stop_sites.len(), artifact.verification))
                            .size(11.0).color(ACCENT));
                        if ui.button("Copy transformed LLVM artifact JSON").clicked()
                            && let Ok(json) = serde_json::to_string_pretty(artifact) {
                                ui.ctx().copy_text(json);
                            }
                        if ui.button("Copy transformed LLVM module").clicked() {
                            ui.ctx().copy_text(artifact.llvm.llvm_ir.clone());
                        }
                        egui::ScrollArea::both().id_salt("ghidra_llvm_simplified_source")
                            .max_height(200.0).show(ui, |ui| {
                                ui.label(RichText::new(&artifact.llvm.llvm_ir).monospace().size(11.0));
                            });
                    }
                    Some(Err(error)) => {
                        ui.label(RichText::new(error).size(11.0).color(BAD));
                    }
                    None => {}
                }
            });
        }
        if pane == GhidraPane::Flow {
            if !snapshot.selected_function.call_targets.is_empty() {
                egui::CollapsingHeader::new(format!(
                    "Calls ({})",
                    snapshot.selected_function.call_targets.len()
                ))
                .id_salt("ghidra_call_targets")
                .default_open(true)
                .show(ui, |ui| {
                    egui::ScrollArea::vertical()
                        .id_salt("ghidra_call_rows")
                        .max_height(120.0)
                        .show_rows(
                            ui,
                            22.0,
                            snapshot.selected_function.call_targets.len(),
                            |ui, range| {
                                for row in range {
                                    let call = &snapshot.selected_function.call_targets[row];
                                    let source = address_map.as_ref().and_then(|map| {
                                        map.to_linked(&call.call_site.space, &call.call_site.offset)
                                    });
                                    let target = call
                                        .target
                                        .as_ref()
                                        .map(|address| {
                                            format!("{}:{}", address.space, address.offset)
                                        })
                                        .unwrap_or_else(|| "unresolved target".to_owned());
                                    ui.horizontal(|ui| {
                                        if ui
                                            .selectable_label(
                                                source.is_some() && self.selected_address == source,
                                                format!(
                                                    "{}:{} → {target}{}",
                                                    call.call_site.space,
                                                    call.call_site.offset,
                                                    if call.computed { " (computed)" } else { "" }
                                                ),
                                            )
                                            .clicked()
                                        {
                                            if source.is_some() {
                                                self.selected_address = source;
                                            }
                                        }
                                        if let Some(target) = &call.target
                                            && snapshot
                                                .functions
                                                .iter()
                                                .any(|function| function.entry == *target)
                                            && ui.button("Open target").clicked()
                                        {
                                            requested = Some(target.offset.clone());
                                            self.selected_address =
                                                address_map.as_ref().and_then(|map| {
                                                    map.to_linked(&target.space, &target.offset)
                                                });
                                        }
                                    });
                                }
                            },
                        );
                });
            }
            if !snapshot.selected_function.flow_edges.is_empty() {
                egui::CollapsingHeader::new(format!(
                    "Analyzed flow edges ({})",
                    snapshot.selected_function.flow_edges.len()
                ))
                .id_salt("ghidra_flow_edges")
                .default_open(true)
                .show(ui, |ui| {
                    egui::ScrollArea::vertical()
                        .id_salt("ghidra_flow_rows")
                        .max_height(120.0)
                        .show_rows(
                            ui,
                            18.0,
                            snapshot.selected_function.flow_edges.len(),
                            |ui, range| {
                                for row in range {
                                    let edge = &snapshot.selected_function.flow_edges[row];
                                    let source = address_map.as_ref().and_then(|map| {
                                        map.to_linked(&edge.source.space, &edge.source.offset)
                                    });
                                    let target = edge
                                        .target
                                        .as_ref()
                                        .map(|address| {
                                            format!("{}:{}", address.space, address.offset)
                                        })
                                        .unwrap_or_else(|| "unresolved".to_owned());
                                    if ui
                                        .selectable_label(
                                            source.is_some() && self.selected_address == source,
                                            RichText::new(format!(
                                                "{}:{} → {target}  {:?}{}{}",
                                                edge.source.space,
                                                edge.source.offset,
                                                edge.kind,
                                                if edge.conditional { " conditional" } else { "" },
                                                if edge.computed { " computed" } else { "" }
                                            ))
                                            .monospace()
                                            .size(11.0),
                                        )
                                        .clicked()
                                    {
                                        if source.is_some() {
                                            self.selected_address = source;
                                        }
                                    }
                                }
                            },
                        );
                });
            }
        }
        if pane == GhidraPane::Metadata {
            if let Some(prototype) = snapshot
                .functions
                .iter()
                .find(|function| function.entry == snapshot.selected_function.entry)
                .and_then(|function| function.prototype.as_ref())
            {
                egui::CollapsingHeader::new("Ghidra prototype evidence")
                    .id_salt("ghidra_prototype_evidence")
                    .default_open(true)
                    .show(ui, |ui| {
                        ui.label(
                            RichText::new(format!(
                                "signature source: {} · convention: {} · return: {} ({})",
                                prototype.signature_source,
                                prototype.calling_convention.as_deref().unwrap_or("unknown"),
                                prototype.return_type.display_name,
                                prototype.return_source
                            ))
                            .size(11.0)
                            .color(MUTED),
                        );
                        for parameter in prototype.parameters.iter().take(16) {
                            ui.label(
                                RichText::new(format!(
                                    "{}: {} ({})",
                                    parameter.name,
                                    parameter.data_type.display_name,
                                    parameter.source_type
                                ))
                                .monospace()
                                .size(11.0),
                            );
                        }
                        if prototype.parameters.len() > 16 {
                            ui.label(
                                RichText::new(format!(
                                    "{} more parameters in snapshot",
                                    prototype.parameters.len() - 16
                                ))
                                .size(11.0)
                                .color(MUTED),
                            );
                        }
                    });
            }
            let layouts = ghidra_composite_evidence(snapshot);
            if !layouts.is_empty() {
                egui::CollapsingHeader::new("Ghidra composite layout evidence")
                .id_salt("ghidra_composite_layout_evidence")
                .default_open(true)
                .show(ui, |ui| {
                    ui.label(
                        RichText::new("Ghidra byte layouts from the prototype and up to 1,024 SSA operations; not asserted source types")
                            .size(11.0)
                            .color(MUTED),
                    );
                    for layout in layouts.iter().take(16) {
                        ui.label(
                            RichText::new(format!(
                                "{} {} · {} bytes{}",
                                match layout.kind {
                                    GhidraDataTypeKind::Struct => "struct",
                                    _ => "union",
                                },
                                layout.display_name,
                                layout
                                    .size_bytes
                                    .map_or("?".to_owned(), |size| size.to_string()),
                                if layout.detail_truncated {
                                    " · truncated"
                                } else {
                                    ""
                                }
                            ))
                            .monospace()
                            .size(11.0),
                        );
                        for field in layout.fields.iter().take(32) {
                            ui.label(
                                RichText::new(format!(
                                    "  +0x{:x}  {:>2} B  {}: {}",
                                    field.offset_bytes,
                                    field.size_bytes,
                                    field.name.as_deref().unwrap_or("<unnamed>"),
                                    field.data_type.display_name
                                ))
                                .monospace()
                                .size(11.0)
                                .color(MUTED),
                            );
                        }
                        if layout.fields.len() > 32 {
                            ui.label(format!(
                                "  {} more fields in snapshot",
                                layout.fields.len() - 32
                            ));
                        }
                    }
                    if layouts.len() > 16 {
                        ui.label(format!(
                            "{} more composites in snapshot",
                            layouts.len() - 16
                        ));
                    }
                });
            }
        }
        if let Some(task) = path_trace_task {
            self.enqueue(task, "Tracing Ghidra path with linked ELF bytes…");
        }
        if let Some(function) = requested
            && let (Some(binary), Some(spec)) =
                (self.current_local_path.clone(), self.spec.as_ref())
        {
            self.enqueue_ghidra(binary, spec.binary_sha256.clone(), Some(function));
        }
    }
    pub(super) fn ghidra_slice_view(&mut self, ui: &mut egui::Ui) {
        let Some(snapshot) = &self.ghidra_snapshot else {
            return;
        };
        let address_map = self
            .spec
            .as_ref()
            .and_then(|spec| GhidraAddressMap::new(snapshot, spec));
        if let Some(result) = &self.ghidra_slice {
            egui::CollapsingHeader::new("Why this P-code value?")
                .id_salt("ghidra_backward_slice")
                .default_open(true)
                .show(ui, |ui| match result {
                    Ok(slice) => {
                        ui.label(
                            RichText::new(format!(
                                "{} source operations · {} unresolved boundaries · path proof: no",
                                slice.steps.len(),
                                slice.boundaries.len()
                            ))
                            .size(11.0)
                            .color(ACCENT),
                        );
                        if ui.button("Copy slice JSON").clicked()
                            && let Ok(json) = serde_json::to_string_pretty(slice)
                        {
                            ui.ctx().copy_text(json);
                        }
                        egui::ScrollArea::vertical()
                            .id_salt("ghidra_slice_steps")
                            .max_height(160.0)
                            .show_rows(ui, 19.0, slice.steps.len(), |ui, range| {
                                for row in range {
                                    let step = &slice.steps[row];
                                    let address = address_map.as_ref().and_then(|map| {
                                        map.to_linked(
                                            &step.source.source_address.space,
                                            &step.source.source_address.offset,
                                        )
                                    });
                                    let label = format!(
                                        "{} #{} {}",
                                        step.source.source_address.offset,
                                        step.site.operation_index,
                                        step.source.mnemonic
                                    );
                                    if ui
                                        .selectable_label(
                                            address.is_some() && self.selected_address == address,
                                            RichText::new(label).monospace().size(11.0),
                                        )
                                        .clicked()
                                    {
                                        if address.is_some() {
                                            self.selected_address = address;
                                        }
                                    }
                                }
                            });
                        for boundary in slice.boundaries.iter().take(24) {
                            ui.label(
                                RichText::new(format!(
                                    "{:?}: {:?}",
                                    boundary.kind, boundary.varnode
                                ))
                                .monospace()
                                .size(11.0)
                                .color(MUTED),
                            );
                        }
                        if slice.boundaries.len() > 24 {
                            ui.label(
                                RichText::new(format!(
                                    "{} more boundaries in JSON",
                                    slice.boundaries.len() - 24
                                ))
                                .size(11.0)
                                .color(MUTED),
                            );
                        }
                    }
                    Err(error) => {
                        ui.label(RichText::new(error).color(BAD));
                    }
                });
        } else {
            ui.label("Select a P-code operation to inspect its dependencies.");
        }
    }
    pub(super) fn frida_action_view(&mut self, ui: &mut egui::Ui) {
        let Some(snapshot) = &self.ghidra_snapshot else {
            return;
        };
        let address_map = self
            .spec
            .as_ref()
            .and_then(|spec| GhidraAddressMap::new(snapshot, spec));
        if self.shell.ghidra.frida == FridaPane::Session {
            ui.label(RichText::new("Observation session").strong());
            ui.label(RichText::new("Record blocks, calls and entry registers for one configured input.").size(12.0).color(MUTED))
                .on_hover_text("Observed blocks and calls are byte checked. Other inputs and the process exit code remain unverified.");
            ui.add_space(10.0);
            ui.horizontal(|ui| {
                ui.label("InputSpec");
                if ui
                    .add(
                        egui::TextEdit::singleline(&mut self.frida_input_path)
                            .hint_text("Path to the input specification (.json)")
                            .desired_width((ui.available_width() - 15.0).min(600.0)),
                    )
                    .changed()
                {
                    self.frida_observation = None;
                    self.frida_rediscovery_plan = None;
                    self.frida_jump_plan = None;
                    self.frida_rediscovered_snapshot = None;
                    if let Some(task) = &self.frida_rediscovery_task {
                        task.cancel.store(true, Ordering::Release);
                    }
                    self.frida_path_comparison = None;
                }
            });
            let linked_entry = address_map.as_ref().and_then(|map| {
                map.to_linked(
                    &snapshot.selected_function.entry.space,
                    &snapshot.selected_function.entry.offset,
                )
            });
            let can_observe = self.shell.frida_runtime.ready()
                && self.current_local_path.is_some()
                && linked_entry.is_some()
                && !self.frida_input_path.trim().is_empty()
                && !self.frida_busy;
            if self.current_local_path.is_none() {
                ui.label(
                    RichText::new("Open a local ELF to observe it.")
                        .size(11.0)
                        .color(MUTED),
                );
            } else if linked_entry.is_none() {
                ui.label(
                    RichText::new("Select a function with a linked ELF address.")
                        .size(11.0)
                        .color(MUTED),
                );
            } else if self.frida_input_path.trim().is_empty() {
                ui.label(
                    RichText::new("Select an InputSpec JSON file to enable observation.")
                        .size(11.0)
                        .color(MUTED),
                );
            }
            if ui
                .add_enabled(can_observe, egui::Button::new("Observe selected function"))
                .on_disabled_hover_text("Requires a ready Frida runtime, a local ELF, a linked function and an InputSpec JSON path.")
                .clicked()
            {
                let cancel = Arc::new(AtomicBool::new(false));
                // Include WSL cold-start/readiness time as well as the bounded
                // observation. The InputSpec still controls target execution.
                let timeout = Duration::from_secs(75);
                let task = Task::ObserveFrida {
                    binary: self.current_local_path.clone().expect("checked above"),
                    binary_sha256: snapshot.binary_sha256.clone(),
                    function: linked_entry.expect("checked above"),
                    snapshot: Box::new(snapshot.clone()),
                    input_path: PathBuf::from(self.frida_input_path.trim()),
                    cancel: Arc::clone(&cancel),
                    timeout,
                };
                match self.tasks.try_send(task) {
                    Ok(()) => {
                        self.frida_busy = true;
                        self.frida_task = Some(ActiveGhidraTask {
                            cancel,
                            started: Instant::now(),
                            timeout,
                        });
                        self.frida_observation = None;
                        self.frida_rediscovery_plan = None;
                        self.frida_jump_plan = None;
                        self.frida_rediscovered_snapshot = None;
                        self.frida_path_comparison = None;
                        self.status = "Observing selected ELF function…".to_owned();
                    }
                    Err(_) => {
                        self.frida_observation =
                            Some(Err("Analysis queue is full. Retry observation.".to_owned()))
                    }
                }
            }
            if self.frida_busy
                && let Some(task) = &self.frida_task
            {
                ghidra_progress(ui, task, "Observing ELF path");
                if ui
                    .add_enabled(
                        !task.cancel.load(Ordering::Acquire),
                        egui::Button::new("Cancel observation"),
                    )
                    .clicked()
                {
                    task.cancel.store(true, Ordering::Release);
                }
            }
        }
        match &self.frida_observation {
            Some(Ok(trace)) => {
                ui.label(RichText::new(format!(
                            "{:?} · {} events · {} verified jump pairs · {} lost · {} · process exit code unknown",
                            trace.status, trace.events.len(), trace.jump_evidence.len(), trace.lost_events,
                            trace.observer,
                        )).size(11.0).color(ACCENT));
                if ui.button("Copy observation JSON").clicked()
                    && let Ok(json) = serde_json::to_string_pretty(trace)
                {
                    ui.ctx().copy_text(json);
                }
                if self.shell.ghidra.frida == FridaPane::Session {
                    if ui
                        .button("Use captured entry registers as P-code seed")
                        .clicked()
                    {
                        let seed = (|| -> Result<String, String> {
                            let binary_path = self
                                .current_local_path
                                .as_ref()
                                .ok_or("No local ELF is open")?;
                            let binary = bounded_read(binary_path)?;
                            let mut input_bytes = Vec::new();
                            fs::File::open(self.frida_input_path.trim())
                                .map_err(|error| error.to_string())?
                                .take((MAX_INPUT_SPEC_BYTES + 1) as u64)
                                .read_to_end(&mut input_bytes)
                                .map_err(|error| error.to_string())?;
                            if input_bytes.len() > MAX_INPUT_SPEC_BYTES {
                                return Err("InputSpec exceeds size limit".into());
                            }
                            let input = parse_input_spec(&input_bytes)?;
                            let seed = frida_entry_pcode_seed(&binary, &input, snapshot, trace)?;
                            String::from_utf8(seed).map_err(|error| error.to_string())
                        })();
                        match seed {
                            Ok(seed) => {
                                self.ghidra_trace_seed_json = seed;
                                self.ghidra_path_trace = None;
                                self.ghidra_path_lines.clear();
                                self.frida_path_comparison = None;
                                self.status = "Captured entry registers loaded as a P-code seed; memory remains unknown".to_owned();
                            }
                            Err(error) => {
                                self.status = format!("Cannot use Frida entry registers: {error}")
                            }
                        }
                    }
                }
                if self.shell.ghidra.frida == FridaPane::Rediscovery {
                    if ui.button("Plan observed indirect calls").clicked() {
                        self.frida_rediscovery_plan = Some((|| -> Result<_, String> {
                            let binary_path = self
                                .current_local_path
                                .as_ref()
                                .ok_or("No local ELF is open")?;
                            let binary = bounded_read(binary_path)?;
                            let mut input_bytes = Vec::new();
                            fs::File::open(self.frida_input_path.trim())
                                .map_err(|error| error.to_string())?
                                .take((MAX_INPUT_SPEC_BYTES + 1) as u64)
                                .read_to_end(&mut input_bytes)
                                .map_err(|error| error.to_string())?;
                            if input_bytes.len() > MAX_INPUT_SPEC_BYTES {
                                return Err("InputSpec exceeds size limit".into());
                            }
                            let input = parse_input_spec(&input_bytes)?;
                            let snapshot_json =
                                serde_json::to_vec(snapshot).map_err(|error| error.to_string())?;
                            plan_observed_calls(&binary, &input, trace, &snapshot_json)
                        })());
                    }
                    if ui.button("Plan observed indirect jumps").clicked() {
                        self.frida_jump_plan = Some((|| -> Result<_, String> {
                            let binary_path = self
                                .current_local_path
                                .as_ref()
                                .ok_or("No local ELF is open")?;
                            let binary = bounded_read(binary_path)?;
                            let mut input_bytes = Vec::new();
                            fs::File::open(self.frida_input_path.trim())
                                .map_err(|error| error.to_string())?
                                .take((MAX_INPUT_SPEC_BYTES + 1) as u64)
                                .read_to_end(&mut input_bytes)
                                .map_err(|error| error.to_string())?;
                            if input_bytes.len() > MAX_INPUT_SPEC_BYTES {
                                return Err("InputSpec exceeds size limit".into());
                            }
                            let input = parse_input_spec(&input_bytes)?;
                            let snapshot_json =
                                serde_json::to_vec(snapshot).map_err(|error| error.to_string())?;
                            plan_observed_jumps(&binary, &input, trace, &snapshot_json)
                        })());
                    }
                    match &self.frida_rediscovery_plan {
                        Some(Ok(plan)) => {
                            ui.label(RichText::new(format!(
                                    "{} byte-verified candidate targets · {} unresolved static call sites · {} omitted by budget",
                                    plan.changed_targets.len(), plan.unresolved_call_sites.len(),
                                    plan.omitted_targets,
                                )).size(11.0).color(ACCENT));
                            ui.label(RichText::new("Observed targets are input-specific; unresolved CFG edges remain open.")
                                    .size(11.0).color(MUTED));
                            for candidate in plan.changed_targets.iter().take(64) {
                                let source = address_map.as_ref().and_then(|map| {
                                    map.to_linked(
                                        &candidate.call_site.space,
                                        &candidate.call_site.offset,
                                    )
                                });
                                let target = address_map.as_ref().and_then(|map| {
                                    map.to_linked(&candidate.target.space, &candidate.target.offset)
                                });
                                ui.horizontal(|ui| {
                                    if ui
                                        .selectable_label(
                                            source.is_some() && self.selected_address == source,
                                            RichText::new(format!(
                                                "{} → {} · {} witnesses",
                                                candidate.call_site.offset,
                                                candidate.target.offset,
                                                candidate.event_sequences.len()
                                            ))
                                            .monospace()
                                            .size(11.0),
                                        )
                                        .clicked()
                                        && source.is_some()
                                    {
                                        self.selected_address = source;
                                    }
                                    if let Some(target) = target
                                        && ui.small_button("Target").clicked()
                                    {
                                        self.selected_address = Some(target);
                                    }
                                });
                            }
                            if ui.button("Copy rediscovery plan JSON").clicked()
                                && let Ok(json) = serde_json::to_string_pretty(plan)
                            {
                                ui.ctx().copy_text(json);
                            }
                            let can_apply = !plan.changed_targets.is_empty()
                                && self.current_local_path.is_some()
                                && !self.frida_rediscovery_busy;
                            if ui
                                .add_enabled(
                                    can_apply,
                                    egui::Button::new(
                                        "Reanalyze observed calls in isolated Ghidra project",
                                    ),
                                )
                                .clicked()
                            {
                                let cancel = Arc::new(AtomicBool::new(false));
                                let timeout = Duration::from_secs(15 * 60);
                                let task = Task::RediscoverFridaFlow {
                                    binary: self.current_local_path.clone().expect("checked above"),
                                    binary_sha256: snapshot.binary_sha256.clone(),
                                    function: trace.selected_elf_vaddr,
                                    snapshot: Box::new(snapshot.clone()),
                                    input_path: PathBuf::from(self.frida_input_path.trim()),
                                    trace: Box::new(trace.clone()),
                                    jumps: false,
                                    cancel: Arc::clone(&cancel),
                                    timeout,
                                };
                                match self.tasks.try_send(task) {
                                    Ok(()) => {
                                        self.frida_rediscovery_mode = "calls".to_owned();
                                        self.frida_rediscovery_busy = true;
                                        self.frida_rediscovery_task = Some(ActiveGhidraTask {
                                            cancel,
                                            started: Instant::now(),
                                            timeout,
                                        });
                                        self.frida_rediscovered_snapshot = None;
                                        self.status = "Reanalyzing observed calls in isolated Ghidra project…".to_owned();
                                    }
                                    Err(_) => self.frida_rediscovered_snapshot = Some(Err(
                                        "Analysis queue is full. Retry observed-call reanalysis."
                                            .to_owned(),
                                    )),
                                }
                            }
                        }
                        Some(Err(error)) => {
                            ui.label(RichText::new(error).size(11.0).color(BAD));
                        }
                        None => {}
                    }
                    match &self.frida_jump_plan {
                        Some(Ok(plan)) => {
                            ui.label(RichText::new(format!(
                                    "{} byte-verified jump targets · {} unresolved static jump sites · {} omitted by budget",
                                    plan.changed_targets.len(), plan.unresolved_jump_sites.len(),
                                    plan.omitted_targets,
                                )).size(11.0).color(ACCENT));
                            ui.label(RichText::new("Each jump target belongs to one observed input; the unknown CFG edge stays open.")
                                    .size(11.0).color(MUTED));
                            for candidate in plan.changed_targets.iter().take(64) {
                                let source = address_map.as_ref().and_then(|map| {
                                    map.to_linked(
                                        &candidate.jump_site.space,
                                        &candidate.jump_site.offset,
                                    )
                                });
                                let target = address_map.as_ref().and_then(|map| {
                                    map.to_linked(&candidate.target.space, &candidate.target.offset)
                                });
                                ui.horizontal(|ui| {
                                    if ui
                                        .selectable_label(
                                            source.is_some() && self.selected_address == source,
                                            RichText::new(format!(
                                                "{} → {} · {} witnesses",
                                                candidate.jump_site.offset,
                                                candidate.target.offset,
                                                candidate.evidence_sequences.len()
                                            ))
                                            .monospace()
                                            .size(11.0),
                                        )
                                        .clicked()
                                        && source.is_some()
                                    {
                                        self.selected_address = source;
                                    }
                                    if let Some(target) = target
                                        && ui.small_button("Target").clicked()
                                    {
                                        self.selected_address = Some(target);
                                    }
                                });
                            }
                            if ui.button("Copy jump rediscovery plan JSON").clicked()
                                && let Ok(json) = serde_json::to_string_pretty(plan)
                            {
                                ui.ctx().copy_text(json);
                            }
                            let can_apply = !plan.changed_targets.is_empty()
                                && self.current_local_path.is_some()
                                && !self.frida_rediscovery_busy;
                            if ui
                                .add_enabled(
                                    can_apply,
                                    egui::Button::new(
                                        "Reanalyze observed jumps in isolated Ghidra project",
                                    ),
                                )
                                .clicked()
                            {
                                let cancel = Arc::new(AtomicBool::new(false));
                                let timeout = Duration::from_secs(15 * 60);
                                let task = Task::RediscoverFridaFlow {
                                    binary: self.current_local_path.clone().expect("checked above"),
                                    binary_sha256: snapshot.binary_sha256.clone(),
                                    function: trace.selected_elf_vaddr,
                                    snapshot: Box::new(snapshot.clone()),
                                    input_path: PathBuf::from(self.frida_input_path.trim()),
                                    trace: Box::new(trace.clone()),
                                    jumps: true,
                                    cancel: Arc::clone(&cancel),
                                    timeout,
                                };
                                match self.tasks.try_send(task) {
                                    Ok(()) => {
                                        self.frida_rediscovery_mode = "jumps".to_owned();
                                        self.frida_rediscovery_busy = true;
                                        self.frida_rediscovery_task = Some(ActiveGhidraTask {
                                            cancel,
                                            started: Instant::now(),
                                            timeout,
                                        });
                                        self.frida_rediscovered_snapshot = None;
                                        self.status = "Reanalyzing observed jumps in isolated Ghidra project…".to_owned();
                                    }
                                    Err(_) => self.frida_rediscovered_snapshot = Some(Err(
                                        "Analysis queue is full. Retry observed-jump reanalysis."
                                            .to_owned(),
                                    )),
                                }
                            }
                        }
                        Some(Err(error)) => {
                            ui.label(RichText::new(error).size(11.0).color(BAD));
                        }
                        None => {}
                    }
                    if self.frida_rediscovery_busy
                        && let Some(task) = &self.frida_rediscovery_task
                    {
                        ghidra_progress(ui, task, "Reanalyzing observed control flow");
                        if ui
                            .add_enabled(
                                !task.cancel.load(Ordering::Acquire),
                                egui::Button::new("Cancel reanalysis"),
                            )
                            .clicked()
                        {
                            task.cancel.store(true, Ordering::Release);
                        }
                    }
                    match &self.frida_rediscovered_snapshot {
                        Some(Ok(rediscovered)) => {
                            ui.label(RichText::new(format!(
                                    "Isolated Ghidra snapshot ({}): {} instructions · {} call targets · {} flow edges",
                                    self.frida_rediscovery_mode,
                                    rediscovered.selected_function.instructions.len(),
                                    rediscovered.selected_function.call_targets.len(),
                                    rediscovered.selected_function.flow_edges.len(),
                                )).size(11.0).color(ACCENT));
                            for call in rediscovered
                                .selected_function
                                .call_targets
                                .iter()
                                .filter(|call| call.computed && call.target.is_some())
                                .take(64)
                            {
                                let source = address_map.as_ref().and_then(|map| {
                                    map.to_linked(&call.call_site.space, &call.call_site.offset)
                                });
                                let target = call.target.as_ref().and_then(|target| {
                                    address_map.as_ref().and_then(|map| {
                                        map.to_linked(&target.space, &target.offset)
                                    })
                                });
                                ui.horizontal(|ui| {
                                    if ui
                                        .selectable_label(
                                            source.is_some() && self.selected_address == source,
                                            RichText::new(format!(
                                                "{} → {} · observed reference",
                                                call.call_site.offset,
                                                call.target.as_ref().map_or("unknown", |target| {
                                                    target.offset.as_str()
                                                }),
                                            ))
                                            .monospace()
                                            .size(11.0),
                                        )
                                        .clicked()
                                        && source.is_some()
                                    {
                                        self.selected_address = source;
                                    }
                                    if let Some(target) = target
                                        && ui.small_button("Target").clicked()
                                    {
                                        self.selected_address = Some(target);
                                    }
                                });
                            }
                            if self.frida_rediscovery_mode == "jumps" {
                                for edge in rediscovered
                                    .selected_function
                                    .flow_edges
                                    .iter()
                                    .filter(|edge| {
                                        edge.kind == hydir_ir::pcode::GhidraFlowKind::Branch
                                            && edge.computed
                                            && edge.target.is_some()
                                    })
                                    .take(64)
                                {
                                    let source = address_map.as_ref().and_then(|map| {
                                        map.to_linked(&edge.source.space, &edge.source.offset)
                                    });
                                    let target = edge.target.as_ref().and_then(|target| {
                                        address_map.as_ref().and_then(|map| {
                                            map.to_linked(&target.space, &target.offset)
                                        })
                                    });
                                    ui.horizontal(|ui| {
                                        if ui
                                            .selectable_label(
                                                source.is_some() && self.selected_address == source,
                                                RichText::new(format!(
                                                    "{} → {} · observed jump reference",
                                                    edge.source.offset,
                                                    edge.target
                                                        .as_ref()
                                                        .map_or("unknown", |target| target
                                                            .offset
                                                            .as_str()),
                                                ))
                                                .monospace()
                                                .size(11.0),
                                            )
                                            .clicked()
                                            && source.is_some()
                                        {
                                            self.selected_address = source;
                                        }
                                        if let Some(target) = target
                                            && ui.small_button("Target").clicked()
                                        {
                                            self.selected_address = Some(target);
                                        }
                                    });
                                }
                            }
                            if ui.button("Copy rediscovered snapshot JSON").clicked()
                                && let Ok(json) = serde_json::to_string_pretty(rediscovered)
                            {
                                ui.ctx().copy_text(json);
                            }
                        }
                        Some(Err(error)) => {
                            ui.label(RichText::new(error).size(11.0).color(BAD));
                        }
                        None => {}
                    }
                }
                if self.shell.ghidra.frida == FridaPane::Compare {
                    if let Some(Ok(path)) = &self.ghidra_path_trace
                        && ui
                            .button("Compare observed path with P-code path")
                            .clicked()
                    {
                        self.frida_path_comparison = Some((|| -> Result<_, String> {
                            let binary_path = self
                                .current_local_path
                                .as_ref()
                                .ok_or("No local ELF is open")?;
                            let binary = bounded_read(binary_path)?;
                            let mut input_bytes = Vec::new();
                            fs::File::open(self.frida_input_path.trim())
                                .map_err(|error| error.to_string())?
                                .take((MAX_INPUT_SPEC_BYTES + 1) as u64)
                                .read_to_end(&mut input_bytes)
                                .map_err(|error| error.to_string())?;
                            if input_bytes.len() > MAX_INPUT_SPEC_BYTES {
                                return Err("InputSpec exceeds size limit".into());
                            }
                            let input = parse_input_spec(&input_bytes)?;
                            compare_pcode_observed_path(&binary, &input, snapshot, trace, path)
                        })());
                    }
                    match &self.frida_path_comparison {
                        Some(Ok(comparison)) => {
                            ui.label(
                                RichText::new(format!(
                                    "Observed path: {:?} · {} blocks · {} calls",
                                    comparison.verdict,
                                    comparison.compared_blocks,
                                    comparison.compared_calls,
                                ))
                                .size(11.0)
                                .color(ACCENT),
                            );
                            if let Some(difference) = &comparison.first_difference {
                                let linked = address_map.as_ref().and_then(|map| {
                                    map.to_linked(
                                        &difference.source.space,
                                        &difference.source.offset,
                                    )
                                });
                                if ui.selectable_label(
                                        linked.is_some() && self.selected_address == linked,
                                        RichText::new(format!(
                                            "First difference at {}: {:?} · expected {:?} · observed {:?}",
                                            difference.source.offset, difference.kind,
                                            difference.expected, difference.observed,
                                        )).monospace().size(11.0),
                                    ).clicked() && linked.is_some() {
                                        self.selected_address = linked;
                                    }
                            }
                            for reason in &comparison.inconclusive_reasons {
                                ui.label(RichText::new(reason).size(11.0).color(MUTED));
                            }
                            if ui.button("Copy observed path comparison JSON").clicked()
                                && let Ok(json) = serde_json::to_string_pretty(comparison)
                            {
                                ui.ctx().copy_text(json);
                            }
                        }
                        Some(Err(error)) => {
                            ui.label(RichText::new(error).size(11.0).color(BAD));
                        }
                        None => {}
                    }
                }
                if self.shell.ghidra.frida == FridaPane::Events {
                    egui::ScrollArea::vertical()
                        .id_salt("frida_observed_events")
                        .max_height(ui.available_height().max(120.0))
                        .show_rows(ui, 18.0, trace.events.len(), |ui, range| {
                            for index in range {
                                let event = &trace.events[index];
                                let source = event.source.elf_vaddr;
                                let target =
                                    event.target.as_ref().and_then(|witness| witness.elf_vaddr);
                                ui.horizontal(|ui| {
                                    let line = format!(
                                        "#{} {:?} {}{}",
                                        event.sequence,
                                        event.kind,
                                        source.map_or_else(
                                            || "unknown".to_owned(),
                                            |address| format!("0x{address:x}")
                                        ),
                                        target.map_or_else(String::new, |address| format!(
                                            " → 0x{address:x}"
                                        ))
                                    );
                                    if ui
                                        .selectable_label(
                                            source.is_some() && self.selected_address == source,
                                            RichText::new(line).monospace().size(11.0),
                                        )
                                        .clicked()
                                        && source.is_some()
                                    {
                                        self.selected_address = source;
                                    }
                                    if let Some(target) = target
                                        && ui.small_button("Target").clicked()
                                    {
                                        self.selected_address = Some(target);
                                    }
                                });
                            }
                        });
                }
            }
            Some(Err(error)) => {
                ui.label(RichText::new(error).size(11.0).color(BAD));
            }
            None => {}
        }
    }
}
