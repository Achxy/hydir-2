//! Instrumentation workspace inspired by iaito's DebugActions and RegistersWidget.
use super::ghidra::FridaPane;
use super::*;
use hydir_execution::{TraceEvent, TraceEventKind, TraceStatus};

#[derive(Default, Clone, Copy, PartialEq, Eq)]
enum EventFilter {
    #[default]
    All,
    Entry,
    Block,
    Call,
    Exit,
}
impl EventFilter {
    const ALL: [Self; 5] = [Self::All, Self::Entry, Self::Block, Self::Call, Self::Exit];
    fn label(self) -> &'static str {
        match self {
            Self::All => "All events",
            Self::Entry => "Entries",
            Self::Block => "Blocks",
            Self::Call => "Calls",
            Self::Exit => "Returns",
        }
    }
    fn accepts(self, kind: &TraceEventKind) -> bool {
        matches!(
            (self, kind),
            (Self::All, _)
                | (Self::Entry, TraceEventKind::Entry)
                | (Self::Block, TraceEventKind::Block)
                | (Self::Call, TraceEventKind::Call)
                | (Self::Exit, TraceEventKind::Exit)
        )
    }
}
fn kind_label(kind: &TraceEventKind) -> &'static str {
    match kind {
        TraceEventKind::Entry => "Entry",
        TraceEventKind::Block => "Block",
        TraceEventKind::Call => "Call",
        TraceEventKind::Exit => "Return",
    }
}
fn matches_event(event: &TraceEvent, filter: EventFilter, query: &str) -> bool {
    filter.accepts(&event.kind)
        && (query.is_empty()
            || format!(
                "{} {} {} {:x} {} {}",
                event.sequence,
                event.thread_id,
                kind_label(&event.kind),
                event.source.runtime_address,
                event
                    .source
                    .elf_vaddr
                    .map(|a| format!("{a:x}"))
                    .unwrap_or_default(),
                event
                    .target
                    .as_ref()
                    .map(|t| format!(
                        "{:x} {}",
                        t.runtime_address,
                        t.elf_vaddr.map(|a| format!("{a:x}")).unwrap_or_default()
                    ))
                    .unwrap_or_default()
            )
            .to_lowercase()
            .contains(query.trim_start_matches("0x")))
}

pub(super) struct Workspace {
    pub(super) show_log: bool,
    settings_open: bool,
    details: bool,
    selected: Option<usize>,
    filter: EventFilter,
    query: String,
    filtered: Vec<usize>,
    filter_key: Option<(usize, String, EventFilter, String)>,
    diagnostics: bool,
}
impl Default for Workspace {
    fn default() -> Self {
        Self {
            show_log: false,
            settings_open: false,
            details: true,
            selected: None,
            filter: EventFilter::All,
            query: String::new(),
            filtered: Vec::new(),
            filter_key: None,
            diagnostics: false,
        }
    }
}
impl Workspace {
    pub(super) fn reset_events(&mut self) {
        self.selected = None;
        self.filter_key = None;
        self.filtered.clear();
        self.filter = EventFilter::All;
        self.query.clear();
    }
    fn update_filter(&mut self, trace: &DynamicTrace) {
        let query = self.query.trim().to_lowercase();
        let key = (
            trace.events.len(),
            trace.input_sha256.clone(),
            self.filter,
            query.clone(),
        );
        if self.filter_key.as_ref() != Some(&key) {
            self.filtered = trace
                .events
                .iter()
                .enumerate()
                .filter(|(_, event)| matches_event(event, self.filter, &query))
                .map(|(index, _)| index)
                .collect();
            if self.selected.is_none_or(|i| !self.filtered.contains(&i)) {
                self.selected = self.filtered.first().copied();
            }
            self.filter_key = Some(key);
        }
    }
}

fn section_header(ui: &mut egui::Ui, title: &str) {
    egui::Frame::new()
        .fill(PANEL)
        .inner_margin(egui::Margin::symmetric(8, 4))
        .show(ui, |ui| {
            ui.set_min_width((ui.available_width() - 1.0).max(0.0));
            ui.label(RichText::new(title).strong().size(13.0));
        });
}
fn trace_status(trace: &DynamicTrace) -> (&'static str, Color32) {
    if trace.status == TraceStatus::InjectionError {
        return ("Frida could not attach", BAD);
    }
    if trace.status == TraceStatus::ProcessFault {
        return ("Program faulted", BAD);
    }
    if trace.status == TraceStatus::TimedOut {
        return ("Run timed out", ADDRESS);
    }
    if !super::frida_session::reached_selected_function(trace) {
        return ("Function was not reached", ADDRESS);
    }
    if trace.status == TraceStatus::Completed && trace.lost_events == 0 {
        ("Recording complete", GOOD)
    } else {
        ("Partial recording", ADDRESS)
    }
}
fn output_text(hex: &str) -> String {
    let bytes: Vec<_> = hex
        .as_bytes()
        .chunks_exact(2)
        .filter_map(|pair| {
            std::str::from_utf8(pair)
                .ok()
                .and_then(|s| u8::from_str_radix(s, 16).ok())
        })
        .collect();
    String::from_utf8_lossy(&bytes).into_owned()
}

impl AnalystApp {
    fn frida_run_blocker(&self) -> Option<&'static str> {
        if self.frida_busy {
            Some("Recording execution")
        } else if self.current_local_path.is_none() {
            Some("Open a local ELF to begin")
        } else if self.ghidra_busy || self.busy {
            Some("Analyzing the selected function")
        } else if self.ghidra_snapshot.is_none() {
            Some("Ghidra analysis is required")
        } else if !self.shell.frida_runtime.ready() {
            Some("The Frida worker is not ready")
        } else if self.shell.frida_session.external_input && self.frida_input_path.trim().is_empty()
        {
            Some("Select an input file in Run settings")
        } else {
            None
        }
    }

    pub(super) fn frida_workbench(&mut self, ui: &mut egui::Ui) {
        self.shell.frida_runtime.poll(ui.ctx());
        self.frida_controls(ui);
        ui.separator();
        ui.horizontal_wrapped(|ui| {
            let count = self
                .frida_observation
                .as_ref()
                .and_then(|r| r.as_ref().ok())
                .map_or(0, |t| t.events.len());
            for (pane, label) in [
                (FridaPane::Events, format!("Trace ({count})")),
                (FridaPane::Rediscovery, "Recover targets".into()),
                (FridaPane::Compare, "Compare P-code".into()),
            ] {
                ui.selectable_value(&mut self.shell.ghidra.frida, pane, label);
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if self.shell.ghidra.frida == FridaPane::Events {
                    ui.toggle_value(&mut self.shell.frida_workspace.details, "Event details");
                }
            });
        });
        self.frida_status(ui);
        let output_max = (ui.available_height() * 0.35).max(75.0);
        egui::Panel::bottom("frida_program_output")
            .resizable(true)
            .default_size(120.0)
            .min_size(70.0)
            .max_size(output_max)
            .frame(egui::Frame::new().fill(BG))
            .show(ui, |ui| self.frida_output(ui));
        egui::CentralPanel::default().frame(egui::Frame::NONE).show(ui, |ui| {
            if self.ghidra_busy || self.frida_observation.is_none() || self.frida_observation.as_ref().is_some_and(Result::is_err) {
                self.frida_empty(ui);
            } else if self.shell.ghidra.frida == FridaPane::Events {
                self.frida_trace_workspace(ui);
            } else {
                egui::ScrollArea::vertical().id_salt("frida_analysis_actions").auto_shrink([false, false]).show(ui, |ui| {
                    ui.add_space(10.0);
                    if self.shell.ghidra.frida == FridaPane::Rediscovery {
                        ui.heading("Recover indirect targets");
                        ui.label("Review destinations seen in this run, then reanalyze them with Ghidra.");
                        ui.add_space(8.0);
                    }
                    self.frida_action_view(ui);
                });
            }
        });
        if self.shell.frida_workspace.settings_open {
            let mut open = true;
            let mut done = false;
            egui::Window::new("Frida run settings")
                .id(egui::Id::new("frida_run_settings"))
                .open(&mut open)
                .collapsible(false)
                .resizable(true)
                .default_width(490.0)
                .show(ui.ctx(), |ui| {
                    self.frida_session_view(ui);
                    ui.separator();
                    done = ui.button("Done").clicked();
                });
            self.shell.frida_workspace.settings_open = open && !done;
        }
    }

    fn frida_controls(&mut self, ui: &mut egui::Ui) {
        let blocker = self.frida_run_blocker();
        ui.horizontal_wrapped(|ui| {
            let run = ui
                .add_enabled(
                    blocker.is_none(),
                    egui::Button::new(RichText::new("Run with Frida").strong())
                        .fill(SELECTED)
                        .min_size(egui::vec2(140.0, 28.0)),
                )
                .on_hover_text(
                    blocker.unwrap_or("Launch the binary and record the selected function"),
                );
            if run.clicked() {
                self.start_frida_run();
            }
            if ui
                .add_enabled(
                    self.frida_busy
                        && self
                            .frida_task
                            .as_ref()
                            .is_some_and(|t| !t.cancel.load(Ordering::Acquire)),
                    egui::Button::new("Stop"),
                )
                .clicked()
                && let Some(task) = &self.frida_task
            {
                task.cancel.store(true, Ordering::Release);
            }
            if ui
                .add_enabled(!self.frida_busy, egui::Button::new("Run settings…"))
                .clicked()
            {
                self.shell.frida_workspace.settings_open = true;
            }
            self.shell.frida_runtime.compact(ui);
            ui.menu_button("Actions", |ui| {
                if ui
                    .add_enabled(
                        self.frida_observation.as_ref().is_some_and(Result::is_ok),
                        egui::Button::new("Copy recording JSON"),
                    )
                    .clicked()
                {
                    if let Some(Ok(trace)) = &self.frida_observation
                        && let Ok(json) = serde_json::to_string_pretty(trace)
                    {
                        ui.ctx().copy_text(json);
                    }
                    ui.close();
                }
                if ui
                    .add_enabled(
                        !self.frida_busy && self.frida_observation.is_some(),
                        egui::Button::new("Clear recording"),
                    )
                    .clicked()
                {
                    self.clear_frida_results();
                    ui.close();
                }
                ui.separator();
                ui.checkbox(&mut self.shell.frida_workspace.show_log, "Analysis console");
                if ui.button("Ghidra bridge…").clicked() {
                    self.shell.ghidra_open = true;
                    ui.close();
                }
            });
        });
        let mut requested = None;
        ui.horizontal_wrapped(|ui| {
            if let Some(binary) = &self.current_local_path {
                ui.label(
                    RichText::new(binary.file_name().unwrap_or_default().to_string_lossy())
                        .monospace(),
                )
                .on_hover_text(binary.display().to_string());
                ui.separator();
            }
            ui.label(RichText::new("Trace function").color(MUTED));
            if let Some(snapshot) = &self.ghidra_snapshot {
                let name = snapshot
                    .functions
                    .iter()
                    .find(|f| f.entry == snapshot.selected_function.entry)
                    .map_or("Selected function", |f| f.name.as_str());
                ui.add_enabled_ui(!self.ghidra_busy && !self.busy && !self.frida_busy, |ui| {
                    egui::ComboBox::from_id_salt("frida_function")
                        .width(180.0)
                        .selected_text(name)
                        .show_ui(ui, |ui| {
                            for function in &snapshot.functions {
                                if ui
                                    .selectable_label(
                                        function.entry == snapshot.selected_function.entry,
                                        format!("{}  {}", function.entry.offset, function.name),
                                    )
                                    .clicked()
                                    && function.entry != snapshot.selected_function.entry
                                {
                                    requested = Some(function.entry.offset.clone());
                                }
                            }
                        });
                });
                ui.label(
                    RichText::new(&snapshot.selected_function.entry.offset)
                        .monospace()
                        .color(ADDRESS),
                );
            }
            ui.separator();
            let args = if self.shell.frida_session.external_input {
                "Input file".into()
            } else if self.shell.frida_session.arguments.is_empty() {
                "No arguments".into()
            } else {
                format!(
                    "{} arguments",
                    self.shell.frida_session.arguments.lines().count()
                )
            };
            if ui.link(args).clicked() {
                self.shell.frida_workspace.settings_open = true;
            }
        });
        if let Some(entry) = requested
            && let (Some(binary), Some(spec)) =
                (self.current_local_path.clone(), self.spec.as_ref())
        {
            self.enqueue_ghidra(binary, spec.binary_sha256.clone(), Some(entry));
        }
    }

    fn frida_status(&self, ui: &mut egui::Ui) {
        ui.horizontal_wrapped(|ui| {
            if self.frida_busy {
                ui.spinner();
                if let Some(task) = &self.frida_task {
                    ui.label(if task.cancel.load(Ordering::Acquire) {
                        "Stopping Frida…".into()
                    } else {
                        format!("Recording · {} s elapsed", task.started.elapsed().as_secs())
                    });
                    ui.ctx().request_repaint_after(Duration::from_millis(100));
                }
            } else if self.ghidra_busy {
                ui.spinner();
                ui.label("Analyzing function…");
            } else if let Some(Ok(trace)) = &self.frida_observation {
                let (status, color) = trace_status(trace);
                ui.colored_label(color, status);
                ui.label(
                    RichText::new(format!(
                        "{} events  ·  {} computed jumps  ·  {} lost",
                        trace.events.len(),
                        trace.jump_evidence.len(),
                        trace.lost_events
                    ))
                    .small()
                    .color(MUTED),
                );
            } else if self.frida_observation.as_ref().is_some_and(Result::is_err) {
                ui.colored_label(BAD, "Run failed — see Diagnostics below");
            } else {
                ui.label(
                    RichText::new(
                        self.frida_run_blocker()
                            .unwrap_or("Ready · launches the program and records this function"),
                    )
                    .small()
                    .color(MUTED),
                );
            }
        });
    }

    fn frida_empty(&mut self, ui: &mut egui::Ui) {
        section_header(ui, "Execution trace");
        ui.add_space((ui.available_height() * 0.20).min(75.0));
        ui.vertical_centered(|ui| {
            if self.ghidra_busy || self.frida_busy {
                ui.spinner();
                ui.heading(if self.frida_busy {
                    "Recording execution"
                } else {
                    "Preparing function"
                });
                ui.label("Results appear here when the operation finishes.");
            } else if self.frida_observation.as_ref().is_some_and(Result::is_err) {
                ui.heading("The run could not start");
                ui.label("Check Diagnostics below, adjust Run settings, then retry.");
                self.shell.frida_workspace.diagnostics = true;
            } else {
                ui.heading("Ready to record");
                ui.label("Run the program to see executed blocks, calls and captured registers.");
                ui.add_space(12.0);
                if ui
                    .add_enabled(
                        self.frida_run_blocker().is_none(),
                        egui::Button::new("Run with Frida").fill(SELECTED),
                    )
                    .clicked()
                {
                    self.start_frida_run();
                }
                if self.current_local_path.is_none() && ui.button("Open ELF…").clicked() {
                    self.shell.project_open = true;
                } else if self.ghidra_snapshot.is_none()
                    && !self.ghidra_busy
                    && ui.button("Set up Ghidra analysis…").clicked()
                {
                    self.shell.ghidra_open = true;
                } else if !self.shell.frida_runtime.ready() {
                    ui.label("Open Worker: setup in the toolbar to configure Frida.");
                }
            }
        });
    }

    fn frida_output(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.selectable_value(
                &mut self.shell.frida_workspace.diagnostics,
                false,
                "Program output",
            );
            ui.selectable_value(
                &mut self.shell.frida_workspace.diagnostics,
                true,
                "Diagnostics",
            );
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if let Some(Ok(trace)) = &self.frida_observation
                    && ui.small_button("Copy").clicked()
                {
                    ui.ctx()
                        .copy_text(if self.shell.frida_workspace.diagnostics {
                            trace.diagnostics.join("\n")
                        } else {
                            format!(
                                "{}{}",
                                output_text(&trace.stdout_hex),
                                output_text(&trace.stderr_hex)
                            )
                        });
                }
            });
        });
        ui.separator();
        egui::ScrollArea::both().id_salt("frida_output_scroll").auto_shrink([false, false]).show(ui, |ui| {
            match &self.frida_observation {
                Some(Ok(trace)) if self.shell.frida_workspace.diagnostics => {
                    ui.monospace(format!("Frida {} · {:?} · {} lost events", trace.frida_version, trace.status, trace.lost_events));
                    if !super::frida_session::reached_selected_function(trace) { ui.colored_label(ADDRESS, "The selected function was not reached. Change the function or inputs, then run again."); }
                    for diagnostic in &trace.diagnostics { ui.monospace(diagnostic); }
                    ui.label(RichText::new("Recording covers one execution. Process exit status is not captured.").small().color(MUTED));
                }
                Some(Ok(trace)) => {
                    if trace.stdout_hex.is_empty() && trace.stderr_hex.is_empty() { ui.label(RichText::new("No program output.").color(MUTED)); }
                    else {
                        if !trace.stdout_hex.is_empty() { ui.add(egui::Label::new(RichText::new(output_text(&trace.stdout_hex)).monospace()).selectable(true)); }
                        if !trace.stderr_hex.is_empty() { ui.add(egui::Label::new(RichText::new(output_text(&trace.stderr_hex)).monospace().color(ADDRESS)).selectable(true)); }
                    }
                }
                Some(Err(error)) => { ui.colored_label(BAD, error); }
                None => { ui.label(RichText::new(if self.frida_busy { "Waiting for the program to finish…" } else { "stdout and stderr will appear here after a run." }).color(MUTED)); }
            }
        });
    }

    fn frida_trace_workspace(&mut self, ui: &mut egui::Ui) {
        if let Some(Ok(trace)) = &self.frida_observation {
            self.shell.frida_workspace.update_filter(trace);
        }
        if self.shell.frida_workspace.details && ui.available_width() >= 650.0 {
            egui::Panel::right("frida_event_details")
                .resizable(true)
                .default_size(265.0)
                .min_size(215.0)
                .max_size(ui.available_width() * 0.45)
                .frame(egui::Frame::new().fill(BG))
                .show(ui, |ui| self.frida_inspector(ui));
        } else if self.shell.frida_workspace.details {
            egui::Panel::bottom("frida_event_details_compact")
                .resizable(true)
                .default_size(130.0)
                .min_size(70.0)
                .max_size((ui.available_height() * 0.45).max(70.0))
                .frame(egui::Frame::new().fill(BG))
                .show(ui, |ui| self.frida_inspector(ui));
        }
        egui::CentralPanel::default()
            .frame(egui::Frame::NONE)
            .show(ui, |ui| self.frida_event_table(ui));
    }

    fn frida_event_table(&mut self, ui: &mut egui::Ui) {
        let Some(Ok(trace)) = &self.frida_observation else {
            return;
        };
        let workspace = &mut self.shell.frida_workspace;
        ui.horizontal(|ui| {
            egui::ComboBox::from_id_salt("frida_event_kind")
                .width(100.0)
                .selected_text(workspace.filter.label())
                .show_ui(ui, |ui| {
                    for filter in EventFilter::ALL {
                        ui.selectable_value(&mut workspace.filter, filter, filter.label());
                    }
                });
            ui.add_sized(
                [ui.available_width(), 26.0],
                egui::TextEdit::singleline(&mut workspace.query)
                    .hint_text("Filter address, event or thread…")
                    .desired_width(f32::INFINITY),
            );
        });
        workspace.update_filter(trace);
        let width = ui.available_width();
        let columns = [
            0.0,
            width * 0.10,
            width * 0.27,
            width * 0.56,
            width * 0.86,
            width,
        ];
        let paint_row =
            |ui: &mut egui::Ui, cells: [&str; 5], selected: bool, header: bool, linked: bool| {
                let (rect, response) = ui.allocate_exact_size(
                    egui::vec2(width, 24.0),
                    if header {
                        egui::Sense::hover()
                    } else {
                        egui::Sense::click()
                    },
                );
                if header || selected || response.hovered() {
                    ui.painter()
                        .rect_filled(rect, 0.0, if selected { SELECTED } else { PANEL });
                }
                for (column, text) in cells.iter().enumerate() {
                    let clip = egui::Rect::from_min_max(
                        egui::pos2(rect.left() + columns[column] + 4.0, rect.top()),
                        egui::pos2(rect.left() + columns[column + 1] - 3.0, rect.bottom()),
                    );
                    let color = if header {
                        MUTED
                    } else if column == 2 && linked {
                        ADDRESS
                    } else {
                        TEXT
                    };
                    ui.painter()
                        .with_clip_rect(clip.intersect(ui.clip_rect()))
                        .text(
                            egui::pos2(clip.left(), rect.center().y),
                            egui::Align2::LEFT_CENTER,
                            text,
                            egui::FontId::monospace(12.0),
                            color,
                        );
                }
                response
            };
        paint_row(
            ui,
            ["#", "Event", "Address", "Target", "Thread"],
            false,
            true,
            false,
        );
        let list_height = (ui.available_height() - 22.0).max(30.0);
        let row_spacing = ui.spacing().item_spacing.y;
        ui.spacing_mut().item_spacing.y = 0.0;
        egui::ScrollArea::vertical()
            .id_salt("frida_trace_rows")
            .max_height(list_height)
            .auto_shrink([false, false])
            .show_rows(ui, 24.0, workspace.filtered.len(), |ui, range| {
                ui.spacing_mut().item_spacing.y = 0.0;
                for row in range {
                    let index = workspace.filtered[row];
                    let event = &trace.events[index];
                    let source = format!(
                        "0x{:x}",
                        event
                            .source
                            .elf_vaddr
                            .unwrap_or(event.source.runtime_address)
                    );
                    let target = event
                        .target
                        .as_ref()
                        .map(|t| format!("0x{:x}", t.elf_vaddr.unwrap_or(t.runtime_address)))
                        .unwrap_or_else(|| "—".into());
                    let response = paint_row(
                        ui,
                        [
                            &event.sequence.to_string(),
                            kind_label(&event.kind),
                            &source,
                            &target,
                            &event.thread_id.to_string(),
                        ],
                        workspace.selected == Some(index),
                        false,
                        event.source.elf_vaddr.is_some(),
                    )
                    .on_hover_text(if event.source.elf_vaddr.is_some() {
                        "Verified ELF address · double-click for disassembly"
                    } else {
                        "Runtime address · no verified ELF mapping"
                    });
                    if response.clicked() {
                        workspace.selected = Some(index);
                        self.selected_address = event.source.elf_vaddr.or(self.selected_address);
                    }
                    if response.double_clicked()
                        && let Some(address) = event.source.elf_vaddr
                    {
                        self.selected_address = Some(address);
                        self.pending_disassembly_scroll = Some(address);
                        self.tab = Tab::Bytes;
                    }
                    response.context_menu(|ui| {
                        if ui.button("Copy address").clicked() {
                            ui.ctx().copy_text(source.clone());
                            ui.close();
                        }
                        if ui
                            .add_enabled(
                                event.source.elf_vaddr.is_some(),
                                egui::Button::new("Show in disassembly"),
                            )
                            .clicked()
                        {
                            self.selected_address = event.source.elf_vaddr;
                            self.pending_disassembly_scroll = event.source.elf_vaddr;
                            self.tab = Tab::Bytes;
                            ui.close();
                        }
                    });
                }
            });
        ui.spacing_mut().item_spacing.y = row_spacing;
        ui.label(
            RichText::new(format!(
                "{} / {} events · select a row to inspect",
                workspace.filtered.len(),
                trace.events.len()
            ))
            .small()
            .color(MUTED),
        );
        if workspace.filtered.is_empty() {
            ui.label("No events match this filter.");
        }
    }

    pub(crate) fn frida_inspector(&mut self, ui: &mut egui::Ui) {
        section_header(ui, "Event details");
        egui::ScrollArea::both()
            .id_salt("frida_event_inspector")
            .auto_shrink([false, false])
            .show(ui, |ui| {
                let Some(Ok(trace)) = &self.frida_observation else {
                    ui.label("Select a recorded event.");
                    return;
                };
                let Some(event) = self
                    .shell
                    .frida_workspace
                    .selected
                    .and_then(|i| trace.events.get(i))
                else {
                    ui.label("Select a recorded event.");
                    return;
                };
                ui.label(
                    RichText::new(format!("#{}  {}", event.sequence, kind_label(&event.kind)))
                        .strong(),
                );
                egui::Grid::new("frida_event_metadata")
                    .num_columns(2)
                    .spacing([12.0, 6.0])
                    .show(ui, |ui| {
                        for (name, value) in [
                            ("Thread", event.thread_id.to_string()),
                            ("Runtime", format!("0x{:x}", event.source.runtime_address)),
                            (
                                "ELF",
                                event
                                    .source
                                    .elf_vaddr
                                    .map(|a| format!("0x{a:x}"))
                                    .unwrap_or_else(|| "Unmapped".into()),
                            ),
                        ] {
                            ui.label(RichText::new(name).color(MUTED));
                            ui.monospace(value);
                            ui.end_row();
                        }
                    });
                if let Some(address) = event.source.elf_vaddr
                    && ui.button("Show disassembly").clicked()
                {
                    self.selected_address = Some(address);
                    self.pending_disassembly_scroll = Some(address);
                    self.tab = Tab::Bytes;
                }
                if let Some(target) = &event.target {
                    ui.separator();
                    ui.label(RichText::new("Target").strong());
                    ui.monospace(format!(
                        "0x{:x}",
                        target.elf_vaddr.unwrap_or(target.runtime_address)
                    ));
                    if let Some(address) = target.elf_vaddr
                        && ui.button("Follow target").clicked()
                    {
                        self.selected_address = Some(address);
                        self.pending_disassembly_scroll = Some(address);
                        self.tab = Tab::Bytes;
                    }
                }
                if let Some(bytes) = &event.source.original_bytes_hex {
                    ui.separator();
                    ui.label(RichText::new("Verified bytes").color(MUTED));
                    ui.monospace(bytes);
                }
                ui.separator();
                ui.label(RichText::new("Captured registers").strong());
                if let Some(registers) = &event.registers {
                    ui.label(
                        RichText::new("State at function entry")
                            .small()
                            .color(MUTED),
                    );
                    egui::Grid::new("frida_registers")
                        .striped(true)
                        .num_columns(2)
                        .spacing([14.0, 4.0])
                        .show(ui, |ui| {
                            for (name, value) in registers {
                                ui.label(RichText::new(name).monospace().color(CYAN));
                                ui.add(
                                    egui::Label::new(
                                        RichText::new(format!("0x{value:016x}")).monospace(),
                                    )
                                    .selectable(true),
                                );
                                ui.end_row();
                            }
                        });
                } else {
                    ui.label("Registers are captured on Entry events.");
                    if let Some(index) = trace.events.iter().rposition(|e| {
                        e.sequence <= event.sequence
                            && e.thread_id == event.thread_id
                            && e.registers.is_some()
                    }) && ui.button("Inspect preceding entry").clicked()
                    {
                        self.shell.frida_workspace.filter = EventFilter::All;
                        self.shell.frida_workspace.query.clear();
                        self.shell.frida_workspace.selected = Some(index);
                    }
                }
            });
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use hydir_execution::TraceWitness;

    fn event(sequence: u64, kind: TraceEventKind, linked: Option<u64>) -> TraceEvent {
        TraceEvent {
            sequence,
            thread_id: 7,
            kind,
            source: TraceWitness {
                runtime_address: 0x70004000 + sequence,
                elf_vaddr: linked,
                original_bytes_hex: linked.map(|_| "90".into()),
            },
            target: None,
            registers: None,
        }
    }
    fn trace() -> DynamicTrace {
        serde_json::from_value(serde_json::json!({
            "schema_version": 3, "binary_sha256": "a".repeat(64), "input_sha256": "b".repeat(64),
            "selected_elf_vaddr": 0x20137c, "ghidra_snapshot_sha256": null,
            "observer": "test", "frida_version": "test", "agent_sha256": "c".repeat(64),
            "runtime_module_base": 0x70000000_u64, "elf_load_bias": 0,
            "budget": {"max_events": 4096, "timeout_ms": 10000}, "status": "completed",
            "lost_events": 0, "stdout_hex": "360a", "stderr_hex": "", "diagnostics": [],
            "events": [event(0, TraceEventKind::Entry, Some(0x20137c)), event(1, TraceEventKind::Call, Some(0x201380)), event(2, TraceEventKind::Block, None)], "jump_evidence": []
        })).unwrap()
    }

    #[test]
    fn filtering_keeps_original_event_identity_and_unmapped_runtime_addresses() {
        let trace = trace();
        let mut browser = Workspace::default();
        browser.update_filter(&trace);
        assert_eq!(browser.selected, Some(0));
        browser.filter = EventFilter::Call;
        browser.update_filter(&trace);
        assert_eq!(browser.filtered, [1]);
        assert_eq!(browser.selected, Some(1));
        browser.filter = EventFilter::All;
        browser.query = "0x70004002".into();
        browser.update_filter(&trace);
        assert_eq!(browser.filtered, [2]);
        assert_eq!(browser.selected, Some(2));
        browser.query = "does-not-exist".into();
        browser.update_filter(&trace);
        assert!(browser.filtered.is_empty());
        assert_eq!(browser.selected, None);
        browser.reset_events();
        browser.update_filter(&trace);
        assert_eq!(browser.filtered, [0, 1, 2]);
    }

    #[test]
    fn run_status_does_not_confuse_injection_failure_with_an_unreached_function() {
        let mut trace = trace();
        assert_eq!(trace_status(&trace).0, "Recording complete");
        trace.lost_events = 1;
        assert_eq!(trace_status(&trace).0, "Partial recording");
        trace.events.clear();
        assert_eq!(trace_status(&trace).0, "Function was not reached");
        trace.status = TraceStatus::InjectionError;
        assert_eq!(trace_status(&trace), ("Frida could not attach", BAD));
        trace.status = TraceStatus::TimedOut;
        assert_eq!(trace_status(&trace).0, "Run timed out");
    }

    #[test]
    fn trace_details_and_output_fit_compact_and_full_workspaces_without_growth() {
        for size in [egui::vec2(750.0, 520.0), egui::vec2(1150.0, 720.0)] {
            let ctx = egui::Context::default();
            let mut app = AnalystApp::new(&ctx);
            app.open_tab(Tab::Frida);
            app.current_local_path = Some(PathBuf::from("demo/hydir-prism.elf"));
            app.ghidra_snapshot = Some(
                serde_json::from_slice(include_bytes!(
                    "../../../../tests/fixtures/ghidra_prism_metadata_v2.json"
                ))
                .unwrap(),
            );
            let mut recording = trace();
            recording.events[0].registers = Some(std::collections::BTreeMap::from([
                ("RIP".into(), 0x20137c),
                ("RSP".into(), 0x7fff00000001),
            ]));
            recording
                .events
                .extend((3..1000).map(|i| event(i, TraceEventKind::Block, Some(0x201380))));
            app.frida_observation = Some(Ok(recording));
            for frame in 0..24 {
                app.shell.ghidra.frida = match frame / 8 {
                    0 => FridaPane::Events,
                    1 => FridaPane::Rediscovery,
                    _ => FridaPane::Compare,
                };
                let mut output = ctx.run_ui(
                    egui::RawInput {
                        screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, size)),
                        ..Default::default()
                    },
                    |ui| {
                        app.frida_workbench(ui);
                        assert!(
                            ui.min_rect().right() <= size.x + 1.0,
                            "Frida grew beyond viewport: {:?}",
                            ui.min_rect()
                        );
                        assert!(
                            ui.min_rect().bottom() <= size.y + 1.0,
                            "Frida grew beyond viewport: {:?}",
                            ui.min_rect()
                        );
                    },
                );
                output.textures_delta.clear();
            }
        }
    }
}
