//! Code-first Ghidra workspace, following iaito's DecompilerWidget and DebugActions.
use super::*;
use std::borrow::Cow;

pub(crate) const GHIDRA_CAPTURE_NAMES: &[&str] = &[
    "ghidra-pcode.png",
    "high-pcode.png",
    "state.png",
    "flow.png",
    "trace.png",
    "call-trace.png",
    "llvm.png",
    "llvm-prefix.png",
    "coverage.png",
    "metadata.png",
    "frida-session.png",
    "frida-events.png",
    "frida-rediscovery.png",
    "frida-comparison.png",
    "pcode-compact.png",
];

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) enum GhidraPane {
    #[default]
    Raw,
    High,
    State,
    Flow,
    Trace,
    Llvm,
    Coverage,
    Metadata,
}

impl GhidraPane {
    pub(super) const ALL: [Self; 8] = [
        Self::Raw,
        Self::High,
        Self::State,
        Self::Flow,
        Self::Trace,
        Self::Llvm,
        Self::Coverage,
        Self::Metadata,
    ];
    fn title(self) -> &'static str {
        match self {
            Self::Raw => "Raw P-code",
            Self::High => "High P-code",
            Self::State => "State",
            Self::Flow => "Control flow",
            Self::Trace => "Trace",
            Self::Llvm => "LLVM",
            Self::Coverage => "Coverage",
            Self::Metadata => "Metadata",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) enum LlvmPane {
    #[default]
    Cfg,
    Prefix,
    Operations,
    Calls,
    Simplified,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) enum TracePane {
    #[default]
    Path,
    Calls,
    Assessment,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) enum FridaPane {
    #[default]
    Events,
    Rediscovery,
    Compare,
}

#[derive(Default)]
pub(super) struct GhidraWorkspace {
    pub(super) pane: GhidraPane,
    pub(super) llvm: LlvmPane,
    pub(super) trace: TracePane,
    pub(super) frida: FridaPane,
    filter: String,
    selected_row: Option<usize>,
    selection_key: Option<(String, String, GhidraPane)>,
    value_details: bool,
}

impl GhidraWorkspace {
    pub(super) fn clear_selection(&mut self) {
        self.selected_row = None;
        self.selection_key = None;
        self.filter.clear();
        self.value_details = false;
    }
}

fn view_tabs<T: Copy + PartialEq>(ui: &mut egui::Ui, id: &str, value: &mut T, tabs: &[(T, &str)]) {
    egui::ScrollArea::horizontal().id_salt(id).show(ui, |ui| {
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 2.0;
            for (tab, title) in tabs {
                let active = *value == *tab;
                let response = ui.add(
                    egui::Button::new(*title)
                        .fill(if active {
                            SELECTED
                        } else {
                            Color32::TRANSPARENT
                        })
                        .stroke(egui::Stroke::NONE),
                );
                if response.clicked() {
                    *value = *tab;
                }
            }
        });
    });
}

impl AnalystApp {
    pub(crate) fn prepare_ghidra_capture(&mut self, step: usize) {
        self.open_tab(if (10..14).contains(&step) {
            Tab::Frida
        } else {
            Tab::GhidraPcode
        });
        self.shell.ghidra.pane = match step {
            1 => GhidraPane::High,
            2 => GhidraPane::State,
            3 => GhidraPane::Flow,
            4 | 5 => GhidraPane::Trace,
            6 | 7 => GhidraPane::Llvm,
            8 => GhidraPane::Coverage,
            9 => GhidraPane::Metadata,
            _ => GhidraPane::Raw,
        };
        self.shell.ghidra.trace = if step == 5 {
            TracePane::Calls
        } else {
            TracePane::Path
        };
        self.shell.ghidra.llvm = if step == 7 {
            LlvmPane::Prefix
        } else {
            LlvmPane::Cfg
        };
        self.shell.ghidra.frida = match step {
            11 => FridaPane::Events,
            12 => FridaPane::Rediscovery,
            13 => FridaPane::Compare,
            _ => FridaPane::Events,
        };
    }

    pub(crate) fn ghidra_workbench(&mut self, ui: &mut egui::Ui) {
        if self.tab == Tab::Frida { self.frida_workbench(ui); return; }
        let frida = self.tab == Tab::Frida;
        let mut requested = None;
        let mut disassembly = None;
        ui.horizontal(|ui| {
            ui.label(RichText::new(if frida { "FRIDA" } else { "GHIDRA" }).strong().color(CYAN));
            ui.separator();
            if let Some(snapshot) = &self.ghidra_snapshot {
                let name = snapshot.functions.iter()
                    .find(|f| f.entry == snapshot.selected_function.entry)
                    .map_or("Selected function", |f| f.name.as_str());
                ui.add_enabled_ui(!self.ghidra_busy && !self.busy && !self.frida_busy, |ui| {
                    egui::ComboBox::from_id_salt("ghidra_function")
                        .width(230.0).selected_text(name).show_ui(ui, |ui| {
                            for function in &snapshot.functions {
                                let selected = function.entry == snapshot.selected_function.entry;
                                if ui.selectable_label(selected, format!("{}  {}", function.entry.offset, function.name)).clicked() && !selected {
                                    requested = Some(function.entry.offset.clone());
                                }
                            }
                        });
                });
                let address = self.spec.as_ref().and_then(|spec| GhidraAddressMap::new(snapshot, spec))
                    .and_then(|map| map.to_linked(&snapshot.selected_function.entry.space, &snapshot.selected_function.entry.offset));
                ui.label(RichText::new(address.map(address_text).unwrap_or_else(|| snapshot.selected_function.entry.offset.clone())).monospace().color(ADDRESS));
                if ui.small_button("Disassembly").on_hover_text("Open the linked machine instructions").clicked() { disassembly = address; }
                if self.ghidra_busy { ui.spinner(); ui.label("Analyzing…"); }
            } else {
                ui.label(RichText::new("No analyzed function").color(MUTED));
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.small_button("Bridge…").clicked() { self.shell.ghidra_open = true; }
                ui.menu_button("?", |ui| {
                    ui.set_max_width(350.0);
                    ui.label(if frida {
                        "Run with Frida launches the open ELF and records the selected function when execution reaches it. Program arguments and advanced input files are optional in Run setup. Recorded events open automatically."
                    } else {
                        "Select a function in the dock or selector. Click a row to follow its address; double-click for disassembly. Right-click to copy or inspect dependencies. High P-code contains Ghidra's SSA and type evidence; raw P-code drives HydIR's lift."
                    });
                });
            });
        });
        ui.separator();
        view_tabs(ui, "pcode_views", &mut self.shell.ghidra.pane,
            &GhidraPane::ALL.map(|pane| (pane, pane.title())));
        ui.add_space(5.0);
        if self.ghidra_snapshot.is_none() {
            egui::Frame::new()
                .fill(PANEL)
                .inner_margin(14.0)
                .show(ui, |ui| {
                    ui.label(
                        RichText::new(if self.ghidra_busy {
                            "Analyzing the open binary"
                        } else {
                            "Ghidra analysis is needed"
                        })
                        .strong(),
                    );
                    ui.label(
                        "Open a local ELF to populate functions, P-code and linked analysis views.",
                    );
                    self.ghidra_bridge_controls(ui);
                    if self.current_local_path.is_none() && ui.button("Open ELF…").clicked() {
                        self.shell.project_open = true;
                    }
                });
            return;
        }
        if let Some(entry) = requested {
            if let (Some(binary), Some(spec)) =
                (self.current_local_path.clone(), self.spec.as_ref())
            {
                self.shell.ghidra.clear_selection();
                self.enqueue_ghidra(binary, spec.binary_sha256.clone(), Some(entry));
            }
        }
        if let Some(address) = disassembly {
            self.selected_address = Some(address);
            self.open_tab(Tab::Bytes);
        }
        if self.ghidra_busy {
            ui.add_space(12.0);
            ui.horizontal(|ui| { ui.spinner(); ui.label("Loading the selected function's analysis…"); });
            if let Some(task) = &self.ghidra_task {
                ghidra_progress(ui, task, "Ghidra analysis");
            }
            return;
        }
        match self.shell.ghidra.pane {
            GhidraPane::Raw | GhidraPane::High | GhidraPane::State => self.ghidra_listing(ui),
            pane => {
                if pane == GhidraPane::Llvm {
                    view_tabs(
                        ui,
                        "llvm_views",
                        &mut self.shell.ghidra.llvm,
                        &[
                            (LlvmPane::Cfg, "CFG module"),
                            (LlvmPane::Prefix, "Exact prefix"),
                            (LlvmPane::Operations, "Single operation"),
                            (LlvmPane::Calls, "Across calls"),
                            (LlvmPane::Simplified, "Simplification"),
                        ],
                    );
                } else if pane == GhidraPane::Trace {
                    view_tabs(
                        ui,
                        "trace_views",
                        &mut self.shell.ghidra.trace,
                        &[
                            (TracePane::Path, "Path & seed"),
                            (TracePane::Calls, "Call trace"),
                            (TracePane::Assessment, "Lift assessment"),
                        ],
                    );
                }
                egui::ScrollArea::vertical()
                    .id_salt(("ghidra_body", format!("{pane:?}")))
                    .auto_shrink([false, false])
                    .show(ui, |ui| self.ghidra_action_view(ui));
            }
        }
    }

    fn ghidra_listing(&mut self, ui: &mut egui::Ui) {
        let pane = self.shell.ghidra.pane;
        let key = self.ghidra_snapshot.as_ref().map(|s| {
            (
                s.binary_sha256.clone(),
                s.selected_function.entry.offset.clone(),
                pane,
            )
        });
        if self.shell.ghidra.selection_key != key {
            self.shell.ghidra.selected_row = None;
            self.shell.ghidra.selection_key = key;
        }
        ui.horizontal(|ui| {
            ui.add(
                egui::TextEdit::singleline(&mut self.shell.ghidra.filter)
                    .hint_text("Filter operations…")
                    .desired_width(230.0),
            );
            if ui.small_button("Clear").clicked() {
                self.shell.ghidra.filter.clear();
            }
            if ui.small_button("Copy listing").clicked() {
                let snapshot = self.ghidra_snapshot.as_ref().unwrap();
                let count = listing_count(self, pane);
                ui.ctx().copy_text(
                    (0..count)
                        .map(|row| listing_row(self, snapshot, pane, row).1.into_owned())
                        .collect::<Vec<_>>()
                        .join("\n"),
                );
            }
            if pane == GhidraPane::Raw {
                ui.toggle_value(&mut self.shell.ghidra.value_details, "Value details");
            }
        });
        let snapshot = self.ghidra_snapshot.as_ref().unwrap();
        let count = listing_count(self, pane);
        ui.horizontal(|ui| {
            ui.label(RichText::new(format!("{} · {} rows · {} instructions", pane.title(), count, snapshot.selected_function.instructions.len())).size(11.0).color(MUTED));
            ui.label(RichText::new("Analysis evidence · equivalence unverified").size(11.0).color(MUTED))
                .on_hover_text("Exact labels describe supported P-code operations. They do not establish equivalence to the original machine code.");
        });
        if pane == GhidraPane::High && count == 0 {
            ui.separator();
            ui.label("No high P-code was exported for this function.");
            if let Some(high) = &snapshot.selected_function.high_pcode {
                ui.label(&high.detail);
            }
            return;
        }
        if pane == GhidraPane::Raw && self.shell.ghidra.value_details {
            egui::Panel::right("pcode_value_details")
                .resizable(true)
                .default_size(280.0)
                .min_size(200.0)
                .max_size((ui.available_width() * 0.45).max(200.0))
                .show(ui, |ui| {
                    egui::ScrollArea::vertical()
                        .id_salt("pcode_value_scroll")
                        .show(ui, |ui| self.ghidra_slice_view(ui));
                });
        }
        let snapshot = self.ghidra_snapshot.as_ref().unwrap();
        let map = self
            .spec
            .as_ref()
            .and_then(|spec| GhidraAddressMap::new(snapshot, spec));
        let query = self.shell.ghidra.filter.to_ascii_lowercase();
        let rows: Vec<usize> = (0..count)
            .filter(|row| {
                query.is_empty()
                    || listing_row(self, snapshot, pane, *row)
                        .1
                        .to_ascii_lowercase()
                        .contains(&query)
            })
            .collect();
        let mut selected = None;
        let mut disassembly = None;
        let mut inspect = None;
        ui.add_space(3.0);
        let row_height = 22.0;
        egui::ScrollArea::both()
            .id_salt(("pcode_listing", format!("{pane:?}")))
            .auto_shrink([false, false])
            .show_rows(ui, row_height, rows.len(), |ui, visible| {
                ui.spacing_mut().item_spacing.y = 0.0;
                for position in visible {
                    let row = rows[position];
                    let (address, text) = listing_row(self, snapshot, pane, row);
                    let linked = address.and_then(|address| {
                        map.as_ref().and_then(|map| map.to_linked_raw(address))
                    });
                    let (sequence, body) = listing_text(&text);
                    let job = pcode_job(
                        body,
                        text.starts_with("ram:")
                            && pane == GhidraPane::Raw
                            && !body.starts_with('#'),
                    );
                    let galley = ui.painter().layout_job(job);
                    let width = ui.available_width().max(170.0 + galley.size().x + 16.0);
                    let (rect, response) =
                        ui.allocate_exact_size(egui::vec2(width, row_height), egui::Sense::click());
                    let active = self.shell.ghidra.selected_row == Some(row);
                    let same_instruction = linked.is_some() && linked == self.selected_address;
                    let background = if active {
                        SELECTED
                    } else if response.hovered() {
                        PANEL
                    } else if same_instruction {
                        Color32::from_rgb(39, 45, 50)
                    } else {
                        BG
                    };
                    ui.painter().rect_filled(rect, 0.0, background);
                    if active {
                        ui.painter().rect_filled(
                            egui::Rect::from_min_size(rect.min, egui::vec2(3.0, row_height)),
                            0.0,
                            ACCENT,
                        );
                    }
                    ui.painter().text(
                        rect.left_center() + egui::vec2(10.0, 0.0),
                        egui::Align2::LEFT_CENTER,
                        linked
                            .map(|a| format!("{a:08x}"))
                            .unwrap_or_else(|| "--------".into()),
                        egui::FontId::monospace(12.0),
                        ADDRESS,
                    );
                    ui.painter().text(
                        rect.left_center() + egui::vec2(101.0, 0.0),
                        egui::Align2::LEFT_CENTER,
                        sequence,
                        egui::FontId::monospace(11.0),
                        MUTED,
                    );
                    ui.painter().galley(
                        rect.min + egui::vec2(165.0, (row_height - galley.size().y) / 2.0),
                        galley,
                        TEXT,
                    );
                    let response = response.on_hover_text(text.as_ref());
                    if response.clicked() {
                        selected = Some((row, linked));
                    }
                    if response.double_clicked() {
                        disassembly = linked;
                    }
                    response.context_menu(|ui| {
                        if ui.button("Copy operation").clicked() {
                            ui.ctx().copy_text(text.to_string());
                            ui.close();
                        }
                        if let Some(address) = linked {
                            if ui.button("Copy address").clicked() {
                                ui.ctx().copy_text(address_text(address));
                                ui.close();
                            }
                            if ui.button("Show in disassembly").clicked() {
                                disassembly = linked;
                                ui.close();
                            }
                        }
                        if pane == GhidraPane::Raw
                            && pcode_line_target(snapshot, row).is_some()
                            && ui.button("Inspect value dependencies").clicked()
                        {
                            inspect = Some(row);
                            ui.close();
                        }
                    });
                }
            });
        if let Some((row, address)) = selected {
            self.shell.ghidra.selected_row = Some(row);
            if address.is_some() {
                self.selected_address = address;
            }
            if pane == GhidraPane::Raw {
                self.ghidra_slice = pcode_line_target(snapshot, row)
                    .map(|target| snapshot.backward_pcode_slice(target));
            }
        }
        if let Some(row) = inspect {
            self.ghidra_slice = pcode_line_target(snapshot, row)
                .map(|target| snapshot.backward_pcode_slice(target));
            self.shell.ghidra.selected_row = Some(row);
            self.shell.ghidra.value_details = true;
        }
        if let Some(address) = disassembly {
            self.selected_address = Some(address);
            self.open_tab(Tab::Bytes);
        }
    }
}

fn listing_count(app: &AnalystApp, pane: GhidraPane) -> usize {
    match pane {
        GhidraPane::State => app.ghidra_state_lines.len(),
        GhidraPane::High => app
            .ghidra_snapshot
            .as_ref()
            .and_then(|s| s.selected_function.high_pcode.as_ref())
            .map_or(0, |h| h.operations.len()),
        _ => app.ghidra_pcode_lines.len(),
    }
}

fn listing_row<'a>(
    app: &'a AnalystApp,
    snapshot: &'a GhidraSnapshot,
    pane: GhidraPane,
    row: usize,
) -> (Option<u64>, Cow<'a, str>) {
    match pane {
        GhidraPane::High => {
            let op = &snapshot
                .selected_function
                .high_pcode
                .as_ref()
                .unwrap()
                .operations[row];
            let output = op
                .output
                .as_ref()
                .map(high_pcode_varnode)
                .unwrap_or_else(|| "_".to_owned());
            let inputs = op
                .inputs
                .iter()
                .map(high_pcode_varnode)
                .collect::<Vec<_>>()
                .join(", ");
            (
                parse_ghidra_offset(&op.source_address.offset),
                Cow::Owned(format!(
                    "{}:{} #{} {output} = {}({inputs}){}",
                    op.source_address.space,
                    op.source_address.offset,
                    op.index,
                    op.mnemonic,
                    if op.is_dead { " [dead]" } else { "" }
                )),
            )
        }
        GhidraPane::State => (
            app.ghidra_state_lines[row].0,
            Cow::Borrowed(&app.ghidra_state_lines[row].1),
        ),
        _ => (
            app.ghidra_pcode_lines[row].0,
            Cow::Borrowed(&app.ghidra_pcode_lines[row].1),
        ),
    }
}

pub(super) fn listing_text(line: &str) -> (&str, &str) {
    let line = line.trim_start();
    let body = line
        .split_once(char::is_whitespace)
        .map_or(line, |(_, body)| body.trim_start());
    if body.starts_with('#') {
        body.split_once(char::is_whitespace)
            .map_or((body, ""), |(seq, body)| (seq, body.trim_start()))
    } else {
        ("", body)
    }
}

fn pcode_job(text: &str, instruction: bool) -> egui::text::LayoutJob {
    let mut job = egui::text::LayoutJob::default();
    let split = text.find(" [exact").or_else(|| text.find(" [opaque"));
    let (code, annotation) = split.map_or((text, ""), |at| text.split_at(at));
    for token in code.split_inclusive(|c: char| !(c.is_ascii_alphanumeric() || c == '_')) {
        let word = token.trim_matches(|c: char| !(c.is_ascii_alphanumeric() || c == '_'));
        let color = if instruction {
            VIOLET
        } else if word.starts_with("0x") || word.bytes().all(|b| b.is_ascii_digit()) {
            ADDRESS
        } else if matches!(
            word,
            "register" | "unique" | "ram" | "const" | "Read" | "Write"
        ) {
            CYAN
        } else if word.len() > 1
            && word
                .bytes()
                .all(|b| b.is_ascii_uppercase() || b == b'_' || b.is_ascii_digit())
        {
            ACCENT
        } else {
            TEXT
        };
        job.append(
            token,
            0.0,
            egui::TextFormat {
                font_id: egui::FontId::monospace(12.0),
                color,
                ..Default::default()
            },
        );
    }
    job.append(
        annotation,
        0.0,
        egui::TextFormat {
            font_id: egui::FontId::monospace(11.0),
            color: if annotation.starts_with(" [opaque") {
                ADDRESS
            } else {
                MUTED
            },
            ..Default::default()
        },
    );
    job.wrap.max_width = f32::INFINITY;
    job
}
