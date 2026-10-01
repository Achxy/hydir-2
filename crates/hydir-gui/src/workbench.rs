//! iaito-inspired desktop chrome. Analysis remains owned by the existing worker.
//! Reference: radareorg/iaito 3383cc1, MainWindow::restoreDocks and Dark.theme.

use super::*;
use serde::{Deserialize, Serialize};
use std::ops::Range;

const BORDER: Color32 = Color32::from_rgb(70, 76, 82);
const SELECTED: Color32 = Color32::from_rgb(32, 73, 94);
const ADDRESS: Color32 = Color32::from_rgb(230, 143, 83);
const CYAN: Color32 = Color32::from_rgb(76, 198, 215);
const ROW: f32 = 21.0;

impl Tab {
    const ALL: [Self; 19] = [
        Self::Overview,
        Self::Strings,
        Self::Imports,
        Self::Sections,
        Self::Search,
        Self::Bytes,
        Self::Graph,
        Self::Hexdump,
        Self::Native,
        Self::GhidraPcode,
        Self::RegionStudio,
        Self::Frida,
        Self::Investigation,
        Self::Cfg,
        Self::Coverage,
        Self::Llvm,
        Self::Passes,
        Self::C,
        Self::Analysis,
    ];

    fn title(self) -> &'static str {
        match self {
            Self::Overview => "Dashboard",
            Self::Strings => "Strings",
            Self::Imports => "Imports",
            Self::Sections => "Sections",
            Self::Search => "Search",
            Self::Bytes => "Disassembly",
            Self::Graph => "Graph",
            Self::Hexdump => "Hexdump",
            Self::Native => "Decompiler",
            Self::GhidraPcode => "Ghidra P-code",
            Self::RegionStudio => "Patching",
            Self::Frida => "Frida",
            Self::Investigation => "Investigation",
            Self::Cfg => "CFG",
            Self::Coverage => "Coverage",
            Self::Llvm => "LLVM IR",
            Self::Passes => "Passes",
            Self::C => "C output",
            Self::Analysis => "Global effects",
        }
    }
}

#[derive(Clone, Copy, Default, PartialEq, Serialize, Deserialize)]
enum Dock {
    #[default]
    Docked,
    Floating,
    Hidden,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(default)]
struct Layout {
    functions: Dock,
    inspector: Dock,
    console_floating: bool,
    console_visible: bool,
    console_height: f32,
    tabs: Vec<Tab>,
}

impl Default for Layout {
    fn default() -> Self {
        Self {
            functions: Dock::Docked,
            inspector: Dock::Hidden,
            console_floating: false,
            console_visible: true,
            console_height: 180.0,
            tabs: vec![
                Tab::Overview,
                Tab::Bytes,
                Tab::Graph,
                Tab::Native,
                Tab::GhidraPcode,
                Tab::Frida,
                Tab::Strings,
                Tab::Imports,
                Tab::Search,
                Tab::Hexdump,
            ],
        }
    }
}

impl Layout {
    fn normalize(&mut self) {
        let mut seen = Vec::new();
        self.tabs.retain(|tab| {
            if seen.contains(tab) {
                false
            } else {
                seen.push(*tab);
                true
            }
        });
        if self.tabs.is_empty() {
            self.tabs.push(Tab::Overview);
        }
        if !self.console_height.is_finite() {
            self.console_height = 180.0;
        }
        self.console_height = self
            .console_height
            .clamp(CONSOLE_MIN_HEIGHT, CONSOLE_MAX_HEIGHT);
    }
}

#[derive(Default)]
struct Navigation {
    addresses: Vec<u64>,
    cursor: usize,
}

impl Navigation {
    fn record(&mut self, address: u64) {
        if self.addresses.get(self.cursor) == Some(&address) {
            return;
        }
        self.addresses.truncate(self.cursor + 1);
        self.addresses.push(address);
        if self.addresses.len() > 256 {
            self.addresses.remove(0);
        }
        self.cursor = self.addresses.len() - 1;
    }

    fn step(&mut self, forward: bool) -> Option<u64> {
        let next = if forward {
            self.cursor.checked_add(1)?
        } else {
            self.cursor.checked_sub(1)?
        };
        let address = *self.addresses.get(next)?;
        self.cursor = next;
        Some(address)
    }
}

pub(super) struct BinaryView {
    bytes: Vec<u8>,
    strings: Vec<Range<usize>>,
    strings_truncated: bool,
}

impl BinaryView {
    pub(super) fn new(bytes: Vec<u8>) -> Self {
        let mut strings = Vec::new();
        let mut start = 0;
        let mut truncated = false;
        for end in 0..=bytes.len() {
            if end < bytes.len() && (bytes[end].is_ascii_graphic() || bytes[end] == b' ') {
                continue;
            }
            if end - start >= 4 {
                if strings.len() == 20_000 {
                    truncated = true;
                    break;
                }
                strings.push(start..end);
            }
            start = end + 1;
        }
        Self {
            bytes,
            strings,
            strings_truncated: truncated,
        }
    }
}

struct FunctionRow {
    name: String,
    selector: String,
    entry: Location,
    size: Option<u64>,
    legacy: bool,
}

#[derive(Default)]
pub(super) struct Shell {
    pub(super) capture: Option<capture::Capture>,
    layout: Layout,
    pub(super) project_open: bool,
    pub(super) ghidra_open: bool,
    ghidra: ghidra::GhidraWorkspace,
    frida_runtime: frida_runtime::Runtime,
    about_open: bool,
    seek_input: String,
    seek_focus: bool,
    filter_focus: bool,
    navigation: Navigation,
    functions: Vec<FunctionRow>,
    sort_by_address: bool,
    descending: bool,
    pub(super) binary: Option<BinaryView>,
    binary_key: Option<(String, bool)>,
    pub(super) binary_error: Option<String>,
    strings_filter: String,
    imports_filter: String,
    sections_filter: String,
    search_query: String,
    command: String,
    commands: Vec<String>,
    command_cursor: Option<usize>,
    transcript: Vec<String>,
    hex_offset: usize,
    hex_follow: Option<u64>,
    last_address: Option<u64>,
    layout_generation: u32,
}

impl Shell {
    pub(super) fn reset_binary(&mut self) {
        self.binary = None;
        self.binary_key = None;
        self.binary_error = None;
        self.functions.clear();
        self.navigation = Navigation::default();
        self.seek_input.clear();
        self.last_address = None;
        self.hex_follow = None;
        self.hex_offset = 0;
        self.project_open = false;
        self.ghidra.clear_selection();
    }
}

pub(super) fn apply_style(ctx: &egui::Context) {
    ctx.set_theme(egui::ThemePreference::Dark);
    let mut style = egui::Style::default();
    let v = &mut style.visuals;
    *v = egui::Visuals::dark();
    v.panel_fill = BG;
    v.window_fill = PANEL;
    v.extreme_bg_color = Color32::from_rgb(27, 30, 32);
    v.faint_bg_color = Color32::from_rgb(39, 43, 47);
    v.override_text_color = Some(TEXT);
    v.selection.bg_fill = SELECTED;
    v.selection.stroke = egui::Stroke::new(1.0, ACCENT);
    v.window_corner_radius = egui::CornerRadius::same(2);
    v.menu_corner_radius = egui::CornerRadius::same(2);
    v.window_stroke = egui::Stroke::new(1.0, BORDER);
    for w in [
        &mut v.widgets.noninteractive,
        &mut v.widgets.inactive,
        &mut v.widgets.hovered,
        &mut v.widgets.active,
        &mut v.widgets.open,
    ] {
        w.corner_radius = egui::CornerRadius::same(2);
        w.bg_stroke = egui::Stroke::new(1.0, BORDER);
        w.fg_stroke = egui::Stroke::new(1.0, TEXT);
    }
    v.widgets.inactive.bg_fill = PANEL;
    v.widgets.hovered.bg_fill = Color32::from_rgb(61, 67, 73);
    v.widgets.active.bg_fill = SELECTED;
    style.spacing.item_spacing = egui::vec2(5.0, 3.0);
    style.spacing.button_padding = egui::vec2(7.0, 3.0);
    style.spacing.interact_size = egui::vec2(24.0, 23.0);
    style.spacing.scroll.floating = false;
    style.spacing.scroll.bar_width = 10.0;
    for (kind, size) in [
        (egui::TextStyle::Body, 13.0),
        (egui::TextStyle::Button, 13.0),
        (egui::TextStyle::Small, 11.0),
        (egui::TextStyle::Heading, 16.0),
    ] {
        style
            .text_styles
            .insert(kind, egui::FontId::proportional(size));
    }
    style
        .text_styles
        .insert(egui::TextStyle::Monospace, egui::FontId::monospace(12.0));
    ctx.set_style_of(egui::Theme::Dark, style);
}

fn dock_title(ui: &mut egui::Ui, title: &str, floating: bool) -> (bool, bool) {
    let mut toggle = false;
    let mut close = false;
    egui::Frame::new()
        .fill(PANEL)
        .inner_margin(egui::Margin::symmetric(6, 2))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.add_space(2.0);
                toggle |= ui
                    .add(egui::Label::new(title).sense(egui::Sense::click()))
                    .double_clicked();
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    close = ui.small_button("×").on_hover_text("Close panel").clicked();
                    toggle |= ui
                        .small_button(if floating { "↙" } else { "↗" })
                        .on_hover_text(if floating {
                            "Dock panel"
                        } else {
                            "Float panel"
                        })
                        .clicked();
                });
            });
        });
    (toggle, close)
}

fn address_text(address: u64) -> String {
    format!("0x{address:08x}")
}

fn virtual_to_offset(spec: &ProgramSpec, address: u64) -> Option<usize> {
    spec.mapped_segments
        .iter()
        .find_map(|segment| {
            let delta = address.checked_sub(segment.virtual_address.0)?;
            (delta < segment.file_size)
                .then(|| segment.file_offset.0.checked_add(delta))
                .flatten()
        })
        .or_else(|| {
            if !spec.mapped_segments.is_empty() {
                return None;
            }
            spec.sections.iter().find_map(|section| {
                let delta = address.checked_sub(section.address.0)?;
                (delta < section.size)
                    .then(|| section.file_offset?.0.checked_add(delta))
                    .flatten()
            })
        })
        .and_then(|offset| usize::try_from(offset).ok())
}

fn offset_to_virtual(spec: &ProgramSpec, offset: usize) -> Option<u64> {
    spec.mapped_segments.iter().find_map(|segment| {
        let delta = (offset as u64).checked_sub(segment.file_offset.0)?;
        (delta < segment.file_size)
            .then(|| segment.virtual_address.0.checked_add(delta))
            .flatten()
    })
}

impl AnalystApp {
    pub(super) fn sync_shell_binary(&mut self) {
        let key = self
            .spec
            .as_ref()
            .map(|s| (s.binary_sha256.clone(), self.remote));
        if key == self.shell.binary_key {
            return;
        }
        let replacing = self.shell.binary_key.is_some();
        self.shell.reset_binary();
        self.shell.binary_key = key.clone();
        if replacing {
            self.selected_address = None;
            self.pending_disassembly_scroll = None;
        }
        let digest = key.as_ref().map(|(digest, _)| digest.as_str());
        if self
            .function_index
            .as_ref()
            .is_some_and(|i| Some(i.binary_sha256.as_str()) != digest)
        {
            self.function_index = None;
        }
        if self
            .disassembly_report
            .as_ref()
            .is_some_and(|r| Some(r.binary_sha256.as_str()) != digest)
        {
            self.disassembly_report = None;
        }
        if let Some((binary_sha256, false)) = key
            && self.current_local_path.is_some()
            && let Err(error) = self.tasks.try_send(Task::ReadBinaryView { binary_sha256 })
        {
            self.shell.binary_error = Some(format!("Could not load byte views: {error}"));
        }
    }

    fn ensure_functions(&mut self) {
        if !self.shell.functions.is_empty() {
            return;
        }
        let Some(spec) = &self.spec else {
            return;
        };
        let mut rows: Vec<FunctionRow> = spec
            .functions
            .iter()
            .map(|f| FunctionRow {
                name: f.name.clone(),
                selector: f.name.clone(),
                entry: f.location.unwrap_or(Location {
                    address_space: 0,
                    value: f.address,
                }),
                size: Some(f.size),
                legacy: true,
            })
            .collect();
        let mut entries: std::collections::HashSet<_> = rows
            .iter()
            .map(|f| (f.entry.address_space, f.entry.value.0))
            .collect();
        if let Some(index) = &self.function_index {
            for f in &index.functions {
                if entries.insert((f.entry.address_space, f.entry.value.0)) {
                    rows.push(FunctionRow {
                        name: indexed_function_label(f),
                        selector: f.id.clone(),
                        entry: f.entry,
                        size: None,
                        legacy: false,
                    });
                }
            }
        }
        rows.sort_by(|a, b| a.name.cmp(&b.name));
        self.shell.functions = rows;
    }

    pub(super) fn show_ghidra_pcode(&mut self) {
        self.open_tab(Tab::GhidraPcode);
    }

    fn open_tab(&mut self, tab: Tab) {
        self.tab = tab;
        if tab == Tab::Native && self.native_view_mode == NativeViewMode::Summary {
            self.native_view_mode = if self
                .typed_native_view
                .as_ref()
                .is_some_and(|v| v.c.is_some())
            {
                NativeViewMode::TypedC
            } else {
                NativeViewMode::LowLevelC
            };
        }
        // A tab change while a function is loading must survive its completion.
        if self.selection_target_tab.is_some() {
            self.selection_target_tab = Some(tab);
        }
        if !self.shell.layout.tabs.contains(&tab) {
            self.shell.layout.tabs.push(tab);
        }
        if tab == Tab::Bytes {
            self.pending_disassembly_scroll = self.selected_address;
        }
        if tab == Tab::Hexdump {
            self.shell.hex_follow = None;
        }
    }

    fn open_function_row(&mut self, index: usize, target: Tab) {
        let ghidra_view = matches!(target, Tab::GhidraPcode | Tab::Frida);
        if self.busy || (ghidra_view && self.ghidra_busy) {
            return;
        }
        let row = &self.shell.functions[index];
        let (name, selector, entry, legacy) = (
            row.name.clone(),
            row.selector.clone(),
            row.entry,
            row.legacy,
        );
        let ghidra_selection = if ghidra_view {
            let Some((binary, snapshot, spec)) = self
                .current_local_path
                .as_ref()
                .zip(self.ghidra_snapshot.as_ref())
                .zip(self.spec.as_ref())
                .map(|((binary, snapshot), spec)| (binary, snapshot, spec))
            else {
                self.open_tab(target);
                self.shell.ghidra_open = true;
                return;
            };
            let Some(address) =
                GhidraAddressMap::new(snapshot, spec).and_then(|map| map.to_ghidra(entry.value.0))
            else {
                self.failure = Some("This function has no mapped Ghidra address".to_owned());
                return;
            };
            Some((
                binary.clone(),
                spec.binary_sha256.clone(),
                format!("0x{address:x}"),
            ))
        } else {
            None
        };
        if legacy {
            self.select(name);
        } else {
            self.select_native(name, selector, entry);
        }
        self.selected_address = Some(entry.value.0);
        self.pending_disassembly_scroll = self.selected_address;
        self.selection_target_tab = Some(target);
        self.open_tab(target);
        if let Some((binary, digest, function)) = ghidra_selection {
            self.enqueue_ghidra(binary, digest, Some(function));
        }
    }

    fn seek(&mut self, query: &str) -> Result<(), String> {
        if self.busy {
            return Err("Wait for the current operation before navigating".to_owned());
        }
        self.ensure_functions();
        if let Some(index) = self
            .shell
            .functions
            .iter()
            .position(|f| f.name == query || f.selector == query)
        {
            let target = if self.tab == Tab::Overview {
                Tab::Bytes
            } else {
                self.tab
            };
            self.open_function_row(index, target);
            return Ok(());
        }
        let address = u64::from_str_radix(
            query
                .trim()
                .trim_start_matches("0x")
                .trim_start_matches("0X"),
            16,
        )
        .map_err(|_| "Enter a function name or a hexadecimal address".to_owned())?;
        let spec = self.spec.as_ref().ok_or("Open a file first")?;
        let mapped = spec.mapped_segments.iter().any(|s| {
            address >= s.virtual_address.0 && address - s.virtual_address.0 < s.memory_size
        }) || spec
            .sections
            .iter()
            .any(|s| address >= s.address.0 && address - s.address.0 < s.size);
        if !mapped {
            return Err(format!(
                "{} is outside the loaded image",
                address_text(address)
            ));
        }
        if let Some(index) = self.shell.functions.iter().position(|f| {
            address >= f.entry.value.0 && address - f.entry.value.0 < f.size.unwrap_or(1).max(1)
        }) {
            let target = if self.tab == Tab::Overview {
                Tab::Bytes
            } else {
                self.tab
            };
            self.open_function_row(index, target);
            self.pending_recipe_address = Some(address);
        }
        self.selected_address = Some(address);
        self.pending_disassembly_scroll = Some(address);
        self.shell.seek_input = address_text(address);
        if self.tab == Tab::Overview {
            self.open_tab(Tab::Bytes);
        }
        Ok(())
    }

    fn seek_or_report(&mut self, query: String) {
        if let Err(error) = self.seek(query.trim()) {
            self.status = error;
        }
    }

    fn navigation_step(&mut self, forward: bool) {
        if self.busy {
            return;
        }
        if let Some(address) = self.shell.navigation.step(forward) {
            self.seek_or_report(address_text(address));
        }
    }

    fn shortcuts(&mut self, ctx: &egui::Context) {
        let command = egui::Modifiers::COMMAND;
        if ctx.input_mut(|i| i.consume_key(command, egui::Key::O)) {
            self.shell.project_open = true;
        }
        if ctx.input_mut(|i| i.consume_key(command, egui::Key::L)) {
            self.shell.seek_focus = true;
        }
        if ctx.input_mut(|i| i.consume_key(command, egui::Key::F)) {
            self.shell.filter_focus = true;
            self.shell.layout.functions = Dock::Docked;
        }
        if ctx.input_mut(|i| i.consume_key(command, egui::Key::S)) {
            self.save_shell_layout();
        }
        if ctx.input_mut(|i| i.consume_key(egui::Modifiers::ALT, egui::Key::ArrowLeft)) {
            self.navigation_step(false);
        }
        if ctx.input_mut(|i| i.consume_key(egui::Modifiers::ALT, egui::Key::ArrowRight)) {
            self.navigation_step(true);
        }
        if ctx.egui_wants_keyboard_input() {
            return;
        }
        if ctx.input_mut(|i| i.consume_key(egui::Modifiers::NONE, egui::Key::G)) {
            self.shell.seek_focus = true;
        }
        if ctx.input_mut(|i| i.consume_key(egui::Modifiers::NONE, egui::Key::Space)) {
            self.open_tab(if self.tab == Tab::Graph {
                Tab::Bytes
            } else {
                Tab::Graph
            });
        }
        if ctx.input_mut(|i| i.consume_key(egui::Modifiers::NONE, egui::Key::Escape)) {
            self.navigation_step(false);
        }
    }

    pub(super) fn menu_and_toolbar(&mut self, ui: &mut egui::Ui) {
        egui::Frame::new()
            .fill(PANEL)
            .inner_margin(egui::Margin::symmetric(6, 2))
            .show(ui, |ui| {
                egui::MenuBar::new().ui(ui, |ui| {
                    ui.menu_button("File", |ui| {
                        if ui.button("Open…                         Ctrl+O").clicked() {
                            self.shell.project_open = true;
                            ui.close();
                        }
                        if let Some(path) = self.workbench.recent_local_path.clone()
                            && ui
                                .add_enabled(!self.busy, egui::Button::new("Open recent file"))
                                .on_hover_text(path.display().to_string())
                                .clicked()
                        {
                            self.enqueue(Task::Open(path), "Opening recent file…");
                            ui.close();
                        }
                        if ui.button("Projects / import / remote…").clicked() {
                            self.shell.project_open = true;
                            ui.close();
                        }
                        ui.separator();
                        if ui.button("Save layout                   Ctrl+S").clicked() {
                            self.save_shell_layout();
                            ui.close();
                        }
                        if ui.button("Quit").clicked() {
                            ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
                        }
                    });
                    ui.menu_button("Edit", |ui| {
                        if ui
                            .add_enabled(
                                self.selected_address.is_some(),
                                egui::Button::new("Copy address"),
                            )
                            .clicked()
                        {
                            ui.ctx()
                                .copy_text(address_text(self.selected_address.unwrap()));
                            ui.close();
                        }
                        if ui.button("Go to…                        G").clicked() {
                            self.shell.seek_focus = true;
                            ui.close();
                        }
                        if ui.button("Find function                 Ctrl+F").clicked() {
                            self.shell.filter_focus = true;
                            self.shell.layout.functions = Dock::Docked;
                            ui.close();
                        }
                        if ui.button("Annotations / properties").clicked() {
                            self.shell.layout.inspector = Dock::Docked;
                            ui.close();
                        }
                    });
                    ui.menu_button("View", |ui| {
                        for tab in [
                            Tab::Overview,
                            Tab::Bytes,
                            Tab::Graph,
                            Tab::Hexdump,
                            Tab::Native,
                            Tab::Strings,
                            Tab::Imports,
                            Tab::Sections,
                            Tab::Search,
                        ] {
                            if ui.selectable_label(self.tab == tab, tab.title()).clicked() {
                                self.open_tab(tab);
                                ui.close();
                            }
                        }
                        ui.separator();
                        if ui.button("Zoom in").clicked() {
                            ui.ctx()
                                .set_zoom_factor((ui.ctx().zoom_factor() + 0.1).min(2.0));
                        }
                        if ui.button("Zoom out").clicked() {
                            ui.ctx()
                                .set_zoom_factor((ui.ctx().zoom_factor() - 0.1).max(0.7));
                        }
                        if ui.button("Reset zoom").clicked() {
                            ui.ctx().set_zoom_factor(1.0);
                        }
                    });
                    ui.menu_button("Windows", |ui| {
                        for (title, dock) in [
                            ("Functions", &mut self.shell.layout.functions),
                            ("Inspector", &mut self.shell.layout.inspector),
                        ] {
                            let mut visible = *dock != Dock::Hidden;
                            if ui.checkbox(&mut visible, title).changed() {
                                *dock = if visible { Dock::Docked } else { Dock::Hidden };
                            }
                        }
                        ui.checkbox(&mut self.console_visible, "Console");
                        ui.separator();
                        ui.menu_button("Add tab", |ui| {
                            for tab in Tab::ALL {
                                if ui.button(tab.title()).clicked() {
                                    self.open_tab(tab);
                                    ui.close();
                                }
                            }
                        });
                        if ui.button("Restore default layout").clicked() {
                            self.reset_shell_layout();
                            ui.close();
                        }
                        if ui.button("Save layout").clicked() {
                            self.save_shell_layout();
                            ui.close();
                        }
                    });
                    ui.menu_button("Analysis", |ui| {
                        if ui
                            .add_enabled(
                                !self.busy && self.spec.is_some(),
                                egui::Button::new("Analyze global effects"),
                            )
                            .clicked()
                        {
                            self.enqueue(Task::Analyze, "Analyzing global effects…");
                            ui.close();
                        }
                        if ui
                            .add_enabled(
                                !self.busy && self.spec.is_some() && !self.remote,
                                egui::Button::new("Measure native coverage"),
                            )
                            .clicked()
                        {
                            self.enqueue(
                                Task::MeasureNativeCoverage,
                                "Measuring native semantics…",
                            );
                            ui.close();
                        }
                        ui.separator();
                        for tab in [
                            Tab::GhidraPcode,
                            Tab::RegionStudio,
                            Tab::Investigation,
                            Tab::Cfg,
                            Tab::Llvm,
                            Tab::Passes,
                            Tab::C,
                            Tab::Coverage,
                            Tab::Analysis,
                        ] {
                            if ui.button(tab.title()).clicked() {
                                self.open_tab(tab);
                                ui.close();
                            }
                        }
                        if ui.button("Ghidra setup / import…").clicked() {
                            self.shell.ghidra_open = true;
                            ui.close();
                        }
                    });
                    ui.menu_button("Ghidra", |ui| {
                        if ui.button("Bridge status / analyze…").clicked() {
                            self.shell.ghidra_open = true;
                            ui.close();
                        }
                        if ui.button("P-code / state / traces / LLVM").clicked() {
                            self.show_ghidra_pcode();
                            ui.close();
                        }
                    });
                    ui.menu_button("Debug", |ui| {
                        if ui.button("Frida observation").clicked() {
                            self.open_tab(Tab::Frida);
                            ui.close();
                        }
                        if ui.button("Triton console").clicked() {
                            self.console_mode = ConsoleMode::Triton;
                            self.console_visible = true;
                            ui.close();
                        }
                        if ui
                            .add_enabled(
                                !self.busy
                                    && self.current_local_path.is_some()
                                    && self.symbol.is_some(),
                                egui::Button::new("Run Triton on selected function"),
                            )
                            .clicked()
                        {
                            self.enqueue(
                                Task::Triton {
                                    path: self.current_local_path.clone().unwrap(),
                                    symbol: self.symbol.clone().unwrap(),
                                },
                                "Running Triton…",
                            );
                            ui.close();
                        }
                    });
                    ui.menu_button("Help", |ui| {
                        if ui.button("Keyboard shortcuts / about").clicked() {
                            self.shell.about_open = true;
                            ui.close();
                        }
                    });
                });
                ui.horizontal(|ui| {
                    if ui
                        .add_enabled(
                            !self.busy && self.shell.navigation.cursor > 0,
                            egui::Button::new("◀"),
                        )
                        .on_hover_text("Back · Alt+Left")
                        .clicked()
                    {
                        self.navigation_step(false);
                    }
                    if ui
                        .add_enabled(
                            !self.busy
                                && self.shell.navigation.cursor + 1
                                    < self.shell.navigation.addresses.len(),
                            egui::Button::new("▶"),
                        )
                        .on_hover_text("Forward · Alt+Right")
                        .clicked()
                    {
                        self.navigation_step(true);
                    }
                    ui.separator();
                    if ui
                        .button("Open")
                        .on_hover_text("Open a file · Ctrl+O")
                        .clicked()
                    {
                        self.shell.project_open = true;
                    }
                    let editor = ui.add(
                        egui::TextEdit::singleline(&mut self.shell.seek_input)
                            .id_salt("address_bar")
                            .hint_text("Type function name or address here")
                            .font(egui::TextStyle::Monospace)
                            .desired_width((ui.available_width() - 390.0).clamp(120.0, 580.0)),
                    );
                    if self.shell.seek_focus {
                        editor.request_focus();
                        self.shell.seek_focus = false;
                    }
                    let go = editor.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                    if ui
                        .add_enabled(!self.busy && self.spec.is_some(), egui::Button::new("Go"))
                        .clicked()
                        || go
                    {
                        self.seek_or_report(self.shell.seek_input.clone());
                    }
                    if ui.button("Ghidra bridge").clicked() {
                        self.shell.ghidra_open = true;
                    }
                    if ui
                        .button("Frida")
                        .on_hover_text("Open Frida session and observation results")
                        .clicked()
                    {
                        self.open_tab(Tab::Frida);
                    }
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if self.busy || self.ghidra_busy {
                            ui.spinner();
                        }
                        ui.label(
                            RichText::new(if self.remote { "Remote" } else { "Local" })
                                .color(MUTED),
                        );
                        if let Some(spec) = &self.spec {
                            ui.label(RichText::new(&spec.file_kind).color(MUTED));
                        }
                    });
                });
                self.binary_overview(ui);
            });
    }

    fn binary_overview(&mut self, ui: &mut egui::Ui) {
        let (rect, response) =
            ui.allocate_exact_size(egui::vec2(ui.available_width(), 14.0), egui::Sense::click());
        ui.painter().rect_filled(rect, 0.0, BG);
        let Some(spec) = &self.spec else {
            return;
        };
        let start = spec
            .mapped_segments
            .iter()
            .map(|s| s.virtual_address.0)
            .min();
        let end = spec
            .mapped_segments
            .iter()
            .filter_map(|s| s.virtual_address.0.checked_add(s.memory_size))
            .max();
        let (Some(start), Some(end)) = (start, end) else {
            return;
        };
        let span = (end.saturating_sub(start)).max(1) as f64;
        let x = |address: u64| {
            rect.left() + (((address.saturating_sub(start)) as f64 / span) as f32) * rect.width()
        };
        for s in &spec.mapped_segments {
            let color = if s.executable {
                Color32::from_rgb(126, 161, 105)
            } else if s.writable {
                ADDRESS
            } else {
                VIOLET
            };
            let region = egui::Rect::from_min_max(
                egui::pos2(x(s.virtual_address.0), rect.top()),
                egui::pos2(
                    x(s.virtual_address.0.saturating_add(s.memory_size)),
                    rect.bottom(),
                ),
            );
            ui.painter().rect_filled(region, 0.0, color);
        }
        for f in self.shell.functions.iter().take(20_000) {
            ui.painter().vline(
                x(f.entry.value.0),
                rect.y_range(),
                egui::Stroke::new(1.0, BG.gamma_multiply(0.55)),
            );
        }
        if let Some(address) = self.selected_address {
            ui.painter()
                .vline(x(address), rect.y_range(), egui::Stroke::new(2.0, TEXT));
        }
        if let Some(pos) = response.hover_pos() {
            let address =
                start.saturating_add((((pos.x - rect.left()) / rect.width()) as f64 * span) as u64);
            let name = spec
                .sections
                .iter()
                .find(|s| address >= s.address.0 && address - s.address.0 < s.size)
                .map_or("unmapped", |s| s.name.as_str());
            response.clone().on_hover_text(format!(
                "{} · {name}\nCode: green · data: orange · read-only: purple",
                address_text(address)
            ));
            if response.clicked() && !self.busy {
                self.seek_or_report(address_text(address));
            }
        }
    }

    fn functions_dock(&mut self, ui: &mut egui::Ui) {
        let (toggle, close) = dock_title(
            ui,
            "Functions",
            self.shell.layout.functions == Dock::Floating,
        );
        if toggle {
            self.shell.layout.functions = if self.shell.layout.functions == Dock::Floating {
                Dock::Docked
            } else {
                Dock::Floating
            };
        }
        if close {
            self.shell.layout.functions = Dock::Hidden;
        }
        ui.horizontal(|ui| {
            if ui
                .selectable_label(
                    !self.shell.sort_by_address,
                    if self.shell.descending {
                        "Name v"
                    } else {
                        "Name ^"
                    },
                )
                .clicked()
            {
                self.shell.descending = !self.shell.sort_by_address && !self.shell.descending;
                self.shell.sort_by_address = false;
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui
                    .selectable_label(self.shell.sort_by_address, "Address")
                    .clicked()
                {
                    self.shell.descending = self.shell.sort_by_address && !self.shell.descending;
                    self.shell.sort_by_address = true;
                }
            });
        });
        let query = self.search.to_lowercase();
        let mut rows: Vec<usize> = self
            .shell
            .functions
            .iter()
            .enumerate()
            .filter(|(_, f)| {
                query.is_empty()
                    || f.name.to_lowercase().contains(&query)
                    || address_text(f.entry.value.0).contains(&query)
            })
            .map(|(index, _)| index)
            .collect();
        if self.shell.sort_by_address {
            rows.sort_by_key(|i| self.shell.functions[*i].entry.value.0);
        }
        if self.shell.descending {
            rows.reverse();
        }
        let mut clicked = None;
        let height = (ui.available_height() - 52.0).max(40.0);
        egui::ScrollArea::vertical()
            .id_salt("functions_table")
            .max_height(height)
            .auto_shrink([false, false])
            .show_rows(ui, ROW, rows.len(), |ui, range| {
                for position in range {
                    let index = rows[position];
                    let f = &self.shell.functions[index];
                    let selected = self.symbol.as_deref() == Some(&f.name);
                    let (rect, response) = ui.allocate_exact_size(
                        egui::vec2(ui.available_width(), ROW),
                        egui::Sense::click(),
                    );
                    if selected || response.hovered() {
                        ui.painter().rect_filled(
                            rect,
                            0.0,
                            if selected { SELECTED } else { PANEL },
                        );
                    }
                    let name_rect = egui::Rect::from_min_max(
                        rect.min,
                        egui::pos2(rect.right() - 82.0, rect.bottom()),
                    );
                    ui.painter()
                        .with_clip_rect(name_rect.intersect(ui.clip_rect()))
                        .text(
                            rect.left_center() + egui::vec2(5.0, 0.0),
                            egui::Align2::LEFT_CENTER,
                            &f.name,
                            egui::FontId::proportional(12.0),
                            TEXT,
                        );
                    ui.painter().text(
                        rect.right_center() - egui::vec2(4.0, 0.0),
                        egui::Align2::RIGHT_CENTER,
                        format!("{:08x}", f.entry.value.0),
                        egui::FontId::monospace(11.0),
                        if selected { TEXT } else { MUTED },
                    );
                    let response = response.on_hover_text(format!(
                        "{}\n{} · {} bytes\n{}",
                        f.name,
                        address_text(f.entry.value.0),
                        f.size.map_or("unknown".to_owned(), |s| s.to_string()),
                        if f.legacy {
                            "ELF symbol"
                        } else {
                            "Recovered function"
                        }
                    ));
                    if response.clicked() && !self.busy {
                        clicked = Some((
                            index,
                            if self.tab == Tab::Overview {
                                Tab::Bytes
                            } else {
                                self.tab
                            },
                        ));
                    }
                    response.context_menu(|ui| {
                        for tab in [
                            Tab::Bytes,
                            Tab::Graph,
                            Tab::Native,
                            Tab::GhidraPcode,
                            Tab::Hexdump,
                            Tab::RegionStudio,
                        ] {
                            if ui
                                .add_enabled(
                                    !self.busy,
                                    egui::Button::new(format!("Show in {}", tab.title())),
                                )
                                .clicked()
                            {
                                clicked = Some((index, tab));
                                ui.close();
                            }
                        }
                        if ui.button("Copy name").clicked() {
                            ui.ctx().copy_text(f.name.clone());
                            ui.close();
                        }
                        if ui.button("Copy address").clicked() {
                            ui.ctx().copy_text(address_text(f.entry.value.0));
                            ui.close();
                        }
                    });
                }
            });
        ui.horizontal(|ui| {
            let filter = ui.add(
                egui::TextEdit::singleline(&mut self.search)
                    .hint_text("Quick Filter")
                    .desired_width((ui.available_width() - 29.0).max(50.0)),
            );
            if self.shell.filter_focus {
                filter.request_focus();
                self.shell.filter_focus = false;
            }
            if ui.small_button("×").on_hover_text("Clear filter").clicked() {
                self.search.clear();
            }
        });
        ui.label(
            RichText::new(format!(
                "{} / {} functions",
                rows.len(),
                self.shell.functions.len()
            ))
            .size(11.0)
            .color(MUTED),
        );
        if let Some((index, tab)) = clicked {
            self.open_function_row(index, tab);
        }
    }

    fn tab_strip(&mut self, ui: &mut egui::Ui) {
        if !self.shell.layout.tabs.contains(&self.tab) {
            self.shell.layout.tabs.push(self.tab);
        }
        let tabs = self.shell.layout.tabs.clone();
        let mut close = None;
        let mut reorder = None;
        egui::Frame::new().fill(PANEL).show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.menu_button("+", |ui| {
                    for tab in Tab::ALL {
                        if ui.button(tab.title()).clicked() {
                            self.open_tab(tab);
                            ui.close();
                        }
                    }
                });
                egui::ScrollArea::horizontal()
                    .id_salt("analysis_tabs")
                    .show(ui, |ui| {
                        ui.spacing_mut().item_spacing.x = 1.0;
                        ui.horizontal(|ui| {
                            for tab in tabs {
                                let active = self.tab == tab;
                                let response = ui.add(
                                    egui::Button::new(tab.title())
                                        .fill(if active { BG } else { PANEL })
                                        .stroke(egui::Stroke::NONE)
                                        .sense(egui::Sense::click_and_drag()),
                                );
                                if active {
                                    ui.painter().hline(
                                        response.rect.x_range(),
                                        response.rect.top(),
                                        egui::Stroke::new(2.0, ACCENT),
                                    );
                                }
                                if response.clicked() {
                                    self.open_tab(tab);
                                }
                                if response.clicked_by(egui::PointerButton::Middle) {
                                    close = Some(tab);
                                }
                                response.dnd_set_drag_payload(tab);
                                if let Some(source) = response.dnd_release_payload::<Tab>() {
                                    reorder = Some((*source, tab));
                                }
                                response
                                    .on_hover_text("Drag to reorder · middle-click to close")
                                    .context_menu(|ui| {
                                        if ui.button("Close tab").clicked() {
                                            close = Some(tab);
                                            ui.close();
                                        }
                                    });
                            }
                        });
                    });
            });
        });
        if let Some((source, target)) = reorder
            && let (Some(from), Some(to)) = (
                self.shell.layout.tabs.iter().position(|t| *t == source),
                self.shell.layout.tabs.iter().position(|t| *t == target),
            )
        {
            self.shell.layout.tabs.remove(from);
            self.shell.layout.tabs.insert(to, source);
        }
        if let Some(tab) = close {
            self.shell.layout.tabs.retain(|t| *t != tab);
            if self.shell.layout.tabs.is_empty() {
                self.shell.layout.tabs.push(Tab::Overview);
            }
            if self.tab == tab {
                self.tab = self.shell.layout.tabs[0];
                if self.selection_target_tab == Some(tab) {
                    self.selection_target_tab = Some(self.tab);
                }
            }
        }
    }

    pub(super) fn workbench_ui(&mut self, ui: &mut egui::Ui) {
        self.capture_before_frame(ui.ctx());
        self.ensure_functions();
        if let Some(address) = self.selected_address {
            self.shell.navigation.record(address);
            if self.shell.last_address != Some(address) {
                self.shell.seek_input = address_text(address);
                self.shell.last_address = Some(address);
            }
        }
        let ctx = ui.ctx().clone();
        self.shortcuts(&ctx);
        let title = self
            .source_label
            .as_deref()
            .and_then(|p| Path::new(p).file_name())
            .and_then(|p| p.to_str())
            .unwrap_or("No file");
        ctx.send_viewport_cmd(egui::ViewportCommand::Title(format!("HydIR — {title}")));
        self.menu_and_toolbar(ui);
        egui::Panel::bottom("workbench_status")
            .exact_size(23.0)
            .resizable(false)
            .frame(
                egui::Frame::new()
                    .fill(PANEL)
                    .inner_margin(egui::Margin::symmetric(7, 2)),
            )
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.label(
                            RichText::new(
                                self.selected_address
                                    .map(address_text)
                                    .unwrap_or_else(|| "No address".to_owned()),
                            )
                            .monospace()
                            .size(11.0),
                        );
                        ui.separator();
                        if ui
                            .small_button(if self.console_visible {
                                "Console v"
                            } else {
                                "Console ^"
                            })
                            .clicked()
                        {
                            self.console_visible = !self.console_visible;
                        }
                        let status = self.failure.as_deref().unwrap_or(&self.status);
                        ui.add(
                            egui::Label::new(
                                RichText::new(status)
                                    .size(11.0)
                                    .color(if self.failure.is_some() { BAD } else { MUTED }),
                            )
                            .truncate(),
                        )
                        .on_hover_text(status);
                    });
                });
            });
        if self.shell.layout.functions == Dock::Docked {
            let panel = egui::Panel::left(egui::Id::new((
                "functions_dock",
                self.shell.layout_generation,
            )))
            .resizable(true)
            .default_size(self.workbench.navigator_width)
            .min_size(180.0)
            .max_size((ui.available_width() * 0.4).max(180.0))
            .frame(egui::Frame::new().fill(BG))
            .show(ui, |ui| self.functions_dock(ui));
            self.workbench.navigator_width = panel.response.rect.width().clamp(180.0, 800.0);
        }
        if self.shell.layout.inspector == Dock::Docked {
            let panel = egui::Panel::right(egui::Id::new((
                "inspector_dock",
                self.shell.layout_generation,
            )))
            .resizable(true)
            .default_size(self.workbench.inspector_width)
            .min_size(220.0)
            .max_size((ui.available_width() * 0.45).max(220.0))
            .frame(egui::Frame::new().fill(BG))
            .show(ui, |ui| self.inspector_dock(ui));
            self.workbench.inspector_width = panel.response.rect.width().clamp(220.0, 800.0);
        }
        if self.console_visible && !self.shell.layout.console_floating {
            let maximum = (ui.available_height() - MAIN_VIEW_MIN_HEIGHT)
                .clamp(CONSOLE_MIN_HEIGHT, CONSOLE_MAX_HEIGHT);
            self.console_height = self.console_height.clamp(CONSOLE_MIN_HEIGHT, maximum);
            egui::Panel::bottom(egui::Id::new((
                "console_dock",
                self.shell.layout_generation,
            )))
            .resizable(true)
            .default_size(self.console_height)
            .min_size(CONSOLE_MIN_HEIGHT)
            .max_size(maximum)
            .frame(egui::Frame::new().fill(BG))
            .show(ui, |ui| {
                self.console_height = ui.available_height();
                self.command_console(ui);
            });
        }
        egui::CentralPanel::default()
            .frame(egui::Frame::new().fill(BG))
            .show(ui, |ui| {
                self.tab_strip(ui);
                egui::Frame::new()
                    .inner_margin(egui::Margin::same(7))
                    .show(ui, |ui| self.main_view(ui));
            });
        self.floating_panels(&ctx);
        self.capture_after_frame(&ctx);
    }

    fn inspector_dock(&mut self, ui: &mut egui::Ui) {
        let (toggle, close) = dock_title(
            ui,
            "Inspector",
            self.shell.layout.inspector == Dock::Floating,
        );
        if toggle {
            self.shell.layout.inspector = if self.shell.layout.inspector == Dock::Floating {
                Dock::Docked
            } else {
                Dock::Floating
            };
        }
        if close {
            self.shell.layout.inspector = Dock::Hidden;
        }
        egui::ScrollArea::vertical()
            .id_salt("inspector_scroll")
            .show(ui, |ui| {
                egui::Frame::new()
                    .inner_margin(egui::Margin::same(7))
                    .show(ui, |ui| self.inspector(ui));
            });
    }

    fn floating_panels(&mut self, ctx: &egui::Context) {
        if self.shell.ghidra_open {
            let mut open = true;
            egui::Window::new("Ghidra bridge")
                .open(&mut open)
                .default_width(540.0)
                .show(ctx, |ui| self.ghidra_bridge_controls(ui));
            self.shell.ghidra_open &= open;
        }
        if self.shell.layout.functions == Dock::Floating {
            egui::Window::new("Functions")
                .id(egui::Id::new("floating_functions"))
                .default_size([320.0, 520.0])
                .show(ctx, |ui| self.functions_dock(ui));
        }
        if self.shell.layout.inspector == Dock::Floating {
            egui::Window::new("Inspector")
                .id(egui::Id::new("floating_inspector"))
                .default_size([360.0, 550.0])
                .show(ctx, |ui| self.inspector_dock(ui));
        }
        if self.console_visible && self.shell.layout.console_floating {
            egui::Window::new("Console")
                .id(egui::Id::new("floating_console"))
                .default_size([720.0, 240.0])
                .show(ctx, |ui| self.command_console(ui));
        }
        if self.shell.project_open {
            let mut open = true;
            egui::Window::new("Open / Project settings")
                .open(&mut open)
                .default_size([650.0, 570.0])
                .max_height((ctx.content_rect().height() - 80.0).max(200.0))
                .show(ctx, |ui| {
                    egui::ScrollArea::vertical()
                        .id_salt("project_sources")
                        .show(ui, |ui| self.project_sources(ui));
                });
            self.shell.project_open &= open;
        }
        if self.shell.about_open {
            egui::Window::new("HydIR · Shortcuts")
                .open(&mut self.shell.about_open)
                .resizable(false)
                .show(ctx, |ui| {
                    ui.label("Reverse engineering and verified patching");
                    ui.separator();
                    for (key, action) in [
                        ("Ctrl+O", "Open file / projects"),
                        ("Ctrl+L / G", "Seek to address or function"),
                        ("Ctrl+F", "Filter functions"),
                        ("Space", "Switch disassembly / graph"),
                        ("Alt+Left / Escape", "Back"),
                        ("Alt+Right", "Forward"),
                        ("Ctrl+S", "Save layout"),
                        ("Drag tab", "Reorder views"),
                        ("Middle-click tab", "Close view"),
                        ("Double-click dock title", "Float / dock panel"),
                    ] {
                        ui.horizontal(|ui| {
                            ui.monospace(format!("{key:<25}"));
                            ui.label(action);
                        });
                    }
                    ui.separator();
                    ui.label("Interface based on iaito's dock layout and Dark palette.");
                    ui.hyperlink_to(
                        "iaito source reference",
                        "https://github.com/radareorg/iaito",
                    );
                    ui.label("Analysis engines: HydIR, Ghidra, Frida, Triton.");
                });
        }
    }

    fn reset_shell_layout(&mut self) {
        self.shell.layout = Layout::default();
        self.shell.layout_generation = self.shell.layout_generation.wrapping_add(1);
        self.workbench.navigator_width = 260.0;
        self.workbench.inspector_width = 290.0;
        self.console_height = 180.0;
        self.console_visible = true;
        self.tab = Tab::Overview;
    }

    pub(super) fn load_shell_layout(&mut self) {
        let loaded = default_db_path()
            .ok()
            .and_then(|p| fs::read(p.with_extension("layout.json")).ok())
            .filter(|bytes| bytes.len() < 64 * 1024)
            .and_then(|bytes| serde_json::from_slice::<Layout>(&bytes).ok());
        if let Some(mut layout) = loaded {
            layout.normalize();
            self.console_visible = layout.console_visible;
            self.console_height = layout.console_height;
            self.shell.layout = layout;
        }
    }

    pub(super) fn save_shell_layout(&mut self) {
        self.shell.layout.console_visible = self.console_visible;
        self.shell.layout.console_height = self.console_height;
        let result = default_db_path().and_then(|path| {
            let path = path.with_extension("layout.json");
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            }
            let bytes = serde_json::to_vec_pretty(&self.shell.layout).map_err(|e| e.to_string())?;
            // Persist only presentation settings, never binary data or credentials.
            fs::write(path, bytes).map_err(|e| e.to_string())
        });
        if let Err(error) = result {
            self.failure = Some(format!("Could not save layout: {error}"));
            return;
        }
        let mut settings = self.workbench.clone();
        if let Some(path) = &self.current_local_path {
            settings.recent_local_path = Some(path.clone());
        }
        self.enqueue(Task::SaveWorkbench(settings), "Saving workbench layout…");
    }
}

mod capture;
mod console;
mod data_views;
mod frida_runtime;
mod ghidra;
mod ghidra_actions;
pub(super) use data_views::source_code;
pub(super) use ghidra::GHIDRA_CAPTURE_NAMES;

#[cfg(test)]
mod tests;
