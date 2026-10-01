use super::*;

impl AnalystApp {
    pub(super) fn command_console(&mut self, ui: &mut egui::Ui) {
        let (toggle, close) = dock_title(ui, "Console", self.shell.layout.console_floating);
        if toggle {
            self.shell.layout.console_floating = !self.shell.layout.console_floating;
        }
        if close {
            self.console_visible = false;
        }
        ui.horizontal(|ui| {
            ui.selectable_value(&mut self.console_mode, ConsoleMode::Activity, "HydIR");
            ui.selectable_value(&mut self.console_mode, ConsoleMode::Triton, "Triton REPL");
            if self.console_mode == ConsoleMode::Activity {
                ui.checkbox(&mut self.console_json, "JSON");
                if ui.small_button("Clear").clicked() {
                    self.shell.transcript.clear();
                    self.history.clear();
                }
            } else if ui.small_button("Clear").clicked() {
                self.triton_console_commands.clear();
                self.triton_console_result = None;
            }
        });
        if self.console_mode == ConsoleMode::Triton {
            self.triton_console_body(ui);
            return;
        }
        let input_height = ui.spacing().interact_size.y
            .max(ui.text_style_height(&egui::TextStyle::Monospace) + 8.0);
        let height = (ui.available_height() - input_height - 2.0 * ui.spacing().item_spacing.y - 4.0).max(0.0);
        egui::ScrollArea::both()
            .id_salt("hydir_console_output")
            .max_height(height)
            .auto_shrink([false, false])
            .stick_to_bottom(true)
            .show(ui, |ui| {
                if self.console_json {
                    let text = if let Some(result) = &self.triton_result {
                        serde_json::to_string_pretty(result)
                    } else {
                        serde_json::to_string_pretty(&self.disassembly_report)
                    };
                    if let Ok(text) = text {
                        ui.add(egui::Label::new(RichText::new(text).monospace()).selectable(true));
                    }
                } else {
                    for entry in self
                        .history
                        .iter()
                        .rev()
                        .take(150)
                        .collect::<Vec<_>>()
                        .into_iter()
                        .rev()
                    {
                        ui.label(
                            RichText::new(format!("INFO: {entry}"))
                                .monospace()
                                .size(12.0)
                                .color(MUTED),
                        );
                    }
                    for line in &self.shell.transcript {
                        ui.label(RichText::new(line).monospace().size(12.0));
                    }
                    if let Some(failure) = &self.failure {
                        ui.colored_label(BAD, RichText::new(failure).monospace());
                    } else if self.busy {
                        ui.colored_label(ACCENT, &self.status);
                    }
                }
            });
        let mut submit = false;
        ui.horizontal(|ui| {
            ui.label(
                RichText::new(
                    self.selected_address
                        .map(|a| format!("[0x{a:08x}]>"))
                        .unwrap_or_else(|| "[HydIR]>".to_owned()),
                )
                .monospace()
                .color(ACCENT),
            );
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            submit |= ui.small_button(">").on_hover_text("Run command").clicked();
            let response = ui.add_sized([ui.available_width(), input_height],
                egui::TextEdit::singleline(&mut self.shell.command)
                    .id_salt("hydir_command")
                    .hint_text("Type '?' for help")
                    .font(egui::TextStyle::Monospace)
                    .desired_width(f32::INFINITY),
            );
            if response.has_focus() {
                let up = ui.input_mut(|i| i.consume_key(egui::Modifiers::NONE, egui::Key::ArrowUp));
                let down =
                    ui.input_mut(|i| i.consume_key(egui::Modifiers::NONE, egui::Key::ArrowDown));
                let len = self.shell.commands.len();
                if up && len > 0 {
                    let index = self.shell.command_cursor.unwrap_or(len).saturating_sub(1);
                    self.shell.command_cursor = Some(index);
                    self.shell.command = self.shell.commands[index].clone();
                } else if down && let Some(index) = self.shell.command_cursor {
                    if index + 1 < len {
                        self.shell.command_cursor = Some(index + 1);
                        self.shell.command = self.shell.commands[index + 1].clone();
                    } else {
                        self.shell.command_cursor = None;
                        self.shell.command.clear();
                    }
                }
            }
            submit |= response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
            if submit {
                response.request_focus();
            }
            });
        });
        if submit {
            let command = std::mem::take(&mut self.shell.command);
            if !command.trim().is_empty() {
                self.shell.commands.push(command.clone());
                if self.shell.commands.len() > 100 {
                    self.shell.commands.remove(0);
                }
                self.shell.command_cursor = None;
                self.run_workbench_command(command.trim());
            }
        }
    }

    pub(super) fn run_workbench_command(&mut self, command: &str) {
        self.shell.transcript.push(format!("> {command}"));
        let (verb, argument) = command.split_once(' ').unwrap_or((command, ""));
        let tab = match verb {
            "dashboard" => Some(Tab::Overview),
            "disasm" | "pd" => Some(Tab::Bytes),
            "graph" | "agf" => Some(Tab::Graph),
            "hex" | "px" => Some(Tab::Hexdump),
            "decompile" | "pdc" => Some(Tab::Native),
            "imports" | "ii" => Some(Tab::Imports),
            "strings" | "iz" => Some(Tab::Strings),
            "sections" | "iS" => Some(Tab::Sections),
            "patch" => Some(Tab::RegionStudio),
            _ => None,
        };
        if let Some(tab) = tab {
            self.open_tab(tab);
        } else {
            match verb {
                "?" | "help" => self.shell.transcript.push(
                    "HydIR commands (view aliases follow iaito conventions):\n  s <address|function>  Seek      s- / s+    Back / forward\n  pd / agf / px / pdc   Disassembly / graph / hex / decompiler\n  ii / iz / iS          Imports / strings / sections\n  dashboard / patch    Open analysis view\n  clear                Clear console\nUse the Triton REPL tab for symbolic expressions.".to_owned()),
                "s" if argument.trim().is_empty() => self.shell.transcript.push(self.selected_address.map(address_text).unwrap_or_else(|| "No address selected".to_owned())),
                "s" | "seek" => { if let Err(error) = self.seek(argument.trim()) { self.shell.transcript.push(error); } }
                "s-" | "back" => self.navigation_step(false),
                "s+" | "forward" => self.navigation_step(true),
                "clear" => { self.shell.transcript.clear(); self.history.clear(); }
                _ => self.shell.transcript.push(format!("Unknown HydIR command: {verb}. Type '?' for supported commands.")),
            }
        }
        if self.shell.transcript.len() > 200 {
            self.shell.transcript.drain(..100);
        }
    }
}
