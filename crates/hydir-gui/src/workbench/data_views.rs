use super::*;

/// Render source in the same compact, numbered code surface as the disassembler.
pub(crate) fn source_code(ui: &mut egui::Ui, source: &str, id: &str) {
    let lines: Vec<&str> = source.lines().collect();
    let line_height = ui.text_style_height(&egui::TextStyle::Monospace);
    egui::ScrollArea::both()
        .id_salt(id)
        .auto_shrink([false, false])
        .show_rows(ui, line_height, lines.len(), |ui, range| {
            for index in range {
                let line = lines[index];
                let mut job = egui::text::LayoutJob::default();
                let format = |color| egui::TextFormat {
                    font_id: egui::FontId::monospace(12.0),
                    color,
                    ..Default::default()
                };
                job.append(&format!("{:>5}   ", index + 1), 0.0, format(MUTED));
                let mut remaining = line;
                while !remaining.is_empty() {
                    let c = remaining.chars().next().unwrap();
                    let (length, color) = if remaining.starts_with("//")
                        || remaining.starts_with(';')
                        || remaining.starts_with("/*")
                    {
                        (remaining.len(), GOOD)
                    } else if c == '"' || c == '\'' {
                        let mut escaped = false;
                        let mut length = remaining.len();
                        for (i, next) in remaining.char_indices().skip(1) {
                            if next == c && !escaped {
                                length = i + next.len_utf8();
                                break;
                            }
                            escaped = next == '\\' && !escaped;
                        }
                        (length, GOOD)
                    } else if c.is_alphanumeric() || c == '_' || c == '%' || c == '@' {
                        let length = remaining
                            .char_indices()
                            .find(|(_, c)| {
                                !c.is_alphanumeric() && *c != '_' && *c != '%' && *c != '@'
                            })
                            .map_or(remaining.len(), |(i, _)| i);
                        let token = &remaining[..length];
                        let color = if c.is_ascii_digit() {
                            ADDRESS
                        } else if matches!(
                            token,
                            "if" | "else"
                                | "return"
                                | "goto"
                                | "while"
                                | "for"
                                | "switch"
                                | "case"
                                | "break"
                                | "const"
                                | "static"
                                | "struct"
                                | "typedef"
                                | "define"
                                | "declare"
                                | "br"
                                | "ret"
                                | "phi"
                                | "call"
                        ) {
                            VIOLET
                        } else if token.starts_with("uint")
                            || token.starts_with("int")
                            || matches!(
                                token,
                                "void"
                                    | "char"
                                    | "bool"
                                    | "size_t"
                                    | "double"
                                    | "float"
                                    | "ptr"
                                    | "i1"
                                    | "i8"
                                    | "i16"
                                    | "i32"
                                    | "i64"
                            )
                        {
                            CYAN
                        } else {
                            TEXT
                        };
                        (length, color)
                    } else {
                        (c.len_utf8(), TEXT)
                    };
                    job.append(&remaining[..length], 0.0, format(color));
                    remaining = &remaining[length..];
                }
                ui.add(egui::Label::new(job).selectable(true));
            }
        });
}

fn filter_bar(ui: &mut egui::Ui, filter: &mut String, count: usize, noun: &str) {
    ui.horizontal(|ui| {
        ui.add(
            egui::TextEdit::singleline(filter)
                .hint_text("Quick Filter")
                .desired_width(280.0),
        );
        if ui.small_button("×").clicked() {
            filter.clear();
        }
        ui.label(RichText::new(format!("{count} {noun}")).color(MUTED));
    });
    ui.separator();
}

pub(crate) fn instruction_row(
    ui: &mut egui::Ui,
    address: u64,
    bytes: &str,
    mnemonic: &str,
    operands: &str,
    target: Option<u64>,
    comment: &str,
    selected: bool,
) -> egui::Response {
    let (rect, response) = ui.allocate_exact_size(
        egui::vec2(ui.available_width().max(950.0), ROW),
        egui::Sense::click(),
    );
    if selected || response.hovered() {
        ui.painter()
            .rect_filled(rect, 0.0, if selected { SELECTED } else { PANEL });
    }
    let color = if mnemonic.starts_with('j') {
        Color32::from_rgb(203, 204, 90)
    } else if mnemonic.starts_with("call") {
        GOOD
    } else if mnemonic.starts_with("ret") || mnemonic == "nop" {
        VIOLET
    } else if mnemonic.starts_with("push") || mnemonic.starts_with("pop") {
        Color32::from_rgb(218, 122, 185)
    } else {
        CYAN
    };
    let painter = ui.painter_at(rect);
    let text = |x, text: &str, color| {
        painter.text(
            egui::pos2(rect.left() + x, rect.center().y),
            egui::Align2::LEFT_CENTER,
            text,
            egui::FontId::monospace(12.0),
            color,
        );
    };
    if target.is_some() {
        text(5.0, "↳", color);
    }
    text(27.0, &address_text(address), ADDRESS);
    text(150.0, &format!("{bytes:.30}"), MUTED);
    text(384.0, mnemonic, color);
    text(
        455.0,
        operands,
        if mnemonic.starts_with('j') {
            ADDRESS
        } else {
            CYAN
        },
    );
    if !comment.is_empty() {
        text(790.0, &format!("; {comment}"), GOOD);
    }
    response
}

impl AnalystApp {
    pub(crate) fn imports_view(&mut self, ui: &mut egui::Ui) {
        let Some(spec) = &self.spec else {
            ui.label("Open a file to inspect imported symbols.");
            return;
        };
        filter_bar(
            ui,
            &mut self.shell.imports_filter,
            spec.imports.len(),
            "imports",
        );
        let query = self.shell.imports_filter.to_lowercase();
        let rows: Vec<_> = spec
            .imports
            .iter()
            .filter(|import| {
                format!("{} {}", import.name, import.library)
                    .to_lowercase()
                    .contains(&query)
            })
            .collect();
        egui::ScrollArea::both()
            .id_salt("imports_table")
            .show(ui, |ui| {
                egui::Grid::new("imports_grid")
                    .striped(true)
                    .min_col_width(210.0)
                    .show(ui, |ui| {
                        ui.strong("Name");
                        ui.strong("Library");
                        ui.end_row();
                        for import in rows {
                            let response = ui.add(
                                egui::Label::new(
                                    RichText::new(&import.name).monospace().color(CYAN),
                                )
                                .sense(egui::Sense::click()),
                            );
                            response.context_menu(|ui| {
                                if ui.button("Copy symbol").clicked() {
                                    ui.ctx().copy_text(import.name.clone());
                                    ui.close();
                                }
                            });
                            ui.monospace(&import.library);
                            ui.end_row();
                        }
                    });
            });
        if spec.imports.is_empty() {
            ui.label(RichText::new("No imports were reported by the ELF loader.").color(MUTED));
        }
    }

    pub(crate) fn sections_view(&mut self, ui: &mut egui::Ui) {
        let Some(spec) = &self.spec else {
            ui.label("Open a file to inspect its section table.");
            return;
        };
        filter_bar(
            ui,
            &mut self.shell.sections_filter,
            spec.sections.len(),
            "sections",
        );
        let query = self.shell.sections_filter.to_lowercase();
        let mut seek = None;
        egui::ScrollArea::both()
            .id_salt("sections_table")
            .show(ui, |ui| {
                egui::Grid::new("sections_grid")
                    .striped(true)
                    .min_col_width(120.0)
                    .show(ui, |ui| {
                        for title in ["Name", "Virtual address", "File offset", "Size", "Kind"] {
                            ui.strong(title);
                        }
                        ui.end_row();
                        for s in spec.sections.iter().filter(|s| {
                            s.name.to_lowercase().contains(&query)
                                || s.kind.to_lowercase().contains(&query)
                        }) {
                            if ui
                                .selectable_label(
                                    false,
                                    RichText::new(&s.name).monospace().color(CYAN),
                                )
                                .double_clicked()
                            {
                                seek = Some((s.address.0, s.file_offset.map(|a| a.0 as usize)));
                            }
                            ui.monospace(address_text(s.address.0));
                            ui.monospace(
                                s.file_offset
                                    .map(|a| address_text(a.0))
                                    .unwrap_or_else(|| "—".to_owned()),
                            );
                            ui.monospace(format!("0x{:x}", s.size));
                            ui.label(&s.kind);
                            ui.end_row();
                        }
                    });
            });
        ui.label(
            RichText::new(
                "Double-click a section to inspect its bytes. Unbacked memory has no file bytes.",
            )
            .size(11.0)
            .color(MUTED),
        );
        if let Some((address, offset)) = seek {
            self.selected_address = Some(address);
            self.open_tab(Tab::Hexdump);
            if let Some(offset) = offset {
                self.shell.hex_offset = offset;
                self.shell.hex_follow = Some(address);
            }
        }
    }

    pub(crate) fn strings_view(&mut self, ui: &mut egui::Ui) {
        let Some(binary) = &self.shell.binary else {
            if let Some(error) = &self.shell.binary_error {
                ui.colored_label(BAD, error);
                return;
            }
            ui.label(if self.remote { "String extraction requires a local ELF. Remote binary bytes have not been downloaded." } else { "Open a local ELF to inspect its strings." });
            return;
        };
        filter_bar(
            ui,
            &mut self.shell.strings_filter,
            binary.strings.len(),
            "ASCII strings (4+ bytes)",
        );
        let query = self.shell.strings_filter.to_lowercase();
        let rows: Vec<_> = binary
            .strings
            .iter()
            .filter(|range| {
                query.is_empty()
                    || String::from_utf8_lossy(&binary.bytes[(*range).clone()])
                        .to_lowercase()
                        .contains(&query)
            })
            .collect();
        ui.monospace(format!(
            "{:<14}  {:<14} {:>7}  {}",
            "File offset", "Virtual address", "Length", "String"
        ));
        let mut clicked = None;
        let row_height = ui.spacing().interact_size.y;
        egui::ScrollArea::both().id_salt("strings_table").show_rows(
            ui,
            row_height,
            rows.len(),
            |ui, range| {
                for index in range {
                    let span = rows[index];
                    let address = self
                        .spec
                        .as_ref()
                        .and_then(|s| offset_to_virtual(s, span.start));
                    let value = String::from_utf8_lossy(
                        &binary.bytes[span.start..span.end.min(span.start + 4096)],
                    );
                    let line = format!(
                        "0x{:08x}      {:<14} {:>7}  {}",
                        span.start,
                        address.map(address_text).unwrap_or_else(|| "—".to_owned()),
                        span.len(),
                        value
                    );
                    let response =
                        ui.selectable_label(false, RichText::new(line).monospace().color(GOOD));
                    if response.double_clicked() {
                        clicked = Some((span.start, address));
                    }
                    response.context_menu(|ui| {
                        if ui.button("Show in Hexdump").clicked() {
                            clicked = Some((span.start, address));
                            ui.close();
                        }
                        if ui.button("Copy string").clicked() {
                            ui.ctx().copy_text(
                                String::from_utf8_lossy(&binary.bytes[span.clone()]).into_owned(),
                            );
                            ui.close();
                        }
                    });
                }
            },
        );
        if binary.strings_truncated {
            ui.colored_label(MUTED, "Showing the first 20,000 strings.");
        }
        if let Some((offset, address)) = clicked {
            self.open_tab(Tab::Hexdump);
            self.selected_address = address;
            self.shell.hex_follow = address;
            self.shell.hex_offset = offset;
        }
    }

    pub(crate) fn hex_view(&mut self, ui: &mut egui::Ui) {
        let Some(binary) = &self.shell.binary else {
            if let Some(error) = &self.shell.binary_error {
                ui.colored_label(BAD, error);
                return;
            }
            ui.label(if self.remote { "Hexdump is available for local files. Remote binary bytes have not been downloaded." } else { "Open a local ELF to inspect its bytes." });
            return;
        };
        let mut unmapped = false;
        if self.shell.hex_follow != self.selected_address {
            self.shell.hex_follow = self.selected_address;
            if let (Some(spec), Some(address)) = (&self.spec, self.selected_address) {
                if let Some(offset) = virtual_to_offset(spec, address) {
                    self.shell.hex_offset = offset;
                } else {
                    unmapped = true;
                }
            }
        } else if let (Some(spec), Some(address)) = (&self.spec, self.selected_address) {
            unmapped = virtual_to_offset(spec, address).is_none();
        }
        ui.horizontal(|ui| {
            ui.label(
                RichText::new(format!(
                    "{} bytes · file offsets · read only",
                    binary.bytes.len()
                ))
                .color(MUTED),
            );
            ui.label("Offset");
            ui.add(
                egui::DragValue::new(&mut self.shell.hex_offset)
                    .hexadecimal(8, false, true)
                    .range(0..=binary.bytes.len().saturating_sub(1)),
            );
        });
        if unmapped {
            ui.colored_label(
                BAD,
                "Selected address has no file-backed bytes; showing the current file offset.",
            );
        }
        ui.separator();
        ui.monospace("Offset        00 01 02 03 04 05 06 07  08 09 0a 0b 0c 0d 0e 0f   ASCII");
        let rows = binary.bytes.len().div_ceil(16);
        let line_height = ui.text_style_height(&egui::TextStyle::Monospace);
        let pending = ui.data_mut(|data| {
            let id = egui::Id::new("hex_last_requested_offset");
            let old = data.get_temp::<usize>(id);
            data.insert_temp(id, self.shell.hex_offset);
            old != Some(self.shell.hex_offset)
        });
        let mut scroll = egui::ScrollArea::both().id_salt("hex_bytes");
        if pending {
            scroll = scroll.vertical_scroll_offset(
                (self.shell.hex_offset / 16) as f32 * (line_height + ui.spacing().item_spacing.y),
            );
        }
        scroll.show_rows(ui, line_height, rows, |ui, range| {
            for row in range {
                let start = row * 16;
                let chunk = &binary.bytes[start..(start + 16).min(binary.bytes.len())];
                let mut job = egui::text::LayoutJob::default();
                let format = |color| egui::TextFormat {
                    font_id: egui::FontId::monospace(12.0),
                    color,
                    ..Default::default()
                };
                job.append(&format!("0x{start:08x}    "), 0.0, format(ADDRESS));
                for i in 0..16 {
                    if i == 8 {
                        job.append(" ", 0.0, format(TEXT));
                    }
                    if let Some(byte) = chunk.get(i) {
                        job.append(
                            &format!("{byte:02x} "),
                            0.0,
                            format(if start + i == self.shell.hex_offset {
                                ACCENT
                            } else if *byte == 0 {
                                MUTED
                            } else {
                                CYAN
                            }),
                        );
                    } else {
                        job.append("   ", 0.0, format(TEXT));
                    }
                }
                let ascii: String = chunk
                    .iter()
                    .map(|b| {
                        if b.is_ascii_graphic() || *b == b' ' {
                            char::from(*b)
                        } else {
                            '.'
                        }
                    })
                    .collect();
                job.append(&format!("  {ascii}"), 0.0, format(GOOD));
                ui.add(egui::Label::new(job).selectable(true));
            }
        });
    }

    pub(crate) fn search_view(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label("Search in binary");
            ui.add(
                egui::TextEdit::singleline(&mut self.shell.search_query)
                    .hint_text("Function, instruction, or string…")
                    .desired_width(400.0),
            );
        });
        ui.label(
            RichText::new("Matches names, decoded instructions, and extracted ASCII strings.")
                .size(11.0)
                .color(MUTED),
        );
        ui.separator();
        let query = self.shell.search_query.trim().to_lowercase();
        if query.len() < 2 {
            ui.label("Enter at least two characters.");
            return;
        }
        let mut results: Vec<(String, Option<u64>, Option<usize>)> = Vec::new();
        for f in &self.shell.functions {
            if results.len() >= 1000 {
                break;
            }
            if f.name.to_lowercase().contains(&query) {
                results.push((
                    format!("Function    {}   {}", address_text(f.entry.value.0), f.name),
                    Some(f.entry.value.0),
                    None,
                ));
            }
        }
        if let Some(report) = &self.disassembly_report {
            for i in &report.instructions {
                if results.len() >= 1000 {
                    break;
                }
                let instruction = format!("{} {}", i.mnemonic, i.operands);
                if instruction.to_lowercase().contains(&query) {
                    results.push((
                        format!("Instruction {}   {instruction}", address_text(i.address.0)),
                        Some(i.address.0),
                        None,
                    ));
                }
            }
        }
        if let Some(binary) = &self.shell.binary {
            for span in &binary.strings {
                if results.len() >= 1000 {
                    break;
                }
                let value = String::from_utf8_lossy(&binary.bytes[span.clone()]);
                if value.to_lowercase().contains(&query) {
                    let address = self
                        .spec
                        .as_ref()
                        .and_then(|s| offset_to_virtual(s, span.start));
                    results.push((
                        format!("String      file+0x{:08x}   {:.160}", span.start, value),
                        address,
                        Some(span.start),
                    ));
                }
            }
        }
        ui.label(format!(
            "{} matches{}",
            results.len(),
            if results.len() == 1000 {
                " (limited to 1,000)"
            } else {
                ""
            }
        ));
        let mut clicked = None;
        let row_height = ui.spacing().interact_size.y;
        egui::ScrollArea::both()
            .id_salt("search_results")
            .show_rows(ui, row_height, results.len(), |ui, range| {
                for i in range {
                    if ui
                        .selectable_label(false, RichText::new(&results[i].0).monospace())
                        .clicked()
                    {
                        clicked = Some((results[i].1, results[i].2));
                    }
                }
            });
        if let Some((address, offset)) = clicked {
            if let Some(offset) = offset {
                self.open_tab(Tab::Hexdump);
                self.selected_address = address;
                self.shell.hex_follow = address;
                self.shell.hex_offset = offset;
            } else if let Some(address) = address {
                self.open_tab(Tab::Bytes);
                self.seek_or_report(address_text(address));
            }
        }
    }

    pub(crate) fn full_disassembly(&mut self, ui: &mut egui::Ui) {
        let Some(report) = &self.disassembly_report else {
            return;
        };
        let mut json = false;
        ui.horizontal(|ui| {
            ui.label(
                RichText::new(format!(
                    "{} instructions · {} sections",
                    report.instructions.len(),
                    report.sections.len()
                ))
                .size(11.0)
                .color(MUTED),
            );
            if !report.gaps.is_empty() {
                ui.colored_label(BAD, format!("{} undecoded gaps", report.gaps.len()));
            }
            json = ui
                .small_button("JSON")
                .on_hover_text("Show disassembly evidence in console")
                .clicked();
        });
        let mut clicked = None;
        let mut follow = None;
        let mut scroll = egui::ScrollArea::both().id_salt("whole_elf_disassembly");
        if let Some(address) = self.pending_disassembly_scroll.take()
            && let Some(position) = report
                .instructions
                .iter()
                .position(|i| i.address.0 >= address)
        {
            scroll = scroll
                .vertical_scroll_offset(position as f32 * (ROW + ui.spacing().item_spacing.y));
        }
        let warnings = report.warnings.len();
        scroll.show_rows(ui, ROW, report.instructions.len(), |ui, range| {
            for index in range {
                let instruction = &report.instructions[index];
                let comment = self
                    .annotations
                    .iter()
                    .find(|a| a.address == Some(instruction.address))
                    .map(|a| a.value.as_str())
                    .or(instruction.function.as_deref())
                    .unwrap_or("");
                let response = instruction_row(
                    ui,
                    instruction.address.0,
                    &instruction.bytes_hex,
                    &instruction.mnemonic,
                    &instruction.operands,
                    instruction.branch_target.map(|a| a.0),
                    comment,
                    self.selected_address == Some(instruction.address.0),
                );
                if response.clicked() {
                    clicked = Some(instruction.address.0);
                }
                if response.double_clicked() {
                    follow = instruction.branch_target.map(|a| a.0);
                }
                response
                    .on_hover_text(format!(
                        "{}\n{:?} · {}",
                        instruction.provenance,
                        instruction.flow,
                        instruction.function.as_deref().unwrap_or("linear sweep")
                    ))
                    .context_menu(|ui| {
                        if let Some(target) = instruction.branch_target
                            && ui
                                .add_enabled(
                                    !self.busy,
                                    egui::Button::new(format!("Follow {}", address_text(target.0))),
                                )
                                .clicked()
                        {
                            follow = Some(target.0);
                            ui.close();
                        }
                        if ui.button("Copy instruction").clicked() {
                            ui.ctx().copy_text(format!(
                                "{}  {} {}",
                                address_text(instruction.address.0),
                                instruction.mnemonic,
                                instruction.operands
                            ));
                            ui.close();
                        }
                        if ui.button("Copy address").clicked() {
                            ui.ctx().copy_text(address_text(instruction.address.0));
                            ui.close();
                        }
                        if ui.button("Show in Hexdump").clicked() {
                            clicked = Some(instruction.address.0);
                            self.tab = Tab::Hexdump;
                            ui.close();
                        }
                        if ui.button("Annotate").clicked() {
                            clicked = Some(instruction.address.0);
                            self.shell.layout.inspector = Dock::Docked;
                            ui.close();
                        }
                    });
            }
        });
        if warnings > 0 {
            ui.label(
                RichText::new(format!(
                    "{warnings} analysis warnings · inspect JSON for provenance and undecoded gaps"
                ))
                .size(11.0)
                .color(MUTED),
            );
        }
        if let Some(address) = clicked {
            self.selected_address = Some(address);
        }
        if let Some(address) = follow {
            self.seek_or_report(address_text(address));
        }
        if json {
            self.console_visible = true;
            self.console_mode = ConsoleMode::Activity;
            self.console_json = true;
        }
    }
}
