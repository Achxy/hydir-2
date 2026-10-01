//! The ordinary observation flow owns its input file; JSON import is optional.
use super::*;
use hydir_execution::{InputSpec, ReplayBudget, ReplayGoal, TraceEventKind};
use std::io::Write;

#[derive(Default)]
pub(super) struct Session {
    pub(super) arguments: String,
    pub(super) external_input: bool,
    managed_input: Option<tempfile::NamedTempFile>,
}

fn default_input(elf: &[u8], arguments: &str) -> Result<InputSpec, String> {
    let input = InputSpec {
        schema_version: 1,
        binary_sha256: format!("{:x}", Sha256::digest(elf)),
        argv_hex: arguments
            .lines()
            .map(|arg| {
                arg.as_bytes()
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect()
            })
            .collect(),
        stdin_hex: String::new(),
        files: Vec::new(),
        origins: Vec::new(),
        goal: ReplayGoal {
            exit_code: Some(0),
            stdout_contains_hex: None,
            stderr_contains_hex: None,
        },
        budget: ReplayBudget {
            timeout_ms: 10000,
            memory_bytes: 1024 * 1024 * 1024,
            output_bytes: 65536,
        },
    };
    check_input(elf, &input)?;
    Ok(input)
}

fn check_input(elf: &[u8], input: &InputSpec) -> Result<(), String> {
    hydir_execution::validate_input_spec(elf, input)?;
    if !input.stdin_hex.is_empty() {
        return Err("Frida does not support stdin yet. Use arguments or files; the interactive PRISM demo requires stdin.".into());
    }
    if input.budget.memory_bytes < 1024 * 1024 * 1024 {
        return Err("Frida requires a memory budget of at least 1 GiB. Update budget.memory_bytes or use Program arguments.".into());
    }
    Ok(())
}

impl Session {
    fn prepare(&mut self, elf: &[u8], path: &mut String) -> Result<(), String> {
        if self.external_input {
            let file = fs::File::open(path.trim())
                .map_err(|error| format!("Cannot open InputSpec: {error}"))?;
            let mut bytes = Vec::new();
            file.take((MAX_INPUT_SPEC_BYTES + 1) as u64)
                .read_to_end(&mut bytes)
                .map_err(|e| e.to_string())?;
            let input = parse_input_spec(&bytes)?;
            check_input(elf, &input)?;
        } else {
            let input = default_input(elf, &self.arguments)?;
            let mut file = tempfile::Builder::new()
                .prefix("hydir-frida-input-")
                .suffix(".json")
                .tempfile()
                .map_err(|e| e.to_string())?;
            file.write_all(&serde_json::to_vec_pretty(&input).map_err(|e| e.to_string())?)
                .map_err(|e| e.to_string())?;
            file.flush().map_err(|e| e.to_string())?;
            *path = file.path().to_string_lossy().into_owned();
            self.managed_input = Some(file);
        }
        Ok(())
    }
}

pub(super) fn reached_selected_function(trace: &DynamicTrace) -> bool {
    trace.events.iter().any(|event| {
        event.kind == TraceEventKind::Entry
            && event.source.elf_vaddr == Some(trace.selected_elf_vaddr)
    })
}

impl AnalystApp {
    pub(crate) fn reveal_frida_events(&mut self) {
        if self.tab == Tab::Frida
            && self
                .frida_observation
                .as_ref()
                .is_some_and(|result| result.as_ref().is_ok_and(reached_selected_function))
        {
            self.shell.ghidra.frida = ghidra::FridaPane::Events;
            self.shell.frida_workspace.reset_events();
        }
    }

    pub(super) fn clear_frida_results(&mut self) {
        self.shell.frida_workspace.reset_events();
        self.frida_observation = None;
        self.frida_rediscovery_plan = None;
        self.frida_jump_plan = None;
        self.frida_rediscovered_snapshot = None;
        self.frida_path_comparison = None;
        if let Some(task) = &self.frida_rediscovery_task {
            task.cancel.store(true, Ordering::Release);
        }
    }

    pub(super) fn frida_session_view(&mut self, ui: &mut egui::Ui) {
        let mut changed = false;
        ui.label("The binary starts from its entry point. Only the selected function is recorded.");
        ui.separator();
        ui.add_enabled_ui(!self.frida_busy, |ui| {
            ui.label(RichText::new("Program arguments").strong());
            ui.label("One argument per line. Leave empty to run without arguments.");
            changed |= ui.add_enabled(!self.shell.frida_session.external_input,
                egui::TextEdit::multiline(&mut self.shell.frida_session.arguments)
                    .hint_text("No arguments")
                    .desired_rows(4).desired_width(f32::INFINITY).font(egui::TextStyle::Monospace)).changed();
            ui.label(RichText::new("Arguments are passed literally, including spaces. Do not add shell quotes.").small().color(MUTED));
            ui.add_space(12.0);
            egui::CollapsingHeader::new("Advanced inputs and limits")
                .default_open(self.shell.frida_session.external_input)
                .show(ui, |ui| {
                    changed |= ui.checkbox(&mut self.shell.frida_session.external_input, "Use an InputSpec JSON file").changed();
                    if self.shell.frida_session.external_input {
                        changed |= ui.add(egui::TextEdit::singleline(&mut self.frida_input_path)
                            .hint_text("Full path to an InputSpec JSON file")
                            .desired_width(f32::INFINITY)).changed();
                        ui.label("The file supplies arguments, files and limits. It must match this binary.");
                    } else {
                        ui.label("Default limits: 10 seconds, 1 GiB memory, 64 KiB output.");
                    }
                });
            ui.add_space(8.0);
            ui.label(RichText::new("Interactive stdin is unavailable. Use an argv- or file-driven program.").color(MUTED));
        });
        if changed {
            self.clear_frida_results();
        }
    }

    pub(super) fn start_frida_run(&mut self) {
        let prepared = (|| -> Result<_, String> {
            let binary = self
                .current_local_path
                .clone()
                .ok_or("Open a local ELF first")?;
            let elf = bounded_read(&binary)?;
            self.shell
                .frida_session
                .prepare(&elf, &mut self.frida_input_path)?;
            let snapshot = self
                .ghidra_snapshot
                .clone()
                .ok_or("Wait for Ghidra analysis")?;
            let function = self
                .spec
                .as_ref()
                .and_then(|spec| GhidraAddressMap::new(&snapshot, spec))
                .and_then(|map| {
                    map.to_linked(
                        &snapshot.selected_function.entry.space,
                        &snapshot.selected_function.entry.offset,
                    )
                })
                .ok_or("The selected function has no linked ELF address")?;
            Ok((binary, snapshot, function))
        })();
        match prepared {
            Ok((binary, snapshot, function)) => {
                let cancel = Arc::new(AtomicBool::new(false));
                let timeout = Duration::from_secs(75);
                let task = Task::ObserveFrida {
                    binary,
                    binary_sha256: snapshot.binary_sha256.clone(),
                    function,
                    snapshot: Box::new(snapshot),
                    input_path: PathBuf::from(self.frida_input_path.trim()),
                    cancel: Arc::clone(&cancel),
                    timeout,
                };
                self.clear_frida_results();
                match self.tasks.try_send(task) {
                    Ok(()) => {
                        self.frida_busy = true;
                        self.frida_task = Some(ActiveGhidraTask {
                            cancel,
                            started: Instant::now(),
                            timeout,
                        });
                        self.status = "Running with Frida…".into();
                    }
                    Err(_) => {
                        self.frida_observation =
                            Some(Err("Analysis queue is full. Retry observation.".into()))
                    }
                }
            }
            Err(error) => self.frida_observation = Some(Err(error)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const ELF: &[u8] = include_bytes!("../../../../demo/hydir-prism.elf");

    #[test]
    fn session_inputs_preserve_literal_arguments_and_have_frida_limits() {
        let input = default_input(ELF, "hello world\nλ\n$(literal)").unwrap();
        assert_eq!(
            input.argv_hex,
            ["68656c6c6f20776f726c64", "cebb", "24286c69746572616c29"]
        );
        assert!(default_input(ELF, "").unwrap().argv_hex.is_empty());
        assert_eq!(input.budget.memory_bytes, 1073741824);
        assert!(default_input(ELF, "bad\0argument").is_err());
    }

    #[test]
    fn external_input_rejects_wrong_binary_stdin_and_small_memory_before_execution() {
        let good = default_input(ELF, "").unwrap();
        let mut input = good.clone();
        input.stdin_hex = "41".into();
        assert!(check_input(ELF, &input).unwrap_err().contains("stdin"));
        input = good.clone();
        input.budget.memory_bytes = 268435456;
        assert!(check_input(ELF, &input).unwrap_err().contains("1 GiB"));
        input = good;
        input.binary_sha256 = "0".repeat(64);
        assert!(check_input(ELF, &input).unwrap_err().contains("SHA-256"));
    }

    #[test]
    fn managed_input_stays_readable_for_worker_and_comparison() {
        let mut session = Session::default();
        let mut path = String::new();
        session.prepare(ELF, &mut path).unwrap();
        let input = parse_input_spec(&fs::read(&path).unwrap()).unwrap();
        check_input(ELF, &input).unwrap();
        drop(session);
        assert!(!Path::new(&path).exists());
    }
}
