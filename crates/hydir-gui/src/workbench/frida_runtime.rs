use super::*;
use hydir_frida_observer::transport::WorkerStatus;

#[derive(Default)]
pub(super) struct Runtime {
    result: Option<Result<WorkerStatus, String>>,
    pending: Option<Receiver<Result<WorkerStatus, String>>>,
    installing: bool,
}

impl Runtime {
    pub(super) fn ready(&self) -> bool {
        self.pending.is_none()
            && self
                .result
                .as_ref()
                .is_some_and(|r| r.as_ref().is_ok_and(|s| s.ready))
    }

    fn start(&mut self, ctx: &egui::Context, install: bool) {
        let (sender, receiver) = mpsc::sync_channel(1);
        let repaint = ctx.clone();
        self.installing = install;
        self.pending = Some(receiver);
        thread::spawn(move || {
            let mut command = Command::new(hydirctl_path());
            command.args(["frida-worker", if install { "install" } else { "status" }]);
            #[cfg(windows)]
            {
                use std::os::windows::process::CommandExt;
                command.creation_flags(0x08000000);
            }
            let result = (|| {
                let output = run_ghidra_command(
                    &mut command,
                    &AtomicBool::new(false),
                    Duration::from_secs(if install { 220 } else { 30 }),
                )?;
                if !output.status.success() {
                    return Err(String::from_utf8_lossy(&output.stderr).trim().to_owned());
                }
                serde_json::from_slice(&output.stdout)
                    .map_err(|error| format!("Cannot read Frida runtime status: {error}"))
            })();
            let _ = sender.send(result);
            repaint.request_repaint();
        });
    }

    pub(super) fn poll(&mut self, ctx: &egui::Context) {
        if let Some(receiver) = &self.pending {
            match receiver.try_recv() {
                Ok(result) => {
                    self.result = Some(result);
                    self.pending = None;
                }
                Err(TryRecvError::Disconnected) => {
                    self.result = Some(Err("Frida runtime check stopped unexpectedly".into()));
                    self.pending = None;
                }
                Err(TryRecvError::Empty) => {}
            }
        }
        if self.result.is_none() && self.pending.is_none() {
            self.start(ctx, false);
        }
        if self.pending.is_some() {
            ctx.request_repaint_after(Duration::from_millis(200));
        }
    }

    pub(super) fn compact(&mut self, ui: &mut egui::Ui) {
        self.poll(ui.ctx());
        ui.menu_button(
            if self.ready() {
                "Worker: ready"
            } else if self.pending.is_some() {
                "Worker: checking…"
            } else {
                "Worker: setup"
            },
            |ui| {
                ui.set_width(360.0);
                self.show(ui);
            },
        );
    }

    pub(super) fn show(&mut self, ui: &mut egui::Ui) {
        self.poll(ui.ctx());
        egui::Frame::new().fill(PANEL).inner_margin(8.0).show(ui, |ui| {
            ui.set_min_width((ui.available_width() - 1.0).max(0.0));
            if self.pending.is_some() {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label(if self.installing { "Installing packaged Frida worker…" } else { "Checking Frida runtime…" });
                });
                ui.ctx().request_repaint_after(Duration::from_millis(200));
                return;
            }
            let (detail, ready, can_install) = match &self.result {
                Some(Ok(status)) => (status.detail.as_str(), status.ready, status.can_install),
                Some(Err(error)) => (error.as_str(), false, false),
                None => ("Frida runtime has not been checked", false, false),
            };
            let detail = detail.to_owned();
            ui.horizontal(|ui| {
                let (marker, _) = ui.allocate_exact_size(egui::vec2(10.0, 10.0), egui::Sense::hover());
                ui.painter().circle_filled(marker.center(), 3.5, if ready { GOOD } else { ADDRESS });
                ui.label(RichText::new(if ready { "Frida ready" } else { "Frida setup required" }).strong())
                    .on_hover_text(&detail);
                if ready { ui.label(RichText::new(if cfg!(windows) { "WSL2 · isolated worker" } else { "Linux · isolated worker" }).small().color(MUTED)); }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.small_button("Recheck").on_hover_text(&detail).clicked() { self.start(ui.ctx(), false); }
                });
            });
            if !ready { ui.label(RichText::new(detail).color(ADDRESS)); }
            if can_install || (cfg!(windows) && !ready) {
              ui.horizontal(|ui| {
                if can_install && ui.button("Install packaged worker").clicked() { self.start(ui.ctx(), true); }
                if cfg!(windows) && !ready && ui.small_button("Copy WSL setup command")
                    .on_hover_text("Run once in Administrator PowerShell, then restart if Windows requests it.").clicked() {
                    ui.ctx().copy_text("wsl --install --no-distribution".into());
                }
              });
            }
        });
    }
}
