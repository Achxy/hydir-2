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

    pub(super) fn show(&mut self, ui: &mut egui::Ui) {
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
            self.start(ui.ctx(), false);
        }
        egui::Frame::new().fill(PANEL).inner_margin(7.0).show(ui, |ui| {
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
            ui.label(RichText::new(detail).color(if ready { GOOD } else { ADDRESS }));
            ui.horizontal(|ui| {
                if can_install && ui.button("Install packaged worker").clicked() { self.start(ui.ctx(), true); }
                if ui.small_button("Recheck runtime").clicked() { self.start(ui.ctx(), false); }
                if cfg!(windows) && !ready && ui.small_button("Copy WSL setup command")
                    .on_hover_text("Run once in Administrator PowerShell, then restart if Windows requests it.").clicked() {
                    ui.ctx().copy_text("wsl --install --no-distribution".into());
                }
            });
        });
    }
}
