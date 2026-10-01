//! Native renderer smoke path; uses the real import/selection worker and real frame captures.
use super::*;

pub(crate) struct Capture {
    output: PathBuf,
    started: Instant,
    step: usize,
    frames: usize,
    pending: bool,
    files: Vec<String>,
}

const VIEWS: &[(Tab, &str)] = &[
    (Tab::Bytes, "disassembly"),
    (Tab::Overview, "dashboard"),
    (Tab::Graph, "graph"),
    (Tab::Hexdump, "hexdump"),
    (Tab::Strings, "strings"),
    (Tab::Imports, "imports"),
    (Tab::Sections, "sections"),
    (Tab::Search, "search"),
    (Tab::Native, "decompiler"),
    (Tab::RegionStudio, "patching"),
    (Tab::Bytes, "inspector"),
    (Tab::Bytes, "project-dialog"),
    (Tab::Bytes, "floating"),
    (Tab::Bytes, "compact"),
];

impl AnalystApp {
    pub(crate) fn start_workbench_capture(&mut self, output: PathBuf) {
        self.reset_shell_layout();
        self.shell.capture = Some(Capture {
            output,
            started: Instant::now(),
            step: 0,
            frames: 0,
            pending: false,
            files: Vec::new(),
        });
    }

    pub(super) fn capture_before_frame(&mut self, ctx: &egui::Context) {
        let Some(mut capture) = self.shell.capture.take() else {
            return;
        };
        if capture.started.elapsed() > Duration::from_secs(120) {
            render_smoke_fail(&capture.output, "Workbench render timed out");
        }
        if self.spec.is_none()
            || self.shell.binary.is_none()
            || self.disassembly_report.is_none()
            || self.busy
        {
            self.shell.capture = Some(capture);
            return;
        }
        let screenshot = ctx.input(|input| {
            input.events.iter().find_map(|e| {
                if let egui::Event::Screenshot { image, .. } = e {
                    Some(Arc::clone(image))
                } else {
                    None
                }
            })
        });
        if let Some(image) = screenshot
            && capture.pending
        {
            let filename = format!("{}.png", VIEWS[capture.step].1);
            if let Err(error) = save_render_smoke_png(&capture.output.join(&filename), &image) {
                render_smoke_fail(&capture.output, &error);
            }
            capture.files.push(filename);
            capture.step += 1;
            capture.frames = 0;
            capture.pending = false;
            if capture.step == VIEWS.len() {
                let manifest = serde_json::json!({
                    "reference": "radareorg/iaito@3383cc1d92131211ce752bb37121043ea8445b0e",
                    "binary_sha256": self.spec.as_ref().unwrap().binary_sha256,
                    "functions": self.shell.functions.len(),
                    "instructions": self.disassembly_report.as_ref().unwrap().instructions.len(),
                    "screenshots": capture.files,
                });
                if let Err(error) = fs::write(
                    capture.output.join("manifest.json"),
                    serde_json::to_vec_pretty(&manifest).unwrap(),
                ) {
                    render_smoke_fail(&capture.output, &error.to_string());
                }
                println!(
                    "Workbench rendered successfully: {}",
                    capture.output.display()
                );
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                return;
            }
        }
        if capture.frames == 0 {
            self.open_tab(VIEWS[capture.step].0);
            self.shell.layout.inspector = if capture.step == 10 {
                Dock::Docked
            } else {
                Dock::Hidden
            };
            self.shell.project_open = capture.step == 11;
            self.shell.layout.functions = if capture.step == 12 {
                Dock::Floating
            } else {
                Dock::Docked
            };
            if capture.step == 7 {
                self.shell.search_query = "mov".to_owned();
            }
            if capture.step == 13 {
                ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize(egui::vec2(1024.0, 720.0)));
            }
        }
        capture.frames += 1;
        self.shell.capture = Some(capture);
    }

    pub(super) fn capture_after_frame(&mut self, ctx: &egui::Context) {
        if let Some(capture) = &mut self.shell.capture
            && capture.frames >= 3
            && !capture.pending
        {
            ctx.send_viewport_cmd(egui::ViewportCommand::Screenshot(egui::UserData::default()));
            capture.pending = true;
        }
    }
}
