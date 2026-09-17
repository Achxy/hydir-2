//! HydIR desktop workbench: a local, asynchronous analyst view over the same
//! native import, CFG recovery, and lifting operations used by the CLI.

use eframe::egui::{self, Color32, RichText};
use hydir_analysis::{AnalysisReport, analyze_elf};
use hydir_api::v1::{
    ArtifactRequest, CreateProjectRequest, DiscoverRequest, FunctionRequest, JobReply, JobRequest,
    ProjectRequest, StartLiftJobRequest, UploadBinaryRequest, hydir_client::HydirClient,
};
use hydir_backend::{MAX_BINARY_BYTES, import_elf, lift_symbol, recover_symbol_cfg};
use hydir_c::emit_c;
use hydir_core::{FunctionCfg, FunctionSpec, ProgramSpec};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::Read,
    net::SocketAddr,
    path::PathBuf,
    sync::mpsc::{self, Receiver, SyncSender},
    thread,
    time::Duration,
};
use tonic::{Request, metadata::MetadataValue, transport::Channel};

const BG: Color32 = Color32::from_rgb(21, 25, 28);
const PANEL: Color32 = Color32::from_rgb(29, 34, 38);
const TEXT: Color32 = Color32::from_rgb(225, 229, 227);
const MUTED: Color32 = Color32::from_rgb(157, 169, 170);
const ACCENT: Color32 = Color32::from_rgb(224, 170, 93);
const GOOD: Color32 = Color32::from_rgb(124, 190, 152);
const BAD: Color32 = Color32::from_rgb(232, 139, 124);

enum Task {
    Open(PathBuf),
    OpenRemote {
        endpoint: String,
        token_file: PathBuf,
        project_id: String,
    },
    CreateRemoteProject {
        endpoint: String,
        token_file: PathBuf,
        name: String,
    },
    UploadRemote {
        endpoint: String,
        token_file: PathBuf,
        project_id: String,
        path: PathBuf,
    },
    Select(String),
    Analyze,
    StartLiftJob {
        symbol: String,
        key: String,
    },
    RefreshJob(String),
    CancelJob(String),
    OpenJobArtifact(String),
}

enum Event {
    Imported {
        source: String,
        remote: bool,
        source_offer: Option<String>,
        spec: ProgramSpec,
    },
    RemoteProjectCreated(String),
    Selected {
        symbol: String,
        cfg: Result<FunctionCfg, String>,
        ir: Result<String, String>,
        c: Result<String, String>,
    },
    Analyzed(Result<AnalysisReport, String>),
    JobUpdated(JobReply),
    JobArtifact(String),
    Failed(String),
}

#[derive(Clone)]
struct RemoteAccess {
    endpoint: String,
    token: String,
    project_id: String,
    revision: u64,
    source_offer: String,
}

enum Source {
    None,
    Local(Vec<u8>),
    Remote(RemoteAccess),
}

fn validate_endpoint(endpoint: &str) -> Result<(), String> {
    let address: SocketAddr = endpoint
        .strip_prefix("http://")
        .ok_or("Remote endpoint must be explicit http://loopback-host:port")?
        .parse()
        .map_err(|_| "Remote endpoint must be a numeric loopback address and port")?;
    if !address.ip().is_loopback() {
        return Err("Plaintext non-loopback remote connections are refused.".to_owned());
    }
    Ok(())
}

fn read_credential(path: &PathBuf) -> Result<String, String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(path)
            .map_err(|e| format!("Cannot inspect credential file: {e}"))?
            .permissions()
            .mode();
        if mode & 0o077 != 0 {
            return Err("Credential file must be private (chmod 600).".to_owned());
        }
    }
    let token = fs::read_to_string(path)
        .map_err(|e| format!("Cannot read credential file: {e}"))?
        .trim()
        .to_owned();
    if token.len() != 64 || !token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("Credential file must contain a 64-character hex token.".to_owned());
    }
    Ok(token)
}

fn authorized<T>(value: T, token: &str) -> Request<T> {
    let mut request = Request::new(value);
    let credential = format!("Bearer {token}")
        .parse::<MetadataValue<_>>()
        .expect("validated hex token");
    request.metadata_mut().insert("authorization", credential);
    request
}

async fn remote_client(access: &RemoteAccess) -> Result<HydirClient<Channel>, String> {
    let channel = Channel::from_shared(access.endpoint.clone())
        .map_err(|e| format!("Invalid endpoint: {e}"))?
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(30))
        .connect()
        .await
        .map_err(|e| format!("Cannot connect to HydIR service: {e}"))?;
    Ok(HydirClient::new(channel).max_decoding_message_size(MAX_BINARY_BYTES + 1024))
}

async fn open_remote(
    endpoint: String,
    token_file: PathBuf,
    project_id: String,
) -> Result<(RemoteAccess, ProgramSpec), String> {
    validate_endpoint(&endpoint)?;
    if project_id.is_empty() {
        return Err("Enter a remote project ID.".to_owned());
    }
    let access = RemoteAccess {
        endpoint,
        token: read_credential(&token_file)?,
        project_id,
        revision: 0,
        source_offer: String::new(),
    };
    let mut client = remote_client(&access).await?;
    let discovery = client
        .discover(authorized(DiscoverRequest {}, &access.token))
        .await
        .map_err(|e| format!("Service discovery failed: {e}"))?
        .into_inner();
    if discovery.api_version != 1 {
        return Err(format!(
            "Unsupported HydIR API version {}",
            discovery.api_version
        ));
    }
    let source_offer =
        if discovery.source_revision.len() == 40 && discovery.source_sha256.len() == 64 {
            format!(
                "Revision {} · SHA-256 {} · hydirctl remote source --output <file.tar>",
                discovery.source_revision, discovery.source_sha256,
            )
        } else {
            discovery.source_status
        };
    let project = client
        .get_project(authorized(
            ProjectRequest {
                project_id: access.project_id.clone(),
                expected_revision: 0,
            },
            &access.token,
        ))
        .await
        .map_err(|e| format!("Cannot open remote project: {e}"))?
        .into_inner();
    if project.binary_sha256.is_empty() {
        return Err(
            "Remote project has no uploaded binary. Use an explicit CLI upload.".to_owned(),
        );
    }
    let access = RemoteAccess {
        revision: project.revision,
        source_offer,
        ..access
    };
    let reply = client
        .inspect(authorized(
            ProjectRequest {
                project_id: access.project_id.clone(),
                expected_revision: access.revision,
            },
            &access.token,
        ))
        .await
        .map_err(|e| format!("Remote inspection failed: {e}"))?
        .into_inner();
    let spec: ProgramSpec = serde_json::from_str(&reply.json)
        .map_err(|e| format!("Invalid remote program model: {e}"))?;
    if spec.binary_sha256 != project.binary_sha256 {
        return Err("Remote project binary hash changed during inspection.".to_owned());
    }
    Ok((access, spec))
}

async fn create_remote_project(
    endpoint: String,
    token_file: PathBuf,
    name: String,
) -> Result<String, String> {
    validate_endpoint(&endpoint)?;
    let name = name.trim();
    if name.is_empty() || name.len() > 128 {
        return Err("Project name must contain 1..=128 characters.".to_owned());
    }
    let access = RemoteAccess {
        endpoint,
        token: read_credential(&token_file)?,
        project_id: String::new(),
        revision: 0,
        source_offer: String::new(),
    };
    let mut client = remote_client(&access).await?;
    let created = client
        .create_project(authorized(
            CreateProjectRequest {
                name: name.to_owned(),
                idempotency_key: uuid::Uuid::new_v4().to_string(),
            },
            &access.token,
        ))
        .await
        .map_err(|error| format!("Could not create remote project: {error}"))?
        .into_inner();
    Ok(created.project_id)
}

async fn upload_remote(
    endpoint: String,
    token_file: PathBuf,
    project_id: String,
    path: PathBuf,
) -> Result<(RemoteAccess, ProgramSpec), String> {
    validate_endpoint(&endpoint)?;
    if project_id.is_empty() {
        return Err("Enter the destination remote project ID.".to_owned());
    }
    let content = bounded_read(&path)?;
    let digest = format!("{:x}", Sha256::digest(&content));
    let access = RemoteAccess {
        endpoint: endpoint.clone(),
        token: read_credential(&token_file)?,
        project_id: project_id.clone(),
        revision: 0,
        source_offer: String::new(),
    };
    let mut client = remote_client(&access).await?;
    let project = client
        .get_project(authorized(
            ProjectRequest {
                project_id: project_id.clone(),
                expected_revision: 0,
            },
            &access.token,
        ))
        .await
        .map_err(|error| format!("Cannot find destination project: {error}"))?
        .into_inner();
    let uploaded = client
        .upload_binary(authorized(
            UploadBinaryRequest {
                project_id: project_id.clone(),
                expected_revision: project.revision,
                content_sha256: digest.clone(),
                content,
            },
            &access.token,
        ))
        .await
        .map_err(|error| {
            format!("Remote upload failed: {error}. Refresh the project revision and retry.")
        })?
        .into_inner();
    if uploaded.binary_sha256 != digest
        || Some(uploaded.revision) != project.revision.checked_add(1)
    {
        return Err("Remote upload returned an unexpected digest or revision.".to_owned());
    }
    let (access, spec) = open_remote(endpoint, token_file, project_id).await?;
    if spec.binary_sha256 != digest || access.revision != uploaded.revision {
        return Err("Remote project changed after upload; reopen it before analysis.".to_owned());
    }
    Ok((access, spec))
}

async fn select_remote(
    access: &RemoteAccess,
    symbol: &str,
) -> (
    Result<FunctionCfg, String>,
    Result<String, String>,
    Result<String, String>,
) {
    let mut client = match remote_client(access).await {
        Ok(client) => client,
        Err(error) => return (Err(error.clone()), Err(error.clone()), Err(error)),
    };
    let request = FunctionRequest {
        project_id: access.project_id.clone(),
        expected_revision: access.revision,
        function_symbol: symbol.to_owned(),
        assume_u64x2: false,
    };
    let cfg = client
        .recover_cfg(authorized(request.clone(), &access.token))
        .await
        .map_err(|e| format!("Remote CFG recovery failed: {e}"))
        .and_then(|reply| {
            serde_json::from_str(&reply.into_inner().json)
                .map_err(|e| format!("Invalid remote CFG: {e}"))
        });
    let ir = client
        .lift(authorized(
            FunctionRequest {
                assume_u64x2: true,
                ..request.clone()
            },
            &access.token,
        ))
        .await
        .map_err(|e| format!("Remote lift failed: {e}"))
        .and_then(|reply| {
            let artifact = reply.into_inner();
            if artifact.project_revision != access.revision
                || format!("{:x}", Sha256::digest(&artifact.content)) != artifact.sha256
            {
                return Err("Remote IR artifact failed revision/digest verification.".to_owned());
            }
            String::from_utf8(artifact.content).map_err(|e| format!("Invalid UTF-8 IR: {e}"))
        });
    let c = client
        .decompile(authorized(
            FunctionRequest {
                assume_u64x2: true,
                ..request
            },
            &access.token,
        ))
        .await
        .map_err(|e| format!("Remote C recovery failed: {e}"))
        .and_then(|reply| {
            let artifact = reply.into_inner();
            if artifact.project_revision != access.revision
                || artifact.media_type != "text/x-csrc"
                || format!("{:x}", Sha256::digest(&artifact.content)) != artifact.sha256
            {
                return Err(
                    "Remote C artifact failed revision/digest/type verification.".to_owned(),
                );
            }
            String::from_utf8(artifact.content).map_err(|e| format!("Invalid UTF-8 C: {e}"))
        });
    (cfg, ir, c)
}

async fn analyze_remote(access: &RemoteAccess) -> Result<AnalysisReport, String> {
    let mut client = remote_client(access).await?;
    let reply = client
        .analyze(authorized(
            ProjectRequest {
                project_id: access.project_id.clone(),
                expected_revision: access.revision,
            },
            &access.token,
        ))
        .await
        .map_err(|error| format!("Remote analysis failed: {error}"))?
        .into_inner();
    serde_json::from_str(&reply.json).map_err(|error| format!("Invalid remote analysis: {error}"))
}

async fn start_remote_job(
    access: &RemoteAccess,
    symbol: &str,
    key: &str,
) -> Result<JobReply, String> {
    let mut client = remote_client(access).await?;
    client
        .start_lift_job(authorized(
            StartLiftJobRequest {
                project_id: access.project_id.clone(),
                expected_revision: access.revision,
                function_symbol: symbol.to_owned(),
                assume_u64x2: true,
                idempotency_key: key.to_owned(),
            },
            &access.token,
        ))
        .await
        .map(|reply| reply.into_inner())
        .map_err(|error| format!("Could not start lift job: {error}"))
}

async fn remote_job(access: &RemoteAccess, job_id: &str, cancel: bool) -> Result<JobReply, String> {
    let mut client = remote_client(access).await?;
    let request = authorized(
        JobRequest {
            project_id: access.project_id.clone(),
            job_id: job_id.to_owned(),
        },
        &access.token,
    );
    let result = if cancel {
        client.cancel_job(request).await
    } else {
        client.get_job(request).await
    };
    result
        .map(|reply| reply.into_inner())
        .map_err(|error| format!("Could not update lift job: {error}"))
}

async fn remote_job_artifact(access: &RemoteAccess, digest: &str) -> Result<String, String> {
    let mut client = remote_client(access).await?;
    let artifact = client
        .get_artifact(authorized(
            ArtifactRequest {
                project_id: access.project_id.clone(),
                sha256: digest.to_owned(),
            },
            &access.token,
        ))
        .await
        .map_err(|error| format!("Could not retrieve job artifact: {error}"))?
        .into_inner();
    if artifact.sha256 != digest
        || artifact.project_revision != access.revision
        || format!("{:x}", Sha256::digest(&artifact.content)) != digest
    {
        return Err("Job artifact failed revision/digest verification.".to_owned());
    }
    String::from_utf8(artifact.content).map_err(|error| format!("Job IR is not UTF-8: {error}"))
}

fn bounded_read(path: &PathBuf) -> Result<Vec<u8>, String> {
    let metadata = fs::metadata(path).map_err(|e| format!("Cannot read binary metadata: {e}"))?;
    if metadata.len() > MAX_BINARY_BYTES as u64 {
        return Err("Binary exceeds the 64 MiB import limit.".to_owned());
    }
    let mut bytes = Vec::new();
    fs::File::open(path)
        .map_err(|e| format!("Cannot open binary: {e}"))?
        .take((MAX_BINARY_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("Cannot read binary: {e}"))?;
    if bytes.len() > MAX_BINARY_BYTES {
        return Err("Binary changed while reading and exceeds the import limit.".to_owned());
    }
    Ok(bytes)
}

fn worker(tasks: Receiver<Task>, events: SyncSender<Event>, ctx: egui::Context) {
    let mut source = Source::None;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("Tokio runtime initialization");
    while let Ok(task) = tasks.recv() {
        let event = match task {
            Task::Open(path) => match bounded_read(&path).and_then(|bytes| {
                import_elf(&bytes)
                    .map(|spec| (bytes, spec))
                    .map_err(|e| format!("ELF import failed: {e}"))
            }) {
                Ok((bytes, spec)) => {
                    source = Source::Local(bytes);
                    Event::Imported {
                        source: path.display().to_string(),
                        remote: false,
                        source_offer: None,
                        spec,
                    }
                }
                Err(error) => Event::Failed(error),
            },
            Task::OpenRemote {
                endpoint,
                token_file,
                project_id,
            } => match runtime.block_on(open_remote(endpoint, token_file, project_id)) {
                Ok((access, spec)) => {
                    let label = format!(
                        "{} · {} · revision {}",
                        access.endpoint, access.project_id, access.revision
                    );
                    let source_offer = access.source_offer.clone();
                    source = Source::Remote(access);
                    Event::Imported {
                        source: label,
                        remote: true,
                        source_offer: Some(source_offer),
                        spec,
                    }
                }
                Err(error) => Event::Failed(error),
            },
            Task::CreateRemoteProject {
                endpoint,
                token_file,
                name,
            } => match runtime.block_on(create_remote_project(endpoint, token_file, name)) {
                Ok(project_id) => Event::RemoteProjectCreated(project_id),
                Err(error) => Event::Failed(error),
            },
            Task::UploadRemote {
                endpoint,
                token_file,
                project_id,
                path,
            } => match runtime.block_on(upload_remote(endpoint, token_file, project_id, path)) {
                Ok((access, spec)) => {
                    let label = format!(
                        "{} · {} · revision {}",
                        access.endpoint, access.project_id, access.revision
                    );
                    let source_offer = access.source_offer.clone();
                    source = Source::Remote(access);
                    Event::Imported {
                        source: label,
                        remote: true,
                        source_offer: Some(source_offer),
                        spec,
                    }
                }
                Err(error) => Event::Failed(error),
            },
            Task::Select(symbol) => match &source {
                Source::Local(bytes) => {
                    let ir = lift_symbol(bytes, &symbol).map_err(|e| e.to_string());
                    let c = ir.as_ref().map_err(Clone::clone).and_then(|ir| emit_c(ir));
                    Event::Selected {
                        cfg: recover_symbol_cfg(bytes, &symbol).map_err(|e| e.to_string()),
                        ir,
                        c,
                        symbol,
                    }
                }
                Source::Remote(access) => {
                    let (cfg, ir, c) = runtime.block_on(select_remote(access, &symbol));
                    Event::Selected { symbol, cfg, ir, c }
                }
                Source::None => {
                    Event::Failed("Open a local ELF or remote project first.".to_owned())
                }
            },
            Task::Analyze => Event::Analyzed(match &source {
                Source::Local(bytes) => analyze_elf(bytes).map_err(|error| error.to_string()),
                Source::Remote(access) => runtime.block_on(analyze_remote(access)),
                Source::None => Err("Open a local ELF or remote project first.".to_owned()),
            }),
            Task::StartLiftJob { symbol, key } => match &source {
                Source::Remote(access) => runtime
                    .block_on(start_remote_job(access, &symbol, &key))
                    .map(Event::JobUpdated)
                    .unwrap_or_else(Event::Failed),
                _ => Event::Failed("Lift jobs require an open remote project.".to_owned()),
            },
            Task::RefreshJob(job_id) => match &source {
                Source::Remote(access) => runtime
                    .block_on(remote_job(access, &job_id, false))
                    .map(Event::JobUpdated)
                    .unwrap_or_else(Event::Failed),
                _ => Event::Failed("Open the owning remote project to refresh its job.".to_owned()),
            },
            Task::CancelJob(job_id) => match &source {
                Source::Remote(access) => runtime
                    .block_on(remote_job(access, &job_id, true))
                    .map(Event::JobUpdated)
                    .unwrap_or_else(Event::Failed),
                _ => Event::Failed("Open the owning remote project to cancel its job.".to_owned()),
            },
            Task::OpenJobArtifact(digest) => match &source {
                Source::Remote(access) => runtime
                    .block_on(remote_job_artifact(access, &digest))
                    .map(Event::JobArtifact)
                    .unwrap_or_else(Event::Failed),
                _ => Event::Failed(
                    "Open the owning remote project to retrieve its artifact.".to_owned(),
                ),
            },
        };
        if events.send(event).is_err() {
            break;
        }
        ctx.request_repaint();
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Tab {
    Bytes,
    Cfg,
    Llvm,
    C,
    Analysis,
}

struct AnalystApp {
    tasks: SyncSender<Task>,
    events: Receiver<Event>,
    path_input: String,
    remote_endpoint: String,
    remote_token_file: String,
    remote_project_id: String,
    remote_project_name: String,
    remote_upload_path: String,
    search: String,
    source_label: Option<String>,
    source_offer: Option<String>,
    remote: bool,
    spec: Option<ProgramSpec>,
    symbol: Option<String>,
    cfg: Option<FunctionCfg>,
    ir: Option<String>,
    c: Option<String>,
    c_error: Option<String>,
    analysis: Option<AnalysisReport>,
    job: Option<JobReply>,
    job_symbol: Option<String>,
    last_job_poll: std::time::Instant,
    selected_address: Option<u64>,
    tab: Tab,
    busy: bool,
    status: String,
    failure: Option<String>,
    history: Vec<String>,
}

impl AnalystApp {
    fn new(ctx: &egui::Context) -> Self {
        let mut visuals = egui::Visuals::dark();
        visuals.panel_fill = BG;
        visuals.window_fill = PANEL;
        visuals.override_text_color = Some(TEXT);
        visuals.selection.bg_fill = Color32::from_rgb(86, 67, 46);
        visuals.selection.stroke.color = ACCENT;
        ctx.set_theme(egui::ThemePreference::Dark);
        ctx.set_visuals(visuals);
        let mut style = (*ctx.style_of(egui::Theme::Dark)).clone();
        style.spacing.item_spacing = egui::vec2(8.0, 7.0);
        style.spacing.button_padding = egui::vec2(10.0, 6.0);
        ctx.set_style_of(egui::Theme::Dark, style);
        let (task_sender, task_receiver) = mpsc::sync_channel(16);
        let (event_sender, event_receiver) = mpsc::sync_channel(16);
        let repaint = ctx.clone();
        thread::spawn(move || worker(task_receiver, event_sender, repaint));
        Self {
            tasks: task_sender,
            events: event_receiver,
            path_input: String::new(),
            remote_endpoint: "http://127.0.0.1:50051".to_owned(),
            remote_token_file: String::new(),
            remote_project_id: String::new(),
            remote_project_name: String::new(),
            remote_upload_path: String::new(),
            search: String::new(),
            source_label: None,
            source_offer: None,
            remote: false,
            spec: None,
            symbol: None,
            cfg: None,
            ir: None,
            c: None,
            c_error: None,
            analysis: None,
            job: None,
            job_symbol: None,
            last_job_poll: std::time::Instant::now(),
            selected_address: None,
            tab: Tab::Bytes,
            busy: false,
            status: "No project open".to_owned(),
            failure: None,
            history: Vec::new(),
        }
    }

    fn enqueue(&mut self, task: Task, status: &str) {
        match self.tasks.try_send(task) {
            Ok(()) => {
                self.busy = true;
                self.status = status.to_owned();
                self.failure = None;
            }
            Err(_) => {
                self.failure = Some("Analysis queue is full. Wait for the current task.".to_owned())
            }
        }
    }

    fn poll(&mut self) {
        while let Ok(event) = self.events.try_recv() {
            self.busy = false;
            match event {
                Event::Imported {
                    source,
                    remote,
                    source_offer,
                    spec,
                } => {
                    self.status = format!("Opened {} functions", spec.functions.len());
                    self.history.push(format!("Opened {source}"));
                    self.source_label = Some(source);
                    self.source_offer = source_offer;
                    self.remote = remote;
                    self.spec = Some(spec);
                    self.symbol = None;
                    self.cfg = None;
                    self.ir = None;
                    self.c = None;
                    self.c_error = None;
                    self.analysis = None;
                    self.job = None;
                    self.job_symbol = None;
                    self.selected_address = None;
                    self.failure = None;
                }
                Event::RemoteProjectCreated(project_id) => {
                    self.remote_project_id = project_id.clone();
                    self.status = format!(
                        "Created remote project {project_id}; select an ELF to upload explicitly"
                    );
                    self.history.push(self.status.clone());
                    self.failure = None;
                }
                Event::Selected { symbol, cfg, ir, c } => {
                    if self.symbol.as_deref() != Some(&symbol) {
                        continue;
                    }
                    self.selected_address = cfg.as_ref().ok().map(|cfg| cfg.entry.0);
                    let (cfg_value, cfg_error) = match cfg {
                        Ok(value) => (Some(value), None),
                        Err(error) => (None, Some(error)),
                    };
                    let (ir_value, ir_error) = match ir {
                        Ok(value) => (Some(value), None),
                        Err(error) => (None, Some(error)),
                    };
                    self.cfg = cfg_value;
                    self.ir = ir_value;
                    match c {
                        Ok(value) => {
                            self.c = Some(value);
                            self.c_error = None;
                        }
                        Err(error) => {
                            self.c = None;
                            self.c_error = Some(error);
                        }
                    }
                    self.failure = ir_error.or(cfg_error);
                    self.status = if self.ir.is_some() {
                        format!(
                            "Lifted {symbol} from machine bytes{}",
                            if self.remote {
                                " via remote service"
                            } else {
                                ""
                            }
                        )
                    } else if self.cfg.is_some() {
                        format!("Recovered CFG for {symbol}; lift unsupported")
                    } else {
                        format!("{symbol} is outside the current recovery contract")
                    };
                    self.history.push(self.status.clone());
                }
                Event::Failed(error) => {
                    self.failure = Some(error.clone());
                    self.status = "Operation failed".to_owned();
                    self.history.push(error);
                }
                Event::Analyzed(result) => match result {
                    Ok(report) => {
                        if self.spec.as_ref().map(|spec| &spec.binary_sha256)
                            != Some(&report.binary_sha256)
                        {
                            self.failure = Some(
                                "Analysis binary digest does not match the open project."
                                    .to_owned(),
                            );
                        } else {
                            self.status =
                                format!("Analyzed {} bounded functions", report.functions.len());
                            self.history.push(self.status.clone());
                            self.analysis = Some(report);
                            self.tab = Tab::Analysis;
                            self.failure = None;
                        }
                    }
                    Err(error) => {
                        self.failure = Some(error.clone());
                        self.status = "Global-effect analysis failed".to_owned();
                        self.history.push(error);
                    }
                },
                Event::JobUpdated(job) => {
                    self.status = format!("Lift job {} · {}", job.job_id, job.state);
                    if !job.diagnostic.is_empty() {
                        self.failure = Some(job.diagnostic.clone());
                    } else {
                        self.failure = None;
                    }
                    self.history.push(self.status.clone());
                    self.job = Some(job);
                    self.last_job_poll = std::time::Instant::now();
                }
                Event::JobArtifact(ir) => {
                    self.ir = Some(ir);
                    self.tab = Tab::Llvm;
                    self.status = "Opened verified lift-job IR artifact".to_owned();
                    self.failure = None;
                }
            }
            if self.history.len() > 40 {
                self.history.drain(..self.history.len() - 40);
            }
        }
    }

    fn selected_function(&self) -> Option<&FunctionSpec> {
        let symbol = self.symbol.as_ref()?;
        self.spec
            .as_ref()?
            .functions
            .iter()
            .find(|function| &function.name == symbol)
    }

    fn select(&mut self, name: String) {
        self.symbol = Some(name.clone());
        self.cfg = None;
        self.ir = None;
        self.c = None;
        self.c_error = None;
        self.selected_address = None;
        self.enqueue(
            Task::Select(name),
            "Recovering function from machine bytes…",
        );
    }

    fn header(&mut self, ui: &mut egui::Ui) {
        egui::Frame::new()
            .fill(PANEL)
            .inner_margin(egui::Margin::symmetric(16, 10))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new("HYDIR").size(19.0).strong().color(ACCENT));
                    ui.separator();
                    ui.label(RichText::new("NATIVE ANALYSIS").size(11.0).color(MUTED));
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.label(
                            RichText::new(if self.remote {
                                "REMOTE · EXPLICIT CONNECTION"
                            } else {
                                "LOCAL · NO UPLOAD"
                            })
                            .size(11.0)
                            .strong()
                            .color(if self.remote {
                                ACCENT
                            } else {
                                GOOD
                            }),
                        );
                        if let Some(spec) = &self.spec {
                            ui.label(
                                RichText::new(format!("SHA-256 {}…", &spec.binary_sha256[..12]))
                                    .monospace()
                                    .size(11.0)
                                    .color(MUTED),
                            );
                        }
                    });
                });
            });
    }

    fn navigator(&mut self, ui: &mut egui::Ui) {
        ui.heading(RichText::new("Program").size(16.0));
        if let Some(label) = &self.source_label {
            ui.label(RichText::new(label).size(11.0).color(ACCENT));
        }
        ui.label(
            RichText::new("Open a local ELF to inspect symbol facts. No binary is uploaded.")
                .size(12.0)
                .color(MUTED),
        );
        ui.add(
            egui::TextEdit::singleline(&mut self.path_input)
                .hint_text("/absolute/path/to/program.elf")
                .desired_width(f32::INFINITY),
        );
        let open = ui.add_enabled(
            !self.busy && !self.path_input.trim().is_empty(),
            egui::Button::new("Open local ELF"),
        );
        if open.clicked() {
            self.enqueue(
                Task::Open(PathBuf::from(self.path_input.trim())),
                "Importing local ELF…",
            );
        }
        ui.separator();
        egui::CollapsingHeader::new("Remote project · explicit transfer")
            .id_salt("remote_project")
            .show(ui, |ui| {
                ui.label(
                    RichText::new(
                        "Opening does not upload. Create or choose a project, then upload only by pressing the labelled transfer button. Analysis may save IR on the service.",
                    )
                    .size(11.0)
                    .color(MUTED),
                );
                ui.label(RichText::new("SERVICE ENDPOINT").size(10.0).color(MUTED));
                ui.add(
                    egui::TextEdit::singleline(&mut self.remote_endpoint)
                        .hint_text("http://127.0.0.1:50051"),
                );
                ui.label(RichText::new("PRIVATE CREDENTIAL FILE").size(10.0).color(MUTED));
                ui.add(
                    egui::TextEdit::singleline(&mut self.remote_token_file)
                        .hint_text("Private credential file path"),
                );
                ui.label(RichText::new("NEW PROJECT NAME").size(10.0).color(MUTED));
                ui.add(egui::TextEdit::singleline(&mut self.remote_project_name).hint_text("Analysis project"));
                let create = ui.add_enabled(
                    !self.busy && !self.remote_token_file.trim().is_empty() && !self.remote_project_name.trim().is_empty(),
                    egui::Button::new("Create remote project"),
                );
                if create.clicked() {
                    self.enqueue(Task::CreateRemoteProject {
                        endpoint: self.remote_endpoint.trim().to_owned(),
                        token_file: PathBuf::from(self.remote_token_file.trim()),
                        name: self.remote_project_name.trim().to_owned(),
                    }, "Creating authenticated remote project…");
                }
                ui.label(RichText::new("PROJECT ID").size(10.0).color(MUTED));
                ui.add(
                    egui::TextEdit::singleline(&mut self.remote_project_id).hint_text("Project ID"),
                );
                let open_remote = ui.add_enabled(
                    !self.busy
                        && !self.remote_token_file.trim().is_empty()
                        && !self.remote_project_id.trim().is_empty(),
                    egui::Button::new("Open remote project"),
                );
                if open_remote.clicked() {
                    self.enqueue(
                        Task::OpenRemote {
                            endpoint: self.remote_endpoint.trim().to_owned(),
                            token_file: PathBuf::from(self.remote_token_file.trim()),
                            project_id: self.remote_project_id.trim().to_owned(),
                        },
                        "Connecting to authenticated HydIR service…",
                    );
                }
                ui.separator();
                ui.label(RichText::new("LOCAL ELF TO UPLOAD").size(10.0).color(MUTED));
                ui.add(egui::TextEdit::singleline(&mut self.remote_upload_path).hint_text("/absolute/path/to/program.elf"));
                ui.label(RichText::new("Upload creates a new immutable binary revision and sends the selected bytes to this service.").size(11.0).color(MUTED));
                let upload = ui.add_enabled(
                    !self.busy
                        && !self.remote_token_file.trim().is_empty()
                        && !self.remote_project_id.trim().is_empty()
                        && !self.remote_upload_path.trim().is_empty(),
                    egui::Button::new("Upload ELF to remote project"),
                );
                if upload.clicked() {
                    self.enqueue(Task::UploadRemote {
                        endpoint: self.remote_endpoint.trim().to_owned(),
                        token_file: PathBuf::from(self.remote_token_file.trim()),
                        project_id: self.remote_project_id.trim().to_owned(),
                        path: PathBuf::from(self.remote_upload_path.trim()),
                    }, "Uploading selected ELF to remote project…");
                }
            });
        ui.separator();
        if let Some(spec) = &self.spec {
            ui.label(
                RichText::new(format!("FUNCTIONS  ·  {}", spec.functions.len()))
                    .size(11.0)
                    .strong()
                    .color(MUTED),
            );
            ui.add(
                egui::TextEdit::singleline(&mut self.search)
                    .hint_text("Search functions")
                    .desired_width(f32::INFINITY),
            );
            let query = self.search.to_lowercase();
            let filtered: Vec<usize> = spec
                .functions
                .iter()
                .enumerate()
                .filter(|(_, function)| function.name.to_lowercase().contains(&query))
                .map(|(index, _)| index)
                .collect();
            let mut clicked = None;
            egui::ScrollArea::vertical()
                .id_salt("function_list")
                .show_rows(ui, 26.0, filtered.len(), |ui, range| {
                    for position in range {
                        let function = &spec.functions[filtered[position]];
                        let selected = self.symbol.as_deref() == Some(&function.name);
                        if ui
                            .selectable_label(
                                selected,
                                RichText::new(&function.name).monospace().size(12.0),
                            )
                            .clicked()
                        {
                            clicked = Some(function.name.clone());
                        }
                    }
                });
            if let Some(name) = clicked {
                self.select(name);
            }
        } else {
            ui.add_space(16.0);
            ui.label(RichText::new("No functions yet").strong());
            ui.label(RichText::new("Open an ELF to populate the function tree.").color(MUTED));
        }
    }

    fn inspector(&mut self, ui: &mut egui::Ui) {
        ui.heading(RichText::new("Inspector").size(16.0));
        ui.separator();
        if let Some(source_offer) = &self.source_offer {
            field(ui, "SOURCE OFFER", source_offer);
            ui.separator();
        }
        let analyze = ui.add_enabled(
            !self.busy && self.spec.is_some(),
            egui::Button::new("Analyze global effects"),
        );
        if analyze.clicked() {
            self.enqueue(
                Task::Analyze,
                "Tracing direct calls and mapped global effects…",
            );
        }
        analyze.on_hover_text(
            "Scans bounded linked-ELF symbols. Unknown calls and indirect memory remain conservative; no binary execution.",
        );
        if let Some(report) = &self.analysis {
            field(
                ui,
                "ANALYSIS SCOPE",
                &format!(
                    "{} functions · {} skipped",
                    report.functions.len(),
                    report.skipped_functions.len()
                ),
            );
        }
        ui.separator();
        if let Some(function) = self.selected_function() {
            ui.label(RichText::new(&function.name).monospace().color(ACCENT));
            field(ui, "ENTRY", &format!("0x{:016x}", function.address.0));
            field(ui, "EXTENT", &format!("{} bytes", function.size));
            field(ui, "SOURCE", &function.provenance);
            field(ui, "ABI", "u64(u64, u64) · analyst assertion for lift");
            if let Some(address) = self.selected_address {
                field(ui, "SELECTED", &format!("0x{address:016x}"));
            }
            if let Some(cfg) = &self.cfg {
                field(
                    ui,
                    "CFG",
                    &format!(
                        "{} reachable blocks · {} edges",
                        cfg.blocks.len(),
                        cfg.edges.len()
                    ),
                );
            }
            field(ui, "MEMORY/CALLS", "Unsupported by this lift");
            if let Some(summary) = self.analysis.as_ref().and_then(|report| {
                report.functions.iter().find(|summary| {
                    summary.name == function.name && summary.entry == function.address
                })
            }) {
                field(ui, "DIRECT CALLS", &summary.direct_callees.join(", "));
                field(
                    ui,
                    "POSSIBLE GLOBAL WRITES",
                    &format!("{} mapped addresses", summary.possible_global_writes.len()),
                );
                field(
                    ui,
                    "UNKNOWN EFFECTS",
                    if summary.unknown_global_effects {
                        "Yes · enumerated addresses are incomplete"
                    } else {
                        "No within declared scope"
                    },
                );
            }
        } else {
            ui.label(
                RichText::new("Select a function to inspect its scope and assumptions.")
                    .color(MUTED),
            );
        }
        ui.add_space(12.0);
        ui.separator();
        ui.heading(RichText::new("Diagnostics").size(14.0));
        if let Some(failure) = &self.failure {
            ui.colored_label(BAD, failure);
        } else {
            ui.colored_label(if self.busy { ACCENT } else { GOOD }, &self.status);
        }
        ui.add_space(12.0);
        ui.separator();
        ui.heading(RichText::new("Jobs / activity").size(14.0));
        let selected_symbol = self.symbol.clone();
        let start = ui.add_enabled(
            self.remote && !self.busy && selected_symbol.is_some(),
            egui::Button::new("Start remote lift job"),
        );
        if start.clicked()
            && let Some(symbol) = selected_symbol
        {
            self.job_symbol = Some(symbol.clone());
            self.enqueue(
                Task::StartLiftJob {
                    symbol,
                    key: uuid::Uuid::new_v4().to_string(),
                },
                "Starting owner-scoped lift job…",
            );
        }
        start.on_disabled_hover_text("Open a remote project and select a function first.");
        if let Some(job) = self.job.clone() {
            field(ui, "JOB", &format!("{} · {}", job.job_id, job.state));
            if let Some(symbol) = &self.job_symbol {
                field(ui, "FUNCTION", symbol);
            }
            if !job.diagnostic.is_empty() {
                ui.colored_label(BAD, &job.diagnostic);
            }
            ui.horizontal(|ui| {
                if ui
                    .add_enabled(!self.busy, egui::Button::new("Refresh job"))
                    .clicked()
                {
                    self.enqueue(Task::RefreshJob(job.job_id.clone()), "Refreshing lift job…");
                }
                let active = job.state == "queued" || job.state == "running";
                let cancel = ui.add_enabled(!self.busy && active, egui::Button::new("Cancel job"));
                if cancel.clicked() {
                    self.enqueue(Task::CancelJob(job.job_id.clone()), "Cancelling lift job…");
                }
                cancel.on_disabled_hover_text("Only queued or running jobs can be cancelled.");
            });
            if job.state == "succeeded" && !job.artifact_sha256.is_empty() {
                field(ui, "ARTIFACT SHA-256", &job.artifact_sha256);
                if ui
                    .add_enabled(!self.busy, egui::Button::new("Open verified job IR"))
                    .clicked()
                {
                    self.enqueue(
                        Task::OpenJobArtifact(job.artifact_sha256),
                        "Retrieving lift-job IR artifact…",
                    );
                }
            }
        }
        egui::ScrollArea::vertical()
            .id_salt("job_list")
            .show(ui, |ui| {
                for entry in self.history.iter().rev() {
                    ui.label(RichText::new(entry).size(11.0).color(MUTED));
                }
            });
    }

    fn main_view(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            for (tab, label) in [
                (Tab::Bytes, "Disassembly"),
                (Tab::Cfg, "CFG"),
                (Tab::Llvm, "LLVM IR"),
                (Tab::Analysis, "Global effects"),
                (Tab::C, "C output"),
            ] {
                let response = ui.add(egui::Button::selectable(self.tab == tab, label));
                if response.clicked() {
                    self.tab = tab;
                }
            }
        });
        ui.separator();
        match self.tab {
            Tab::Bytes => self.disassembly(ui),
            Tab::Cfg => self.cfg_view(ui),
            Tab::Llvm => self.llvm_view(ui),
            Tab::Analysis => self.analysis_view(ui),
            Tab::C => self.c_view(ui),
        }
    }

    fn disassembly(&mut self, ui: &mut egui::Ui) {
        let Some(cfg) = &self.cfg else {
            ui.label(
                RichText::new("Select a supported function to decode reachable instructions.")
                    .color(MUTED),
            );
            return;
        };
        let mut clicked = None;
        egui::ScrollArea::vertical()
            .id_salt("bytes_view")
            .show_rows(ui, 26.0, cfg.blocks.len(), |ui, range| {
                for index in range {
                    let block = &cfg.blocks[index];
                    let selected = self.selected_address == Some(block.address.0);
                    let line = format!(
                        "{:016x}   {:<18} {}",
                        block.address.0, block.bytes_hex, block.mnemonic
                    );
                    if ui
                        .selectable_label(selected, RichText::new(line).monospace().size(12.0))
                        .clicked()
                    {
                        clicked = Some(block.address.0);
                    }
                }
            });
        if let Some(address) = clicked {
            self.selected_address = Some(address);
        }
    }

    fn cfg_view(&mut self, ui: &mut egui::Ui) {
        let Some(cfg) = &self.cfg else {
            ui.label(RichText::new("CFG recovery is unavailable for this function.").color(MUTED));
            return;
        };
        ui.label(RichText::new(&cfg.recovery_scope).size(11.0).color(MUTED));
        let mut clicked = None;
        egui::ScrollArea::vertical()
            .id_salt("cfg_view")
            .show(ui, |ui| {
                for block in &cfg.blocks {
                    let selected = self.selected_address == Some(block.address.0);
                    let edges: Vec<String> = cfg
                        .edges
                        .iter()
                        .filter(|edge| edge.source == block.address)
                        .map(|edge| format!("{:?} → 0x{:x}", edge.kind, edge.target.0))
                        .collect();
                    let text = format!(
                        "0x{:016x}  {:<8}  {}",
                        block.address.0,
                        block.mnemonic,
                        edges.join("   ")
                    );
                    if ui
                        .selectable_label(selected, RichText::new(text).monospace().size(11.0))
                        .clicked()
                    {
                        clicked = Some(block.address.0);
                    }
                }
            });
        if let Some(address) = clicked {
            self.selected_address = Some(address);
        }
    }

    fn llvm_view(&mut self, ui: &mut egui::Ui) {
        let Some(ir) = &self.ir else {
            ui.label(RichText::new("LLVM lift is unavailable; inspect the diagnostic for the unsupported instruction or state.").color(MUTED));
            return;
        };
        if let Some(address) = self.selected_address
            && let Some(slice) = ir_slice(ir, address)
        {
            ui.label(
                RichText::new(format!("SELECTED INSTRUCTION  ·  0x{address:x}"))
                    .size(11.0)
                    .strong()
                    .color(ACCENT),
            );
            ui.label(RichText::new(slice).monospace().size(11.0));
            ui.separator();
        }
        egui::ScrollArea::both()
            .id_salt("llvm_view")
            .show(ui, |ui| {
                ui.code(ir);
            });
    }

    fn c_view(&mut self, ui: &mut egui::Ui) {
        if let Some(c) = &self.c {
            ui.label(
                RichText::new("SCALAR LLVM-TO-C · EXPLICIT CFG / SSA COPIES")
                    .size(11.0)
                    .color(ACCENT),
            );
            egui::ScrollArea::both().id_salt("c_view").show(ui, |ui| {
                ui.code(c);
            });
        } else if let Some(error) = &self.c_error {
            ui.colored_label(BAD, error);
            ui.label(
                RichText::new("A C-generation failure does not discard a valid CFG or LLVM lift.")
                    .color(MUTED),
            );
        } else {
            ui.label(
                RichText::new("Select a supported scalar function to generate C.").color(MUTED),
            );
        }
    }

    fn analysis_view(&mut self, ui: &mut egui::Ui) {
        let Some(report) = &self.analysis else {
            ui.label(
                RichText::new("Run global-effect analysis to see cross-function results.")
                    .color(MUTED),
            );
            return;
        };
        ui.label(RichText::new(&report.scope).size(11.0).color(MUTED));
        ui.label(RichText::new(&report.assumption).size(11.0).color(MUTED));
        if !report.skipped_functions.is_empty() {
            ui.colored_label(
                BAD,
                format!(
                    "{} symbols skipped; this is not whole-program coverage",
                    report.skipped_functions.len()
                ),
            );
        }
        ui.separator();
        egui::ScrollArea::both()
            .id_salt("analysis_view")
            .show(ui, |ui| {
                for summary in &report.functions {
                    let selected = self.symbol.as_deref() == Some(&summary.name);
                    let color = if summary.unknown_global_effects {
                        BAD
                    } else {
                        GOOD
                    };
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(if selected { "▸" } else { " " }).color(ACCENT));
                        ui.label(
                            RichText::new(format!("0x{:016x}  {}", summary.entry.0, summary.name))
                                .monospace(),
                        );
                        ui.label(
                            RichText::new(format!(
                                "SCC {} · {} calls · {} reads · {} writes",
                                summary.scc_id,
                                summary.direct_callees.len(),
                                summary.possible_global_reads.len(),
                                summary.possible_global_writes.len()
                            ))
                            .size(11.0)
                            .color(MUTED),
                        );
                        ui.label(
                            RichText::new(if summary.unknown_global_effects {
                                "UNKNOWN EFFECTS"
                            } else {
                                "BOUNDED"
                            })
                            .size(10.0)
                            .color(color),
                        );
                    });
                    if selected {
                        ui.indent(("analysis", summary.entry.0), |ui| {
                            field(ui, "CALLEES", &summary.direct_callees.join(", "));
                            field(
                                ui,
                                "POSSIBLE WRITES",
                                &summary
                                    .possible_global_writes
                                    .iter()
                                    .map(|reference| {
                                        format!("{}:0x{:x}", reference.section, reference.address.0)
                                    })
                                    .collect::<Vec<_>>()
                                    .join(", "),
                            );
                            field(
                                ui,
                                "UNRESOLVED TARGETS",
                                &summary
                                    .unresolved_targets
                                    .iter()
                                    .map(|address| format!("0x{:x}", address.0))
                                    .collect::<Vec<_>>()
                                    .join(", "),
                            );
                        });
                    }
                }
            });
    }
}

fn field(ui: &mut egui::Ui, label: &str, value: &str) {
    ui.label(RichText::new(label).size(10.0).strong().color(MUTED));
    ui.label(RichText::new(value).size(12.0));
    ui.add_space(5.0);
}

fn ir_slice(ir: &str, address: u64) -> Option<String> {
    let marker = format!("b{address:x}:\n");
    let start = ir.find(&marker)?;
    let rest = &ir[start..];
    let next_block = rest[marker.len()..]
        .find("\nb")
        .map(|offset| marker.len() + offset);
    let function_end = rest.find("\n}");
    let end = match (next_block, function_end) {
        (Some(next), Some(end)) => next.min(end),
        (Some(next), None) => next,
        (None, Some(end)) => end,
        (None, None) => return None,
    };
    Some(rest[..end].trim().to_owned())
}

impl eframe::App for AnalystApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.poll();
        if !self.busy
            && self.last_job_poll.elapsed() >= std::time::Duration::from_millis(750)
            && let Some(job) = &self.job
            && matches!(job.state.as_str(), "queued" | "running")
        {
            self.enqueue(Task::RefreshJob(job.job_id.clone()), "Refreshing lift job…");
        }
        ui.ctx()
            .request_repaint_after(std::time::Duration::from_millis(250));
        self.header(ui);
        egui::Panel::left("navigator")
            .resizable(true)
            .default_size(260.0)
            .min_size(180.0)
            .show(ui, |ui| {
                egui::Frame::new()
                    .inner_margin(egui::Margin::same(12))
                    .show(ui, |ui| self.navigator(ui));
            });
        egui::Panel::right("inspector")
            .resizable(true)
            .default_size(290.0)
            .min_size(220.0)
            .show(ui, |ui| {
                egui::Frame::new()
                    .inner_margin(egui::Margin::same(12))
                    .show(ui, |ui| self.inspector(ui));
            });
        egui::CentralPanel::default().show(ui, |ui| {
            egui::Frame::new()
                .inner_margin(egui::Margin::same(12))
                .show(ui, |ui| self.main_view(ui));
        });
    }
}

fn main() -> eframe::Result<()> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    if let [probe, endpoint, token_file, binary] = arguments.as_slice()
        && probe == "--probe-create-upload"
    {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("Tokio runtime initialization");
        let result = runtime.block_on(async {
            let project_id = create_remote_project(
                endpoint.clone(),
                PathBuf::from(token_file),
                "GUI transfer probe".to_owned(),
            )
            .await?;
            let (access, spec) = upload_remote(
                endpoint.clone(),
                PathBuf::from(token_file),
                project_id,
                PathBuf::from(binary),
            )
            .await?;
            Ok::<_, String>((access.project_id, access.revision, spec.functions.len()))
        });
        match result {
            Ok((project_id, revision, functions)) => {
                println!(
                    "HydIR GUI transfer operations passed: project {project_id}, revision {revision}, {functions} functions"
                );
                return Ok(());
            }
            Err(error) => {
                eprintln!("HydIR GUI transfer probe failed: {error}");
                std::process::exit(1);
            }
        }
    }
    if let [probe, endpoint, token_file, project_id, symbol] = arguments.as_slice()
        && probe == "--probe-remote"
    {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("Tokio runtime initialization");
        let result = runtime.block_on(async {
            let (access, spec) = open_remote(
                endpoint.clone(),
                PathBuf::from(token_file),
                project_id.clone(),
            )
            .await?;
            let (cfg, ir, c) = select_remote(&access, symbol).await;
            let cfg = cfg?;
            let ir = ir?;
            let c = c?;
            if !c.contains("uint64_t hydir_lifted(") {
                return Err(
                    "Remote C artifact did not contain the expected lifted function.".to_owned(),
                );
            }
            let analysis = analyze_remote(&access).await?;
            if analysis.binary_sha256 != spec.binary_sha256 {
                return Err("Remote analysis model digest differs from open project.".to_owned());
            }
            let started =
                start_remote_job(&access, symbol, &uuid::Uuid::new_v4().to_string()).await?;
            let mut job = started;
            for _ in 0..40 {
                if !matches!(job.state.as_str(), "queued" | "running") {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
                job = remote_job(&access, &job.job_id, false).await?;
            }
            if job.state != "succeeded" {
                return Err(format!(
                    "Remote GUI lift job did not succeed: {} · {}",
                    job.state, job.diagnostic
                ));
            }
            let job_ir = remote_job_artifact(&access, &job.artifact_sha256).await?;
            if job_ir != ir {
                return Err("Remote GUI lift job IR differs from direct lift.".to_owned());
            }
            Ok::<_, String>((
                spec.functions.len(),
                cfg.blocks.len(),
                ir.len(),
                analysis.functions.len(),
            ))
        });
        match result {
            Ok((functions, blocks, ir_bytes, analyzed)) => {
                println!(
                    "HydIR GUI remote operations passed: {functions} functions, {blocks} selected blocks, {ir_bytes} IR bytes, {analyzed} global-effect summaries, one completed lift job"
                );
                return Ok(());
            }
            Err(error) => {
                eprintln!("HydIR GUI remote probe failed: {error}");
                std::process::exit(1);
            }
        }
    }
    if !arguments.is_empty() {
        eprintln!(
            "Usage: hydir [--probe-remote <endpoint> <token-file> <project-id> <symbol> | --probe-create-upload <endpoint> <token-file> <elf>]"
        );
        std::process::exit(2);
    }
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("HydIR · Native Analysis")
            .with_inner_size([1400.0, 850.0]),
        ..Default::default()
    };
    eframe::run_native(
        "HydIR",
        options,
        Box::new(|context| Ok(Box::new(AnalystApp::new(&context.egui_ctx)))),
    )
}

#[cfg(test)]
mod tests {
    use super::{ir_slice, validate_endpoint};

    #[test]
    fn extracts_selected_instruction_ir_without_crossing_next_block() {
        let ir = "b1000:\n  ; 0x1000: 90\n  br label %b1001\nb1001:\n  ret i64 0\n}\n";
        assert_eq!(
            ir_slice(ir, 0x1000).unwrap(),
            "b1000:\n  ; 0x1000: 90\n  br label %b1001"
        );
    }

    #[test]
    fn remote_endpoint_requires_explicit_loopback() {
        assert!(validate_endpoint("http://127.0.0.1:50051").is_ok());
        assert!(validate_endpoint("http://[::1]:50051").is_ok());
        assert!(validate_endpoint("http://0.0.0.0:50051").is_err());
        assert!(validate_endpoint("http://192.0.2.1:50051").is_err());
        assert!(validate_endpoint("https://127.0.0.1:50051").is_err());
    }
}
