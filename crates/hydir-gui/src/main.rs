//! HydIR desktop workbench: a local, asynchronous analyst view over the same
//! native import, CFG recovery, and lifting operations used by the CLI.

use eframe::egui::{self, Color32, RichText};
use egui_graph::{NodeId, layout_from_sizes};
use egui_graph_egui::Direction as GraphDirection;
use hydir_analysis::{AnalysisReport, analyze_elf};
use hydir_api::v1::{
    AnnotationRequest, ArtifactRequest, CreateProjectRequest, DiscoverRequest, FunctionRequest,
    JobReply, JobRequest, PatchRequest, ProjectRequest, RebuildRequest, StartLiftJobRequest,
    TransformRequest, UploadBinaryRequest, hydir_client::HydirClient,
};
use hydir_backend::{MAX_BINARY_BYTES, disassemble_elf, import_elf, lift_symbol, recover_symbol_cfg};
use hydir_c::emit_structured_c;
use hydir_core::{
    Address, AnalystAnnotation, AnnotationKind, DisassemblyReport, FactSource, FunctionCfg,
    FunctionSpec, ProgramSpec, overlay_analyst_assumptions,
};
use hydir_patch::{PatchDocument, parse_patch_json, patch_binary};
use hydir_project::{LocalProject, LocalProjectStore, WorkbenchSettings};
use hydir_recompile::rebuild_bytes;
use hydir_transform::{parse_passes, transform};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{Read, Write},
    net::SocketAddr,
    path::{Path, PathBuf},
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
const PINNED_OPT: &str = "/usr/bin/opt-14";
const PINNED_CLANG: &str = "/usr/bin/clang-14";

enum Task {
    LoadWorkbench,
    SaveWorkbench(WorkbenchSettings),
    Open(PathBuf),
    OpenGhidraGraph(PathBuf),
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
    Disassemble,
    Analyze,
    RefreshAnnotations {
        binary_sha256: String,
    },
    AddAnnotation {
        binary_sha256: String,
        kind: AnnotationKind,
        address: Option<u64>,
        scope: String,
        value: String,
        key: String,
    },
    StartLiftJob {
        symbol: String,
        key: String,
    },
    RefreshJob(String),
    CancelJob(String),
    OpenJobArtifact(String),
    TransformRemote {
        symbol: String,
        passes: String,
        key: String,
    },
    TransformLocal {
        symbol: String,
        passes: String,
        output_dir: PathBuf,
    },
    RebuildRemote {
        key: String,
    },
    RebuildLocal {
        output_dir: PathBuf,
    },
    PatchLocal {
        symbol: String,
        replacement: String,
        output_path: PathBuf,
    },
    PatchRemote {
        symbol: String,
        replacement: String,
        key: String,
    },
    ExportRebuiltRemote {
        digest: String,
        path: PathBuf,
    },
}

enum Event {
    WorkbenchLoaded(Result<WorkbenchSettings, String>),
    WorkbenchSaved(WorkbenchSettings),
    Imported {
        source: String,
        remote: bool,
        revision: Option<u64>,
        named_pass_transform: bool,
        whole_rebuild: bool,
        source_offer: Option<String>,
        spec: ProgramSpec,
    },
    GhidraGraphLoaded(Result<GhidraGraph, String>),
    RemoteProjectCreated(String),
    Selected {
        symbol: String,
        cfg: Result<FunctionCfg, String>,
        ir: Result<String, String>,
        c: Result<String, String>,
    },
    Disassembled(Result<DisassemblyReport, String>),
    Analyzed(Result<AnalysisReport, String>),
    AnnotationsLoaded {
        binary_sha256: String,
        annotations: Vec<AnalystAnnotation>,
    },
    AnnotationAdded {
        source: String,
        revision: u64,
        spec: ProgramSpec,
        annotations: Vec<AnalystAnnotation>,
    },
    JobUpdated(JobReply),
    JobArtifact(String),
    Transformed {
        source: String,
        revision: u64,
        before: String,
        after: String,
        report: String,
        changed: bool,
        c: Result<String, String>,
    },
    LocalTransformed {
        before: String,
        after: String,
        report: String,
        c: Result<String, String>,
        output_dir: PathBuf,
    },
    Rebuilt {
        source: String,
        revision: u64,
        spec: ProgramSpec,
        ir: String,
        report: String,
        binary_sha256: String,
    },
    LocalRebuilt {
        spec: ProgramSpec,
        revision: u64,
        ir: String,
        report: String,
        binary_sha256: String,
        output_dir: PathBuf,
    },
    LocalPatched {
        spec: ProgramSpec,
        revision: u64,
        binary_sha256: String,
        output_path: PathBuf,
    },
    RemotePatched {
        source: String,
        revision: u64,
        spec: ProgramSpec,
        binary_sha256: String,
    },
    ArtifactExported {
        path: PathBuf,
        digest: String,
    },
    MutationUncertain(String),
    Failed(String),
}

#[derive(Clone)]
struct RemoteAccess {
    endpoint: String,
    token: String,
    project_id: String,
    revision: u64,
    source_offer: String,
    named_pass_transform: bool,
    whole_rebuild: bool,
}

#[derive(Clone, Debug, serde::Deserialize)]
struct GhidraGraph {
    schema_version: u32,
    source: String,
    program: String,
    functions: Vec<GhidraFunction>,
    #[serde(default)]
    cfg_edges: Vec<GhidraEdge>,
    #[serde(default)]
    call_edges: Vec<GhidraEdge>,
}

#[derive(Clone, Debug, serde::Deserialize)]
struct GhidraFunction {
    name: String,
    entry: String,
    #[allow(dead_code)]
    size: u64,
    #[serde(default)]
    blocks: Vec<GhidraBlock>,
}

#[derive(Clone, Debug, serde::Deserialize)]
struct GhidraBlock {
    address: String,
    mnemonic: String,
}

#[derive(Clone, Debug, serde::Deserialize)]
struct GhidraEdge {
    source: String,
    target: String,
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
        named_pass_transform: false,
        whole_rebuild: false,
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
        named_pass_transform: discovery.named_pass_transform,
        whole_rebuild: discovery.whole_rebuild,
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
        named_pass_transform: false,
        whole_rebuild: false,
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
        named_pass_transform: false,
        whole_rebuild: false,
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

async fn list_remote_annotations(
    access: &RemoteAccess,
    binary_sha256: &str,
) -> Result<Vec<AnalystAnnotation>, String> {
    let mut client = remote_client(access).await?;
    let reply = client
        .list_annotations(authorized(
            ProjectRequest {
                project_id: access.project_id.clone(),
                expected_revision: access.revision,
            },
            &access.token,
        ))
        .await
        .map_err(|error| format!("Remote annotations unavailable: {error}"))?
        .into_inner();
    let ledger: serde_json::Value = serde_json::from_str(&reply.json)
        .map_err(|error| format!("Invalid remote annotation ledger: {error}"))?;
    if ledger["project_id"] != access.project_id
        || ledger["revision"] != access.revision
        || ledger["binary_sha256"] != binary_sha256
    {
        return Err("Remote annotation ledger identity differs from open project.".to_owned());
    }
    serde_json::from_value(ledger["annotations"].clone())
        .map_err(|error| format!("Invalid remote annotation facts: {error}"))
}

async fn add_remote_annotation(
    access: &RemoteAccess,
    binary_sha256: &str,
    kind: AnnotationKind,
    address: Option<u64>,
    scope: &str,
    value: &str,
    key: &str,
) -> Result<(u64, ProgramSpec, Vec<AnalystAnnotation>), String> {
    let kind_label = match kind {
        AnnotationKind::Name => "name",
        AnnotationKind::Comment => "comment",
        AnnotationKind::Assumption => "assumption",
    };
    let mut client = remote_client(access).await?;
    let added = client
        .add_annotation(authorized(
            AnnotationRequest {
                project_id: access.project_id.clone(),
                expected_revision: access.revision,
                idempotency_key: key.to_owned(),
                kind: kind_label.to_owned(),
                address: address.map_or_else(String::new, |address| format!("0x{address:016x}")),
                value: value.to_owned(),
                scope: scope.to_owned(),
            },
            &access.token,
        ))
        .await
        .map_err(|error| format!("Remote annotation failed: {error}"))?
        .into_inner();
    if added.project_id != access.project_id
        || added.revision != access.revision + 1
        || added.binary_sha256 != binary_sha256
    {
        return Err("Remote annotation returned an unexpected revision or binary.".to_owned());
    }
    let updated = RemoteAccess {
        revision: added.revision,
        ..access.clone()
    };
    let inspected = client
        .inspect(authorized(
            ProjectRequest {
                project_id: updated.project_id.clone(),
                expected_revision: updated.revision,
            },
            &updated.token,
        ))
        .await
        .map_err(|error| format!("Cannot reopen annotated revision: {error}"))?
        .into_inner();
    let spec: ProgramSpec = serde_json::from_str(&inspected.json)
        .map_err(|error| format!("Invalid annotated program model: {error}"))?;
    if spec.binary_sha256 != binary_sha256 {
        return Err("Annotated program digest changed unexpectedly.".to_owned());
    }
    let annotations = list_remote_annotations(&updated, binary_sha256).await?;
    if !annotations.iter().any(|annotation| {
        annotation.created_revision == updated.revision
            && annotation.kind == kind
            && annotation.address.map(|address| address.0) == address
            && annotation.value == value
            && annotation.scope == scope
    }) {
        return Err("Saved annotation is absent from the returned ledger.".to_owned());
    }
    Ok((updated.revision, spec, annotations))
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

async fn verified_text_artifact(
    client: &mut HydirClient<Channel>,
    access: &RemoteAccess,
    revision: u64,
    digest: &str,
    media_type: &str,
) -> Result<String, String> {
    let artifact = client
        .get_artifact(authorized(
            ArtifactRequest {
                project_id: access.project_id.clone(),
                sha256: digest.to_owned(),
            },
            &access.token,
        ))
        .await
        .map_err(|error| format!("Could not retrieve {media_type} artifact: {error}"))?
        .into_inner();
    if artifact.sha256 != digest
        || artifact.project_revision != revision
        || artifact.media_type != media_type
        || format!("{:x}", Sha256::digest(&artifact.content)) != digest
    {
        return Err(format!(
            "{media_type} artifact failed digest/type/revision verification."
        ));
    }
    String::from_utf8(artifact.content)
        .map_err(|error| format!("{media_type} artifact is not UTF-8: {error}"))
}

async fn transform_remote(
    access: &RemoteAccess,
    symbol: &str,
    passes: &str,
    key: &str,
) -> Result<(u64, String, String, String, bool), String> {
    if !access.named_pass_transform {
        return Err("Service does not advertise named-pass transformation.".to_owned());
    }
    parse_passes(passes)?;
    let mut client = remote_client(access).await?;
    let reply = client
        .transform(authorized(
            TransformRequest {
                project_id: access.project_id.clone(),
                expected_revision: access.revision,
                function_symbol: symbol.to_owned(),
                assume_u64x2: true,
                trusted_fixture: true,
                passes: passes.to_owned(),
                idempotency_key: key.to_owned(),
            },
            &access.token,
        ))
        .await
        .map_err(|error| format!("Remote transform failed: {error}"))?
        .into_inner();
    if reply.project_id != access.project_id
        || Some(reply.project_revision) != access.revision.checked_add(1)
    {
        return Err("Transform returned an unexpected project or revision.".to_owned());
    }
    let before = verified_text_artifact(
        &mut client,
        access,
        reply.project_revision,
        &reply.before_sha256,
        "text/x-llvm-ir",
    )
    .await?;
    let after = verified_text_artifact(
        &mut client,
        access,
        reply.project_revision,
        &reply.after_sha256,
        "text/x-llvm-ir",
    )
    .await?;
    let report = verified_text_artifact(
        &mut client,
        access,
        reply.project_revision,
        &reply.report_sha256,
        "application/json",
    )
    .await?;
    if report != reply.report_json || reply.ir_text_changed != (before != after) {
        return Err("Transform report or change flag differs from stored artifacts.".to_owned());
    }
    Ok((
        reply.project_revision,
        before,
        after,
        report,
        reply.ir_text_changed,
    ))
}

async fn rebuild_remote(
    access: &RemoteAccess,
    key: &str,
) -> Result<(u64, ProgramSpec, String, String, String), String> {
    if !access.whole_rebuild {
        return Err("Service does not advertise whole-executable rebuilding.".to_owned());
    }
    let mut client = remote_client(access).await?;
    let reply = client
        .rebuild(authorized(
            RebuildRequest {
                project_id: access.project_id.clone(),
                expected_revision: access.revision,
                trusted_fixture: true,
                idempotency_key: key.to_owned(),
            },
            &access.token,
        ))
        .await
        .map_err(|error| format!("Remote rebuild failed: {error}"))?
        .into_inner();
    if reply.project_id != access.project_id
        || Some(reply.revision) != access.revision.checked_add(1)
    {
        return Err("Rebuild returned an unexpected project or revision.".to_owned());
    }
    let ir = verified_text_artifact(
        &mut client,
        access,
        reply.revision,
        &reply.ir_sha256,
        "text/x-llvm-ir",
    )
    .await?;
    let report = verified_text_artifact(
        &mut client,
        access,
        reply.revision,
        &reply.report_sha256,
        "application/json",
    )
    .await?;
    if report != reply.report_json {
        return Err("Rebuild report differs from stored artifact.".to_owned());
    }
    let project = client
        .get_project(authorized(
            ProjectRequest {
                project_id: access.project_id.clone(),
                expected_revision: reply.revision,
            },
            &access.token,
        ))
        .await
        .map_err(|error| format!("Could not verify rebuilt project: {error}"))?
        .into_inner();
    if project.binary_sha256 != reply.binary_sha256 || project.revision != reply.revision {
        return Err("Rebuilt project binary digest or revision differs from reply.".to_owned());
    }
    let inspection = client
        .inspect(authorized(
            ProjectRequest {
                project_id: access.project_id.clone(),
                expected_revision: reply.revision,
            },
            &access.token,
        ))
        .await
        .map_err(|error| format!("Could not inspect rebuilt binary: {error}"))?
        .into_inner();
    let spec: ProgramSpec = serde_json::from_str(&inspection.json)
        .map_err(|error| format!("Invalid rebuilt program model: {error}"))?;
    if spec.binary_sha256 != reply.binary_sha256 {
        return Err("Rebuilt program model digest differs from project.".to_owned());
    }
    Ok((reply.revision, spec, ir, report, reply.binary_sha256))
}

async fn export_rebuilt_remote(
    access: &RemoteAccess,
    digest: &str,
    path: &PathBuf,
) -> Result<(), String> {
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
        .map_err(|error| format!("Could not retrieve rebuilt ELF: {error}"))?
        .into_inner();
    if artifact.sha256 != digest
        || artifact.project_revision != access.revision
        || artifact.media_type != "application/x-elf"
        || format!("{:x}", Sha256::digest(&artifact.content)) != digest
    {
        return Err("Rebuilt ELF failed digest/type/revision verification.".to_owned());
    }
    import_elf(&artifact.content)
        .map_err(|error| format!("Retrieved ELF failed import: {error}"))?;
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o700);
    }
    let mut file = options
        .open(path)
        .map_err(|error| format!("Could not create new export file: {error}"))?;
    let write_result = file
        .write_all(&artifact.content)
        .and_then(|()| file.sync_all());
    if let Err(error) = write_result {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(format!("Could not complete ELF export: {error}"));
    }
    Ok(())
}

fn new_output_dir(path: &Path) -> Result<(), String> {
    if !path.is_absolute() {
        return Err("Output directory must be an absolute path.".to_owned());
    }
    fs::create_dir(path)
        .map_err(|error| format!("Could not create a new output directory: {error}"))
}

fn transform_local(
    binary: &[u8],
    symbol: &str,
    passes: &str,
    output_dir: &Path,
) -> Result<(String, String, String), String> {
    let raw = lift_symbol(binary, symbol).map_err(|error| error.to_string())?;
    let result = transform(&raw, passes, Path::new(PINNED_OPT))?;
    let before = String::from_utf8(result.before.clone())
        .map_err(|error| format!("Canonical LLVM IR is not UTF-8: {error}"))?;
    let after = String::from_utf8(result.after.clone())
        .map_err(|error| format!("Transformed LLVM IR is not UTF-8: {error}"))?;
    let report = serde_json::json!({
        "scope": "trusted scalar function; named LLVM passes",
        "function": symbol,
        "passes": result.pipeline,
        "llvm_version": result.llvm_version,
        "llvm_verified": true,
        "ir_text_changed": before != after,
        "raw_sha256": format!("{:x}", Sha256::digest(&result.raw)),
        "before_sha256": format!("{:x}", Sha256::digest(&result.before)),
        "after_sha256": format!("{:x}", Sha256::digest(&result.after)),
    })
    .to_string();
    new_output_dir(output_dir)?;
    for (name, content) in [
        ("raw.ll", result.raw.as_slice()),
        ("before.ll", result.before.as_slice()),
        ("after.ll", result.after.as_slice()),
        ("report.json", report.as_bytes()),
    ] {
        fs::write(output_dir.join(name), content)
            .map_err(|error| format!("Could not write {name} in new output directory: {error}"))?;
    }
    Ok((before, after, report))
}

fn rebuild_local(
    binary: &[u8],
    output_dir: &Path,
) -> Result<(Vec<u8>, ProgramSpec, String, String, String), String> {
    let result = rebuild_bytes(binary, Path::new(PINNED_CLANG), Path::new(PINNED_OPT))
        .map_err(|error| error.to_string())?;
    let spec = import_elf(&result.executable)
        .map_err(|error| format!("Rebuilt ELF failed import: {error}"))?;
    let ir = String::from_utf8(result.ir.clone())
        .map_err(|error| format!("Rebuilt LLVM IR is not UTF-8: {error}"))?;
    let report = String::from_utf8(result.report_json.clone())
        .map_err(|error| format!("Rebuild report is not UTF-8: {error}"))?;
    let digest = format!("{:x}", Sha256::digest(&result.executable));
    if spec.binary_sha256 != digest {
        return Err("Rebuilt ELF model digest differs from produced bytes.".to_owned());
    }
    new_output_dir(output_dir)?;
    fs::write(output_dir.join("whole.ll"), result.ir)
        .map_err(|error| format!("Could not save rebuilt LLVM IR: {error}"))?;
    fs::write(output_dir.join("report.json"), result.report_json)
        .map_err(|error| format!("Could not save rebuild report: {error}"))?;
    let executable_path = output_dir.join("rebuilt");
    fs::write(&executable_path, &result.executable)
        .map_err(|error| format!("Could not save rebuilt ELF: {error}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&executable_path, fs::Permissions::from_mode(0o700))
            .map_err(|error| format!("Could not make rebuilt ELF executable: {error}"))?;
    }
    Ok((result.executable, spec, ir, report, digest))
}

fn patch_document(binary_sha256: &str, symbol: &str, replacement: &str) -> Result<Vec<u8>, String> {
    let document = PatchDocument {
        schema_version: 1,
        binary_sha256: binary_sha256.to_owned(),
        function_symbol: symbol.to_owned(),
        prototype: "u64(u64,u64)".to_owned(),
        replacement: replacement.to_owned(),
    };
    let bytes = serde_json::to_vec(&document)
        .map_err(|error| format!("Could not encode scalar patch: {error}"))?;
    parse_patch_json(&bytes)?;
    Ok(bytes)
}

fn write_new_elf(path: &Path, content: &[u8]) -> Result<(), String> {
    if !path.is_absolute() {
        return Err("ELF output path must be absolute.".to_owned());
    }
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o700);
    }
    let mut file = options
        .open(path)
        .map_err(|error| format!("Could not create new ELF file: {error}"))?;
    if let Err(error) = file.write_all(content).and_then(|()| file.sync_all()) {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(format!("Could not complete ELF output: {error}"));
    }
    Ok(())
}

fn patch_local(
    binary: &[u8],
    symbol: &str,
    replacement: &str,
    output_path: &Path,
) -> Result<(Vec<u8>, ProgramSpec, String), String> {
    let digest = format!("{:x}", Sha256::digest(binary));
    let document = patch_document(&digest, symbol, replacement)?;
    let validated = parse_patch_json(&document)?;
    let patched = patch_binary(binary, &validated)?;
    let spec = import_elf(&patched.content)
        .map_err(|error| format!("Patched ELF failed import: {error}"))?;
    if spec.binary_sha256 != patched.patched_sha256 {
        return Err("Patched ELF model digest differs from produced bytes.".to_owned());
    }
    write_new_elf(output_path, &patched.content)?;
    Ok((patched.content, spec, patched.patched_sha256))
}

async fn patch_remote(
    access: &RemoteAccess,
    symbol: &str,
    replacement: &str,
    key: &str,
) -> Result<(u64, ProgramSpec, String), String> {
    let mut client = remote_client(access).await?;
    let current = client
        .get_project(authorized(
            ProjectRequest {
                project_id: access.project_id.clone(),
                expected_revision: access.revision,
            },
            &access.token,
        ))
        .await
        .map_err(|error| format!("Could not verify current project before patch: {error}"))?
        .into_inner();
    if current.revision != access.revision || current.binary_sha256.is_empty() {
        return Err("Remote project revision changed; reopen it before patching.".to_owned());
    }
    let document = patch_document(&current.binary_sha256, symbol, replacement)?;
    let reply = client
        .apply_patch(authorized(
            PatchRequest {
                project_id: access.project_id.clone(),
                expected_revision: access.revision,
                patch_json: document,
                idempotency_key: key.to_owned(),
                trusted_fixture: true,
                assume_u64x2: true,
                assume_entry_only: true,
            },
            &access.token,
        ))
        .await
        .map_err(|error| format!("Remote scalar patch failed: {error}"))?
        .into_inner();
    if reply.project_id != access.project_id
        || Some(reply.revision) != access.revision.checked_add(1)
        || reply.binary_sha256 != reply.artifact_sha256
    {
        return Err(
            "Patch returned an unexpected project, revision, or artifact digest.".to_owned(),
        );
    }
    let artifact = client
        .get_artifact(authorized(
            ArtifactRequest {
                project_id: access.project_id.clone(),
                sha256: reply.artifact_sha256.clone(),
            },
            &access.token,
        ))
        .await
        .map_err(|error| format!("Could not retrieve patched ELF: {error}"))?
        .into_inner();
    if artifact.project_revision != reply.revision
        || artifact.sha256 != reply.binary_sha256
        || artifact.media_type != "application/x-elf"
        || format!("{:x}", Sha256::digest(&artifact.content)) != reply.binary_sha256
    {
        return Err("Patched ELF failed digest/type/revision verification.".to_owned());
    }
    let spec = import_elf(&artifact.content)
        .map_err(|error| format!("Patched ELF failed import: {error}"))?;
    if spec.binary_sha256 != reply.binary_sha256 {
        return Err("Patched ELF model digest differs from project.".to_owned());
    }
    let project = client
        .get_project(authorized(
            ProjectRequest {
                project_id: access.project_id.clone(),
                expected_revision: reply.revision,
            },
            &access.token,
        ))
        .await
        .map_err(|error| format!("Could not verify patched project: {error}"))?
        .into_inner();
    if project.revision != reply.revision || project.binary_sha256 != reply.binary_sha256 {
        return Err("Patched project state differs from patch reply.".to_owned());
    }
    Ok((reply.revision, spec, reply.binary_sha256))
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

fn attach_local_project(path: &Path, spec: &ProgramSpec) -> Result<LocalProject, String> {
    LocalProjectStore::open_default()?.open_binary(path, spec)
}

fn list_local_annotations(project: &LocalProject) -> Result<Vec<AnalystAnnotation>, String> {
    LocalProjectStore::open_default()?.list_annotations(project)
}

fn add_local_annotation(
    project: &LocalProject,
    bytes: &[u8],
    binary_sha256: &str,
    kind: AnnotationKind,
    address: Option<u64>,
    scope: &str,
    value: &str,
    key: &str,
) -> Result<(LocalProject, ProgramSpec, Vec<AnalystAnnotation>), String> {
    let mut spec =
        import_elf(bytes).map_err(|error| format!("Local ELF import failed: {error}"))?;
    if spec.binary_sha256 != binary_sha256 || project.binary_sha256 != binary_sha256 {
        return Err("Local annotation binary differs from the selected ELF".to_owned());
    }
    let mut store = LocalProjectStore::open_default()?;
    let updated = store.add_annotation(
        project,
        &spec,
        kind,
        address.map(Address),
        value,
        scope,
        key,
    )?;
    let annotations = store.list_annotations(&updated)?;
    overlay_analyst_assumptions(&mut spec, &annotations);
    Ok((updated, spec, annotations))
}

fn worker(tasks: Receiver<Task>, events: SyncSender<Event>, ctx: egui::Context) {
    let mut source = Source::None;
    let mut local_project: Option<LocalProject> = None;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("Tokio runtime initialization");
    while let Ok(task) = tasks.recv() {
        let event = match task {
            Task::LoadWorkbench => Event::WorkbenchLoaded(
                LocalProjectStore::open_default().and_then(|store| store.load_workbench_settings()),
            ),
            Task::SaveWorkbench(settings) => {
                match LocalProjectStore::open_default()
                    .and_then(|mut store| store.save_workbench_settings(&settings))
                {
                    Ok(()) => Event::WorkbenchSaved(settings),
                    Err(error) => Event::Failed(format!("Could not save workbench: {error}")),
                }
            }
            Task::Open(path) => match bounded_read(&path).and_then(|bytes| {
                let spec = import_elf(&bytes).map_err(|e| format!("ELF import failed: {e}"))?;
                let project = attach_local_project(&path, &spec)?;
                Ok((bytes, spec, project))
            }) {
                Ok((bytes, spec, project)) => {
                    source = Source::Local(bytes);
                    let revision = project.revision;
                    local_project = Some(project);
                    Event::Imported {
                        source: path.display().to_string(),
                        remote: false,
                        revision: Some(revision),
                        named_pass_transform: false,
                        whole_rebuild: false,
                        source_offer: None,
                        spec,
                    }
                }
                Err(error) => Event::Failed(error),
            },
            Task::OpenGhidraGraph(path) => match fs::read_to_string(&path)
                .map_err(|error| format!("Could not read Ghidra graph: {error}"))
                .and_then(|text| {
                    serde_json::from_str::<GhidraGraph>(&text)
                        .map_err(|error| format!("Invalid Ghidra graph JSON: {error}"))
                })
            {
                Ok(graph) => Event::GhidraGraphLoaded(Ok(graph)),
                Err(error) => Event::GhidraGraphLoaded(Err(error)),
            },
            Task::OpenRemote {
                endpoint,
                token_file,
                project_id,
            } => match runtime.block_on(open_remote(endpoint, token_file, project_id)) {
                Ok((access, spec)) => {
                    local_project = None;
                    let label = format!(
                        "{} · {} · revision {}",
                        access.endpoint, access.project_id, access.revision
                    );
                    let source_offer = access.source_offer.clone();
                    let revision = access.revision;
                    let named_pass_transform = access.named_pass_transform;
                    let whole_rebuild = access.whole_rebuild;
                    source = Source::Remote(access);
                    Event::Imported {
                        source: label,
                        remote: true,
                        revision: Some(revision),
                        named_pass_transform,
                        whole_rebuild,
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
                    local_project = None;
                    let label = format!(
                        "{} · {} · revision {}",
                        access.endpoint, access.project_id, access.revision
                    );
                    let source_offer = access.source_offer.clone();
                    let revision = access.revision;
                    let named_pass_transform = access.named_pass_transform;
                    let whole_rebuild = access.whole_rebuild;
                    source = Source::Remote(access);
                    Event::Imported {
                        source: label,
                        remote: true,
                        revision: Some(revision),
                        named_pass_transform,
                        whole_rebuild,
                        source_offer: Some(source_offer),
                        spec,
                    }
                }
                Err(error) => Event::Failed(error),
            },
            Task::Select(symbol) => match &source {
                Source::Local(bytes) => {
                    let ir = lift_symbol(bytes, &symbol).map_err(|e| e.to_string());
                    let c = ir
                        .as_ref()
                        .map_err(Clone::clone)
                        .and_then(|ir| emit_structured_c(ir));
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
            Task::Disassemble => Event::Disassembled(match &source {
                Source::Local(bytes) => disassemble_elf(bytes).map_err(|error| error.to_string()),
                Source::Remote(_) => Err("Whole-ELF disassembly is currently local-only.".to_owned()),
                Source::None => Err("Open a local ELF before disassembling it.".to_owned()),
            }),
            Task::Analyze => Event::Analyzed(match &source {
                Source::Local(bytes) => analyze_elf(bytes).map_err(|error| error.to_string()),
                Source::Remote(access) => runtime.block_on(analyze_remote(access)),
                Source::None => Err("Open a local ELF or remote project first.".to_owned()),
            }),
            Task::RefreshAnnotations { binary_sha256 } => match &source {
                Source::Local(_) => local_project
                    .as_ref()
                    .ok_or("Open a local ELF to load annotations".to_owned())
                    .and_then(|project| {
                        if project.binary_sha256 != binary_sha256 {
                            return Err(
                                "Local annotation digest differs from the open ELF".to_owned()
                            );
                        }
                        list_local_annotations(project)
                    })
                    .map(|annotations| Event::AnnotationsLoaded {
                        binary_sha256,
                        annotations,
                    })
                    .unwrap_or_else(Event::Failed),
                Source::Remote(access) => runtime
                    .block_on(list_remote_annotations(access, &binary_sha256))
                    .map(|annotations| Event::AnnotationsLoaded {
                        binary_sha256,
                        annotations,
                    })
                    .unwrap_or_else(Event::Failed),
                Source::None => Event::Failed(
                    "Open a local ELF or remote project to load annotations.".to_owned(),
                ),
            },
            Task::AddAnnotation {
                binary_sha256,
                kind,
                address,
                scope,
                value,
                key,
            } => match &mut source {
                Source::Local(bytes) => {
                    let result = local_project
                        .as_ref()
                        .ok_or("Open a local ELF before adding an annotation".to_owned())
                        .and_then(|project| {
                            add_local_annotation(
                                project,
                                bytes,
                                &binary_sha256,
                                kind,
                                address,
                                &scope,
                                &value,
                                &key,
                            )
                        });
                    match result {
                        Ok((updated, spec, annotations)) => {
                            let source_label = format!(
                                "{} · local revision {}",
                                updated.path.display(),
                                updated.revision
                            );
                            let revision = updated.revision;
                            local_project = Some(updated);
                            Event::AnnotationAdded {
                                source: source_label,
                                revision,
                                spec,
                                annotations,
                            }
                        }
                        Err(error) => Event::Failed(format!(
                            "{error} Annotation key {key}; reopen the local ELF if its bytes changed."
                        )),
                    }
                }
                Source::Remote(access) => match runtime.block_on(add_remote_annotation(
                    access,
                    &binary_sha256,
                    kind,
                    address,
                    &scope,
                    &value,
                    &key,
                )) {
                    Ok((revision, spec, annotations)) => {
                        access.revision = revision;
                        Event::AnnotationAdded {
                            source: format!(
                                "{} · {} · revision {}",
                                access.endpoint, access.project_id, revision
                            ),
                            revision,
                            spec,
                            annotations,
                        }
                    }
                    Err(error) => {
                        source = Source::None;
                        Event::MutationUncertain(format!(
                            "{error} Mutation key {key}. Reopen the remote project before another mutation; the request may have committed."
                        ))
                    }
                },
                Source::None => Event::Failed(
                    "Open a local ELF or remote project to add an annotation.".to_owned(),
                ),
            },
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
            Task::TransformRemote {
                symbol,
                passes,
                key,
            } => match &mut source {
                Source::Remote(access) => {
                    match runtime.block_on(transform_remote(access, &symbol, &passes, &key)) {
                        Ok((revision, before, after, report, changed)) => {
                            access.revision = revision;
                            let source = format!(
                                "{} · {} · revision {}",
                                access.endpoint, access.project_id, revision
                            );
                            let c = emit_structured_c(&after);
                            Event::Transformed {
                                source,
                                revision,
                                before,
                                after,
                                report,
                                changed,
                                c,
                            }
                        }
                        Err(error) => {
                            source = Source::None;
                            Event::MutationUncertain(format!(
                                "{error} Mutation key {key}. Reopen the remote project before another mutation; the request may have committed."
                            ))
                        }
                    }
                }
                _ => Event::Failed("Open a remote project before running passes.".to_owned()),
            },
            Task::TransformLocal {
                symbol,
                passes,
                output_dir,
            } => match &source {
                Source::Local(bytes) => match transform_local(bytes, &symbol, &passes, &output_dir)
                {
                    Ok((before, after, report)) => {
                            let c = emit_structured_c(&after);
                        Event::LocalTransformed {
                            before,
                            after,
                            report,
                            c,
                            output_dir,
                        }
                    }
                    Err(error) => Event::Failed(error),
                },
                _ => Event::Failed("Open a local ELF before running local passes.".to_owned()),
            },
            Task::RebuildRemote { key } => match &mut source {
                Source::Remote(access) => match runtime.block_on(rebuild_remote(access, &key)) {
                    Ok((revision, spec, ir, report, binary_sha256)) => {
                        access.revision = revision;
                        let source = format!(
                            "{} · {} · revision {}",
                            access.endpoint, access.project_id, revision
                        );
                        Event::Rebuilt {
                            source,
                            revision,
                            spec,
                            ir,
                            report,
                            binary_sha256,
                        }
                    }
                    Err(error) => {
                        source = Source::None;
                        Event::MutationUncertain(format!(
                            "{error} Mutation key {key}. Reopen the remote project before another mutation; the request may have committed."
                        ))
                    }
                },
                _ => Event::Failed("Open a remote project before rebuilding.".to_owned()),
            },
            Task::RebuildLocal { output_dir } => match &source {
                Source::Local(bytes) => match rebuild_local(bytes, &output_dir) {
                    Ok((rebuilt, spec, ir, report, binary_sha256)) => {
                        match attach_local_project(&output_dir.join("rebuilt"), &spec) {
                            Ok(project) => {
                                let revision = project.revision;
                                local_project = Some(project);
                                source = Source::Local(rebuilt);
                                Event::LocalRebuilt {
                                    spec,
                                    revision,
                                    ir,
                                    report,
                                    binary_sha256,
                                    output_dir,
                                }
                            }
                            Err(error) => Event::Failed(format!(
                                "Rebuilt ELF was written, but its local project could not open: {error}"
                            )),
                        }
                    }
                    Err(error) => Event::Failed(error),
                },
                _ => Event::Failed("Open a local ELF before rebuilding.".to_owned()),
            },
            Task::PatchLocal {
                symbol,
                replacement,
                output_path,
            } => match &source {
                Source::Local(bytes) => {
                    match patch_local(bytes, &symbol, &replacement, &output_path) {
                        Ok((patched, spec, binary_sha256)) => {
                            match attach_local_project(&output_path, &spec) {
                                Ok(project) => {
                                    let revision = project.revision;
                                    local_project = Some(project);
                                    source = Source::Local(patched);
                                    Event::LocalPatched {
                                        spec,
                                        revision,
                                        binary_sha256,
                                        output_path,
                                    }
                                }
                                Err(error) => Event::Failed(format!(
                                    "Patched ELF was written, but its local project could not open: {error}"
                                )),
                            }
                        }
                        Err(error) => Event::Failed(error),
                    }
                }
                _ => Event::Failed("Open a local ELF before patching.".to_owned()),
            },
            Task::PatchRemote {
                symbol,
                replacement,
                key,
            } => match &mut source {
                Source::Remote(access) => {
                    match runtime.block_on(patch_remote(access, &symbol, &replacement, &key)) {
                        Ok((revision, spec, binary_sha256)) => {
                            access.revision = revision;
                            let source = format!(
                                "{} · {} · revision {}",
                                access.endpoint, access.project_id, revision
                            );
                            Event::RemotePatched {
                                source,
                                revision,
                                spec,
                                binary_sha256,
                            }
                        }
                        Err(error) => {
                            source = Source::None;
                            Event::MutationUncertain(format!(
                                "{error} Mutation key {key}. Reopen the remote project before another mutation; the request may have committed."
                            ))
                        }
                    }
                }
                _ => Event::Failed("Open a remote project before patching.".to_owned()),
            },
            Task::ExportRebuiltRemote { digest, path } => match &source {
                Source::Remote(access) => runtime
                    .block_on(export_rebuilt_remote(access, &digest, &path))
                    .map(|()| Event::ArtifactExported { path, digest })
                    .unwrap_or_else(Event::Failed),
                _ => Event::Failed(
                    "Open the owning remote project to export its rebuilt ELF.".to_owned(),
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
    Graph,
    Cfg,
    Llvm,
    Passes,
    C,
    Analysis,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum GraphMode {
    Function,
    Program,
    Ghidra,
}

struct AnalystApp {
    tasks: SyncSender<Task>,
    events: Receiver<Event>,
    path_input: String,
    ghidra_graph_path: String,
    workbench: WorkbenchSettings,
    workbench_loaded: bool,
    startup_open_local: Option<PathBuf>,
    current_local_path: Option<PathBuf>,
    remote_endpoint: String,
    remote_token_file: String,
    remote_project_id: String,
    remote_project_name: String,
    remote_upload_path: String,
    pass_pipeline: String,
    trusted_fixture: bool,
    transform_before: Option<String>,
    transform_after: Option<String>,
    transform_report: Option<String>,
    rebuild_report: Option<String>,
    rebuilt_binary_sha256: Option<String>,
    rebuild_output_path: String,
    local_pass_output_dir: String,
    local_rebuild_output_dir: String,
    rebuilt_exported_path: Option<PathBuf>,
    patch_replacement: String,
    patch_output_path: String,
    patch_digest: Option<String>,
    patch_exported_path: Option<PathBuf>,
    entry_only_assertion: bool,
    search: String,
    initial_symbol: Option<String>,
    source_label: Option<String>,
    source_offer: Option<String>,
    remote: bool,
    project_revision: Option<u64>,
    named_pass_transform: bool,
    whole_rebuild: bool,
    spec: Option<ProgramSpec>,
    ghidra_graph: Option<GhidraGraph>,
    symbol: Option<String>,
    cfg: Option<FunctionCfg>,
    ir: Option<String>,
    c: Option<String>,
    c_error: Option<String>,
    analysis: Option<AnalysisReport>,
    disassembly_report: Option<DisassemblyReport>,
    console_json: bool,
    annotations: Vec<AnalystAnnotation>,
    annotation_kind: AnnotationKind,
    annotation_value: String,
    annotation_scope: String,
    annotation_program_wide: bool,
    job: Option<JobReply>,
    job_symbol: Option<String>,
    last_job_poll: std::time::Instant,
    selected_address: Option<u64>,
    tab: Tab,
    graph_mode: GraphMode,
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
            ghidra_graph_path: String::new(),
            workbench: WorkbenchSettings::default(),
            workbench_loaded: false,
            startup_open_local: None,
            current_local_path: None,
            remote_endpoint: "http://127.0.0.1:50051".to_owned(),
            remote_token_file: String::new(),
            remote_project_id: String::new(),
            remote_project_name: String::new(),
            remote_upload_path: String::new(),
            pass_pipeline: "instcombine,sccp,simplifycfg,dce".to_owned(),
            trusted_fixture: false,
            transform_before: None,
            transform_after: None,
            transform_report: None,
            rebuild_report: None,
            rebuilt_binary_sha256: None,
            rebuild_output_path: String::new(),
            local_pass_output_dir: String::new(),
            local_rebuild_output_dir: String::new(),
            rebuilt_exported_path: None,
            patch_replacement: "return arg0 - arg1;".to_owned(),
            patch_output_path: String::new(),
            patch_digest: None,
            patch_exported_path: None,
            entry_only_assertion: false,
            search: String::new(),
            initial_symbol: None,
            source_label: None,
            source_offer: None,
            remote: false,
            project_revision: None,
            named_pass_transform: false,
            whole_rebuild: false,
            spec: None,
            ghidra_graph: None,
            symbol: None,
            cfg: None,
            ir: None,
            c: None,
            c_error: None,
            analysis: None,
            disassembly_report: None,
            console_json: false,
            annotations: Vec::new(),
            annotation_kind: AnnotationKind::Comment,
            annotation_value: String::new(),
            annotation_scope: "analyst review of current binary".to_owned(),
            annotation_program_wide: false,
            job: None,
            job_symbol: None,
            last_job_poll: std::time::Instant::now(),
            selected_address: None,
            tab: Tab::Bytes,
            graph_mode: GraphMode::Function,
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
                Event::WorkbenchLoaded(result) => {
                    self.workbench_loaded = true;
                    match result {
                        Ok(settings) => {
                            self.workbench = settings;
                            self.status = "Saved workbench loaded".to_owned();
                        }
                        Err(error) => {
                            self.failure = Some(format!(
                                "Saved workbench unavailable; using default panes: {error}"
                            ));
                            self.history.push(format!(
                                "Saved workbench unavailable; using default panes: {error}"
                            ));
                            self.status = "Workbench defaults active".to_owned();
                        }
                    }
                    if let Some(path) = self.startup_open_local.take() {
                        self.enqueue(Task::Open(path), "Importing local ELF…");
                    }
                }
                Event::WorkbenchSaved(settings) => {
                    self.workbench = settings;
                    self.status = "Workbench layout and recent local path saved".to_owned();
                    self.history.push(self.status.clone());
                    self.failure = None;
                }
                Event::Imported {
                    source,
                    remote,
                    revision,
                    named_pass_transform,
                    whole_rebuild,
                    source_offer,
                    spec,
                } => {
                    let binary_sha256 = spec.binary_sha256.clone();
                    self.status = format!("Opened {} functions", spec.functions.len());
                    self.history.push(format!("Opened {source}"));
                    self.current_local_path = if remote {
                        None
                    } else {
                        Some(PathBuf::from(&source))
                    };
                    self.source_label = Some(source);
                    self.source_offer = source_offer;
                    self.remote = remote;
                    self.project_revision = revision;
                    self.named_pass_transform = named_pass_transform;
                    self.whole_rebuild = whole_rebuild;
                    self.spec = Some(spec);
                    self.symbol = None;
                    self.cfg = None;
                    self.ir = None;
                    self.c = None;
                    self.c_error = None;
                    self.analysis = None;
                    self.disassembly_report = None;
                    self.console_json = false;
                    self.annotations.clear();
                    self.job = None;
                    self.job_symbol = None;
                    self.selected_address = None;
                    self.transform_before = None;
                    self.transform_after = None;
                    self.transform_report = None;
                    self.rebuild_report = None;
                    self.rebuilt_binary_sha256 = None;
                    self.rebuilt_exported_path = None;
                    self.patch_digest = None;
                    self.patch_exported_path = None;
                    self.rebuild_output_path.clear();
                    self.trusted_fixture = false;
                    self.entry_only_assertion = false;
                    self.failure = None;
                    if let Some(symbol) = self.initial_symbol.take() {
                        self.select(symbol);
                    }
                    self.enqueue(
                        Task::RefreshAnnotations { binary_sha256 },
                        "Loading revisioned analyst annotations…",
                    );
                }
                Event::GhidraGraphLoaded(result) => match result {
                    Ok(graph) => {
                        if graph.schema_version != 1 || graph.source != "ghidra" {
                            self.failure = Some("Unsupported Ghidra graph schema or source".to_owned());
                        } else {
                            self.status = format!("Loaded Ghidra graph for {}", graph.program);
                            self.history.push(self.status.clone());
                            self.ghidra_graph = Some(graph);
                            self.graph_mode = GraphMode::Ghidra;
                            self.tab = Tab::Graph;
                            self.failure = None;
                        }
                    }
                    Err(error) => {
                        self.status = "Ghidra graph load failed".to_owned();
                        self.history.push(error.clone());
                        self.failure = Some(error);
                    }
                },
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
                Event::Disassembled(result) => match result {
                    Ok(report) => {
                        let digest_matches = self
                            .spec
                            .as_ref()
                            .map(|spec| spec.binary_sha256 == report.binary_sha256)
                            .unwrap_or(false);
                        if !digest_matches {
                            self.failure = Some(
                                "Disassembly binary digest does not match the open ELF."
                                    .to_owned(),
                            );
                            self.status = "Disassembly discarded".to_owned();
                        } else {
                            self.status = format!(
                                "Disassembled {} instructions across {} executable sections",
                                report.instructions.len(),
                                report.sections.len()
                            );
                            self.history.push(self.status.clone());
                            self.disassembly_report = Some(report);
                            self.console_json = false;
                            self.tab = Tab::Bytes;
                            self.failure = None;
                        }
                    }
                    Err(error) => {
                        self.failure = Some(error.clone());
                        self.status = "Whole-ELF disassembly failed".to_owned();
                        self.history.push(error);
                    }
                },
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
                Event::AnnotationsLoaded {
                    binary_sha256,
                    annotations,
                } => {
                    if self.spec.as_ref().map(|spec| spec.binary_sha256.as_str())
                        == Some(binary_sha256.as_str())
                    {
                        self.status = format!("Loaded {} analyst annotations", annotations.len());
                        if let Some(spec) = &mut self.spec {
                            spec.assumptions.retain(|assumption| {
                                assumption.provenance.source != FactSource::AnalystAssertion
                            });
                            overlay_analyst_assumptions(spec, &annotations);
                        }
                        self.annotations = annotations;
                        self.failure = None;
                    }
                }
                Event::AnnotationAdded {
                    source,
                    revision,
                    spec,
                    annotations,
                } => {
                    self.source_label = Some(source);
                    self.project_revision = Some(revision);
                    self.spec = Some(spec);
                    self.annotations = annotations;
                    self.analysis = None;
                    self.cfg = None;
                    self.ir = None;
                    self.c = None;
                    self.c_error = None;
                    self.job = None;
                    self.job_symbol = None;
                    self.transform_before = None;
                    self.transform_after = None;
                    self.transform_report = None;
                    self.trusted_fixture = false;
                    self.entry_only_assertion = false;
                    self.annotation_value.clear();
                    self.status = format!("Saved analyst annotation in revision {revision}");
                    self.history.push(self.status.clone());
                    self.failure = None;
                }
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
                Event::Transformed {
                    source,
                    revision,
                    before,
                    after,
                    report,
                    changed,
                    c,
                } => {
                    self.remote = true;
                    self.source_label = Some(source);
                    self.project_revision = Some(revision);
                    self.trusted_fixture = false;
                    self.entry_only_assertion = false;
                    self.transform_before = Some(before);
                    self.transform_after = Some(after.clone());
                    self.transform_report = Some(report);
                    self.ir = Some(after);
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
                    self.tab = Tab::Passes;
                    self.status = format!(
                        "Pass pipeline saved revision {revision} · IR text {}",
                        if changed { "changed" } else { "unchanged" }
                    );
                    self.history.push(self.status.clone());
                    self.failure = None;
                }
                Event::LocalTransformed {
                    before,
                    after,
                    report,
                    c,
                    output_dir,
                } => {
                    self.transform_before = Some(before);
                    self.transform_after = Some(after.clone());
                    self.transform_report = Some(report);
                    self.ir = Some(after);
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
                    self.trusted_fixture = false;
                    self.entry_only_assertion = false;
                    self.tab = Tab::Passes;
                    self.status =
                        format!("Local pass experiment saved to {}", output_dir.display());
                    self.history.push(self.status.clone());
                    self.failure = None;
                }
                Event::Rebuilt {
                    source,
                    revision,
                    spec,
                    ir,
                    report,
                    binary_sha256,
                } => {
                    self.spec = Some(spec);
                    self.remote = true;
                    self.current_local_path = None;
                    self.source_label = Some(source);
                    self.project_revision = Some(revision);
                    self.trusted_fixture = false;
                    self.entry_only_assertion = false;
                    self.symbol = None;
                    self.cfg = None;
                    self.ir = Some(ir);
                    self.c = None;
                    self.c_error = None;
                    self.analysis = None;
                    self.annotations.clear();
                    self.job = None;
                    self.job_symbol = None;
                    self.selected_address = None;
                    self.transform_before = None;
                    self.transform_after = None;
                    self.transform_report = None;
                    self.rebuild_report = Some(report);
                    self.rebuilt_binary_sha256 = Some(binary_sha256.clone());
                    self.rebuild_output_path.clear();
                    self.rebuilt_exported_path = None;
                    self.patch_digest = None;
                    self.patch_exported_path = None;
                    self.status = format!(
                        "Rebuilt executable saved as revision {revision} · SHA-256 {}…",
                        &binary_sha256[..12]
                    );
                    self.history.push(self.status.clone());
                    self.tab = Tab::Llvm;
                    self.failure = None;
                    self.enqueue(
                        Task::RefreshAnnotations { binary_sha256 },
                        "Loading rebuilt remote project annotations…",
                    );
                }
                Event::LocalRebuilt {
                    spec,
                    revision,
                    ir,
                    report,
                    binary_sha256,
                    output_dir,
                } => {
                    self.current_local_path = Some(output_dir.join("rebuilt"));
                    self.source_label = Some(output_dir.join("rebuilt").display().to_string());
                    self.source_offer = None;
                    self.spec = Some(spec);
                    self.remote = false;
                    self.project_revision = Some(revision);
                    self.symbol = None;
                    self.cfg = None;
                    self.ir = Some(ir);
                    self.c = None;
                    self.c_error = None;
                    self.analysis = None;
                    self.annotations.clear();
                    self.job = None;
                    self.job_symbol = None;
                    self.selected_address = None;
                    self.transform_before = None;
                    self.transform_after = None;
                    self.transform_report = None;
                    self.rebuild_report = Some(report);
                    self.rebuilt_binary_sha256 = Some(binary_sha256.clone());
                    self.rebuilt_exported_path = Some(output_dir.join("rebuilt"));
                    self.patch_digest = None;
                    self.patch_exported_path = None;
                    self.trusted_fixture = false;
                    self.entry_only_assertion = false;
                    self.status = format!(
                        "Local rebuilt executable saved · SHA-256 {}…",
                        &binary_sha256[..12]
                    );
                    self.history.push(self.status.clone());
                    self.tab = Tab::Llvm;
                    self.failure = None;
                    self.enqueue(
                        Task::RefreshAnnotations { binary_sha256 },
                        "Loading rebuilt local project annotations…",
                    );
                }
                Event::LocalPatched {
                    spec,
                    revision,
                    binary_sha256,
                    output_path,
                } => {
                    self.current_local_path = Some(output_path.clone());
                    self.source_label = Some(output_path.display().to_string());
                    self.source_offer = None;
                    self.spec = Some(spec);
                    self.remote = false;
                    self.project_revision = Some(revision);
                    self.symbol = None;
                    self.cfg = None;
                    self.ir = None;
                    self.c = None;
                    self.c_error = None;
                    self.analysis = None;
                    self.annotations.clear();
                    self.transform_before = None;
                    self.transform_after = None;
                    self.transform_report = None;
                    self.rebuild_report = None;
                    self.rebuilt_binary_sha256 = None;
                    self.rebuilt_exported_path = None;
                    self.patch_digest = Some(binary_sha256.clone());
                    self.patch_exported_path = Some(output_path.clone());
                    self.trusted_fixture = false;
                    self.entry_only_assertion = false;
                    self.status = format!(
                        "Patched local ELF saved · SHA-256 {}…",
                        &binary_sha256[..12]
                    );
                    self.history.push(self.status.clone());
                    self.failure = None;
                    self.enqueue(
                        Task::RefreshAnnotations { binary_sha256 },
                        "Loading patched local project annotations…",
                    );
                }
                Event::RemotePatched {
                    source,
                    revision,
                    spec,
                    binary_sha256,
                } => {
                    self.source_label = Some(source);
                    self.spec = Some(spec);
                    self.remote = true;
                    self.current_local_path = None;
                    self.project_revision = Some(revision);
                    self.symbol = None;
                    self.cfg = None;
                    self.ir = None;
                    self.c = None;
                    self.c_error = None;
                    self.analysis = None;
                    self.annotations.clear();
                    self.transform_before = None;
                    self.transform_after = None;
                    self.transform_report = None;
                    self.rebuild_report = None;
                    self.rebuilt_binary_sha256 = None;
                    self.rebuilt_exported_path = None;
                    self.patch_digest = Some(binary_sha256.clone());
                    self.patch_exported_path = None;
                    self.trusted_fixture = false;
                    self.entry_only_assertion = false;
                    self.status = format!(
                        "Patched remote ELF saved as revision {revision} · SHA-256 {}…",
                        &binary_sha256[..12]
                    );
                    self.history.push(self.status.clone());
                    self.failure = None;
                    self.enqueue(
                        Task::RefreshAnnotations { binary_sha256 },
                        "Loading patched remote project annotations…",
                    );
                }
                Event::ArtifactExported { path, digest } => {
                    let label = if self.patch_digest.as_deref() == Some(digest.as_str()) {
                        self.patch_exported_path = Some(path.clone());
                        "patched"
                    } else if self.rebuilt_binary_sha256.as_deref() == Some(digest.as_str()) {
                        self.rebuilt_exported_path = Some(path.clone());
                        "rebuilt"
                    } else {
                        "ELF"
                    };
                    self.status = format!("Verified {label} ELF exported to {}", path.display());
                    self.history.push(self.status.clone());
                    self.failure = None;
                }
                Event::MutationUncertain(error) => {
                    self.remote = false;
                    self.project_revision = None;
                    self.spec = None;
                    self.symbol = None;
                    self.cfg = None;
                    self.ir = None;
                    self.c = None;
                    self.analysis = None;
                    self.annotations.clear();
                    self.rebuilt_binary_sha256 = None;
                    self.rebuilt_exported_path = None;
                    self.patch_digest = None;
                    self.patch_exported_path = None;
                    self.trusted_fixture = false;
                    self.entry_only_assertion = false;
                    self.status = "Remote project requires reopening".to_owned();
                    self.failure = Some(error.clone());
                    self.history.push(error);
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
        if let Some(revision) = self.project_revision {
            ui.label(
                RichText::new(format!(
                    "{} REVISION  ·  {revision}",
                    if self.remote { "REMOTE" } else { "LOCAL" }
                ))
                .size(10.0)
                .strong()
                .color(ACCENT),
            );
        }
        ui.label(
            RichText::new(if self.remote {
                "Remote project is open. Uploading another ELF always requires the explicit transfer action."
            } else {
                "Open a local ELF to inspect symbol facts. No binary is uploaded."
            })
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
        let disassemble = ui.add_enabled(
            !self.busy && self.spec.is_some() && !self.remote,
            egui::Button::new("Disassemble ELF"),
        );
        if disassemble.clicked() {
            self.enqueue(Task::Disassemble, "Disassembling executable ELF sections…");
        }
        disassemble.on_disabled_hover_text(
            "Open a local ELF first. Whole-ELF disassembly is currently local-only.",
        );
        ui.separator();
        egui::CollapsingHeader::new("Ghidra bridge")
            .id_salt("ghidra_bridge")
            .show(ui, |ui| {
                ui.label(
                    RichText::new("Load HydIRExport.java JSON as external evidence; native HydIR facts stay separate.")
                        .size(11.0)
                        .color(MUTED),
                );
                ui.add(
                    egui::TextEdit::singleline(&mut self.ghidra_graph_path)
                        .hint_text("/absolute/path/to/ghidra-graph.json")
                        .desired_width(f32::INFINITY),
                );
                let load = ui.add_enabled(
                    !self.busy && !self.ghidra_graph_path.trim().is_empty(),
                    egui::Button::new("Load Ghidra graph"),
                );
                if load.clicked() {
                    self.enqueue(
                        Task::OpenGhidraGraph(PathBuf::from(self.ghidra_graph_path.trim())),
                        "Loading Ghidra graph…",
                    );
                }
                if let Some(graph) = &self.ghidra_graph {
                    ui.label(
                        RichText::new(format!(
                            "Loaded: {} functions / {} call edges / {}",
                            graph.functions.len(), graph.call_edges.len(), graph.program
                        ))
                        .size(11.0)
                        .color(ACCENT),
                    );
                }
            });
        egui::CollapsingHeader::new("Saved workbench · on this device")
            .id_salt("saved_workbench")
            .default_open(true)
            .show(ui, |ui| {
                ui.label(
                    RichText::new(
                        "Save the pane widths and recent local ELF path in the private local database. Credentials and binary bytes are never saved here.",
                    )
                    .size(11.0)
                    .color(MUTED),
                );
                if let Some(path) = &self.workbench.recent_local_path {
                    ui.label(RichText::new(path.display().to_string()).monospace().size(11.0));
                    if ui
                        .add_enabled(!self.busy, egui::Button::new("Reopen saved local ELF"))
                        .clicked()
                    {
                        let path = path.clone();
                        self.path_input = path.display().to_string();
                        self.enqueue(Task::Open(path), "Reopening saved local ELF…");
                    }
                } else {
                    ui.label(RichText::new("No local ELF saved yet").size(11.0).color(MUTED));
                }
                if ui
                    .add_enabled(!self.busy, egui::Button::new("Save workbench layout"))
                    .clicked()
                {
                    let mut settings = self.workbench.clone();
                    if let Some(path) = &self.current_local_path {
                        settings.recent_local_path = Some(path.clone());
                    }
                    self.enqueue(Task::SaveWorkbench(settings), "Saving workbench layout…");
                }
            });
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
        egui::CollapsingHeader::new("Analyst annotations · unverified")
            .default_open(false)
            .show(ui, |ui| {
                ui.label(
                    RichText::new(
                        "Names, comments, and assumptions are analyst assertions, not recovered ELF facts. Saving creates a new project revision; a changed binary digest will not reuse them.",
                    )
                    .size(11.0)
                    .color(MUTED),
                );
                field(
                    ui,
                    "CURRENT BINARY LEDGER",
                    &format!("{} facts", self.annotations.len()),
                );
                egui::ScrollArea::vertical()
                    .id_salt("analyst_annotations")
                    .max_height(160.0)
                    .show_rows(ui, 38.0, self.annotations.len(), |ui, range| {
                        for index in range {
                            let annotation = &self.annotations[index];
                            let kind = match annotation.kind {
                                AnnotationKind::Name => "NAME",
                                AnnotationKind::Comment => "COMMENT",
                                AnnotationKind::Assumption => "ASSUMPTION",
                            };
                            let address = annotation.address.map_or_else(
                                || "program".to_owned(),
                                |address| format!("0x{:016x}", address.0),
                            );
                            let preview: String = annotation.value.chars().take(80).collect();
                            ui.label(
                                RichText::new(format!(
                                    "{kind} · {address} · r{}",
                                    annotation.created_revision
                                ))
                                .size(10.0)
                                .color(ACCENT),
                            );
                            ui.label(RichText::new(preview).size(11.0).color(TEXT))
                                .on_hover_text(format!(
                                    "{}\nScope: {}\nProvenance: analyst assertion",
                                    annotation.value, annotation.scope
                                ));
                        }
                    });
                ui.label(
                    RichText::new(if self.remote {
                        "REMOTE LEDGER · owner-scoped · authenticated"
                    } else {
                        "LOCAL LEDGER · private SQLite · no upload"
                    })
                    .size(10.0)
                    .color(MUTED),
                );
                egui::ComboBox::from_id_salt("annotation_kind")
                    .selected_text(match self.annotation_kind {
                        AnnotationKind::Name => "Name",
                        AnnotationKind::Comment => "Comment",
                        AnnotationKind::Assumption => "Assumption",
                    })
                    .show_ui(ui, |ui| {
                        ui.selectable_value(&mut self.annotation_kind, AnnotationKind::Name, "Name");
                        ui.selectable_value(&mut self.annotation_kind, AnnotationKind::Comment, "Comment");
                        ui.selectable_value(&mut self.annotation_kind, AnnotationKind::Assumption, "Assumption");
                    });
                ui.checkbox(&mut self.annotation_program_wide, "Program-wide (no address)");
                let address = if self.annotation_program_wide {
                    None
                } else {
                    self.selected_address
                        .or_else(|| self.selected_function().map(|function| function.address.0))
                };
                field(
                    ui,
                    "ADDRESS",
                    &address.map_or_else(|| "program-wide".to_owned(), |value| format!("0x{value:016x}")),
                );
                ui.label(RichText::new("SCOPE").size(10.0).color(MUTED));
                ui.add(
                    egui::TextEdit::singleline(&mut self.annotation_scope)
                        .hint_text("Where this assertion applies"),
                );
                ui.label(RichText::new("VALUE").size(10.0).color(MUTED));
                ui.add(
                    egui::TextEdit::multiline(&mut self.annotation_value)
                        .desired_rows(2)
                        .hint_text("Analyst-authored name, comment, or assumption"),
                );
                let can_save = self.spec.is_some()
                    && !self.busy
                    && (address.is_some() || self.annotation_program_wide)
                    && (self.annotation_kind != AnnotationKind::Name || address.is_some())
                    && !self.annotation_scope.trim().is_empty()
                    && !self.annotation_value.trim().is_empty();
                let save = ui.add_enabled(can_save, egui::Button::new("Save analyst annotation"));
                if save.clicked()
                    && let Some(spec) = &self.spec
                {
                    self.enqueue(
                        Task::AddAnnotation {
                            binary_sha256: spec.binary_sha256.clone(),
                            kind: self.annotation_kind,
                            address,
                            scope: self.annotation_scope.trim().to_owned(),
                            value: self.annotation_value.trim().to_owned(),
                            key: uuid::Uuid::new_v4().to_string(),
                        },
                        "Saving analyst annotation as an immutable revision…",
                    );
                }
                save.on_disabled_hover_text(
                    "Requires an open remote project, a scope and value, and a selected address unless program-wide is chosen. Names always require an address.",
                );
            });
        ui.separator();
        egui::CollapsingHeader::new("Build & patch · trusted fixtures")
            .default_open(false)
            .show(ui, |ui| {
        ui.checkbox(
            &mut self.trusted_fixture,
            "Trusted fixture; I authorize compiler processing",
        );
        ui.label(RichText::new("Only the documented static freestanding Linux x86-64 subset is rebuildable. Rebuilding never executes or behaviorally validates the binary.").size(11.0).color(MUTED));
        if self.remote {
            let rebuild = ui.add_enabled(
                self.whole_rebuild && self.trusted_fixture && !self.busy,
                egui::Button::new("Rebuild whole executable remotely"),
            );
            if rebuild.clicked() {
                self.enqueue(
                    Task::RebuildRemote {
                        key: uuid::Uuid::new_v4().to_string(),
                    },
                    "Rebuilding trusted executable in bounded worker…",
                );
            }
            rebuild.on_disabled_hover_text(
                "Service must advertise rebuild; assert a trusted fixture first.",
            );
        } else {
            ui.label(
                RichText::new("LOCAL OUTPUT DIRECTORY · NEW DIRECTORY ONLY")
                    .size(10.0)
                    .color(MUTED),
            );
            ui.add(
                egui::TextEdit::singleline(&mut self.local_rebuild_output_dir)
                    .hint_text("/absolute/path/to/new-rebuild"),
            );
            let local_capable = cfg!(all(target_os = "linux", target_arch = "x86_64"));
            let rebuild = ui.add_enabled(
                self.spec.is_some()
                    && local_capable
                    && self.trusted_fixture
                    && !self.busy
                    && !self.local_rebuild_output_dir.trim().is_empty(),
                egui::Button::new("Rebuild local whole executable"),
            );
            if rebuild.clicked() {
                self.enqueue(
                    Task::RebuildLocal {
                        output_dir: PathBuf::from(self.local_rebuild_output_dir.trim()),
                    },
                    "Rebuilding trusted local executable…",
                );
            }
            rebuild.on_disabled_hover_text("Requires an open local ELF, Linux x86-64 with pinned Clang/LLVM 14.0.6, a new absolute output directory, and the trusted-fixture assertion.");
        }
        if let Some(digest) = &self.rebuilt_binary_sha256 {
            field(ui, "REBUILT ELF SHA-256", digest);
            if let Some(path) = &self.rebuilt_exported_path {
                field(ui, "SAVED ELF", &path.display().to_string());
            } else {
                ui.label(
                    RichText::new("EXPORT PATH · NEW FILE ONLY")
                        .size(10.0)
                        .color(MUTED),
                );
                ui.add(
                    egui::TextEdit::singleline(&mut self.rebuild_output_path)
                        .hint_text("/absolute/path/to/rebuilt.elf"),
                );
                let export = ui.add_enabled(
                    !self.busy && !self.rebuild_output_path.trim().is_empty(),
                    egui::Button::new("Export verified rebuilt ELF"),
                );
                if export.clicked() {
                    self.enqueue(
                        Task::ExportRebuiltRemote {
                            digest: digest.clone(),
                            path: PathBuf::from(self.rebuild_output_path.trim()),
                        },
                        "Retrieving and verifying rebuilt ELF…",
                    );
                }
                export.on_disabled_hover_text(
                    "Enter a new destination file path; existing files are never overwritten.",
                );
            }
        }
        if let Some(report) = &self.rebuild_report {
            egui::CollapsingHeader::new("Rebuild diagnostics").show(ui, |ui| {
                ui.code(report);
            });
        }
        ui.separator();
        ui.heading(RichText::new("Scalar patch v1").size(14.0));
        ui.label(RichText::new("Whole-function, entry-only u64(u64,u64) return expression. The replacement must fit the original symbol. This intentionally changes behavior; no equivalence is claimed.").size(11.0).color(MUTED));
        ui.label(RichText::new("REPLACEMENT").size(10.0).color(MUTED));
        ui.add(
            egui::TextEdit::singleline(&mut self.patch_replacement)
                .hint_text("return arg0 - arg1;"),
        );
        ui.checkbox(
            &mut self.entry_only_assertion,
            "I assert no control flow enters this function interior",
        );
        ui.label(
            RichText::new(if self.remote {
                "EXPORT PATCHED ELF · NEW FILE ONLY"
            } else {
                "LOCAL PATCH OUTPUT · NEW FILE ONLY"
            })
            .size(10.0)
            .color(MUTED),
        );
        ui.add(
            egui::TextEdit::singleline(&mut self.patch_output_path)
                .hint_text("/absolute/path/to/patched.elf"),
        );
        let selected_symbol = self.symbol.clone();
        let patch_ready = self.spec.is_some()
            && selected_symbol.is_some()
            && self.trusted_fixture
            && self.entry_only_assertion
            && !self.patch_replacement.trim().is_empty()
            && !self.busy
            && (self.remote || !self.patch_output_path.trim().is_empty());
        let patch = ui.add_enabled(
            patch_ready,
            egui::Button::new(if self.remote {
                "Apply scalar patch remotely"
            } else {
                "Apply scalar patch locally"
            }),
        );
        if patch.clicked()
            && let Some(symbol) = selected_symbol
        {
            let task = if self.remote {
                Task::PatchRemote {
                    symbol,
                    replacement: self.patch_replacement.trim().to_owned(),
                    key: uuid::Uuid::new_v4().to_string(),
                }
            } else {
                Task::PatchLocal {
                    symbol,
                    replacement: self.patch_replacement.trim().to_owned(),
                    output_path: PathBuf::from(self.patch_output_path.trim()),
                }
            };
            self.enqueue(task, "Validating and applying bounded scalar patch…");
        }
        patch.on_disabled_hover_text("Select a function, enter a supported return expression, assert trusted fixture and entry-only control flow, and provide a new output file for local patching.");
        if let Some(digest) = &self.patch_digest {
            field(ui, "PATCHED ELF SHA-256", digest);
            if let Some(path) = &self.patch_exported_path {
                field(ui, "SAVED ELF", &path.display().to_string());
            } else {
                let export = ui.add_enabled(
                    !self.busy && !self.patch_output_path.trim().is_empty(),
                    egui::Button::new("Export verified patched ELF"),
                );
                if export.clicked() {
                    self.enqueue(
                        Task::ExportRebuiltRemote {
                            digest: digest.clone(),
                            path: PathBuf::from(self.patch_output_path.trim()),
                        },
                        "Retrieving and verifying patched ELF…",
                    );
                }
                export.on_disabled_hover_text(
                    "Enter a new local file path; existing files are never overwritten.",
                );
            }
        }
            });
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
                    "OBSERVED SITES",
                    &format!(
                        "{} call · {} memory · partial recovery",
                        summary.call_sites.len(),
                        summary.reference_sites.len()
                    ),
                );
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
        if let Some(report) = &self.disassembly_report
            && let Some(address) = self.selected_address
            && let Some(instruction) = report
                .instructions
                .iter()
                .find(|instruction| instruction.address.0 == address)
        {
            ui.separator();
            ui.heading(RichText::new("Selected instruction").size(14.0));
            field(ui, "ADDRESS", &format!("0x{:016x}", instruction.address.0));
            field(ui, "BYTES", &instruction.bytes_hex);
            field(
                ui,
                "ASSEMBLY",
                &format!("{} {}", instruction.mnemonic, instruction.operands),
            );
            field(ui, "FLOW", &format!("{:?}", instruction.flow));
            field(
                ui,
                "BRANCH TARGET",
                &instruction
                    .branch_target
                    .map_or_else(|| "none".to_owned(), |target| format!("0x{:016x}", target.0)),
            );
            field(ui, "PROVENANCE", &instruction.provenance);
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
                (Tab::Graph, "Graph"),
                (Tab::Cfg, "CFG"),
                (Tab::Llvm, "LLVM IR"),
                (Tab::Passes, "Passes"),
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
            Tab::Graph => self.graph_view(ui),
            Tab::Cfg => self.cfg_view(ui),
            Tab::Llvm => self.llvm_view(ui),
            Tab::Passes => self.passes_view(ui),
            Tab::Analysis => self.analysis_view(ui),
            Tab::C => self.c_view(ui),
        }
    }

    fn disassembly(&mut self, ui: &mut egui::Ui) {
        if self.disassembly_report.is_some() {
            self.full_disassembly(ui);
            return;
        }
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

    fn full_disassembly(&mut self, ui: &mut egui::Ui) {
        let Some(report) = self.disassembly_report.clone() else {
            return;
        };
        ui.horizontal(|ui| {
            ui.label(
                RichText::new(format!(
                    "{} executable sections · {} instructions · {} gaps",
                    report.sections.len(),
                    report.instructions.len(),
                    report.gaps.len()
                ))
                .color(ACCENT),
            );
            if ui.button("Show JSON in console").clicked() {
                self.console_json = true;
            }
        });
        ui.label(
            RichText::new("Trusted symbol/entry CFG recovery is mixed with explicitly marked linear-sweep uncertainty.")
                .size(11.0)
                .color(MUTED),
        );
        ui.separator();
        ui.horizontal(|ui| {
            ui.label(RichText::new("ADDRESS").size(10.0).color(MUTED));
            ui.add_space(92.0);
            ui.label(RichText::new("BYTES").size(10.0).color(MUTED));
            ui.add_space(95.0);
            ui.label(RichText::new("INSTRUCTION").size(10.0).color(MUTED));
            ui.add_space(160.0);
            ui.label(RichText::new("FLOW / TARGET").size(10.0).color(MUTED));
        });
        let instructions = report.instructions;
        let mut clicked = None;
        egui::ScrollArea::vertical()
            .id_salt("whole_elf_disassembly")
            .show_rows(ui, 25.0, instructions.len(), |ui, range| {
                for index in range {
                    let instruction = &instructions[index];
                    let selected = self.selected_address == Some(instruction.address.0);
                    let target = instruction
                        .branch_target
                        .map_or_else(String::new, |address| format!(" → 0x{:x}", address.0));
                    let line = format!(
                        "0x{:016x}  {:<18} {:<26} {:?}{}",
                        instruction.address.0,
                        instruction.bytes_hex,
                        format!("{} {}", instruction.mnemonic, instruction.operands),
                        instruction.flow,
                        target,
                    );
                    if ui
                        .selectable_label(selected, RichText::new(line).monospace().size(11.0))
                        .clicked()
                    {
                        clicked = Some(instruction.address.0);
                    }
                }
            });
        if let Some(address) = clicked {
            self.selected_address = Some(address);
        }
        if !report.warnings.is_empty() || !report.gaps.is_empty() {
            ui.separator();
            egui::CollapsingHeader::new(format!(
                "Uncertainty · {} warnings · {} gaps",
                report.warnings.len(),
                report.gaps.len()
            ))
            .default_open(false)
            .show(ui, |ui| {
                for warning in report.warnings.iter().take(32) {
                    ui.colored_label(BAD, warning);
                }
                for gap in report.gaps.iter().take(32) {
                    ui.label(
                        RichText::new(format!(
                            "0x{:x} +{} · {} · {}",
                            gap.address.0, gap.size, gap.reason, gap.provenance
                        ))
                        .monospace()
                        .size(11.0)
                        .color(MUTED),
                    );
                }
            });
        }
    }

    fn console_view(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.heading(RichText::new("Console").size(14.0));
            ui.label(RichText::new("LOCAL ANALYSIS OUTPUT · no shell execution").size(10.0).color(MUTED));
            if self.disassembly_report.is_some() {
                if ui
                    .button(if self.console_json { "Show activity" } else { "Show JSON" })
                    .clicked()
                {
                    self.console_json = !self.console_json;
                }
                if ui.button("Copy JSON").clicked()
                    && let Some(report) = &self.disassembly_report
                    && let Ok(json) = serde_json::to_string_pretty(report)
                {
                    ui.ctx().copy_text(json);
                }
            }
        });
        egui::ScrollArea::vertical()
            .id_salt("console_output")
            .max_height(130.0)
            .show(ui, |ui| {
                if self.console_json {
                    if let Some(report) = &self.disassembly_report
                        && let Ok(json) = serde_json::to_string_pretty(report)
                    {
                        ui.code(json);
                    }
                } else {
                    if let Some(failure) = &self.failure {
                        ui.colored_label(BAD, failure);
                    } else {
                        ui.colored_label(if self.busy { ACCENT } else { GOOD }, &self.status);
                    }
                    if let Some(report) = &self.disassembly_report {
                        for warning in report.warnings.iter().take(8) {
                            ui.colored_label(BAD, warning);
                        }
                    }
                    for entry in self.history.iter().rev().take(8) {
                        ui.label(RichText::new(entry).size(11.0).color(MUTED));
                    }
                }
            });
    }

    fn graph_view(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label(RichText::new("GRAPH SCOPE").size(10.0).color(MUTED));
            if ui
                .selectable_label(self.graph_mode == GraphMode::Function, "Selected function CFG")
                .clicked()
            {
                self.graph_mode = GraphMode::Function;
            }
            if ui
                .selectable_label(self.graph_mode == GraphMode::Program, "Program calls")
                .clicked()
            {
                self.graph_mode = GraphMode::Program;
            }
            if self.ghidra_graph.is_some()
                && ui
                    .selectable_label(self.graph_mode == GraphMode::Ghidra, "Ghidra evidence")
                    .clicked()
            {
                self.graph_mode = GraphMode::Ghidra;
            }
        });
        ui.label(
            RichText::new(match self.graph_mode {
                GraphMode::Function => {
                    "Automatic layered layout of recovered one-instruction CFG blocks. Click a block to inspect its address."
                }
                GraphMode::Program => {
                    "Function-level call graph from bounded native analysis. Missing edges are unknown, not proven absent."
                }
                GraphMode::Ghidra => {
                    "Imported Ghidra function/call graph. This is external evidence, not native HydIR recovery."
                }
            })
            .size(11.0)
            .color(MUTED),
        );

        let mut nodes: Vec<(NodeId, String, bool)> = Vec::new();
        let mut edges: Vec<(NodeId, NodeId)> = Vec::new();
        match self.graph_mode {
            GraphMode::Function => {
                let Some(cfg) = &self.cfg else {
                    ui.label(RichText::new("Select a function to build its CFG graph.").color(MUTED));
                    return;
                };
                for block in &cfg.blocks {
                    nodes.push((
                        NodeId::new(("block", block.address.0)),
                        format!("0x{:x}\n{}", block.address.0, block.mnemonic),
                        self.selected_address == Some(block.address.0),
                    ));
                }
                for edge in &cfg.edges {
                    edges.push((
                        NodeId::new(("block", edge.source.0)),
                        NodeId::new(("block", edge.target.0)),
                    ));
                }
            }
            GraphMode::Program => {
                let Some(spec) = &self.spec else {
                    ui.label(RichText::new("Open an ELF to build its function graph.").color(MUTED));
                    return;
                };
                for function in &spec.functions {
                    nodes.push((
                        NodeId::new(("function", function.name.as_str())),
                        format!("{}\n0x{:x}", function.name, function.address.0),
                        self.symbol.as_deref() == Some(function.name.as_str()),
                    ));
                }
                let Some(report) = &self.analysis else {
                    ui.label(
                        RichText::new("Run Global effects / Analyze to populate bounded call edges.")
                            .color(MUTED),
                    );
                    return;
                };
                for summary in &report.functions {
                    for callee in &summary.direct_callees {
                        if spec.functions.iter().any(|function| function.name == *callee) {
                            let source = NodeId::new(("function", summary.name.as_str()));
                            let target = NodeId::new(("function", callee.as_str()));
                            if source != target {
                                edges.push((source, target));
                            }
                        }
                    }
                }
                /*
                 * Analysis names are the authoritative bounded call graph.
                 * Unresolved and indirect targets intentionally do not become
                 * fake nodes here; the analysis pane retains those facts.
                 */
                for call in &spec.calls {
                    let source = spec.functions.iter().find(|function| {
                        function.address.0 <= call.source.0
                            && call.source.0 < function.address.0.saturating_add(function.size)
                    });
                    let target = call.target.and_then(|address| {
                        spec.functions.iter().find(|function| function.address == address)
                    });
                    if let (Some(source), Some(target)) = (source, target)
                        && !edges.contains(&(
                            NodeId::new(("function", source.name.as_str())),
                            NodeId::new(("function", target.name.as_str())),
                        ))
                    {
                        edges.push((
                            NodeId::new(("function", source.name.as_str())),
                            NodeId::new(("function", target.name.as_str())),
                        ));
                    }
                }
            }
            GraphMode::Ghidra => {
                let Some(graph) = &self.ghidra_graph else {
                    ui.label(RichText::new("Load a Ghidra JSON export to show its graph.").color(MUTED));
                    return;
                };
                let selected = self
                    .symbol
                    .as_deref()
                    .and_then(|name| graph.functions.iter().find(|function| function.name == name))
                    .or_else(|| graph.functions.first());
                let Some(function) = selected else {
                    ui.label(RichText::new("The Ghidra export contains no functions.").color(MUTED));
                    return;
                };
                let block_addresses: std::collections::HashSet<&str> =
                    function.blocks.iter().map(|block| block.address.as_str()).collect();
                for block in &function.blocks {
                    nodes.push((
                        NodeId::new(("ghidra-block", block.address.as_str())),
                        format!("{}\n{}", block.address, block.mnemonic),
                        block.address == function.entry,
                    ));
                }
                for edge in &graph.cfg_edges {
                    if block_addresses.contains(edge.source.as_str())
                        && block_addresses.contains(edge.target.as_str())
                    {
                        let source = NodeId::new(("ghidra-block", edge.source.as_str()));
                        let target = NodeId::new(("ghidra-block", edge.target.as_str()));
                        edges.push((source, target));
                    }
                }
                ui.label(
                    RichText::new(format!(
                        "Ghidra CFG / {} / {} blocks / {} edges",
                        function.name,
                        function.blocks.len(),
                        edges.len()
                    ))
                    .size(11.0)
                    .color(MUTED),
                );
            }
        }

        if nodes.is_empty() {
            ui.label(RichText::new("No graph nodes recovered.").color(MUTED));
            return;
        }

        let node_size = [190.0_f32, 58.0_f32];
        let layout_nodes = nodes
            .iter()
            .map(|(id, _, _)| (*id, egui_graph_egui::vec2(node_size[0], node_size[1])));
        let layout = layout_from_sizes(layout_nodes, edges.iter().copied(), GraphDirection::LeftToRight);
        let min_x = layout.values().map(|position| position.x).fold(f32::INFINITY, f32::min);
        let min_y = layout.values().map(|position| position.y).fold(f32::INFINITY, f32::min);
        let max_x = layout.values().map(|position| position.x).fold(f32::NEG_INFINITY, f32::max);
        let max_y = layout.values().map(|position| position.y).fold(f32::NEG_INFINITY, f32::max);
        let canvas_size = egui::vec2(
            (max_x - min_x + node_size[0] + 80.0).max(ui.available_width()),
            (max_y - min_y + node_size[1] + 80.0).max(260.0),
        );

        egui::ScrollArea::both()
            .id_salt("graph_canvas")
            .show(ui, |ui| {
                let (canvas, _) = ui.allocate_exact_size(canvas_size, egui::Sense::hover());
                let painter = ui.painter_at(canvas);
                let offset = canvas.min + egui::vec2(40.0 - min_x, 40.0 - min_y);
                let mut rects = std::collections::HashMap::new();
                for (id, label, selected) in &nodes {
                    let position = layout
                        .get(id)
                        .map(|position| offset + egui::vec2(position.x, position.y))
                        .unwrap_or(canvas.min);
                    let rect = egui::Rect::from_min_size(position, egui::vec2(node_size[0], node_size[1]));
                    rects.insert(*id, rect);
                    painter.rect_filled(rect, 6.0, if *selected { Color32::from_rgb(82, 66, 45) } else { PANEL });
                    painter.rect_stroke(rect, 6.0, egui::Stroke::new(1.0, if *selected { ACCENT } else { MUTED }), egui::StrokeKind::Outside);
                    painter.text(
                        rect.left_top() + egui::vec2(10.0, 9.0),
                        egui::Align2::LEFT_TOP,
                        label,
                        egui::FontId::monospace(11.0),
                        TEXT,
                    );
                    let response = ui.interact(rect, ui.id().with(("graph-node", id.value())), egui::Sense::click());
                    if response.clicked() && self.graph_mode == GraphMode::Function {
                        if let Some(address) = label.strip_prefix("0x").and_then(|value| value.split('\n').next()).and_then(|value| u64::from_str_radix(value, 16).ok()) {
                            self.selected_address = Some(address);
                        }
                    }
                }
                for (source, target) in &edges {
                    if let (Some(source_rect), Some(target_rect)) = (rects.get(source), rects.get(target)) {
                        let start = source_rect.right_center();
                        let end = target_rect.left_center();
                        painter.line_segment([start, end], egui::Stroke::new(1.5, ACCENT));
                        let direction = (end - start).normalized();
                        let tip = end;
                        let left = tip - direction * 10.0 + egui::vec2(-direction.y, direction.x) * 4.0;
                        let right = tip - direction * 10.0 - egui::vec2(-direction.y, direction.x) * 4.0;
                        painter.add(egui::Shape::convex_polygon(vec![tip, left, right], ACCENT, egui::Stroke::NONE));
                    }
                }
            });
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

    fn passes_view(&mut self, ui: &mut egui::Ui) {
        ui.label(
            RichText::new(if self.remote {
                "NAMED LLVM PASS PIPELINE · REMOTE EXPERIMENT"
            } else {
                "NAMED LLVM PASS PIPELINE · LOCAL EXPERIMENT"
            })
            .size(11.0)
            .strong()
            .color(ACCENT),
        );
        ui.label(RichText::new("Allowed passes: instcombine, sccp, simplifycfg, dce. Raw, before, after, and report artifacts are retained. LLVM verification runs at the pass boundary.").size(11.0).color(MUTED));
        ui.label(
            RichText::new("PASSES (COMMA-SEPARATED)")
                .size(10.0)
                .color(MUTED),
        );
        ui.add(egui::TextEdit::singleline(&mut self.pass_pipeline).desired_width(f32::INFINITY));
        let selected = self.symbol.clone();
        let has_passes = !self.pass_pipeline.trim().is_empty();
        if !self.remote {
            ui.label(
                RichText::new("LOCAL EXPERIMENT DIRECTORY · NEW DIRECTORY ONLY")
                    .size(10.0)
                    .color(MUTED),
            );
            ui.add(
                egui::TextEdit::singleline(&mut self.local_pass_output_dir)
                    .hint_text("/absolute/path/to/new-experiment"),
            );
        }
        let local_capable = cfg!(all(target_os = "linux", target_arch = "x86_64"));
        let mode_capable = if self.remote {
            self.named_pass_transform
        } else {
            local_capable && !self.local_pass_output_dir.trim().is_empty()
        };
        let run = ui.add_enabled(
            mode_capable && self.trusted_fixture && !self.busy && selected.is_some() && has_passes,
            egui::Button::new("Run named passes on selected function"),
        );
        if run.clicked()
            && let Some(symbol) = selected
        {
            let task = if self.remote {
                Task::TransformRemote {
                    symbol,
                    passes: self.pass_pipeline.trim().to_owned(),
                    key: uuid::Uuid::new_v4().to_string(),
                }
            } else {
                Task::TransformLocal {
                    symbol,
                    passes: self.pass_pipeline.trim().to_owned(),
                    output_dir: PathBuf::from(self.local_pass_output_dir.trim()),
                }
            };
            self.enqueue(task, "Verifying and saving pass experiment…");
        }
        run.on_disabled_hover_text("Select a function, assert a trusted fixture in Build & patch, and provide the mode's required LLVM capability/output directory.");
        ui.separator();
        if let (Some(before), Some(after)) = (&self.transform_before, &self.transform_after) {
            ui.columns(2, |columns| {
                columns[0].label(
                    RichText::new("BEFORE · VERIFIED LLVM IR")
                        .size(11.0)
                        .strong()
                        .color(MUTED),
                );
                egui::ScrollArea::both()
                    .id_salt("pass_before")
                    .show(&mut columns[0], |ui| {
                        ui.code(before);
                    });
                columns[1].label(
                    RichText::new("AFTER · VERIFIED LLVM IR")
                        .size(11.0)
                        .strong()
                        .color(ACCENT),
                );
                egui::ScrollArea::both()
                    .id_salt("pass_after")
                    .show(&mut columns[1], |ui| {
                        ui.code(after);
                    });
            });
            if let Some(report) = &self.transform_report {
                egui::CollapsingHeader::new("Pass diagnostics").show(ui, |ui| {
                    ui.code(report);
                });
            }
        } else {
            ui.label(RichText::new("No pass experiment on this revision. Select a function and run a named pipeline to compare verified IR.").color(MUTED));
        }
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
                            field(
                                ui,
                                "CALL SITES",
                                &format!(
                                    "{} observed within this symbol",
                                    summary.call_sites.len()
                                ),
                            );
                            for call in summary.call_sites.iter().take(24) {
                                ui.label(
                                    RichText::new(format!(
                                        "0x{:016x}  →  {}",
                                        call.source.0,
                                        call.target.map_or_else(
                                            || "unresolved".to_owned(),
                                            |target| format!("0x{:016x}", target.0)
                                        )
                                    ))
                                    .monospace()
                                    .size(11.0)
                                    .color(if call.target.is_some() { TEXT } else { BAD }),
                                );
                            }
                            if summary.call_sites.len() > 24 {
                                ui.label(RichText::new("Showing first 24 call sites").color(MUTED));
                            }
                            field(
                                ui,
                                "MEMORY REFERENCES",
                                &format!(
                                    "{} observed within this symbol",
                                    summary.reference_sites.len()
                                ),
                            );
                            for reference in summary.reference_sites.iter().take(24) {
                                ui.label(
                                    RichText::new(format!(
                                        "0x{:016x}  →  {}",
                                        reference.source.0,
                                        reference.target.map_or_else(
                                            || "unresolved".to_owned(),
                                            |target| format!("0x{:016x}", target.0)
                                        )
                                    ))
                                    .monospace()
                                    .size(11.0)
                                    .color(
                                        if reference.target.is_some() {
                                            TEXT
                                        } else {
                                            BAD
                                        },
                                    ),
                                );
                            }
                            if summary.reference_sites.len() > 24 {
                                ui.label(
                                    RichText::new("Showing first 24 memory references")
                                        .color(MUTED),
                                );
                            }
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
        if !self.workbench_loaded {
            self.header(ui);
            egui::CentralPanel::default().show(ui, |ui| {
                ui.label("Loading private workbench settings…");
            });
            ui.ctx().request_repaint_after(Duration::from_millis(50));
            return;
        }
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
        let navigator = egui::Panel::left("navigator")
            .resizable(true)
            .default_size(self.workbench.navigator_width)
            .min_size(180.0)
            .show(ui, |ui| {
                egui::Frame::new()
                    .inner_margin(egui::Margin::same(12))
                    .show(ui, |ui| self.navigator(ui));
            });
        self.workbench.navigator_width = navigator.response.rect.width().clamp(180.0, 800.0);
        let inspector = egui::Panel::right("inspector")
            .resizable(true)
            .default_size(self.workbench.inspector_width)
            .min_size(220.0)
            .show(ui, |ui| {
                egui::ScrollArea::vertical()
                    .id_salt("inspector_scroll")
                    .show(ui, |ui| {
                        egui::Frame::new()
                            .inner_margin(egui::Margin::same(12))
                            .show(ui, |ui| self.inspector(ui));
                    });
            });
        self.workbench.inspector_width = inspector.response.rect.width().clamp(220.0, 800.0);
        egui::Panel::bottom("console")
            .resizable(true)
            .default_size(150.0)
            .min_size(70.0)
            .show(ui, |ui| self.console_view(ui));
        egui::CentralPanel::default().show(ui, |ui| {
            egui::Frame::new()
                .inner_margin(egui::Margin::same(12))
                .show(ui, |ui| self.main_view(ui));
        });
    }
}

fn main() -> eframe::Result<()> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    if let [probe, binary] = arguments.as_slice()
        && probe == "--probe-workbench"
    {
        let result = (|| {
            if std::env::var_os("HYDIR_LOCAL_DB").is_none() {
                return Err(
                    "Set HYDIR_LOCAL_DB to a private absolute test database path".to_owned(),
                );
            }
            let path = PathBuf::from(binary);
            let bytes = bounded_read(&path)?;
            let spec = import_elf(&bytes).map_err(|error| error.to_string())?;
            let project = attach_local_project(&path, &spec)?;
            let settings = WorkbenchSettings {
                navigator_width: 344.0,
                inspector_width: 368.0,
                recent_local_path: Some(project.path.clone()),
            };
            LocalProjectStore::open_default()?.save_workbench_settings(&settings)?;
            let reopened = LocalProjectStore::open_default()?.load_workbench_settings()?;
            let reopened_project = attach_local_project(
                reopened
                    .recent_local_path
                    .as_deref()
                    .ok_or("Recent local ELF path was not saved")?,
                &spec,
            )?;
            if reopened != settings || reopened_project.id != project.id {
                return Err("Saved workbench did not reopen the same local project".to_owned());
            }
            Ok::<_, String>(())
        })();
        match result {
            Ok(()) => {
                println!("HydIR GUI workbench save/reopen operations passed");
                return Ok(());
            }
            Err(error) => {
                eprintln!("HydIR GUI workbench probe failed: {error}");
                std::process::exit(1);
            }
        }
    }
    if let [probe, binary] = arguments.as_slice()
        && probe == "--probe-local-annotation"
    {
        let result = (|| {
            if std::env::var_os("HYDIR_LOCAL_DB").is_none() {
                return Err(
                    "Set HYDIR_LOCAL_DB to a private absolute test database path".to_owned(),
                );
            }
            let path = PathBuf::from(binary);
            let bytes = bounded_read(&path)?;
            let spec = import_elf(&bytes).map_err(|error| error.to_string())?;
            let project = attach_local_project(&path, &spec)?;
            let statement = "GUI local analyst assertion; not independently validated";
            let (updated, overlaid, annotations) = add_local_annotation(
                &project,
                &bytes,
                &spec.binary_sha256,
                AnnotationKind::Assumption,
                None,
                "trusted fixture only",
                statement,
                &uuid::Uuid::new_v4().to_string(),
            )?;
            let reopened = attach_local_project(&path, &spec)?;
            let persisted = list_local_annotations(&reopened)?;
            if updated.revision != project.revision + 1
                || reopened.revision != updated.revision
                || !overlaid.assumptions.iter().any(|assumption| {
                    assumption.statement == statement
                        && assumption.provenance.source == FactSource::AnalystAssertion
                })
                || !persisted.iter().any(|annotation| {
                    annotation.id
                        == annotations
                            .last()
                            .map(|fact| fact.id.clone())
                            .unwrap_or_default()
                })
            {
                return Err(
                    "GUI local annotation probe returned inconsistent project facts".to_owned(),
                );
            }
            Ok::<_, String>(updated.revision)
        })();
        match result {
            Ok(revision) => {
                println!(
                    "HydIR GUI local annotation operations passed: private revision {revision}, reopened analyst fact"
                );
                return Ok(());
            }
            Err(error) => {
                eprintln!("HydIR GUI local annotation probe failed: {error}");
                std::process::exit(1);
            }
        }
    }
    if let [probe, endpoint, token_file, binary] = arguments.as_slice()
        && probe == "--probe-annotation"
    {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("Tokio runtime initialization");
        let result = runtime.block_on(async {
            let token_file = PathBuf::from(token_file);
            let project_id = create_remote_project(
                endpoint.clone(),
                token_file.clone(),
                "GUI annotation probe".to_owned(),
            )
            .await?;
            let (access, spec) = upload_remote(
                endpoint.clone(),
                token_file,
                project_id,
                PathBuf::from(binary),
            )
            .await?;
            let statement = "GUI analyst assertion; not independently validated";
            let (revision, annotated_spec, annotations) = add_remote_annotation(
                &access,
                &spec.binary_sha256,
                AnnotationKind::Assumption,
                None,
                "trusted fixture only",
                statement,
                &uuid::Uuid::new_v4().to_string(),
            )
            .await?;
            if revision != access.revision + 1
                || annotated_spec.binary_sha256 != spec.binary_sha256
                || !annotated_spec.assumptions.iter().any(|assumption| {
                    assumption.statement == statement
                        && assumption.provenance.source == FactSource::AnalystAssertion
                })
                || annotations.len() != 1
            {
                return Err("GUI annotation probe returned inconsistent analyst facts.".to_owned());
            }
            let mut reopened = access;
            reopened.revision = revision;
            let persisted = list_remote_annotations(&reopened, &spec.binary_sha256).await?;
            if persisted.len() != annotations.len()
                || persisted[0].id != annotations[0].id
                || persisted[0].value != annotations[0].value
            {
                return Err("GUI annotation probe ledger changed after reopening.".to_owned());
            }
            Ok::<_, String>(revision)
        });
        match result {
            Ok(revision) => {
                println!(
                    "HydIR GUI annotation operations passed: immutable revision {revision}, one persistent analyst fact"
                );
                return Ok(());
            }
            Err(error) => {
                eprintln!("HydIR GUI annotation probe failed: {error}");
                std::process::exit(1);
            }
        }
    }
    if let [probe, binary, symbol, replacement, output] = arguments.as_slice()
        && probe == "--probe-local-patch"
    {
        let result = bounded_read(&PathBuf::from(binary))
            .and_then(|bytes| patch_local(&bytes, symbol, replacement, Path::new(output)));
        match result {
            Ok((patched, spec, digest)) if !patched.is_empty() && spec.binary_sha256 == digest => {
                println!("HydIR GUI local patch operations passed: patched ELF SHA-256 {digest}");
                return Ok(());
            }
            Ok(_) => {
                eprintln!("HydIR GUI local patch probe returned inconsistent artifacts");
                std::process::exit(1);
            }
            Err(error) => {
                eprintln!("HydIR GUI local patch probe failed: {error}");
                std::process::exit(1);
            }
        }
    }
    if let [
        probe,
        endpoint,
        token_file,
        binary,
        symbol,
        replacement,
        output,
    ] = arguments.as_slice()
        && probe == "--probe-remote-patch"
    {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("Tokio runtime initialization");
        let result = runtime.block_on(async {
            let token_file = PathBuf::from(token_file);
            let project_id = create_remote_project(
                endpoint.clone(),
                token_file.clone(),
                "GUI scalar patch probe".to_owned(),
            )
            .await?;
            let (mut access, _) = upload_remote(
                endpoint.clone(),
                token_file,
                project_id,
                PathBuf::from(binary),
            )
            .await?;
            let (revision, spec, digest) = patch_remote(
                &access,
                symbol,
                replacement,
                &uuid::Uuid::new_v4().to_string(),
            )
            .await?;
            if spec.binary_sha256 != digest {
                return Err("GUI patch probe returned inconsistent program model.".to_owned());
            }
            access.revision = revision;
            export_rebuilt_remote(&access, &digest, &PathBuf::from(output)).await?;
            Ok::<_, String>((revision, digest))
        });
        match result {
            Ok((revision, digest)) => {
                println!(
                    "HydIR GUI remote patch operations passed: revision {revision}, exported ELF SHA-256 {digest}"
                );
                return Ok(());
            }
            Err(error) => {
                eprintln!("HydIR GUI remote patch probe failed: {error}");
                std::process::exit(1);
            }
        }
    }
    if let [probe, binary, symbol, output_dir] = arguments.as_slice()
        && probe == "--probe-local-pass"
    {
        let result = bounded_read(&PathBuf::from(binary)).and_then(|bytes| {
            transform_local(
                &bytes,
                symbol,
                "instcombine,sccp,simplifycfg,dce",
                Path::new(output_dir),
            )
        });
        match result {
            Ok((before, after, report))
                if before != after && report.contains("\"llvm_verified\":true") =>
            {
                println!(
                    "HydIR GUI local pass operations passed: verified before/after IR in {output_dir}"
                );
                return Ok(());
            }
            Ok(_) => {
                eprintln!("HydIR GUI local pass probe did not observe a verified IR change");
                std::process::exit(1);
            }
            Err(error) => {
                eprintln!("HydIR GUI local pass probe failed: {error}");
                std::process::exit(1);
            }
        }
    }
    if let [probe, binary, output_dir] = arguments.as_slice()
        && probe == "--probe-local-rebuild"
    {
        let result = bounded_read(&PathBuf::from(binary))
            .and_then(|bytes| rebuild_local(&bytes, Path::new(output_dir)));
        match result {
            Ok((rebuilt, spec, ir, report, digest))
                if spec.binary_sha256 == digest
                    && !rebuilt.is_empty()
                    && !ir.is_empty()
                    && report.contains("\"llvm_verified\": true") =>
            {
                println!("HydIR GUI local rebuild operations passed: rebuilt ELF SHA-256 {digest}");
                return Ok(());
            }
            Ok(_) => {
                eprintln!("HydIR GUI local rebuild probe returned inconsistent artifacts");
                std::process::exit(1);
            }
            Err(error) => {
                eprintln!("HydIR GUI local rebuild probe failed: {error}");
                std::process::exit(1);
            }
        }
    }
    if let [probe, endpoint, token_file, binary, symbol] = arguments.as_slice()
        && probe == "--probe-transform"
    {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("Tokio runtime initialization");
        let result = runtime.block_on(async {
            let token_file = PathBuf::from(token_file);
            let project_id = create_remote_project(
                endpoint.clone(),
                token_file.clone(),
                "GUI pass probe".to_owned(),
            )
            .await?;
            let (access, _) = upload_remote(
                endpoint.clone(),
                token_file,
                project_id,
                PathBuf::from(binary),
            )
            .await?;
            let (revision, before, after, report, changed) = transform_remote(
                &access,
                symbol,
                "instcombine,sccp,simplifycfg,dce",
                &uuid::Uuid::new_v4().to_string(),
            )
            .await?;
            if !changed || before == after || !report.contains("llvm_verified") {
                return Err("GUI pass probe did not observe a verified IR change.".to_owned());
            }
            Ok::<_, String>(revision)
        });
        match result {
            Ok(revision) => {
                println!(
                    "HydIR GUI pass operations passed: immutable revision {revision}, verified before/after IR"
                );
                return Ok(());
            }
            Err(error) => {
                eprintln!("HydIR GUI pass probe failed: {error}");
                std::process::exit(1);
            }
        }
    }
    if let [probe, endpoint, token_file, binary, output] = arguments.as_slice()
        && probe == "--probe-rebuild"
    {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("Tokio runtime initialization");
        let result = runtime.block_on(async {
            let token_file = PathBuf::from(token_file);
            let project_id = create_remote_project(
                endpoint.clone(),
                token_file.clone(),
                "GUI rebuild probe".to_owned(),
            )
            .await?;
            let (mut access, _) = upload_remote(
                endpoint.clone(),
                token_file,
                project_id,
                PathBuf::from(binary),
            )
            .await?;
            let (revision, spec, ir, report, digest) =
                rebuild_remote(&access, &uuid::Uuid::new_v4().to_string()).await?;
            let report_json: serde_json::Value = serde_json::from_str(&report)
                .map_err(|error| format!("Invalid rebuild report: {error}"))?;
            if spec.binary_sha256 != digest || ir.is_empty() || report_json["llvm_verified"] != true
            {
                return Err("GUI rebuild probe returned inconsistent artifacts.".to_owned());
            }
            access.revision = revision;
            export_rebuilt_remote(&access, &digest, &PathBuf::from(output)).await?;
            Ok::<_, String>((revision, digest))
        });
        match result {
            Ok((revision, digest)) => {
                println!(
                    "HydIR GUI rebuild operations passed: immutable revision {revision}, exported ELF SHA-256 {digest}"
                );
                return Ok(());
            }
            Err(error) => {
                eprintln!("HydIR GUI rebuild probe failed: {error}");
                std::process::exit(1);
            }
        }
    }
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
    let open_local = if let [flag, path] = arguments.as_slice()
        && flag == "--open-local"
    {
        Some((PathBuf::from(path), None))
    } else if let [flag, path, symbol] = arguments.as_slice()
        && flag == "--open-local"
    {
        Some((PathBuf::from(path), Some(symbol.clone())))
    } else if arguments.is_empty() {
        None
    } else {
        eprintln!(
            "Usage: hydir [--open-local <elf> [function-symbol] | --probe-workbench <elf> (requires HYDIR_LOCAL_DB) | --probe-local-annotation <elf> (requires HYDIR_LOCAL_DB) | --probe-remote <endpoint> <token-file> <project-id> <symbol> | --probe-create-upload <endpoint> <token-file> <elf> | --probe-annotation <endpoint> <token-file> <elf> | --probe-transform <endpoint> <token-file> <elf> <symbol> | --probe-rebuild <endpoint> <token-file> <elf> <new-output-file> | --probe-local-pass <elf> <symbol> <new-output-dir> | --probe-local-rebuild <elf> <new-output-dir> | --probe-local-patch <elf> <symbol> <replacement> <new-output-file> | --probe-remote-patch <endpoint> <token-file> <elf> <symbol> <replacement> <new-output-file>]"
        );
        std::process::exit(2);
    };
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("HydIR · Native Analysis")
            .with_inner_size([1400.0, 850.0]),
        ..Default::default()
    };
    eframe::run_native(
        "HydIR",
        options,
        Box::new(move |context| {
            let mut app = AnalystApp::new(&context.egui_ctx);
            app.enqueue(Task::LoadWorkbench, "Loading saved workbench…");
            if let Some((path, symbol)) = open_local {
                app.path_input = path.display().to_string();
                app.initial_symbol = symbol;
                app.startup_open_local = Some(path);
            }
            Ok(Box::new(app))
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::{AnalystApp, Event, Tab, ir_slice, validate_endpoint};
    use hydir_core::{
        AnalystAnnotation, AnnotationKind, FactProvenance, FactSource, ProgramSpec, RecoveryState,
    };
    use std::sync::mpsc;

    #[test]
    fn annotation_refresh_overlays_once_and_rejects_stale_binary_events() {
        let mut app = AnalystApp::new(&eframe::egui::Context::default());
        let (sender, receiver) = mpsc::sync_channel(3);
        app.events = receiver;
        app.spec = Some(ProgramSpec {
            schema_version: 2,
            binary_sha256: "a".repeat(64),
            target_triple: "x86_64-unknown-elf".to_owned(),
            abi: "System V AMD64".to_owned(),
            file_kind: "executable".to_owned(),
            image_base: None,
            entry_point: None,
            data_layout: None,
            address_spaces: Vec::new(),
            mapped_segments: Vec::new(),
            sections: Vec::new(),
            functions: Vec::new(),
            imports: Vec::new(),
            relocations: Vec::new(),
            calls: Vec::new(),
            references: Vec::new(),
            call_recovery: RecoveryState::NotAttempted,
            reference_recovery: RecoveryState::NotAttempted,
            assumptions: Vec::new(),
            recovery_scope: "test".to_owned(),
            unresolved_control_flow: true,
        });
        let annotation = AnalystAnnotation {
            id: "analyst-1".to_owned(),
            binary_sha256: "a".repeat(64),
            created_revision: 2,
            kind: AnnotationKind::Assumption,
            address: None,
            value: "unverified caller contract".to_owned(),
            scope: "whole binary".to_owned(),
            provenance: FactProvenance {
                source: FactSource::AnalystAssertion,
                scope: "test assertion".to_owned(),
            },
        };
        for _ in 0..2 {
            sender
                .send(Event::AnnotationsLoaded {
                    binary_sha256: "a".repeat(64),
                    annotations: vec![annotation.clone()],
                })
                .unwrap();
            app.poll();
        }
        assert_eq!(app.spec.as_ref().unwrap().assumptions.len(), 1);
        sender
            .send(Event::AnnotationsLoaded {
                binary_sha256: "b".repeat(64),
                annotations: Vec::new(),
            })
            .unwrap();
        app.poll();
        assert_eq!(app.annotations.len(), 1);
        assert_eq!(app.spec.as_ref().unwrap().assumptions.len(), 1);
    }

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

    #[test]
    fn uncertain_remote_mutation_forces_reopen_and_clears_artifacts() {
        let mut app = AnalystApp::new(&eframe::egui::Context::default());
        let (sender, receiver) = mpsc::sync_channel(1);
        app.events = receiver;
        app.remote = true;
        app.project_revision = Some(2);
        app.trusted_fixture = true;
        app.entry_only_assertion = true;
        app.rebuilt_binary_sha256 = Some("rebuild-digest".to_owned());
        app.patch_digest = Some("patch-digest".to_owned());
        sender
            .send(Event::MutationUncertain(
                "request may have committed".to_owned(),
            ))
            .unwrap();
        app.poll();
        assert!(!app.remote);
        assert!(app.project_revision.is_none());
        assert!(!app.trusted_fixture && !app.entry_only_assertion);
        assert!(app.rebuilt_binary_sha256.is_none() && app.patch_digest.is_none());
        assert!(
            app.failure
                .as_deref()
                .unwrap()
                .contains("may have committed")
        );
    }

    #[test]
    fn local_pass_completion_shows_verified_views_and_resets_assertion() {
        let mut app = AnalystApp::new(&eframe::egui::Context::default());
        let (sender, receiver) = mpsc::sync_channel(1);
        app.events = receiver;
        app.trusted_fixture = true;
        sender
            .send(Event::LocalTransformed {
                before: "before".to_owned(),
                after: "after".to_owned(),
                report: "verified".to_owned(),
                c: Ok("generated C".to_owned()),
                output_dir: "/tmp/hydir-test-output".into(),
            })
            .unwrap();
        app.poll();
        assert!(matches!(app.tab, Tab::Passes));
        assert_eq!(app.transform_before.as_deref(), Some("before"));
        assert_eq!(app.ir.as_deref(), Some("after"));
        assert_eq!(app.c.as_deref(), Some("generated C"));
        assert!(!app.trusted_fixture);
    }
}
