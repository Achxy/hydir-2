//! HydIR desktop workbench: a local, asynchronous analyst view over the same
//! native import, CFG recovery, and lifting operations used by the CLI.

use eframe::egui::{self, Color32, RichText};
use egui_graph::{LayoutNode, LayoutParams, NodeId, layout_from_sizes, layout_routed};
use egui_graph_egui::Direction as GraphDirection;
use hydir_analysis::{AnalysisReport, analyze_elf};
use hydir_api::v1::{
    AnnotationRequest, ArtifactRequest, CreateProjectRequest, DiscoverRequest, FunctionRequest,
    JobReply, JobRequest, ProjectRequest, RebuildRequest, StartLiftJobRequest, TransformRequest,
    UploadBinaryRequest, hydir_client::HydirClient,
};
use hydir_api::v2::{
    ArtifactReply as ArtifactReplyV2, PatchRequest as PatchRequestV2, RegionRequest,
    VerifyPatchRequest, hydir_v2_client::HydirV2Client,
};
use hydir_api::v3::{
    ArtifactReply as ArtifactReplyV3, ProgramArtifactRequest, hydir_v3_client::HydirV3Client,
};
use hydir_backend::{
    MAX_BINARY_BYTES, disassemble_elf, import_elf, lift_physical_region, lift_symbol,
    recover_symbol_cfg, region_contract,
};
use hydir_c::{build_decompilation_unit, emit_structured_c};
use hydir_core::{
    Address, AnalystAnnotation, AnnotationKind, DecompilationUnit, DisassemblyReport, FactSource,
    FunctionCfg, FunctionSpec, Location, PhysicalRegionIr, ProgramSpec, RegionSpec,
    overlay_analyst_assumptions, parse_program_spec_json,
};
use hydir_decompile::{
    NativeCoverageReport, NativeDecompilation, decompile_function_at, decompile_symbol,
    discover_functions, emit_pcode_exact_operation_llvm, measure_native_coverage,
};
use hydir_execution::{
    AnalysisRecipe, MAX_ANALYSIS_RECIPE_JSON_BYTES, StopPoint, parse_analysis_recipe,
    validate_analysis_recipe,
};
use hydir_hlc::{
    HighCfgStatement, HighCfgTerminator, HighLevelCfgCir, HighLevelCir, HighStatement,
    emit_typed_c, emit_typed_cfg_c, lower_high_level_cfg_cir, lower_high_level_cir,
};
use hydir_ir::pcode::{
    GhidraSnapshot, MAX_GHIDRA_SNAPSHOT_BYTES, PcodeEffect, PcodeSemanticFunctionIr,
    PcodeStateFunctionIr, PcodeVarnode, parse_ghidra_snapshot,
};
use hydir_ir::{
    Cir, FunctionEvidenceState, FunctionIndex, FunctionIr, IndexedFunction, MachineFunctionIr,
    MachineOperation, StateFunctionIr,
};
use hydir_model::{AnalysisModel, TypeDefinitionKind, import_dwarf, infer_model, init_model};
use hydir_patch::{
    PatchBundle, PatchDocument, PlacementStrategy, compile_patch_binary, parse_patch_bundle_json,
    parse_patch_document,
};
use hydir_project::{LocalAnnotationInput, LocalProject, LocalProjectStore, WorkbenchSettings};
use hydir_recompile::rebuild_bytes;
use hydir_transform::{parse_passes, transform};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{Read, Write},
    net::SocketAddr,
    path::{Path, PathBuf},
    process::{Command, Stdio},
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
const INFO: Color32 = Color32::from_rgb(104, 177, 216);
const VIOLET: Color32 = Color32::from_rgb(180, 145, 222);
const CONSOLE_MIN_HEIGHT: f32 = 100.0;
const CONSOLE_MAX_HEIGHT: f32 = 900.0;
const MAIN_VIEW_MIN_HEIGHT: f32 = 120.0;
const PINNED_OPT: &str = "/usr/bin/opt-14";
const PINNED_CLANG: &str = "/usr/bin/clang-14";

fn resized_console_height(current: f32, drag_delta_y: f32, maximum: f32) -> f32 {
    (current - drag_delta_y).clamp(CONSOLE_MIN_HEIGHT, maximum)
}

enum Task {
    LoadWorkbench,
    SaveWorkbench(WorkbenchSettings),
    Open(PathBuf),
    OpenRecipe(PathBuf),
    OpenGhidraGraph(PathBuf),
    AnalyzeGhidra {
        binary: PathBuf,
        binary_sha256: String,
        function: Option<String>,
    },
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
    SelectNative {
        label: String,
        selector: String,
        entry: Location,
    },
    Disassemble,
    Triton {
        path: PathBuf,
        symbol: String,
    },
    TritonConsole {
        commands: Vec<String>,
    },
    Analyze,
    MeasureNativeCoverage,
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
    PreviewPatch {
        symbol: String,
        replacement: String,
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
        function_index: Result<FunctionIndex, String>,
    },
    RecipeLoaded(Result<AnalysisRecipe, String>),
    GhidraGraphLoaded(Result<GhidraGraph, String>),
    GhidraAnalyzed {
        binary_sha256: String,
        result: Result<GhidraSnapshot, String>,
    },
    RemoteProjectCreated(String),
    Selected {
        symbol: String,
        cfg: Result<FunctionCfg, String>,
        ir: Result<String, String>,
        c: Result<String, String>,
        region_artifacts: Box<RegionArtifacts>,
        native: Box<Result<NativeDecompilation, String>>,
    },
    NativeSelected {
        label: String,
        native: Box<Result<NativeDecompilation, String>>,
        typed: Box<Result<TypedNativeView, String>>,
    },
    Disassembled(Result<DisassemblyReport, String>),
    Triton(Result<serde_json::Value, String>),
    TritonConsole {
        commands: Vec<String>,
        result: Result<serde_json::Value, String>,
    },
    Analyzed(Result<AnalysisReport, String>),
    NativeCoverageMeasured(Result<NativeCoverageReport, String>),
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
    PatchPreview {
        bundle: PatchBundle,
        verification_report: String,
    },
    ArtifactExported {
        path: PathBuf,
        digest: String,
    },
    MutationUncertain(String),
    Failed(String),
}

struct RegionArtifacts {
    region: Result<RegionSpec, String>,
    physical_ir: Result<PhysicalRegionIr, String>,
    decompilation: Result<DecompilationUnit, String>,
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
    let uri: tonic::codegen::http::Uri = endpoint
        .parse()
        .map_err(|_| "Remote endpoint is not a valid URI.".to_owned())?;
    let scheme = uri.scheme_str().ok_or("Remote endpoint has no scheme.")?;
    let authority = uri
        .authority()
        .ok_or("Remote endpoint has no host authority.")?;
    if authority.as_str().contains('@')
        || uri
            .path_and_query()
            .is_some_and(|path| path.as_str() != "/")
    {
        return Err("Remote endpoint must not contain credentials, a path, or a query.".to_owned());
    }
    match scheme {
        "http" => {
            let address: SocketAddr = authority.as_str().parse().map_err(|_| {
                "Plaintext endpoint must use a numeric loopback address and port.".to_owned()
            })?;
            if !address.ip().is_loopback() {
                return Err("Plaintext non-loopback remote connections are refused.".to_owned());
            }
        }
        "https" if !authority.host().is_empty() => {}
        "https" => return Err("TLS endpoint has no host.".to_owned()),
        _ => return Err("Remote endpoint scheme must be http or https.".to_owned()),
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
    if !valid_bearer_token(&token) {
        return Err(
            "Credential file must contain a bounded static token or compact JWT.".to_owned(),
        );
    }
    Ok(token)
}

fn valid_bearer_token(token: &str) -> bool {
    let static_token = token.len() == 64 && token.bytes().all(|byte| byte.is_ascii_hexdigit());
    let compact_jwt = token.len() <= 16 * 1024
        && token.split('.').count() == 3
        && token.split('.').all(|segment| {
            !segment.is_empty()
                && segment
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        });
    static_token || compact_jwt
}

fn authorized<T>(value: T, token: &str) -> Request<T> {
    let mut request = Request::new(value);
    let credential = format!("Bearer {token}")
        .parse::<MetadataValue<_>>()
        .expect("validated ASCII bearer token");
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

async fn remote_v2_client(access: &RemoteAccess) -> Result<HydirV2Client<Channel>, String> {
    let channel = Channel::from_shared(access.endpoint.clone())
        .map_err(|e| format!("Invalid endpoint: {e}"))?
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(30))
        .connect()
        .await
        .map_err(|e| format!("Cannot connect to HydIR v2 service: {e}"))?;
    Ok(HydirV2Client::new(channel).max_decoding_message_size(2 * 1024 * 1024 + 1024))
}

async fn remote_v3_client(access: &RemoteAccess) -> Result<HydirV3Client<Channel>, String> {
    let channel = Channel::from_shared(access.endpoint.clone())
        .map_err(|e| format!("Invalid endpoint: {e}"))?
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(30))
        .connect()
        .await
        .map_err(|e| format!("Cannot connect to HydIR v3 service: {e}"))?;
    Ok(HydirV3Client::new(channel).max_decoding_message_size(MAX_BINARY_BYTES + 1024))
}

fn decode_v2_artifact<T: serde::de::DeserializeOwned>(
    artifact: ArtifactReplyV2,
    access: &RemoteAccess,
    expected_media_type: &str,
) -> Result<T, String> {
    if artifact.project_revision != access.revision
        || artifact.media_type != expected_media_type
        || format!("{:x}", Sha256::digest(&artifact.content)) != artifact.sha256
    {
        return Err(format!(
            "Remote {expected_media_type} artifact failed revision, digest, or media-type verification."
        ));
    }
    serde_json::from_slice(&artifact.content)
        .map_err(|error| format!("Invalid remote {expected_media_type} artifact: {error}"))
}

fn decode_v3_artifact<T: serde::de::DeserializeOwned>(
    artifact: ArtifactReplyV3,
    access: &RemoteAccess,
    expected_media_type: &str,
) -> Result<T, String> {
    if artifact.project_revision != access.revision
        || artifact.media_type != expected_media_type
        || format!("{:x}", Sha256::digest(&artifact.content)) != artifact.sha256
    {
        return Err(format!(
            "Remote {expected_media_type} artifact failed revision, digest, or media-type verification."
        ));
    }
    serde_json::from_slice(&artifact.content)
        .map_err(|error| format!("Invalid remote {expected_media_type} artifact: {error}"))
}

async fn remote_native_json<T: serde::de::DeserializeOwned>(
    access: &RemoteAccess,
    stage: &str,
    function_selector: &str,
    media_type: &str,
) -> Result<T, String> {
    let mut client = remote_v3_client(access).await?;
    let artifact = client
        .get_program_artifact(authorized(
            ProgramArtifactRequest {
                project_id: access.project_id.clone(),
                expected_revision: access.revision,
                stage: stage.to_owned(),
                function_selector: function_selector.to_owned(),
            },
            &access.token,
        ))
        .await
        .map_err(|error| format!("Remote native {stage} recovery failed: {error}"))?
        .into_inner();
    decode_v3_artifact(artifact, access, media_type)
}

async fn remote_function_index(access: &RemoteAccess) -> Result<FunctionIndex, String> {
    remote_native_json(
        access,
        "function_index",
        "",
        "application/vnd.hydir.function-index+json;version=1",
    )
    .await
}

async fn remote_native_decompilation(
    access: &RemoteAccess,
    selector: &str,
) -> Result<NativeDecompilation, String> {
    let machine_ir: MachineFunctionIr = remote_native_json(
        access,
        "machine",
        selector,
        "application/vnd.hydir.machine-ir+json;version=1",
    )
    .await?;
    let state_ir: StateFunctionIr = remote_native_json(
        access,
        "state",
        selector,
        "application/vnd.hydir.state-ir+json;version=1",
    )
    .await?;
    let function_ir: FunctionIr = remote_native_json(
        access,
        "function",
        selector,
        "application/vnd.hydir.function-ir+json;version=1",
    )
    .await?;
    let cir: Cir = remote_native_json(
        access,
        "cir",
        selector,
        "application/vnd.hydir.cir+json;version=1",
    )
    .await?;
    let unit: DecompilationUnit = remote_native_json(
        access,
        "unit",
        selector,
        "application/vnd.hydir.decompilation-unit+json;version=2",
    )
    .await?;
    if machine_ir.binary_sha256 != state_ir.binary_sha256
        || machine_ir.binary_sha256 != function_ir.binary_sha256
        || machine_ir.binary_sha256 != cir.binary_sha256
        || machine_ir.binary_sha256 != unit.binary_sha256
        || machine_ir.function_id != state_ir.function_id
        || machine_ir.function_id != function_ir.function_id
        || machine_ir.function_id != cir.function_id
        || unit.function_id.as_deref() != Some(machine_ir.function_id.as_str())
        || machine_ir.entry != state_ir.entry
        || machine_ir.entry != function_ir.entry
        || machine_ir.entry != cir.entry
    {
        return Err("Remote native artifacts do not share one binary/function identity".to_owned());
    }
    Ok(NativeDecompilation {
        machine_ir,
        state_ir,
        function_ir,
        cir,
        low_level_c: unit.low_level_c.unwrap_or(unit.c_source),
        structured_c: unit.structured_c,
        diagnostics: unit.diagnostics,
    })
}

fn local_region_artifacts(
    bytes: &[u8],
    symbol: &str,
    ir: &Result<String, String>,
) -> RegionArtifacts {
    let region = region_contract(bytes, symbol).map_err(|error| error.to_string());
    let physical_ir = region
        .as_ref()
        .map_err(Clone::clone)
        .and_then(|region| lift_physical_region(region).map_err(|error| error.to_string()));
    let decompilation = region.as_ref().map_err(Clone::clone).and_then(|region| {
        ir.as_ref().map_err(Clone::clone).and_then(|ir| {
            build_decompilation_unit(
                region.clone(),
                ir.clone(),
                concat!("hydir-gui/", env!("CARGO_PKG_VERSION")),
            )
        })
    });
    RegionArtifacts {
        region,
        physical_ir,
        decompilation,
    }
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
    let spec: ProgramSpec = parse_program_spec_json(reply.json.as_bytes())
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
    Result<RegionSpec, String>,
    Result<PhysicalRegionIr, String>,
    Result<DecompilationUnit, String>,
) {
    let mut client = match remote_client(access).await {
        Ok(client) => client,
        Err(error) => {
            return (
                Err(error.clone()),
                Err(error.clone()),
                Err(error.clone()),
                Err(error.clone()),
                Err(error.clone()),
                Err(error),
            );
        }
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
    let mut client_v2 = match remote_v2_client(access).await {
        Ok(client) => client,
        Err(error) => {
            return (
                cfg,
                ir,
                c,
                Err(error.clone()),
                Err(error.clone()),
                Err(error),
            );
        }
    };
    let region_request = RegionRequest {
        project_id: access.project_id.clone(),
        expected_revision: access.revision,
        function_symbol: symbol.to_owned(),
        assume_u64x2: true,
    };
    let region = client_v2
        .get_region(authorized(region_request.clone(), &access.token))
        .await
        .map_err(|error| format!("Remote RegionSpec recovery failed: {error}"))
        .and_then(|reply| {
            decode_v2_artifact(
                reply.into_inner(),
                access,
                "application/vnd.hydir.region-spec+json;version=3",
            )
        });
    let physical_ir = client_v2
        .lift_region(authorized(region_request.clone(), &access.token))
        .await
        .map_err(|error| format!("Remote PhysicalRegionIR recovery failed: {error}"))
        .and_then(|reply| {
            decode_v2_artifact(
                reply.into_inner(),
                access,
                "application/vnd.hydir.physical-region-ir+json;version=1",
            )
        });
    let decompilation = client_v2
        .decompile_region(authorized(region_request, &access.token))
        .await
        .map_err(|error| format!("Remote DecompilationUnit recovery failed: {error}"))
        .and_then(|reply| {
            decode_v2_artifact(
                reply.into_inner(),
                access,
                "application/vnd.hydir.decompilation-unit+json;version=1",
            )
        });
    (cfg, ir, c, region, physical_ir, decompilation)
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
    let spec: ProgramSpec = parse_program_spec_json(inspected.json.as_bytes())
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
    let spec: ProgramSpec = parse_program_spec_json(inspection.json.as_bytes())
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
    parse_patch_document(&bytes)?;
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
    let (document, _) = parse_patch_document(&document)?;
    let patched = compile_patch_binary(binary, &document)?;
    let spec = import_elf(&patched.content)
        .map_err(|error| format!("Patched ELF failed import: {error}"))?;
    if spec.binary_sha256 != patched.patched_sha256 {
        return Err("Patched ELF model digest differs from produced bytes.".to_owned());
    }
    write_new_elf(output_path, &patched.content)?;
    Ok((patched.content, spec, patched.patched_sha256))
}

fn preview_patch_local(
    binary: &[u8],
    symbol: &str,
    replacement: &str,
) -> Result<(PatchBundle, String), String> {
    let digest = format!("{:x}", Sha256::digest(binary));
    let document = patch_document(&digest, symbol, replacement)?;
    let (document, _) = parse_patch_document(&document)?;
    let result = compile_patch_binary(binary, &document)?;
    Ok((
        result.bundle,
        "Structural verification passed locally. Behavior execution was not run.".to_owned(),
    ))
}

async fn preview_patch_remote(
    access: &RemoteAccess,
    symbol: &str,
    replacement: &str,
) -> Result<(PatchBundle, String), String> {
    let mut legacy = remote_client(access).await?;
    let current = legacy
        .get_project(authorized(
            ProjectRequest {
                project_id: access.project_id.clone(),
                expected_revision: access.revision,
            },
            &access.token,
        ))
        .await
        .map_err(|error| format!("Could not verify current project before preview: {error}"))?
        .into_inner();
    if current.revision != access.revision || current.binary_sha256.is_empty() {
        return Err("Remote project revision changed; reopen it before previewing.".to_owned());
    }
    let patch_json = patch_document(&current.binary_sha256, symbol, replacement)?;
    let request = PatchRequestV2 {
        project_id: access.project_id.clone(),
        expected_revision: access.revision,
        idempotency_key: uuid::Uuid::new_v4().to_string(),
        patch_json,
        trusted_fixture: true,
        assume_u64x2: true,
        assume_entry_only: true,
    };
    let mut client = remote_v2_client(access).await?;
    let artifact = client
        .compile_patch(authorized(request, &access.token))
        .await
        .map_err(|error| format!("Remote PatchLang preview failed: {error}"))?
        .into_inner();
    if artifact.project_revision != access.revision
        || artifact.media_type != "application/vnd.hydir.patch-bundle+json;version=2"
        || format!("{:x}", Sha256::digest(&artifact.content)) != artifact.sha256
    {
        return Err("Remote PatchBundle preview failed digest/type/revision checks.".to_owned());
    }
    let bundle = parse_patch_bundle_json(&artifact.content)?;
    let verification = client
        .verify_patch(authorized(
            VerifyPatchRequest {
                project_id: access.project_id.clone(),
                expected_revision: access.revision,
                patch_bundle_json: artifact.content,
            },
            &access.token,
        ))
        .await
        .map_err(|error| format!("Remote PatchBundle verification failed: {error}"))?
        .into_inner();
    if !verification.structurally_valid {
        return Err("Remote service rejected the PatchBundle structure.".to_owned());
    }
    Ok((bundle, verification.report_json))
}

async fn patch_remote(
    access: &RemoteAccess,
    symbol: &str,
    replacement: &str,
    key: &str,
) -> Result<(u64, ProgramSpec, String), String> {
    let mut legacy = remote_client(access).await?;
    let current = legacy
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
    let mut client = remote_v2_client(access).await?;
    let reply = client
        .apply_patch(authorized(
            PatchRequestV2 {
                project_id: access.project_id.clone(),
                expected_revision: access.revision,
                idempotency_key: key.to_owned(),
                patch_json: document,
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
        || reply.binary_sha256.len() != 64
        || reply.patch_bundle_sha256.len() != 64
    {
        return Err(
            "Patch returned an unexpected project, revision, or artifact digest.".to_owned(),
        );
    }
    let artifact = legacy
        .get_artifact(authorized(
            ArtifactRequest {
                project_id: access.project_id.clone(),
                sha256: reply.binary_sha256.clone(),
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
    let project = legacy
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

fn bounded_read_recipe(path: &Path) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    fs::File::open(path)
        .map_err(|error| format!("Cannot open investigation recipe: {error}"))?
        .take((MAX_ANALYSIS_RECIPE_JSON_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("Cannot read investigation recipe: {error}"))?;
    if bytes.len() > MAX_ANALYSIS_RECIPE_JSON_BYTES {
        return Err("Investigation recipe exceeds the 24 MiB limit".to_owned());
    }
    Ok(bytes)
}

fn recipe_elf_address(recipe: &AnalysisRecipe, runtime_address: u64) -> Option<u64> {
    let stop = recipe.snapshot.stop.as_ref()?;
    let code_length = recipe.resume_plan.code_hex.len() / 2;
    captured_code_elf_address(
        stop,
        recipe.resume_plan.code_address,
        code_length,
        runtime_address,
    )
}

fn captured_code_elf_address(
    stop: &StopPoint,
    code_address: u64,
    code_length: usize,
    runtime_address: u64,
) -> Option<u64> {
    let code_end = code_address.checked_add(code_length as u64)?;
    if stop.runtime_pc != code_address || !(code_address..code_end).contains(&runtime_address) {
        return None;
    }
    let offset = runtime_address.checked_sub(stop.runtime_pc)?;
    let translated = runtime_address.checked_sub(stop.load_bias?)?;
    (translated == stop.elf_vaddr?.checked_add(offset)?).then_some(translated)
}

fn hydirctl_path() -> PathBuf {
    if let Ok(executable) = std::env::current_exe() {
        let sibling = executable.with_file_name(if cfg!(windows) {
            "hydirctl.exe"
        } else {
            "hydirctl"
        });
        if sibling.is_file() {
            return sibling;
        }
    }
    PathBuf::from(if cfg!(windows) {
        "hydirctl.exe"
    } else {
        "hydirctl"
    })
}

fn ghidra_snapshot_path(binary_sha256: &str, function: Option<&str>) -> Result<PathBuf, String> {
    if binary_sha256.len() != 64
        || !binary_sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err("Invalid opened binary digest for Ghidra cache".to_owned());
    }
    let key = match function {
        Some(entry) => {
            let digits = entry
                .strip_prefix("0x")
                .ok_or("Ghidra function entry must be a hex address".to_owned())?;
            let address = u64::from_str_radix(digits, 16)
                .map_err(|_| "Invalid Ghidra function entry".to_owned())?;
            format!("entry-{address:016x}")
        }
        None => "default".to_owned(),
    };
    #[cfg(target_os = "windows")]
    let base = std::env::var_os("LOCALAPPDATA")
        .or_else(|| std::env::var_os("APPDATA"))
        .map(PathBuf::from)
        .ok_or("Cannot determine the Windows user cache directory".to_owned())?;
    #[cfg(target_os = "macos")]
    let base = std::env::var_os("HOME")
        .map(|home| PathBuf::from(home).join("Library/Caches"))
        .ok_or("Cannot determine the macOS user cache directory".to_owned())?;
    #[cfg(target_os = "linux")]
    let base = std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".cache")))
        .ok_or("Cannot determine the Linux user cache directory".to_owned())?;
    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    let base = std::env::temp_dir();
    let output_dir = base.join("HydIR").join("ghidra").join(binary_sha256);
    fs::create_dir_all(&output_dir)
        .map_err(|error| format!("Could not prepare Ghidra cache directory: {error}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&output_dir, fs::Permissions::from_mode(0o700))
            .map_err(|error| format!("Could not protect Ghidra cache directory: {error}"))?;
    }
    Ok(output_dir.join(format!("{key}.json")))
}

fn run_ghidra_cli(
    binary: &Path,
    binary_sha256: &str,
    function: Option<&str>,
) -> Result<GhidraSnapshot, String> {
    let snapshot_path = ghidra_snapshot_path(binary_sha256, function)?;
    {
        let mut command = Command::new(hydirctl_path());
        command
            .args(["ghidra", "analyze"])
            .arg(binary)
            .arg("--output")
            .arg(&snapshot_path);
        if let Some(function) = function {
            command.arg("--function").arg(function);
        }
        let output = command
            .output()
            .map_err(|error| format!("Could not start automatic Ghidra analysis: {error}"))?;
        if !output.status.success() {
            let detail = if output.stderr.is_empty() {
                &output.stdout
            } else {
                &output.stderr
            };
            let detail = String::from_utf8_lossy(detail);
            return Err(format!(
                "Ghidra analysis failed ({}): {}",
                output.status,
                detail.chars().take(4096).collect::<String>().trim()
            ));
        }
        let size = fs::metadata(&snapshot_path)
            .map_err(|error| format!("Ghidra did not produce a snapshot: {error}"))?
            .len();
        if size == 0 || size > MAX_GHIDRA_SNAPSHOT_BYTES as u64 {
            return Err("Ghidra snapshot is empty or exceeds the GUI import limit".to_owned());
        }
        let bytes = fs::read(&snapshot_path)
            .map_err(|error| format!("Could not read Ghidra snapshot: {error}"))?;
        parse_ghidra_snapshot(&bytes, binary_sha256)
    }
}

fn pcode_varnode(varnode: &PcodeVarnode) -> String {
    format!("{}:{}[{}]", varnode.space, varnode.offset, varnode.size)
}

fn pcode_display_lines(
    snapshot: &GhidraSnapshot,
    semantics: Option<&PcodeSemanticFunctionIr>,
) -> Vec<(Option<u64>, String)> {
    let mut lines = Vec::new();
    for (instruction_index, instruction) in
        snapshot.selected_function.instructions.iter().enumerate()
    {
        let address =
            u64::from_str_radix(instruction.address.offset.trim_start_matches("0x"), 16).ok();
        lines.push((
            address,
            format!(
                "{}:{}  {:<20} {}",
                instruction.address.space,
                instruction.address.offset,
                instruction.bytes,
                instruction.mnemonic
            ),
        ));
        for (operation_index, operation) in instruction.pcode.iter().enumerate() {
            let effect = semantics
                .and_then(|semantics| semantics.instructions.get(instruction_index))
                .and_then(|instruction| instruction.operations.get(operation_index))
                .map(|operation| match &operation.effect {
                    PcodeEffect::Assign { operation, .. } => format!(" [exact {operation:?}]"),
                    PcodeEffect::Opaque { reason, .. } => format!(" [opaque: {reason}]"),
                })
                .unwrap_or_default();
            let output = operation
                .output
                .as_ref()
                .map(|varnode| format!("{} = ", pcode_varnode(varnode)))
                .unwrap_or_default();
            let inputs = operation
                .inputs
                .iter()
                .map(pcode_varnode)
                .collect::<Vec<_>>()
                .join(", ");
            let userop = operation
                .userop_name
                .as_ref()
                .map(|name| format!(" [{name}]"))
                .unwrap_or_default();
            lines.push((
                address,
                format!(
                    "    {}:{} #{}:{}  {}{}{}({}){}",
                    operation.source_address.space,
                    operation.source_address.offset,
                    operation.sequence_index,
                    operation.sequence_time,
                    output,
                    operation.mnemonic,
                    userop,
                    inputs,
                    effect
                ),
            ));
        }
    }
    lines
}

fn pcode_state_lines(state: &PcodeStateFunctionIr) -> Vec<(Option<u64>, String)> {
    let mut lines = Vec::new();
    for instruction in &state.instructions {
        let address =
            u64::from_str_radix(instruction.address.offset.trim_start_matches("0x"), 16).ok();
        for (index, operation) in instruction.operations.iter().enumerate() {
            let accesses = operation
                .accesses
                .iter()
                .map(|access| {
                    let ordinal = access
                        .input_index
                        .map_or(String::new(), |index| format!("{index}:"));
                    format!(
                        "{:?} {ordinal}{}:{}[{}]",
                        access.kind,
                        access.varnode.space,
                        access.varnode.offset,
                        access.varnode.size
                    )
                })
                .collect::<Vec<_>>()
                .join("  ");
            let effect = match &operation.effect {
                PcodeEffect::Assign { operation, .. } => format!("{operation:?}"),
                PcodeEffect::Opaque { class, .. } => format!("opaque {class:?}"),
            };
            lines.push((
                address,
                format!(
                    "{}:{} #{index} {:<20} {accesses}{}",
                    instruction.address.space,
                    instruction.address.offset,
                    effect,
                    if operation.may_clobber_unlisted_state {
                        "  possible unlisted state clobber"
                    } else {
                        ""
                    }
                ),
            ));
        }
    }
    lines
}

fn run_triton_cli(path: &Path, symbol: &str) -> Result<serde_json::Value, String> {
    let path_text = path.display().to_string();
    let output = Command::new(hydirctl_path())
        .args(["triton", &path_text, symbol])
        .output()
        .map_err(|error| format!("Could not start hydirctl Triton command: {error}"))?;
    if !output.status.success() {
        let detail = String::from_utf8_lossy(&output.stderr);
        return Err(format!("Triton analysis failed: {}", detail.trim()));
    }
    if output.stdout.len() > 1024 * 1024 {
        return Err("Triton result exceeds the 1 MiB GUI limit".to_owned());
    }
    let result: serde_json::Value = serde_json::from_slice(&output.stdout)
        .map_err(|error| format!("Triton returned invalid JSON: {error}"))?;
    if result.get("backend").and_then(serde_json::Value::as_str) != Some("triton") {
        return Err("Triton result has an unexpected backend".to_owned());
    }
    Ok(result)
}

fn run_triton_console_cli(commands: &[String]) -> Result<serde_json::Value, String> {
    let request = serde_json::json!({
        "schema_version": 1,
        "operation": "console",
        "commands": commands,
    });
    let input = serde_json::to_vec(&request)
        .map_err(|error| format!("Could not encode Triton console request: {error}"))?;
    let mut child = Command::new(hydirctl_path())
        .arg("triton-console")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("Could not start the Triton console: {error}"))?;
    child
        .stdin
        .take()
        .ok_or("Triton console stdin is unavailable".to_owned())?
        .write_all(&input)
        .map_err(|error| format!("Could not send Triton console command: {error}"))?;
    let output = child
        .wait_with_output()
        .map_err(|error| format!("Could not read Triton console output: {error}"))?;
    if !output.status.success() {
        let detail = String::from_utf8_lossy(&output.stderr);
        return Err(format!("Triton console failed: {}", detail.trim()));
    }
    if output.stdout.len() > 1024 * 1024 {
        return Err("Triton console result exceeds the 1 MiB GUI limit".to_owned());
    }
    let result: serde_json::Value = serde_json::from_slice(&output.stdout)
        .map_err(|error| format!("Triton console returned invalid JSON: {error}"))?;
    if result.get("operation").and_then(serde_json::Value::as_str) != Some("console") {
        return Err("Triton console returned an unexpected operation".to_owned());
    }
    Ok(result)
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
    input: LocalAnnotationInput<'_>,
) -> Result<(LocalProject, ProgramSpec, Vec<AnalystAnnotation>), String> {
    let mut spec =
        import_elf(bytes).map_err(|error| format!("Local ELF import failed: {error}"))?;
    if spec.binary_sha256 != binary_sha256 || project.binary_sha256 != binary_sha256 {
        return Err("Local annotation binary differs from the selected ELF".to_owned());
    }
    let mut store = LocalProjectStore::open_default()?;
    let updated = store.add_annotation(project, &spec, input)?;
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
                    let function_index = discover_functions(&bytes);
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
                        function_index,
                    }
                }
                Err(error) => Event::Failed(error),
            },
            Task::OpenRecipe(path) => {
                let result = match &source {
                    Source::Local(elf) => bounded_read_recipe(&path).and_then(|json| {
                        let recipe = parse_analysis_recipe(&json)?;
                        validate_analysis_recipe(elf, &recipe)
                            .map_err(|error| format!("Recipe verification failed: {error}"))?;
                        Ok(recipe)
                    }),
                    _ => Err("Open the matching local ELF before loading a recipe".to_owned()),
                };
                Event::RecipeLoaded(result)
            }
            Task::OpenGhidraGraph(path) => match fs::read_to_string(&path)
                .map_err(|error| format!("Could not read Ghidra graph: {error}"))
                .and_then(|text| {
                    serde_json::from_str::<GhidraGraph>(&text)
                        .map_err(|error| format!("Invalid Ghidra graph JSON: {error}"))
                }) {
                Ok(graph) => Event::GhidraGraphLoaded(Ok(graph)),
                Err(error) => Event::GhidraGraphLoaded(Err(error)),
            },
            Task::AnalyzeGhidra {
                binary,
                binary_sha256,
                function,
            } => {
                let completion = events.clone();
                let repaint = ctx.clone();
                thread::spawn(move || {
                    let result = run_ghidra_cli(&binary, &binary_sha256, function.as_deref());
                    let _ = completion.send(Event::GhidraAnalyzed {
                        binary_sha256,
                        result,
                    });
                    repaint.request_repaint();
                });
                continue;
            },
            Task::OpenRemote {
                endpoint,
                token_file,
                project_id,
            } => match runtime.block_on(open_remote(endpoint, token_file, project_id)) {
                Ok((access, spec)) => {
                    let function_index = runtime.block_on(remote_function_index(&access));
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
                        function_index,
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
                    let function_index = runtime.block_on(remote_function_index(&access));
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
                        function_index,
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
                    let region_artifacts = local_region_artifacts(bytes, &symbol, &ir);
                    Event::Selected {
                        cfg: recover_symbol_cfg(bytes, &symbol).map_err(|e| e.to_string()),
                        ir,
                        c,
                        region_artifacts: Box::new(region_artifacts),
                        native: Box::new(decompile_symbol(bytes, &symbol)),
                        symbol,
                    }
                }
                Source::Remote(access) => {
                    let (cfg, ir, c, region, physical_ir, decompilation) =
                        runtime.block_on(select_remote(access, &symbol));
                    let native = runtime.block_on(remote_native_decompilation(access, &symbol));
                    Event::Selected {
                        symbol,
                        cfg,
                        ir,
                        c,
                        region_artifacts: Box::new(RegionArtifacts {
                            region,
                            physical_ir,
                            decompilation,
                        }),
                        native: Box::new(native),
                    }
                }
                Source::None => {
                    Event::Failed("Open a local ELF or remote project first.".to_owned())
                }
            },
            Task::SelectNative {
                label,
                selector,
                entry,
            } => {
                let native = match &source {
                    Source::Local(bytes) => decompile_function_at(bytes, entry),
                    Source::Remote(access) => {
                        runtime.block_on(remote_native_decompilation(access, &selector))
                    }
                    Source::None => Err("Open an ELF before selecting a function".to_owned()),
                };
                let typed = match (&source, &native) {
                    (Source::Local(bytes), Ok(native)) => {
                        local_typed_view(bytes, local_project.as_ref(), native)
                    }
                    (Source::Remote(_), _) => Err("Typed model view is local-only in this desktop release".to_owned()),
                    (_, Err(error)) => Err(error.clone()),
                    _ => Err("Open a local ELF to inspect typed C".to_owned()),
                };
                Event::NativeSelected {
                    native: Box::new(native),
                    typed: Box::new(typed),
                    label,
                }
            }
            Task::Disassemble => Event::Disassembled(match &source {
                Source::Local(bytes) => disassemble_elf(bytes).map_err(|error| error.to_string()),
                Source::Remote(_) => {
                    Err("Whole-ELF disassembly is currently local-only.".to_owned())
                }
                Source::None => Err("Open a local ELF before disassembling it.".to_owned()),
            }),
            Task::Triton { path, symbol } => Event::Triton(run_triton_cli(&path, &symbol)),
            Task::TritonConsole { commands } => Event::TritonConsole {
                result: run_triton_console_cli(&commands),
                commands,
            },
            Task::Analyze => Event::Analyzed(match &source {
                Source::Local(bytes) => analyze_elf(bytes).map_err(|error| error.to_string()),
                Source::Remote(access) => runtime.block_on(analyze_remote(access)),
                Source::None => Err("Open a local ELF or remote project first.".to_owned()),
            }),
            Task::MeasureNativeCoverage => Event::NativeCoverageMeasured(match &source {
                Source::Local(bytes) => measure_native_coverage(bytes),
                Source::Remote(_) => Err(
                    "Native coverage measurement is currently local-only; remote artifacts remain available through gRPC v3."
                        .to_owned(),
                ),
                Source::None => Err("Open a local ELF before measuring coverage.".to_owned()),
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
                                LocalAnnotationInput {
                                    kind,
                                    address: address.map(Address),
                                    scope: &scope,
                                    value: &value,
                                    idempotency_key: &key,
                                },
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
            Task::PreviewPatch {
                symbol,
                replacement,
            } => match &source {
                Source::Local(bytes) => preview_patch_local(bytes, &symbol, &replacement)
                    .map(|(bundle, verification_report)| Event::PatchPreview {
                        bundle,
                        verification_report,
                    })
                    .unwrap_or_else(Event::Failed),
                Source::Remote(access) => runtime
                    .block_on(preview_patch_remote(access, &symbol, &replacement))
                    .map(|(bundle, verification_report)| Event::PatchPreview {
                        bundle,
                        verification_report,
                    })
                    .unwrap_or_else(Event::Failed),
                Source::None => Event::Failed(
                    "Open a local ELF or remote project before previewing a patch.".to_owned(),
                ),
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
    Overview,
    GhidraPcode,
    Investigation,
    RegionStudio,
    Native,
    Bytes,
    Graph,
    Cfg,
    Coverage,
    Llvm,
    Passes,
    C,
    Analysis,
}

enum COutputSource<'a> {
    Scalar(&'a str),
    Native(&'a NativeDecompilation),
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum RegionStudioMode {
    Contract,
    MachineIr,
    DecompilePatch,
    Evidence,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum ConsoleMode {
    Activity,
    Triton,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum GraphMode {
    Function,
    Program,
    Ghidra,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum NativeViewMode {
    Summary,
    TypedC,
    Types,
    LowLevelC,
    StructuredC,
    MachineIr,
    StateIr,
    FunctionIr,
    Cir,
    Evidence,
}

struct TypedNativeView {
    model: AnalysisModel,
    ir: Option<HighLevelCir>,
    cfg_ir: Option<HighLevelCfgCir>,
    c: Option<String>,
    diagnostic: Option<String>,
}

fn local_typed_view(
    bytes: &[u8],
    project: Option<&LocalProject>,
    native: &NativeDecompilation,
) -> Result<TypedNativeView, String> {
    let saved = project
        .map(|project| LocalProjectStore::open_default()?.load_model(project))
        .transpose()?
        .flatten();
    let model = if let Some(model) = saved {
        model
    } else {
        let mut model = init_model(bytes)?;
        let _ = import_dwarf(bytes, &mut model)?;
        infer_model(&mut model, &[(&native.machine_ir, &native.function_ir)])?;
        model
    };
    hydir_model::validate_model(bytes, &model)?;
    let (ir, cfg_ir, c, diagnostic) =
        match lower_high_level_cir(&native.machine_ir, &native.function_ir, &model) {
            Ok(ir) => match emit_typed_c(&ir, &model) {
                Ok(c) => (Some(ir), None, Some(c), None),
                Err(error) => (Some(ir), None, None, Some(error)),
            },
            Err(linear_error) => {
                match lower_high_level_cfg_cir(&native.machine_ir, &native.function_ir, &model) {
                    Ok(cfg) => match emit_typed_cfg_c(&cfg, &model) {
                        Ok(c) => (None, Some(cfg), Some(c), None),
                        Err(error) => (None, Some(cfg), None, Some(error)),
                    },
                    Err(cfg_error) => (
                        None,
                        None,
                        None,
                        Some(format!("Linear: {linear_error}; CFG: {cfg_error}")),
                    ),
                }
            }
        };
    // The model remains available for type inspection even when typed C is
    // outside the current lowering contract.
    Ok(TypedNativeView {
        model,
        ir,
        cfg_ir,
        c,
        diagnostic,
    })
}

fn typed_source_sites(
    ui: &mut egui::Ui,
    ir: &HighLevelCir,
    selected_address: Option<u64>,
) -> Option<u64> {
    let mut selected = None;
    for statement in &ir.statements {
        let (label, site) = match statement {
            HighStatement::Let { name, site, .. } => (format!("local {name}"), site),
            HighStatement::StoreField { field, site, .. } => (format!("store {field}"), site),
            HighStatement::Return { site, .. } => ("return".to_owned(), site),
        };
        if ui
            .selectable_label(
                selected_address == Some(site.value.0),
                format!("0x{:x} · {label}", site.value.0),
            )
            .clicked()
        {
            selected = Some(site.value.0);
        }
    }
    selected
}

fn typed_cfg_source_sites(
    ui: &mut egui::Ui,
    ir: &HighLevelCfgCir,
    selected_address: Option<u64>,
) -> Option<u64> {
    let mut selected = None;
    for block in &ir.blocks {
        for statement in &block.statements {
            let (label, site) = match statement {
                HighCfgStatement::Assign { target, site, .. } => (target.as_str(), site),
                HighCfgStatement::Load { target, site, .. } => (target.as_str(), site),
                HighCfgStatement::Store { site, .. } => ("store", site),
            };
            if ui
                .selectable_label(
                    selected_address == Some(site.value.0),
                    format!("0x{:x} · {label}", site.value.0),
                )
                .clicked()
            {
                selected = Some(site.value.0);
            }
        }
        let (label, site) = match &block.terminator {
            HighCfgTerminator::Goto { site, .. } => ("goto", site),
            HighCfgTerminator::Branch { site, .. } => ("branch", site),
            HighCfgTerminator::Return { site, .. } => ("return", site),
        };
        if ui
            .selectable_label(
                selected_address == Some(site.value.0),
                format!("0x{:x} · {label}", site.value.0),
            )
            .clicked()
        {
            selected = Some(site.value.0);
        }
    }
    selected
}

fn typed_types_view(ui: &mut egui::Ui, model: &AnalysisModel) -> Option<u64> {
    ui.label(format!(
        "Model revision {} · {} types · {} functions · {} unresolved conflicts",
        model.revision,
        model.types.len(),
        model.functions.len(),
        model.conflicts.len()
    ));
    let mut selected = None;
    for ty in &model.types {
        ui.collapsing(
            format!(
                "{} · {} bytes{}",
                ty.name,
                ty.size_bytes,
                if ty.size_is_lower_bound {
                    " or more"
                } else {
                    ""
                }
            ),
            |ui| match &ty.kind {
                TypeDefinitionKind::Struct { fields } | TypeDefinitionKind::Union { fields } => {
                    for field in fields {
                        ui.label(format!(
                            "+0x{:x}  {}: {:?}",
                            field.offset_bytes, field.name, field.ty
                        ));
                        for evidence in &field.evidence {
                            if let Some(site) = evidence.site {
                                if ui
                                    .small_button(format!(
                                        "0x{:x} · {:?}: {}",
                                        site.value.0, evidence.source, evidence.detail
                                    ))
                                    .clicked()
                                {
                                    selected = Some(site.value.0);
                                }
                            }
                        }
                    }
                }
                TypeDefinitionKind::Enum { variants, .. } => {
                    for (name, value) in variants {
                        ui.label(format!("{name} = {value}"));
                    }
                }
                TypeDefinitionKind::Alias { target } => {
                    ui.label(format!("Alias of {target:?}"));
                }
            },
        );
    }
    for conflict in &model.conflicts {
        ui.colored_label(ACCENT, format!("{}: {}", conflict.subject, conflict.detail));
    }
    selected
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum GraphNodeTone {
    Normal,
    Selected,
    Opaque,
    External,
}

#[derive(Clone)]
enum GraphNodeAction {
    Address(u64),
    Function {
        label: String,
        selector: String,
        entry: Location,
        legacy_symbol: bool,
    },
}

struct WorkbenchGraphNode {
    id: NodeId,
    label: String,
    tone: GraphNodeTone,
    action: Option<GraphNodeAction>,
}

struct WorkbenchGraphEdge {
    source: NodeId,
    target: NodeId,
    label: String,
    unresolved: bool,
}

struct AnalystApp {
    tasks: SyncSender<Task>,
    events: Receiver<Event>,
    path_input: String,
    recipe_path_input: String,
    ghidra_graph_path: String,
    workbench: WorkbenchSettings,
    workbench_loaded: bool,
    startup_open_local: Option<PathBuf>,
    startup_recipe_path: Option<PathBuf>,
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
    patch_preview: Option<PatchBundle>,
    patch_verification_report: Option<String>,
    patch_output_path: String,
    patch_digest: Option<String>,
    patch_exported_path: Option<PathBuf>,
    entry_only_assertion: bool,
    search: String,
    graph_filter: String,
    initial_symbol: Option<String>,
    source_label: Option<String>,
    source_offer: Option<String>,
    remote: bool,
    project_revision: Option<u64>,
    named_pass_transform: bool,
    whole_rebuild: bool,
    spec: Option<ProgramSpec>,
    function_index: Option<FunctionIndex>,
    function_index_error: Option<String>,
    ghidra_graph: Option<GhidraGraph>,
    ghidra_snapshot: Option<GhidraSnapshot>,
    ghidra_semantics: Option<PcodeSemanticFunctionIr>,
    ghidra_pcode_lines: Vec<(Option<u64>, String)>,
    ghidra_state_lines: Vec<(Option<u64>, String)>,
    ghidra_exact_operations: Vec<(usize, usize, Option<u64>)>,
    ghidra_llvm_operation: Option<String>,
    ghidra_busy: bool,
    pending_ghidra: Option<(PathBuf, String)>,
    symbol: Option<String>,
    cfg: Option<FunctionCfg>,
    ir: Option<String>,
    c: Option<String>,
    c_error: Option<String>,
    region: Option<RegionSpec>,
    region_error: Option<String>,
    physical_region_ir: Option<PhysicalRegionIr>,
    physical_region_error: Option<String>,
    decompilation: Option<DecompilationUnit>,
    decompilation_error: Option<String>,
    native_decompilation: Option<NativeDecompilation>,
    native_decompilation_error: Option<String>,
    typed_native_view: Option<TypedNativeView>,
    typed_native_error: Option<String>,
    native_coverage: Option<NativeCoverageReport>,
    native_coverage_error: Option<String>,
    analysis: Option<AnalysisReport>,
    disassembly_report: Option<DisassemblyReport>,
    investigation_recipe: Option<AnalysisRecipe>,
    triton_result: Option<serde_json::Value>,
    triton_console_result: Option<serde_json::Value>,
    triton_console_commands: Vec<String>,
    triton_console_input: String,
    console_mode: ConsoleMode,
    console_visible: bool,
    console_height: f32,
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
    pending_recipe_address: Option<u64>,
    pending_disassembly_scroll: Option<u64>,
    selection_target_tab: Option<Tab>,
    tab: Tab,
    region_studio_mode: RegionStudioMode,
    graph_mode: GraphMode,
    native_view_mode: NativeViewMode,
    graph_zoom: f32,
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
            recipe_path_input: String::new(),
            ghidra_graph_path: String::new(),
            workbench: WorkbenchSettings::default(),
            workbench_loaded: false,
            startup_open_local: None,
            startup_recipe_path: None,
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
            patch_preview: None,
            patch_verification_report: None,
            patch_output_path: String::new(),
            patch_digest: None,
            patch_exported_path: None,
            entry_only_assertion: false,
            search: String::new(),
            graph_filter: String::new(),
            initial_symbol: None,
            source_label: None,
            source_offer: None,
            remote: false,
            project_revision: None,
            named_pass_transform: false,
            whole_rebuild: false,
            spec: None,
            function_index: None,
            function_index_error: None,
            ghidra_graph: None,
            ghidra_snapshot: None,
            ghidra_semantics: None,
            ghidra_pcode_lines: Vec::new(),
            ghidra_state_lines: Vec::new(),
            ghidra_exact_operations: Vec::new(),
            ghidra_llvm_operation: None,
            ghidra_busy: false,
            pending_ghidra: None,
            symbol: None,
            cfg: None,
            ir: None,
            c: None,
            c_error: None,
            region: None,
            region_error: None,
            physical_region_ir: None,
            physical_region_error: None,
            decompilation: None,
            decompilation_error: None,
            native_decompilation: None,
            native_decompilation_error: None,
            typed_native_view: None,
            typed_native_error: None,
            native_coverage: None,
            native_coverage_error: None,
            analysis: None,
            disassembly_report: None,
            investigation_recipe: None,
            triton_result: None,
            triton_console_result: None,
            triton_console_commands: Vec::new(),
            triton_console_input: String::new(),
            console_mode: ConsoleMode::Triton,
            console_visible: false,
            console_height: 220.0,
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
            pending_recipe_address: None,
            pending_disassembly_scroll: None,
            selection_target_tab: None,
            tab: Tab::Overview,
            region_studio_mode: RegionStudioMode::Contract,
            graph_mode: GraphMode::Function,
            native_view_mode: NativeViewMode::Summary,
            graph_zoom: 1.0,
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

    fn enqueue_ghidra(&mut self, binary: PathBuf, binary_sha256: String, function: Option<String>) {
        if self.ghidra_busy {
            return;
        }
        match self.tasks.try_send(Task::AnalyzeGhidra {
            binary,
            binary_sha256,
            function,
        }) {
            Ok(()) => {
                self.ghidra_busy = true;
                self.status = "Analyzing ELF with Ghidra…".to_owned();
                self.failure = None;
            }
            Err(_) => {
                self.failure = Some("Analysis queue is full. Retry Ghidra analysis.".to_owned());
            }
        }
    }

    fn poll(&mut self) {
        while let Ok(event) = self.events.try_recv() {
            if !matches!(&event, Event::GhidraAnalyzed { .. }) {
                self.busy = false;
            }
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
                    function_index,
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
                    match function_index {
                        Ok(index) => {
                            self.status =
                                format!("Opened {} native functions", index.functions.len());
                            self.function_index = Some(index);
                            self.function_index_error = None;
                        }
                        Err(error) => {
                            self.function_index = None;
                            self.function_index_error = Some(error);
                        }
                    }
                    self.symbol = None;
                    self.cfg = None;
                    self.ir = None;
                    self.c = None;
                    self.c_error = None;
                    self.clear_region_artifacts();
                    self.analysis = None;
                    self.native_coverage = None;
                    self.native_coverage_error = None;
                    self.disassembly_report = None;
                    self.ghidra_snapshot = None;
                    self.ghidra_semantics = None;
                    self.ghidra_pcode_lines.clear();
                    self.ghidra_state_lines.clear();
                    self.ghidra_exact_operations.clear();
                    self.ghidra_llvm_operation = None;
                    self.investigation_recipe = None;
                    self.triton_result = None;
                    self.console_json = false;
                    self.annotations.clear();
                    self.job = None;
                    self.job_symbol = None;
                    self.selected_address = None;
                    self.pending_recipe_address = None;
                    self.pending_disassembly_scroll = None;
                    self.transform_before = None;
                    self.transform_after = None;
                    self.transform_report = None;
                    self.rebuild_report = None;
                    self.rebuilt_binary_sha256 = None;
                    self.rebuilt_exported_path = None;
                    self.patch_digest = None;
                    self.patch_exported_path = None;
                    self.patch_preview = None;
                    self.patch_verification_report = None;
                    self.rebuild_output_path.clear();
                    self.trusted_fixture = false;
                    self.entry_only_assertion = false;
                    self.failure = None;
                    self.tab = Tab::Overview;
                    if let Some(symbol) = self.initial_symbol.take() {
                        self.select(symbol);
                    }
                    self.enqueue(
                        Task::RefreshAnnotations {
                            binary_sha256: binary_sha256.clone(),
                        },
                        "Loading revisioned analyst annotations…",
                    );
                    if !remote && let Some(path) = self.startup_recipe_path.take() {
                        self.recipe_path_input = path.display().to_string();
                        self.enqueue(Task::OpenRecipe(path), "Verifying investigation recipe…");
                    }
                    if let Some(binary) = self.current_local_path.clone() {
                        self.pending_ghidra = Some((binary, binary_sha256));
                        if !self.ghidra_busy
                            && let Some((binary, digest)) = self.pending_ghidra.take()
                        {
                            self.enqueue_ghidra(binary, digest, None);
                        }
                    } else {
                        self.pending_ghidra = None;
                    }
                }
                Event::RecipeLoaded(result) => match result {
                    Ok(recipe) => {
                        if self
                            .spec
                            .as_ref()
                            .is_none_or(|spec| spec.binary_sha256 != recipe.claim.binary_sha256)
                        {
                            self.failure =
                                Some("Recipe binary digest differs from the open ELF".to_owned());
                            self.status = "Investigation recipe discarded".to_owned();
                        } else {
                            self.selected_address =
                                recipe_elf_address(&recipe, recipe.claim.failed_decision_address);
                            self.status = "Verified investigation recipe loaded".to_owned();
                            self.history.push(self.status.clone());
                            self.investigation_recipe = Some(recipe);
                            self.tab = Tab::Investigation;
                            self.failure = None;
                        }
                    }
                    Err(error) => {
                        self.status = "Investigation recipe rejected".to_owned();
                        self.history.push(error.clone());
                        self.failure = Some(error);
                    }
                },
                Event::GhidraGraphLoaded(result) => match result {
                    Ok(graph) => {
                        if graph.schema_version != 1 || graph.source != "ghidra" {
                            self.failure =
                                Some("Unsupported Ghidra graph schema or source".to_owned());
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
                Event::GhidraAnalyzed {
                    binary_sha256,
                    result,
                } => {
                    self.ghidra_busy = false;
                    if self
                        .spec
                        .as_ref()
                        .is_none_or(|spec| spec.binary_sha256 != binary_sha256)
                    {
                        if let Some((binary, digest)) = self.pending_ghidra.take() {
                            self.enqueue_ghidra(binary, digest, None);
                        }
                        continue;
                    }
                    match result {
                        Ok(snapshot) => {
                            self.status = format!(
                                "Ghidra analyzed {} functions; raw P-code is ready",
                                snapshot.functions.len()
                            );
                            self.history.push(self.status.clone());
                            self.ghidra_semantics = snapshot
                                .pcode_function_ir()
                                .ok()
                                .map(|source| source.lower_semantics());
                            self.ghidra_pcode_lines =
                                pcode_display_lines(&snapshot, self.ghidra_semantics.as_ref());
                            self.ghidra_state_lines = self
                                .ghidra_semantics
                                .as_ref()
                                .map(|semantic| pcode_state_lines(&semantic.lower_state()))
                                .unwrap_or_default();
                            self.ghidra_exact_operations = self
                                .ghidra_semantics
                                .as_ref()
                                .map(|semantic| {
                                    semantic
                                        .instructions
                                        .iter()
                                        .enumerate()
                                        .flat_map(|(instruction_index, instruction)| {
                                            instruction
                                                .operations
                                                .iter()
                                                .enumerate()
                                                .filter(|(_, operation)| {
                                                    matches!(
                                                        operation.effect,
                                                        PcodeEffect::Assign { .. }
                                                    )
                                                })
                                                .map(move |(operation_index, _)| {
                                                    let address = u64::from_str_radix(
                                                        instruction
                                                            .address
                                                            .offset
                                                            .trim_start_matches("0x"),
                                                        16,
                                                    )
                                                    .ok();
                                                    (instruction_index, operation_index, address)
                                                })
                                        })
                                        .collect()
                                })
                                .unwrap_or_default();
                            self.ghidra_llvm_operation = None;
                            self.ghidra_snapshot = Some(snapshot);
                            self.failure = None;
                        }
                        Err(error) => {
                            self.status = "Ghidra analysis failed".to_owned();
                            self.history.push(error.clone());
                            self.failure = Some(error);
                        }
                    }
                    if let Some((binary, digest)) = self.pending_ghidra.take() {
                        self.enqueue_ghidra(binary, digest, None);
                    }
                }
                Event::RemoteProjectCreated(project_id) => {
                    self.remote_project_id = project_id.clone();
                    self.status = format!(
                        "Created remote project {project_id}; select an ELF to upload explicitly"
                    );
                    self.history.push(self.status.clone());
                    self.failure = None;
                }
                Event::Selected {
                    symbol,
                    cfg,
                    ir,
                    c,
                    region_artifacts,
                    native,
                } => {
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
                    let RegionArtifacts {
                        region,
                        physical_ir,
                        decompilation,
                    } = *region_artifacts;
                    match region {
                        Ok(value) => {
                            self.region = Some(value);
                            self.region_error = None;
                        }
                        Err(error) => {
                            self.region = None;
                            self.region_error = Some(error);
                        }
                    }
                    match physical_ir {
                        Ok(value) => {
                            self.physical_region_ir = Some(value);
                            self.physical_region_error = None;
                        }
                        Err(error) => {
                            self.physical_region_ir = None;
                            self.physical_region_error = Some(error);
                        }
                    }
                    match decompilation {
                        Ok(value) => {
                            self.decompilation = Some(value);
                            self.decompilation_error = None;
                        }
                        Err(error) => {
                            self.decompilation = None;
                            self.decompilation_error = Some(error);
                        }
                    }
                    match *native {
                        Ok(value) => {
                            self.native_decompilation = Some(value);
                            self.native_decompilation_error = None;
                        }
                        Err(error) => {
                            self.native_decompilation = None;
                            self.native_decompilation_error = Some(error);
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
                    if let Some(address) = self.pending_recipe_address.take() {
                        self.selected_address = Some(address);
                    }
                    self.tab = self
                        .selection_target_tab
                        .take()
                        .unwrap_or(Tab::RegionStudio);
                }
                Event::NativeSelected {
                    label,
                    native,
                    typed,
                } => {
                    if self.symbol.as_deref() != Some(&label) {
                        continue;
                    }
                    match *native {
                        Ok(value) => {
                            self.selected_address = Some(value.machine_ir.entry.value.0);
                            self.status = format!("Native-decompiled {label}");
                            self.native_decompilation = Some(value);
                            self.native_decompilation_error = None;
                            self.failure = None;
                        }
                        Err(error) => {
                            self.status = format!("Native decompilation failed for {label}");
                            self.native_decompilation = None;
                            self.native_decompilation_error = Some(error.clone());
                            self.failure = Some(error);
                        }
                    }
                    match *typed {
                        Ok(view) => {
                            self.typed_native_view = Some(view);
                            self.typed_native_error = None;
                        }
                        Err(error) => {
                            self.typed_native_view = None;
                            self.typed_native_error = Some(error);
                        }
                    }
                    self.history.push(self.status.clone());
                    if let Some(address) = self.pending_recipe_address.take() {
                        self.selected_address = Some(address);
                    }
                    self.tab = self.selection_target_tab.take().unwrap_or(Tab::Native);
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
                                "Disassembly binary digest does not match the open ELF.".to_owned(),
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
                            if let Some(address) = self.pending_recipe_address.take() {
                                self.selected_address = Some(address);
                            }
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
                Event::Triton(result) => match result {
                    Ok(result) => {
                        let digest_matches = self
                            .spec
                            .as_ref()
                            .and_then(|spec| {
                                result
                                    .get("binary_sha256")
                                    .and_then(serde_json::Value::as_str)
                                    .map(|digest| digest == spec.binary_sha256)
                            })
                            .unwrap_or(false);
                        if !digest_matches {
                            self.failure = Some(
                                "Triton binary digest does not match the open ELF.".to_owned(),
                            );
                            self.status = "Triton result discarded".to_owned();
                        } else {
                            let paths = result
                                .get("paths")
                                .and_then(serde_json::Value::as_array)
                                .map_or(0, Vec::len);
                            self.status =
                                format!("Triton symbolic analysis complete ({paths} paths)");
                            self.history.push(self.status.clone());
                            self.triton_result = Some(result);
                            self.console_mode = ConsoleMode::Activity;
                            self.console_visible = true;
                            self.console_json = true;
                            self.failure = None;
                        }
                    }
                    Err(error) => {
                        self.failure = Some(error.clone());
                        self.status = "Triton analysis failed".to_owned();
                        self.history.push(error);
                    }
                },
                Event::TritonConsole { commands, result } => match result {
                    Ok(result) => {
                        self.triton_console_commands = commands;
                        self.triton_console_result = Some(result);
                        self.console_mode = ConsoleMode::Triton;
                        self.console_visible = true;
                        self.status = "Triton console command completed".to_owned();
                        self.failure = None;
                    }
                    Err(error) => {
                        self.triton_console_input = commands.last().cloned().unwrap_or_default();
                        self.console_mode = ConsoleMode::Triton;
                        self.console_visible = true;
                        self.status = "Triton console command failed".to_owned();
                        self.failure = Some(error.clone());
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
                Event::NativeCoverageMeasured(result) => match result {
                    Ok(report) => {
                        if self.spec.as_ref().map(|spec| &spec.binary_sha256)
                            != Some(&report.binary_sha256)
                        {
                            self.failure = Some(
                                "Coverage binary digest does not match the open project."
                                    .to_owned(),
                            );
                        } else {
                            self.status = format!(
                                "Measured native semantics across {} lifted functions",
                                report.lifted_functions
                            );
                            self.history.push(self.status.clone());
                            self.native_coverage = Some(report);
                            self.native_coverage_error = None;
                            self.tab = Tab::Coverage;
                            self.failure = None;
                        }
                    }
                    Err(error) => {
                        self.native_coverage = None;
                        self.native_coverage_error = Some(error.clone());
                        self.failure = Some(error.clone());
                        self.status = "Native coverage measurement failed".to_owned();
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
                    self.clear_region_artifacts();
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
                    self.clear_region_artifacts();
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
                    self.clear_region_artifacts();
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
                    self.clear_region_artifacts();
                    self.analysis = None;
                    self.native_coverage = None;
                    self.native_coverage_error = None;
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
                    self.clear_region_artifacts();
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
                Event::PatchPreview {
                    bundle,
                    verification_report,
                } => {
                    let placement = match bundle.placement_plan.strategy {
                        PlacementStrategy::InPlace => "in-place",
                        PlacementStrategy::EntryTrampoline => "RX-segment trampoline",
                    };
                    self.status = format!(
                        "Patch preview verified · {placement} · {} compiled bytes",
                        bundle.placement_plan.replacement_size
                    );
                    self.history.push(self.status.clone());
                    self.patch_preview = Some(bundle);
                    self.patch_verification_report = Some(verification_report);
                    self.failure = None;
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
                    self.clear_region_artifacts();
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
                    self.patch_preview = None;
                    self.patch_verification_report = None;
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
                    self.clear_region_artifacts();
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
                    self.patch_preview = None;
                    self.patch_verification_report = None;
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
                    self.clear_region_artifacts();
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

    fn selected_indexed_function(&self) -> Option<&IndexedFunction> {
        let index = self.function_index.as_ref()?;
        if let Some(function_id) = self
            .native_decompilation
            .as_ref()
            .map(|native| native.machine_ir.function_id.as_str())
            && let Some(function) = index
                .functions
                .iter()
                .find(|function| function.id == function_id)
        {
            return Some(function);
        }
        let selected = self.symbol.as_deref()?;
        index
            .functions
            .iter()
            .find(|function| indexed_function_label(function) == selected)
    }

    fn clear_region_artifacts(&mut self) {
        self.region = None;
        self.region_error = None;
        self.physical_region_ir = None;
        self.physical_region_error = None;
        self.decompilation = None;
        self.decompilation_error = None;
        self.native_decompilation = None;
        self.native_decompilation_error = None;
        self.typed_native_view = None;
        self.typed_native_error = None;
        self.region_studio_mode = RegionStudioMode::Contract;
        self.native_view_mode = NativeViewMode::Summary;
    }

    fn select(&mut self, name: String) {
        self.selection_target_tab = None;
        self.symbol = Some(name.clone());
        self.cfg = None;
        self.ir = None;
        self.c = None;
        self.c_error = None;
        self.clear_region_artifacts();
        self.selected_address = None;
        self.enqueue(
            Task::Select(name),
            "Recovering function from machine bytes…",
        );
    }

    fn select_native(&mut self, label: String, selector: String, entry: Location) {
        self.selection_target_tab = None;
        self.symbol = Some(label.clone());
        self.cfg = None;
        self.ir = None;
        self.c = None;
        self.c_error = None;
        self.clear_region_artifacts();
        self.selected_address = Some(entry.value.0);
        self.enqueue(
            Task::SelectNative {
                label,
                selector,
                entry,
            },
            "Running bounded native decompilation…",
        );
    }

    fn open_recipe_site(&mut self, runtime_address: u64, target: Tab) {
        let Some(recipe) = &self.investigation_recipe else {
            return;
        };
        let Some(address) = recipe_elf_address(recipe, runtime_address) else {
            self.failure = Some("Captured address has no verified ELF translation".to_owned());
            return;
        };
        let entry = recipe_elf_address(recipe, recipe.resume_plan.code_address);
        let already_selected = entry.is_some_and(|entry| {
            self.native_decompilation
                .as_ref()
                .is_some_and(|native| native.machine_ir.entry.value.0 == entry)
        });
        self.selected_address = Some(address);
        self.pending_disassembly_scroll = Some(address);
        if target == Tab::Bytes {
            if self.disassembly_report.is_some() {
                self.tab = Tab::Bytes;
            } else {
                self.pending_recipe_address = Some(address);
                self.enqueue(
                    Task::Disassemble,
                    "Locating recipe site in ELF disassembly…",
                );
            }
            return;
        }
        if already_selected {
            self.tab = target;
            if target == Tab::Native {
                self.native_view_mode = NativeViewMode::TypedC;
            } else if target == Tab::Graph {
                self.graph_mode = GraphMode::Function;
            }
            return;
        }
        let action = self.function_index.as_ref().and_then(|index| {
            index
                .functions
                .iter()
                .find(|function| Some(function.entry.value.0) == entry)
                .map(|function| indexed_function_action(function, self.spec.as_ref()))
        });
        if let Some(GraphNodeAction::Function {
            label,
            selector,
            entry,
            legacy_symbol,
        }) = action
        {
            if legacy_symbol {
                self.select(label);
            } else {
                self.select_native(label, selector, entry);
            }
            self.pending_recipe_address = Some(address);
            self.pending_disassembly_scroll = Some(address);
            self.selection_target_tab = Some(target);
            if target == Tab::Native {
                self.native_view_mode = NativeViewMode::TypedC;
            } else if target == Tab::Graph {
                self.graph_mode = GraphMode::Function;
            }
        } else if self.disassembly_report.is_some() {
            self.tab = Tab::Bytes;
            self.status = "No exact recovered function entry; showing ELF disassembly".to_owned();
        } else {
            self.pending_recipe_address = Some(address);
            self.enqueue(
                Task::Disassemble,
                "Locating recipe site in ELF disassembly…",
            );
        }
    }

    fn header(&mut self, ui: &mut egui::Ui) {
        egui::Frame::new()
            .fill(PANEL)
            .inner_margin(egui::Margin::symmetric(16, 10))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new("HYDIR").size(19.0).strong().color(ACCENT));
                    ui.separator();
                    ui.label(
                        RichText::new("REGION DECOMPILATION · VERIFIED PATCHING")
                            .size(11.0)
                            .strong()
                            .color(MUTED),
                    );
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
                        if ui
                            .add(egui::Button::selectable(
                                self.console_visible,
                                if self.console_visible {
                                    "Hide console"
                                } else {
                                    "Open console"
                                },
                            ))
                            .clicked()
                        {
                            self.console_visible = !self.console_visible;
                        }
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
        ui.label(RichText::new("Investigation recipe").strong().color(ACCENT));
        ui.add(
            egui::TextEdit::singleline(&mut self.recipe_path_input)
                .hint_text("/absolute/path/to/recipe.json")
                .desired_width(f32::INFINITY),
        );
        let load_recipe = ui.add_enabled(
            !self.busy
                && !self.remote
                && self.spec.is_some()
                && !self.recipe_path_input.trim().is_empty(),
            egui::Button::new("Verify and open recipe"),
        );
        if load_recipe.clicked() {
            self.enqueue(
                Task::OpenRecipe(PathBuf::from(self.recipe_path_input.trim())),
                "Verifying investigation recipe…",
            );
        }
        load_recipe.on_disabled_hover_text("Open the matching local ELF first.");
        let triton = ui.add_enabled(
            !self.busy
                && !self.remote
                && self.spec.is_some()
                && self.current_local_path.is_some()
                && self.symbol.is_some(),
            egui::Button::new("Run Triton"),
        );
        if triton.clicked()
            && let (Some(path), Some(symbol)) =
                (self.current_local_path.clone(), self.symbol.clone())
        {
            self.enqueue(
                Task::Triton { path, symbol },
                "Running Triton symbolic analysis…",
            );
        }
        triton.on_disabled_hover_text(
            "Open a local ELF and select a function before running Triton.",
        );
        ui.separator();
        egui::CollapsingHeader::new("Ghidra bridge")
            .id_salt("ghidra_bridge")
            .default_open(true)
            .show(ui, |ui| {
                ui.label(
                    RichText::new("Hydir runs headless Ghidra for local ELFs and imports its validated P-code snapshot.")
                        .size(11.0)
                        .color(MUTED),
                );
                let analyze = ui.add_enabled(
                    !self.busy
                        && !self.ghidra_busy
                        && self.current_local_path.is_some()
                        && self.spec.is_some(),
                    egui::Button::new("Analyze with Ghidra"),
                );
                if analyze.clicked()
                    && let (Some(binary), Some(spec)) =
                        (self.current_local_path.clone(), self.spec.as_ref())
                {
                    self.enqueue_ghidra(binary, spec.binary_sha256.clone(), None);
                }
                if let Some(snapshot) = &self.ghidra_snapshot {
                    ui.label(
                        RichText::new(format!(
                            "{} functions · {} · selected {}",
                            snapshot.functions.len(),
                            snapshot.program.ghidra_version,
                            snapshot.selected_function.entry.offset
                        ))
                        .size(11.0)
                        .color(ACCENT),
                    );
                    if ui.button("Browse raw P-code").clicked() {
                        self.tab = Tab::GhidraPcode;
                    }
                }
                ui.separator();
                ui.label(RichText::new("Legacy v1 graph import").size(11.0).color(MUTED));
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
                        .hint_text("http://127.0.0.1:50051 or https://host:port"),
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
            ui.label(
                RichText::new("The native FunctionIndex may still contain stripped entries.")
                    .color(MUTED),
            );
        }
        if let Some(index) = &self.function_index {
            ui.separator();
            ui.label(
                RichText::new(format!(
                    "NATIVE FUNCTION INDEX  ·  {}",
                    index.functions.len()
                ))
                .size(11.0)
                .strong()
                .color(ACCENT),
            );
            let query = self.search.to_lowercase();
            let candidates = index
                .functions
                .iter()
                .filter_map(|function| {
                    let label = function.name.clone().unwrap_or_else(|| {
                        format!(
                            "sub_{}_{}",
                            function.entry.address_space, function.entry.value.0
                        )
                    });
                    (label.to_lowercase().contains(&query)
                        || function.id.to_lowercase().contains(&query))
                    .then_some((label, function.id.clone(), function.entry, function.state))
                })
                .collect::<Vec<_>>();
            let mut clicked = None;
            egui::ScrollArea::vertical()
                .id_salt("native_function_list")
                .max_height(220.0)
                .show_rows(ui, 26.0, candidates.len(), |ui, range| {
                    for position in range {
                        let (label, _, entry, state) = &candidates[position];
                        let selected = self.symbol.as_deref() == Some(label);
                        if ui
                            .selectable_label(
                                selected,
                                RichText::new(format!(
                                    "{label}  [{}:0x{:x}]  {:?}",
                                    entry.address_space, entry.value.0, state
                                ))
                                .monospace()
                                .size(11.0),
                            )
                            .clicked()
                        {
                            clicked = Some((label.clone(), candidates[position].1.clone(), *entry));
                        }
                    }
                });
            if let Some((label, selector, entry)) = clicked {
                let legacy_symbol = self.spec.as_ref().and_then(|spec| {
                    spec.functions
                        .iter()
                        .find(|function| function.name == label)
                        .map(|function| function.name.clone())
                });
                if let Some(symbol) = legacy_symbol {
                    self.select(symbol);
                } else {
                    self.select_native(label, selector, entry);
                }
            }
        } else if let Some(error) = &self.function_index_error {
            ui.colored_label(MUTED, error);
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
        let coverage = ui.add_enabled(
            !self.busy && self.spec.is_some() && !self.remote,
            egui::Button::new("Measure native coverage"),
        );
        if coverage.clicked() {
            self.enqueue(
                Task::MeasureNativeCoverage,
                "Lifting discovered functions and measuring native semantics...",
            );
        }
        coverage.on_disabled_hover_text(
            "Open a local ELF first. Coverage lifts every discovered function and may take time on large binaries.",
        );
        if let Some(report) = &self.native_coverage {
            field(
                ui,
                "NATIVE COVERAGE",
                &format!(
                    "{} lifted / {} discovered; {} exact / {} opaque instructions",
                    report.lifted_functions,
                    report.discovered_functions,
                    report.exact_instructions,
                    report.opaque_instructions
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
        ui.heading(RichText::new("HydIR PatchLang").size(14.0));
        ui.label(RichText::new("Source-located u64 declarations, assignments, arithmetic, and a final return. HydIR previews PatchIR and chooses in-place or a reversible RX-segment trampoline. Behavior changes are intentional; equivalence is not claimed.").size(11.0).color(MUTED));
        ui.label(RichText::new("PATCH SOURCE").size(10.0).color(MUTED));
        let editor = ui.add(
            egui::TextEdit::multiline(&mut self.patch_replacement)
                .font(egui::TextStyle::Monospace)
                .desired_rows(5)
                .hint_text("u64 result = arg0;\nresult = result - arg1;\nreturn result;"),
        );
        if editor.changed() {
            self.patch_preview = None;
            self.patch_verification_report = None;
        }
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
        let preview_ready = self.spec.is_some()
            && selected_symbol.is_some()
            && self.trusted_fixture
            && self.entry_only_assertion
            && !self.patch_replacement.trim().is_empty()
            && !self.busy;
        let preview = ui.add_enabled(preview_ready, egui::Button::new("Compile & verify preview"));
        if preview.clicked()
            && let Some(symbol) = selected_symbol.clone()
        {
            self.enqueue(
                Task::PreviewPatch {
                    symbol,
                    replacement: self.patch_replacement.trim().to_owned(),
                },
                "Compiling and structurally verifying PatchLang preview…",
            );
        }
        preview.on_disabled_hover_text("Select a function and assert the trusted-fixture and entry-only contracts before previewing.");
        let preview_current = self.patch_preview.as_ref().is_some_and(|bundle| {
            bundle.source.replacement == self.patch_replacement.trim()
                && Some(bundle.source.function_symbol.as_str()) == selected_symbol.as_deref()
                && self
                    .spec
                    .as_ref()
                    .is_some_and(|spec| spec.binary_sha256 == bundle.source.binary_sha256)
        });
        let patch_ready = preview_ready
            && preview_current
            && (self.remote || !self.patch_output_path.trim().is_empty());
        let patch = ui.add_enabled(
            patch_ready,
            egui::Button::new(if self.remote {
                "Apply verified patch remotely"
            } else {
                "Apply verified patch locally"
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
            self.enqueue(task, "Applying the verified HydIR patch…");
        }
        patch.on_disabled_hover_text("Compile a current verified preview first; local apply also requires a new output path.");
        if let Some(bundle) = &self.patch_preview {
            let placement = match bundle.placement_plan.strategy {
                PlacementStrategy::InPlace => "in-place",
                PlacementStrategy::EntryTrampoline => "entry trampoline to appended RX segment",
            };
            ui.separator();
            ui.label(
                RichText::new(if preview_current {
                    "CURRENT VERIFIED PREVIEW"
                } else {
                    "STALE PREVIEW · COMPILE AGAIN"
                })
                .size(10.0)
                .color(if preview_current { GOOD } else { BAD }),
            );
            field(ui, "PLACEMENT", placement);
            field(
                ui,
                "REGION / CODE",
                &format!(
                    "{} bytes / {} bytes",
                    bundle.placement_plan.original_size,
                    bundle.placement_plan.replacement_size
                ),
            );
            field(
                ui,
                "PATCHIR",
                &format!("{} typed statements", bundle.typed_patch_ir.statements.len()),
            );
            if let Some(segment) = &bundle.placement_plan.executable_segment {
                field(
                    ui,
                    "RX SEGMENT",
                    &format!(
                        "file 0x{:x} · VA 0x{:x} · {} bytes",
                        segment.file_offset, segment.virtual_address.0, segment.file_size
                    ),
                );
            }
            egui::CollapsingHeader::new("Byte-level patch delta").show(ui, |ui| {
                field(ui, "ORIGINAL REGION", &bundle.original_region_hex);
                field(ui, "COMPILED CODE", &bundle.compiled_bytes_hex);
                if let Some(entry) = &bundle.placement_plan.entry_bytes_hex {
                    field(ui, "NEW ENTRY", entry);
                }
            });
            egui::CollapsingHeader::new("Verification evidence").show(ui, |ui| {
                for evidence in &bundle.verification_evidence {
                    ui.label(format!(
                        "{} · {:?} · {}",
                        evidence.check, evidence.status, evidence.details
                    ));
                }
                if let Some(report) = &self.patch_verification_report {
                    ui.code(report);
                }
            });
        }
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
        } else if let Some(function) = self.selected_indexed_function() {
            ui.label(
                RichText::new(indexed_function_label(function))
                    .monospace()
                    .color(ACCENT),
            );
            field(
                ui,
                "ENTRY",
                &format!(
                    "{}:0x{:016x}",
                    function.entry.address_space, function.entry.value.0
                ),
            );
            field(ui, "FUNCTION ID", &function.id);
            field(ui, "EVIDENCE STATE", &format!("{:?}", function.state));
            field(
                ui,
                "BLOCK ENTRIES",
                &function.block_entries.len().to_string(),
            );
            field(ui, "EXTENTS", &function.extents.len().to_string());
            field(
                ui,
                "CANDIDATE TARGETS",
                &function.candidate_targets.len().to_string(),
            );
            if let Some(address) = self.selected_address {
                field(ui, "SELECTED", &format!("0x{address:016x}"));
            }
            if let Some(native) = &self.native_decompilation {
                field(
                    ui,
                    "NATIVE CFG",
                    &format!(
                        "{} blocks - {} instructions",
                        native.machine_ir.blocks.len(),
                        native_instruction_count(native)
                    ),
                );
                field(
                    ui,
                    "SEMANTIC FIDELITY",
                    &format!("{:?}", native.cir.semantic_fidelity),
                );
                field(
                    ui,
                    "OPAQUE INSTRUCTIONS",
                    &native_opaque_instruction_count(native).to_string(),
                );
                field(
                    ui,
                    "REWRITE READY",
                    if native.cir.rewrite_ready {
                        "yes"
                    } else {
                        "no"
                    },
                );
            }
            if !function.evidence.is_empty() {
                egui::CollapsingHeader::new("Entry evidence")
                    .default_open(false)
                    .show(ui, |ui| {
                        for evidence in &function.evidence {
                            ui.label(
                                RichText::new(format!(
                                    "{} - {}",
                                    evidence.kind, evidence.description
                                ))
                                .size(11.0)
                                .color(MUTED),
                            );
                        }
                    });
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
                &instruction.branch_target.map_or_else(
                    || "none".to_owned(),
                    |target| format!("0x{:016x}", target.0),
                ),
            );
            field(ui, "PROVENANCE", &instruction.provenance);
        }
        if let Some(native) = &self.native_decompilation
            && let Some(address) = self.selected_address
            && let Some(instruction) = native
                .machine_ir
                .blocks
                .iter()
                .flat_map(|block| &block.instructions)
                .find(|instruction| instruction.address.value.0 == address)
        {
            ui.separator();
            ui.heading(RichText::new("Selected native instruction").size(14.0));
            field(
                ui,
                "ADDRESS",
                &format!(
                    "{}:0x{:016x}",
                    instruction.address.address_space, instruction.address.value.0
                ),
            );
            field(ui, "BYTES", &instruction.bytes_hex);
            field(
                ui,
                "INSTRUCTION",
                &format!("{} {:?}", instruction.mnemonic, instruction.operands),
            );
            field(ui, "SEMANTICS", &format!("{:?}", instruction.operation));
            field(ui, "EFFECTS", &format!("{:?}", instruction.effects));
            field(ui, "EDGES", &format!("{:?}", instruction.edges));
        }
        ui.add_space(12.0);
        ui.separator();
        ui.heading(RichText::new("Diagnostics").size(14.0));
        if let Some(failure) = &self.failure {
            ui.colored_label(BAD, failure);
        } else {
            ui.colored_label(
                if self.busy || self.ghidra_busy {
                    ACCENT
                } else {
                    GOOD
                },
                &self.status,
            );
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
        ui.horizontal_wrapped(|ui| {
            for (tab, label) in [
                (Tab::Overview, "Overview"),
                (Tab::GhidraPcode, "Ghidra P-code"),
                (Tab::Investigation, "Investigation"),
                (Tab::RegionStudio, "Region Studio"),
                (Tab::Native, "Native decompiler"),
                (Tab::Bytes, "Disassembly"),
                (Tab::Graph, "Graph"),
                (Tab::Cfg, "CFG"),
                (Tab::Coverage, "Coverage"),
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
            Tab::Overview => self.overview_view(ui),
            Tab::GhidraPcode => self.ghidra_pcode_view(ui),
            Tab::Investigation => self.investigation_view(ui),
            Tab::RegionStudio => self.region_studio(ui),
            Tab::Native => self.native_explorer_view(ui),
            Tab::Bytes => self.disassembly(ui),
            Tab::Graph => self.graph_view(ui),
            Tab::Cfg => self.cfg_view(ui),
            Tab::Coverage => self.coverage_view(ui),
            Tab::Llvm => self.llvm_view(ui),
            Tab::Passes => self.passes_view(ui),
            Tab::Analysis => self.analysis_view(ui),
            Tab::C => self.c_view(ui),
        }
    }

    fn ghidra_pcode_view(&mut self, ui: &mut egui::Ui) {
        ui.heading(RichText::new("Ghidra function index and raw P-code").color(ACCENT));
        let Some(snapshot) = &self.ghidra_snapshot else {
            ui.label(
                RichText::new("Open a local ELF to run automatic Ghidra analysis, or retry from the Program pane.")
                    .color(MUTED),
            );
            return;
        };
        ui.label(
            RichText::new(format!(
                "Snapshot v{} · {} · {} · binary SHA-256 {}",
                snapshot.schema_version,
                snapshot.program.language_id,
                snapshot.program.compiler_spec_id,
                snapshot.binary_sha256
            ))
            .size(11.0)
            .color(MUTED),
        );
        ui.label(
            RichText::new("P-code is imported evidence. Semantic lowering and equivalence are separate checks.")
                .size(11.0)
                .color(MUTED),
        );
        if let Some(semantics) = &self.ghidra_semantics {
            let exact = semantics
                .instructions
                .iter()
                .flat_map(|instruction| &instruction.operations)
                .filter(|operation| matches!(operation.effect, PcodeEffect::Assign { .. }))
                .count();
            let opaque = semantics.diagnostics.len();
            ui.label(
                RichText::new(format!(
                    "Rust semantic pass: {exact} exact operations · {opaque} opaque operations · function equivalence unverified"
                ))
                .size(11.0)
                .color(if opaque == 0 { GOOD } else { ACCENT }),
            );
            if opaque > 0 {
                egui::CollapsingHeader::new(format!("Opaque effect diagnostics ({opaque})"))
                    .id_salt("ghidra_semantic_diagnostics")
                    .show(ui, |ui| {
                        for diagnostic in semantics.diagnostics.iter().take(30) {
                            ui.label(
                                RichText::new(format!(
                                    "{}:{} #{} · {}",
                                    diagnostic.source_address.space,
                                    diagnostic.source_address.offset,
                                    diagnostic.sequence_index,
                                    diagnostic.message
                                ))
                                .monospace()
                                .size(11.0)
                                .color(BAD),
                            );
                        }
                        if opaque > 30 {
                            ui.label(
                                RichText::new(format!(
                                    "{} more; all are marked in raw P-code below",
                                    opaque - 30
                                ))
                                .size(11.0)
                                .color(MUTED),
                            );
                        }
                    });
            }
        }
        egui::CollapsingHeader::new(format!("Ordered state effects ({})", self.ghidra_state_lines.len()))
            .id_salt("ghidra_ordered_state")
            .show(ui, |ui| {
                ui.label(RichText::new("Reads and writes follow source P-code order. Possible effects and unlisted clobbers remain explicit.")
                    .size(11.0).color(MUTED));
                if ui.button("Copy state effects").clicked() {
                    ui.ctx().copy_text(self.ghidra_state_lines.iter()
                        .map(|(_, line)| line.as_str()).collect::<Vec<_>>().join("\n"));
                }
                egui::ScrollArea::both().id_salt("ghidra_ordered_state_rows")
                    .max_height(180.0)
                    .show_rows(ui, 18.0, self.ghidra_state_lines.len(), |ui, range| {
                        for row in range {
                            let (address, line) = &self.ghidra_state_lines[row];
                            if ui.selectable_label(self.selected_address == *address,
                                RichText::new(line).monospace().size(11.0)).clicked() {
                                self.selected_address = *address;
                            }
                        }
                    });
            });
        let mut selected_exact = None;
        egui::CollapsingHeader::new(format!("LLVM for exact operations ({})", self.ghidra_exact_operations.len()))
            .id_salt("ghidra_exact_llvm")
            .show(ui, |ui| {
                ui.label(RichText::new("Each selection emits one P-code value operation. This is not a whole-function lift.")
                    .size(11.0).color(MUTED));
                egui::ScrollArea::vertical().id_salt("ghidra_exact_llvm_rows")
                    .max_height(120.0)
                    .show_rows(ui, 18.0, self.ghidra_exact_operations.len(), |ui, range| {
                        for row in range {
                            let (instruction_index, operation_index, address) = self.ghidra_exact_operations[row];
                            if let Some(semantic) = self.ghidra_semantics.as_ref()
                                && let Some(instruction) = semantic.instructions.get(instruction_index)
                                && let Some(operation) = instruction.operations.get(operation_index) {
                                let label = format!("{}:{}  #{} {}", instruction.address.space,
                                    instruction.address.offset, operation_index, operation.source.mnemonic);
                                if ui.selectable_label(self.selected_address == address,
                                    RichText::new(label).monospace().size(11.0)).clicked() {
                                    selected_exact = Some((instruction_index, operation_index, address));
                                }
                            }
                        }
                    });
                if let Some(llvm) = &self.ghidra_llvm_operation {
                    if ui.button("Copy LLVM operation").clicked() {
                        ui.ctx().copy_text(llvm.clone());
                    }
                    egui::ScrollArea::both().id_salt("ghidra_exact_llvm_source")
                        .max_height(180.0).show(ui, |ui| {
                            ui.label(RichText::new(llvm).monospace().size(11.0));
                        });
                }
            });
        if let Some((instruction_index, operation_index, address)) = selected_exact {
            self.selected_address = address;
            self.ghidra_llvm_operation = self
                .ghidra_semantics
                .as_ref()
                .and_then(|semantic| semantic.instructions.get(instruction_index))
                .and_then(|instruction| instruction.operations.get(operation_index))
                .map(|operation| {
                    emit_pcode_exact_operation_llvm(operation)
                        .unwrap_or_else(|error| format!("LLVM emission failed: {error}"))
                });
        }
        ui.separator();
        ui.label(RichText::new("FUNCTIONS").strong().color(ACCENT));
        let mut requested = None;
        egui::ScrollArea::vertical()
            .id_salt("ghidra_function_index")
            .max_height(150.0)
            .show_rows(ui, 26.0, snapshot.functions.len(), |ui, range| {
                for row in range {
                    let function = &snapshot.functions[row];
                    let selected = function.entry == snapshot.selected_function.entry;
                    if ui
                        .add_enabled(
                            !self.busy && !self.ghidra_busy,
                            egui::Button::selectable(
                                selected,
                                format!(
                                    "{}:{}  {}  ({} bytes)",
                                    function.entry.space,
                                    function.entry.offset,
                                    function.name,
                                    function.size
                                ),
                            ),
                        )
                        .clicked()
                        && !selected
                    {
                        requested = Some(function.entry.offset.clone());
                    }
                }
            });
        if !snapshot.selected_function.call_targets.is_empty() {
            egui::CollapsingHeader::new(format!(
                "Calls ({})",
                snapshot.selected_function.call_targets.len()
            ))
            .id_salt("ghidra_call_targets")
            .show(ui, |ui| {
                egui::ScrollArea::vertical()
                    .id_salt("ghidra_call_rows")
                    .max_height(120.0)
                    .show_rows(
                        ui,
                        22.0,
                        snapshot.selected_function.call_targets.len(),
                        |ui, range| {
                            for row in range {
                                let call = &snapshot.selected_function.call_targets[row];
                                let source = u64::from_str_radix(
                                    call.call_site.offset.trim_start_matches("0x"),
                                    16,
                                )
                                .ok();
                                let target = call
                                    .target
                                    .as_ref()
                                    .map(|address| format!("{}:{}", address.space, address.offset))
                                    .unwrap_or_else(|| "unresolved target".to_owned());
                                ui.horizontal(|ui| {
                                    if ui
                                        .selectable_label(
                                            self.selected_address == source,
                                            format!(
                                                "{}:{} → {target}{}",
                                                call.call_site.space,
                                                call.call_site.offset,
                                                if call.computed { " (computed)" } else { "" }
                                            ),
                                        )
                                        .clicked()
                                    {
                                        self.selected_address = source;
                                    }
                                    if let Some(target) = &call.target
                                        && snapshot
                                            .functions
                                            .iter()
                                            .any(|function| function.entry == *target)
                                        && ui.button("Open target").clicked()
                                    {
                                        requested = Some(target.offset.clone());
                                    }
                                });
                            }
                        },
                    );
            });
        }
        if !snapshot.selected_function.flow_edges.is_empty() {
            egui::CollapsingHeader::new(format!(
                "Analyzed flow edges ({})",
                snapshot.selected_function.flow_edges.len()
            ))
            .id_salt("ghidra_flow_edges")
            .show(ui, |ui| {
                egui::ScrollArea::vertical()
                    .id_salt("ghidra_flow_rows")
                    .max_height(120.0)
                    .show_rows(
                        ui,
                        18.0,
                        snapshot.selected_function.flow_edges.len(),
                        |ui, range| {
                            for row in range {
                                let edge = &snapshot.selected_function.flow_edges[row];
                                let source = u64::from_str_radix(
                                    edge.source.offset.trim_start_matches("0x"),
                                    16,
                                )
                                .ok();
                                let target = edge
                                    .target
                                    .as_ref()
                                    .map(|address| format!("{}:{}", address.space, address.offset))
                                    .unwrap_or_else(|| "unresolved".to_owned());
                                if ui
                                    .selectable_label(
                                        self.selected_address == source,
                                        RichText::new(format!(
                                            "{}:{} → {target}  {:?}{}{}",
                                            edge.source.space,
                                            edge.source.offset,
                                            edge.kind,
                                            if edge.conditional { " conditional" } else { "" },
                                            if edge.computed { " computed" } else { "" }
                                        ))
                                        .monospace()
                                        .size(11.0),
                                    )
                                    .clicked()
                                {
                                    self.selected_address = source;
                                }
                            }
                        },
                    );
            });
        }
        let selected_name = snapshot
            .functions
            .iter()
            .find(|function| function.entry == snapshot.selected_function.entry)
            .map_or("selected function", |function| function.name.as_str());
        ui.separator();
        ui.horizontal(|ui| {
            ui.label(
                RichText::new(format!(
                    "RAW P-CODE · {} · {} instructions",
                    selected_name,
                    snapshot.selected_function.instructions.len()
                ))
                .strong()
                .color(INFO),
            );
            if ui.button("Copy").clicked() {
                ui.ctx().copy_text(
                    self.ghidra_pcode_lines
                        .iter()
                        .map(|(_, line)| line.as_str())
                        .collect::<Vec<_>>()
                        .join("\n"),
                );
            }
        });
        egui::ScrollArea::both()
            .id_salt("ghidra_raw_pcode")
            .show_rows(ui, 18.0, self.ghidra_pcode_lines.len(), |ui, range| {
                for row in range {
                    let (address, line) = &self.ghidra_pcode_lines[row];
                    if ui
                        .selectable_label(
                            self.selected_address == *address,
                            RichText::new(line).monospace().size(11.0),
                        )
                        .clicked()
                    {
                        self.selected_address = *address;
                    }
                }
            });
        if let Some(function) = requested
            && let (Some(binary), Some(spec)) =
                (self.current_local_path.clone(), self.spec.as_ref())
        {
            self.enqueue_ghidra(binary, spec.binary_sha256.clone(), Some(function));
        }
    }

    fn investigation_view(&mut self, ui: &mut egui::Ui) {
        let Some(recipe) = self.investigation_recipe.as_ref() else {
            ui.heading("Investigation");
            ui.label(RichText::new(
                "Open a matching local ELF, then verify an exported recipe in the Program pane.",
            ).color(MUTED));
            return;
        };
        let claim = &recipe.claim;
        let static_decision = recipe_elf_address(recipe, claim.failed_decision_address);
        let mut jump = None;
        ui.heading(RichText::new("Verified investigation record").color(ACCENT));
        ui.label(RichText::new(&claim.statement).strong());
        ui.label(
            RichText::new("Recorded artifact checks passed. Native outcomes shown here are observations from the recipe; use recipe replay for fresh runs.")
                .size(11.0)
                .color(MUTED),
        );
        ui.add_space(8.0);
        ui.horizontal_wrapped(|ui| {
            metric_readout(ui, "ORIGINAL", "GOAL MISSED", BAD);
            metric_readout(ui, "CANDIDATE", "GOAL MET", GOOD);
            metric_readout(
                ui,
                "CHANGED BYTES",
                &claim.changed_bytes.len().to_string(),
                ACCENT,
            );
            metric_readout(ui, "TRACE SCOPE", "ONE CAPTURED SEED", INFO);
        });
        ui.add_space(8.0);
        field(ui, "ORIGIN", &claim.origin_id);
        field(
            ui,
            "FAILED DECISION",
            &format!(
                "{} · occurrence {} · runtime 0x{:x}",
                claim.failed_decision_kind,
                claim.failed_decision_occurrence,
                claim.failed_decision_address
            ),
        );
        if let Some(address) = static_decision {
            field(ui, "ELF ADDRESS", &format!("0x{address:x}"));
        } else {
            ui.colored_label(
                ACCENT,
                "No verified runtime-to-ELF address mapping; static navigation is unavailable.",
            );
        }
        ui.horizontal_wrapped(|ui| {
            if ui
                .add_enabled(
                    !self.busy && static_decision.is_some(),
                    egui::Button::new("Open C source sites"),
                )
                .clicked()
            {
                jump = Some((claim.failed_decision_address, Tab::Native));
            }
            if ui
                .add_enabled(
                    !self.busy && static_decision.is_some(),
                    egui::Button::new("Open CFG graph"),
                )
                .clicked()
            {
                jump = Some((claim.failed_decision_address, Tab::Graph));
            }
            if ui
                .add_enabled(
                    !self.busy && static_decision.is_some(),
                    egui::Button::new("Open disassembly"),
                )
                .clicked()
            {
                jump = Some((claim.failed_decision_address, Tab::Bytes));
            }
        });
        ui.separator();
        ui.heading(RichText::new("Input byte changes").size(16.0));
        for change in &claim.changed_bytes {
            let linked = claim
                .relevant_origin_offsets
                .contains(&change.origin_offset);
            ui.label(
                RichText::new(format!(
                    "{} +{} (channel +{}): {:02x} → {:02x}{}",
                    claim.origin_id,
                    change.origin_offset,
                    change.channel_offset,
                    change.before,
                    change.after,
                    if linked {
                        " · in failed trace slice"
                    } else {
                        ""
                    }
                ))
                .monospace()
                .color(if linked { GOOD } else { ACCENT }),
            );
        }
        ui.add_space(6.0);
        ui.heading(RichText::new("Source instructions").size(16.0));
        let slice = &recipe.bridge_result["input_condition_slice"];
        let instructions = slice["instructions"].as_array();
        let source_indices = slice["source_occurrences"].as_array();
        let sources = source_indices
            .into_iter()
            .flat_map(|indices| indices.iter())
            .filter_map(|value| {
                let index = value.as_u64()? as usize;
                let instruction = instructions?.get(index)?;
                let runtime = instruction["address"].as_u64()?;
                let disassembly = instruction["disassembly"].as_str()?.to_owned();
                Some((
                    index,
                    runtime,
                    disassembly,
                    recipe_elf_address(recipe, runtime),
                ))
            })
            .collect::<Vec<_>>();
        egui::ScrollArea::vertical()
            .id_salt("investigation_source_instructions")
            .max_height(250.0)
            .show_rows(ui, 24.0, sources.len(), |ui, range| {
                for index in range {
                    let (occurrence, runtime, disassembly, elf_address) = &sources[index];
                    let label = if let Some(address) = elf_address {
                        format!("#{occurrence} · ELF 0x{address:x} · {disassembly}")
                    } else {
                        format!("#{occurrence} · runtime 0x{runtime:x} · {disassembly}")
                    };
                    if ui
                        .add_enabled(
                            !self.busy && elf_address.is_some(),
                            egui::Button::new(RichText::new(label).monospace().size(11.0)),
                        )
                        .clicked()
                    {
                        jump = Some((*runtime, Tab::Bytes));
                    }
                }
            });
        ui.separator();
        ui.label(
            RichText::new("Unresolved dependencies and assumptions")
                .strong()
                .color(ACCENT),
        );
        for assumption in &claim.assumptions {
            ui.label(
                RichText::new(format!("Assumption: {assumption}"))
                    .size(11.0)
                    .color(MUTED),
            );
        }
        for unresolved in &claim.unresolved_dependencies {
            ui.label(
                RichText::new(format!("Unresolved: {unresolved}"))
                    .size(11.0)
                    .color(MUTED),
            );
        }
        if let Some((runtime, target)) = jump {
            self.open_recipe_site(runtime, target);
        }
    }

    fn overview_view(&mut self, ui: &mut egui::Ui) {
        let Some(spec) = &self.spec else {
            ui.vertical_centered(|ui| {
                ui.add_space(60.0);
                ui.heading(
                    RichText::new("Open a Linux x86-64 ELF")
                        .size(24.0)
                        .color(ACCENT),
                );
                ui.label(
                    RichText::new(
                        "Paste a path in the Program pane or drop an ELF anywhere in this window.",
                    )
                    .color(MUTED),
                );
                ui.add_space(10.0);
                ui.label("Hydir loads and analyzes bytes without executing the input program.");
            });
            return;
        };

        let indexed_functions = self
            .function_index
            .as_ref()
            .map_or(0, |index| index.functions.len());
        let first_function_action = self
            .function_index
            .as_ref()
            .and_then(|index| index.functions.first())
            .map(|function| indexed_function_action(function, Some(spec)));
        let native_ready = self.native_decompilation.is_some();
        let selected = self.symbol.as_deref().unwrap_or("none");
        ui.heading(RichText::new("Native ELF workbench").size(22.0).color(TEXT));
        ui.label(RichText::new(&spec.recovery_scope).size(11.0).color(MUTED));
        ui.add_space(8.0);
        ui.horizontal_wrapped(|ui| {
            metric_readout(ui, "ELF", &spec.file_kind, INFO);
            metric_readout(ui, "TARGET", &spec.target_triple, VIOLET);
            metric_readout(ui, "FUNCTIONS", &indexed_functions.to_string(), ACCENT);
            metric_readout(ui, "IMPORTS", &spec.imports.len().to_string(), TEXT);
            metric_readout(ui, "RELOCATIONS", &spec.relocations.len().to_string(), TEXT);
            metric_readout(
                ui,
                "UNCERTAINTIES",
                &spec.uncertainties.len().to_string(),
                if spec.uncertainties.is_empty() {
                    GOOD
                } else {
                    BAD
                },
            );
        });
        ui.add_space(12.0);

        let mut open_graph = false;
        let mut open_native = false;
        let mut open_disassembly = false;
        let mut run_coverage = false;
        let mut decompile_first = false;
        ui.horizontal_wrapped(|ui| {
            if ui.button("Open graph explorer").clicked() {
                open_graph = true;
            }
            if ui
                .add_enabled(native_ready, egui::Button::new("Inspect native IR / C"))
                .clicked()
            {
                open_native = true;
            }
            if ui
                .add_enabled(
                    !native_ready && first_function_action.is_some(),
                    egui::Button::new("Decompile first discovered function"),
                )
                .clicked()
            {
                decompile_first = true;
            }
            if ui
                .add_enabled(!self.remote, egui::Button::new("Disassemble whole ELF"))
                .clicked()
            {
                open_disassembly = true;
            }
            if ui
                .add_enabled(!self.remote, egui::Button::new("Measure semantic coverage"))
                .clicked()
            {
                run_coverage = true;
            }
        });
        ui.label(
            RichText::new(format!("Selected function: {selected}"))
                .monospace()
                .size(11.0)
                .color(if native_ready { GOOD } else { MUTED }),
        );
        ui.add_space(12.0);

        ui.columns(2, |columns| {
            columns[0].heading(RichText::new("Pipeline").size(15.0).color(ACCENT));
            stage_status(
                &mut columns[0],
                "01",
                "ELF loader",
                &format!(
                    "{} address spaces / {} mapped segments / {} sections",
                    spec.address_spaces.len(),
                    spec.mapped_segments.len(),
                    spec.sections.len()
                ),
                true,
            );
            stage_status(
                &mut columns[0],
                "02",
                "Function discovery",
                &format!("{indexed_functions} evidence-backed entries"),
                self.function_index.is_some(),
            );
            stage_status(
                &mut columns[0],
                "03",
                "Native lifting",
                if native_ready {
                    "MachineIR -> StateIR -> FunctionIR -> CIR"
                } else {
                    "Select a function to lift"
                },
                native_ready,
            );
            stage_status(
                &mut columns[0],
                "04",
                "C generation",
                self.native_decompilation
                    .as_ref()
                    .map_or("Waiting for native lift", |native| {
                        if native.structured_c.is_some() {
                            "Low-level and structured C available"
                        } else {
                            "Compilable low-level C available"
                        }
                    }),
                native_ready,
            );

            columns[1].heading(RichText::new("Evidence and safety").size(15.0).color(INFO));
            field(&mut columns[1], "BINARY SHA-256", &spec.binary_sha256);
            field(
                &mut columns[1],
                "ENTRY",
                &spec.entry_location.map_or_else(
                    || "not declared".to_owned(),
                    |entry| format!("{}:0x{:x}", entry.address_space, entry.value.0),
                ),
            );
            field(
                &mut columns[1],
                "DYNAMIC SYMBOLS",
                &spec.dynamic_symbols.len().to_string(),
            );
            field(
                &mut columns[1],
                "UNWIND RANGES",
                &spec.unwind_ranges.len().to_string(),
            );
            field(
                &mut columns[1],
                "RUNTIME RANGES",
                &spec.runtime_ranges.len().to_string(),
            );
            field(
                &mut columns[1],
                "UNRESOLVED CONTROL",
                if spec.unresolved_control_flow {
                    "yes"
                } else {
                    "no"
                },
            );
            if let Some(index) = &self.function_index
                && !index.diagnostics.is_empty()
            {
                columns[1].separator();
                columns[1].label(
                    RichText::new(format!(
                        "Discovery diagnostics ({})",
                        index.diagnostics.len()
                    ))
                    .strong()
                    .color(BAD),
                );
                for diagnostic in index.diagnostics.iter().take(8) {
                    columns[1].label(
                        RichText::new(format!("{}: {}", diagnostic.code, diagnostic.message))
                            .size(11.0)
                            .color(MUTED),
                    );
                }
            }
        });

        if open_graph {
            self.graph_mode = if self.native_decompilation.is_some() {
                GraphMode::Function
            } else {
                GraphMode::Program
            };
            self.tab = Tab::Graph;
        } else if open_native {
            self.tab = Tab::Native;
        } else if decompile_first {
            if let Some(GraphNodeAction::Function {
                label,
                selector,
                entry,
                legacy_symbol,
            }) = first_function_action
            {
                if legacy_symbol {
                    self.select(label);
                } else {
                    self.select_native(label, selector, entry);
                }
                self.selection_target_tab = Some(Tab::Native);
            }
        } else if open_disassembly {
            self.enqueue(
                Task::Disassemble,
                "Disassembling executable ELF sections...",
            );
        } else if run_coverage {
            self.enqueue(
                Task::MeasureNativeCoverage,
                "Lifting discovered functions and measuring native semantics...",
            );
        }
    }

    fn region_studio(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.vertical(|ui| {
                ui.heading(
                    RichText::new("HydIR Region Studio")
                        .size(22.0)
                        .strong()
                        .color(ACCENT),
                );
                ui.label(
                    RichText::new(
                        "Native region decompilation, physical-state inspection, PatchLang compilation, and reversible ELF placement",
                    )
                    .size(11.0)
                    .color(MUTED),
                );
            });
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let (label, color) = if self.busy {
                    ("WORKING", ACCENT)
                } else if self.region.is_some() {
                    ("DIGEST-BOUND", GOOD)
                } else if self.symbol.is_some() {
                    ("FAIL-CLOSED", BAD)
                } else {
                    ("AWAITING REGION", MUTED)
                };
                ui.label(RichText::new(label).size(11.0).strong().color(color));
            });
        });
        ui.add_space(8.0);

        let contract_ready = self.region.is_some();
        let machine_ready = self.physical_region_ir.is_some();
        let c_ready = self.decompilation.is_some() || self.c.is_some();
        let patch_ready = self.patch_preview.is_some();
        let applied = self.patch_digest.is_some();
        ui.columns(5, |columns| {
            stage_status(
                &mut columns[0],
                "01",
                "REGION CONTRACT",
                if contract_ready { "BOUND" } else { "PENDING" },
                contract_ready,
            );
            stage_status(
                &mut columns[1],
                "02",
                "PHYSICAL IR",
                if machine_ready {
                    "RECOVERED"
                } else {
                    "BLOCKED"
                },
                machine_ready,
            );
            stage_status(
                &mut columns[2],
                "03",
                "DECOMPILE",
                if c_ready { "AVAILABLE" } else { "BLOCKED" },
                c_ready,
            );
            stage_status(
                &mut columns[3],
                "04",
                "PATCH PLAN",
                if patch_ready {
                    "VERIFIED"
                } else {
                    "NOT COMPILED"
                },
                patch_ready,
            );
            stage_status(
                &mut columns[4],
                "05",
                "OUTPUT ELF",
                if applied { "SAVED" } else { "UNCHANGED" },
                applied,
            );
        });
        ui.add_space(8.0);

        if self.spec.is_none() {
            ui.add_space(32.0);
            ui.heading("Open a Linux x86-64 ELF to begin");
            ui.label(
                RichText::new(
                    "HydIR keeps the input immutable and derives every displayed artifact from its SHA-256-bound bytes.",
                )
                .color(MUTED),
            );
            ui.label("Use the Program panel on the left, or reopen your saved local ELF.");
            return;
        }
        if self.symbol.is_none() {
            let first = self
                .spec
                .as_ref()
                .and_then(|spec| spec.functions.first())
                .map(|function| function.name.clone());
            ui.add_space(32.0);
            ui.heading("Choose a function-sized region");
            ui.label(
                RichText::new(
                    "Select any symbol from the function navigator. HydIR will recover the boundary contract, physical operations, deterministic C, and patch eligibility together.",
                )
                .color(MUTED),
            );
            if let Some(name) = first
                && ui
                    .add_enabled(
                        !self.busy,
                        egui::Button::new(format!("Open first region · {name}")),
                    )
                    .clicked()
            {
                self.select(name);
            }
            return;
        }

        ui.horizontal_wrapped(|ui| {
            for (mode, label) in [
                (RegionStudioMode::Contract, "Contract & safety"),
                (RegionStudioMode::MachineIr, "Physical state IR"),
                (RegionStudioMode::DecompilePatch, "C ↔ PatchLang"),
                (RegionStudioMode::Evidence, "Evidence & provenance"),
            ] {
                if ui
                    .add(egui::Button::selectable(
                        self.region_studio_mode == mode,
                        label,
                    ))
                    .clicked()
                {
                    self.region_studio_mode = mode;
                }
            }
        });
        ui.separator();
        match self.region_studio_mode {
            RegionStudioMode::Contract => self.region_contract_view(ui),
            RegionStudioMode::MachineIr => self.physical_region_view(ui),
            RegionStudioMode::DecompilePatch => self.decompile_patch_view(ui),
            RegionStudioMode::Evidence => self.region_evidence_view(ui),
        }
    }

    fn region_contract_view(&mut self, ui: &mut egui::Ui) {
        let Some(region) = &self.region else {
            ui.colored_label(
                BAD,
                self.region_error
                    .as_deref()
                    .unwrap_or("RegionSpec recovery did not produce an artifact."),
            );
            return;
        };
        ui.columns(2, |columns| {
            columns[0].vertical(|ui| {
                ui.heading(RichText::new(&region.symbol_name).monospace().color(ACCENT));
                ui.separator();
                field(ui, "REGION", &format!("0x{:016x} + {} bytes", region.entry.0, region.byte_length));
                field(ui, "REGION SHA-256", &region.bytes_sha256);
                field(ui, "EXITS", &format_addresses(&region.exits));
                field(ui, "DIRECT CALL CONTRACTS", &region.calls.len().to_string());
                field(ui, "RELOCATIONS", &region.relocations.len().to_string());
                field(
                    ui,
                    "STACK",
                    &region.stack_delta.map_or_else(
                        || "unresolved".to_owned(),
                        |delta| format!("RSP {delta:+} at return · entry alignment {}", region.stack_entry_alignment.map_or_else(|| "unknown".to_owned(), |value| value.to_string())),
                    ),
                );
                ui.separator();
                ui.label(RichText::new("PHYSICAL LIVE-IN").size(10.0).strong().color(INFO));
                physical_location_chips(ui, &region.physical_live_in);
                ui.label(RichText::new("PHYSICAL LIVE-OUT").size(10.0).strong().color(VIOLET));
                physical_location_chips(ui, &region.physical_live_out);
            });
            columns[1].vertical(|ui| {
                let stable = region.replacement_ready && region.unresolved_facts.is_empty();
                ui.heading(
                    RichText::new(if stable {
                        "Replacement boundary proven"
                    } else {
                        "Safety gate is holding"
                    })
                    .color(if stable { GOOD } else { BAD }),
                );
                ui.separator();
                ui.label(
                    RichText::new(if stable {
                        "The region contract contains the required boundary state."
                    } else {
                        "HydIR recovered useful semantics but will not promote missing facts into assumptions."
                    })
                    .color(MUTED),
                );
                ui.add_space(8.0);
                if region.unresolved_facts.is_empty() {
                    ui.colored_label(GOOD, "✓ No unresolved RegionSpec facts");
                } else {
                    for fact in &region.unresolved_facts {
                        ui.horizontal_wrapped(|ui| {
                            ui.colored_label(BAD, "●");
                            ui.label(fact);
                        });
                    }
                }
                if !region.observed_interior_entries.is_empty() {
                    ui.separator();
                    ui.colored_label(BAD, "OBSERVED INTERIOR ENTRIES");
                    for entry in &region.observed_interior_entries {
                        ui.label(format!("0x{:016x} · {}", entry.entry.0, entry.reason));
                    }
                }
            });
        });
    }

    fn physical_region_view(&mut self, ui: &mut egui::Ui) {
        let Some(ir) = &self.physical_region_ir else {
            ui.colored_label(
                BAD,
                self.physical_region_error
                    .as_deref()
                    .unwrap_or("PhysicalRegionIR recovery did not produce an artifact."),
            );
            ui.label(
                RichText::new("The RegionSpec remains available; unsupported semantics do not erase recovered evidence.")
                    .color(MUTED),
            );
            return;
        };
        ui.horizontal_wrapped(|ui| {
            metric_readout(ui, "INSTRUCTIONS", &ir.instructions.len().to_string(), INFO);
            metric_readout(ui, "INPUTS", &ir.physical_inputs.len().to_string(), INFO);
            metric_readout(
                ui,
                "OUTPUTS",
                &ir.physical_outputs.len().to_string(),
                VIOLET,
            );
            metric_readout(ui, "EXITS", &ir.exits.len().to_string(), ACCENT);
            metric_readout(ui, "CALLS", &ir.calls.len().to_string(), ACCENT);
            metric_readout(
                ui,
                "LOWERING",
                if ir.lowering_ready { "READY" } else { "GATED" },
                if ir.lowering_ready { GOOD } else { BAD },
            );
        });
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            ui.label(
                RichText::new("ADDRESS / BYTES")
                    .size(10.0)
                    .strong()
                    .color(MUTED),
            );
            ui.add_space(115.0);
            ui.label(
                RichText::new("MACHINE OPERATION")
                    .size(10.0)
                    .strong()
                    .color(MUTED),
            );
        });
        ui.separator();
        egui::ScrollArea::vertical()
            .id_salt("physical_region_ir")
            .show(ui, |ui| {
                for instruction in &ir.instructions {
                    let selected = self.selected_address == Some(instruction.address.0);
                    let operation = format!("{:?}", instruction.operation);
                    let response = ui.scope(|ui| {
                        ui.horizontal(|ui| {
                            ui.label(
                                RichText::new(format!(
                                    "0x{:016x}  {:<18}",
                                    instruction.address.0, instruction.bytes_hex
                                ))
                                .monospace()
                                .size(11.0)
                                .color(if selected { ACCENT } else { TEXT }),
                            );
                            ui.label(RichText::new(&instruction.mnemonic).monospace().strong());
                            ui.label(RichText::new(operation).monospace().size(11.0).color(INFO));
                        });
                        ui.label(
                            RichText::new(format!(
                                "reads {:?} · writes {:?} · flags {:?}/{:?} · memory {:?} · control {:?} · next {}",
                                instruction.effects.read_registers,
                                instruction.effects.written_registers,
                                instruction.effects.read_flags,
                                instruction.effects.written_flags,
                                instruction.effects.memory,
                                instruction.effects.control,
                                format_addresses(&instruction.successors),
                            ))
                            .monospace()
                            .size(10.0)
                            .color(MUTED),
                        );
                        ui.separator();
                    });
                    if response.response.interact(egui::Sense::click()).clicked() {
                        self.selected_address = Some(instruction.address.0);
                    }
                }
            });
    }

    fn decompile_patch_view(&mut self, ui: &mut egui::Ui) {
        let structured_c = self
            .decompilation
            .as_ref()
            .map(|unit| unit.c_source.clone())
            .or_else(|| self.c.clone());
        let native_fallback = if structured_c.is_none() {
            self.native_decompilation.as_ref().map(|native| {
                (
                    native_function_excerpt(&native.low_level_c).to_owned(),
                    format!("{:?}", native.cir.semantic_fidelity),
                    native_opaque_instruction_count(native),
                    native.cir.rewrite_ready,
                )
            })
        } else {
            None
        };
        let structured_error = self
            .decompilation_error
            .as_deref()
            .or(self.c_error.as_deref())
            .unwrap_or("this region is outside the structured recovery contract")
            .to_owned();
        ui.columns(2, |columns| {
            columns[0].heading(
                RichText::new(if native_fallback.is_some() {
                    "Native low-level C"
                } else {
                    "Deterministic C"
                })
                .color(INFO),
            );
            columns[0].label(
                RichText::new(if native_fallback.is_some() {
                    "Native function excerpt · complete C and diagnostics in the native view"
                } else {
                    "Read-only decompilation · machine-address provenance retained"
                })
                .size(10.0)
                .color(MUTED),
            );
            if let Some((_, fidelity, opaque, rewrite_ready)) = &native_fallback {
                columns[0].label(
                    RichText::new(format!("Structured C unavailable: {structured_error}"))
                    .size(11.0)
                    .color(ACCENT),
                );
                columns[0].label(
                    RichText::new(format!(
                        "Native fidelity: {fidelity} · {opaque} opaque instruction{} · rewrite ready: {}",
                        if *opaque == 1 { "" } else { "s" },
                        if *rewrite_ready { "yes" } else { "no" }
                    ))
                    .size(11.0)
                    .color(if *opaque == 0 { MUTED } else { ACCENT }),
                );
                if columns[0].small_button("Open native IR, C and diagnostics").clicked() {
                    self.tab = Tab::Native;
                }
            }
            egui::ScrollArea::both()
                .id_salt("region_studio_c")
                .max_height(430.0)
                .show(&mut columns[0], |ui| {
                    if let Some(source) = structured_c
                        .as_deref()
                        .or_else(|| native_fallback.as_ref().map(|native| native.0.as_str()))
                    {
                        ui.code(source);
                    } else {
                        ui.colored_label(
                            BAD,
                            self.decompilation_error
                                .as_deref()
                                .or(self.c_error.as_deref())
                                .unwrap_or("Structured C is unavailable for this region."),
                        );
                    }
                });

            columns[1].heading(RichText::new("HydIR PatchLang").color(VIOLET));
            columns[1].label(
                RichText::new("Typed replacement source · compiled to PatchIR and native bytes")
                    .size(10.0)
                    .color(MUTED),
            );
            let editor = columns[1].add(
                egui::TextEdit::multiline(&mut self.patch_replacement)
                    .font(egui::TextStyle::Monospace)
                    .desired_rows(12)
                    .desired_width(f32::INFINITY)
                    .hint_text("u64 result = arg0 - arg1;\nreturn result;"),
            );
            if editor.changed() {
                self.patch_preview = None;
                self.patch_verification_report = None;
            }
            columns[1].horizontal(|ui| {
                if ui.small_button("Identity template").clicked() {
                    self.patch_replacement = "return arg0;".to_owned();
                    self.patch_preview = None;
                }
                if ui.small_button("Subtract template").clicked() {
                    self.patch_replacement = "u64 result = arg0 - arg1;\nreturn result;".to_owned();
                    self.patch_preview = None;
                }
            });
            columns[1].checkbox(
                &mut self.trusted_fixture,
                "Trusted fixture; authorize compiler processing",
            );
            columns[1].checkbox(
                &mut self.entry_only_assertion,
                "Assert no control flow enters the region interior",
            );
            columns[1].label(RichText::new("OUTPUT ELF · NEW FILE ONLY").size(10.0).color(MUTED));
            columns[1].add(
                egui::TextEdit::singleline(&mut self.patch_output_path)
                    .hint_text("C:\\path\\to\\patched.elf")
                    .desired_width(f32::INFINITY),
            );
            let selected_symbol = self.symbol.clone();
            let preview_ready = self.spec.is_some()
                && selected_symbol.is_some()
                && self.trusted_fixture
                && self.entry_only_assertion
                && !self.patch_replacement.trim().is_empty()
                && !self.busy;
            columns[1].horizontal(|ui| {
                let preview = ui.add_enabled(
                    preview_ready,
                    egui::Button::new("Compile + verify plan"),
                );
                if preview.clicked()
                    && let Some(symbol) = selected_symbol.clone()
                {
                    self.enqueue(
                        Task::PreviewPatch {
                            symbol,
                            replacement: self.patch_replacement.trim().to_owned(),
                        },
                        "Compiling PatchLang and verifying placement…",
                    );
                }
                preview.on_disabled_hover_text(
                    "Select a region and explicitly accept the trusted-fixture and entry-only contracts.",
                );
                let preview_current = self.patch_preview.as_ref().is_some_and(|bundle| {
                    bundle.source.replacement == self.patch_replacement.trim()
                        && Some(bundle.source.function_symbol.as_str()) == selected_symbol.as_deref()
                        && self.spec.as_ref().is_some_and(|spec| {
                            spec.binary_sha256 == bundle.source.binary_sha256
                        })
                });
                let apply_ready = preview_ready
                    && preview_current
                    && (self.remote || !self.patch_output_path.trim().is_empty());
                let apply = ui.add_enabled(
                    apply_ready,
                    egui::Button::new(if self.remote {
                        "Apply as new revision"
                    } else {
                        "Apply to copy"
                    }),
                );
                if apply.clicked()
                    && let Some(symbol) = selected_symbol.clone()
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
                    self.enqueue(task, "Applying the verified HydIR patch…");
                }
                apply.on_disabled_hover_text(
                    "Compile a current verified plan first. Local apply requires a new output path.",
                );
            });
        });
        self.patch_plan_summary(ui);
    }

    fn patch_plan_summary(&self, ui: &mut egui::Ui) {
        let Some(bundle) = &self.patch_preview else {
            ui.add_space(8.0);
            ui.label(
                RichText::new(
                    "Compile the PatchLang source to reveal PatchIR, byte delta, placement strategy, and structural verification evidence.",
                )
                .color(MUTED),
            );
            return;
        };
        let placement = match bundle.placement_plan.strategy {
            PlacementStrategy::InPlace => "IN-PLACE REPLACEMENT",
            PlacementStrategy::EntryTrampoline => "ENTRY TRAMPOLINE → NEW RX SEGMENT",
        };
        ui.add_space(10.0);
        ui.separator();
        ui.vertical(|ui| {
            ui.horizontal_wrapped(|ui| {
                ui.colored_label(GOOD, "✓ STRUCTURALLY VERIFIED");
                ui.separator();
                ui.label(RichText::new(placement).strong().color(ACCENT));
                ui.separator();
                ui.label(format!(
                    "{} region bytes → {} compiled bytes · {} PatchIR statements",
                    bundle.placement_plan.original_size,
                    bundle.placement_plan.replacement_size,
                    bundle.typed_patch_ir.statements.len(),
                ));
            });
            if let Some(segment) = &bundle.placement_plan.executable_segment {
                ui.label(
                    RichText::new(format!(
                        "RX segment: file 0x{:x} · VA 0x{:x} · {} bytes",
                        segment.file_offset, segment.virtual_address.0, segment.file_size,
                    ))
                    .monospace()
                    .size(11.0)
                    .color(MUTED),
                );
            }
            egui::CollapsingHeader::new("Byte-level delta")
                .default_open(true)
                .show(ui, |ui| {
                    field(ui, "ORIGINAL REGION", &bundle.original_region_hex);
                    field(ui, "COMPILED CODE", &bundle.compiled_bytes_hex);
                    if let Some(entry) = &bundle.placement_plan.entry_bytes_hex {
                        field(ui, "NEW ENTRY", entry);
                    }
                });
        });
    }

    fn region_evidence_view(&mut self, ui: &mut egui::Ui) {
        ui.columns(2, |columns| {
            columns[0].heading(RichText::new("Artifact provenance").color(INFO));
            if let Some(region) = &self.region {
                field(&mut columns[0], "BINARY SHA-256", &region.binary_sha256);
                field(&mut columns[0], "REGION SHA-256", &region.bytes_sha256);
                field(
                    &mut columns[0],
                    "ADDRESS MODEL",
                    &format!("{:?}", region.address_kind),
                );
                field(
                    &mut columns[0],
                    "FACT SOURCE",
                    &format!("{:?}", region.provenance.source),
                );
                field(&mut columns[0], "RECOVERY SCOPE", &region.provenance.scope);
            }
            if let Some(unit) = &self.decompilation {
                columns[0].separator();
                field(&mut columns[0], "ENGINE", &unit.engine_version);
                field(
                    &mut columns[0],
                    "STATEMENT MAPPINGS",
                    &unit.statement_provenance.len().to_string(),
                );
                for mapping in &unit.statement_provenance {
                    columns[0].label(
                        RichText::new(format!(
                            "C {}–{} ← {}",
                            mapping.c_start_line,
                            mapping.c_end_line,
                            format_addresses(&mapping.addresses),
                        ))
                        .monospace()
                        .size(11.0),
                    );
                }
            }

            columns[1].heading(RichText::new("Release gates").color(VIOLET));
            if let Some(unit) = &self.decompilation {
                for diagnostic in &unit.diagnostics {
                    let color = if diagnostic.blocks_stable_operation {
                        BAD
                    } else {
                        ACCENT
                    };
                    columns[1].label(
                        RichText::new(format!("{} · {:?}", diagnostic.code, diagnostic.severity))
                            .strong()
                            .color(color),
                    );
                    columns[1].label(RichText::new(&diagnostic.message).color(MUTED));
                    columns[1].add_space(5.0);
                }
            } else if let Some(error) = &self.decompilation_error {
                columns[1].colored_label(BAD, error);
            }
            if let Some(bundle) = &self.patch_preview {
                columns[1].separator();
                columns[1].label(RichText::new("PATCH VERIFICATION").strong().color(GOOD));
                for evidence in &bundle.verification_evidence {
                    let passed = format!("{:?}", evidence.status).eq_ignore_ascii_case("passed");
                    columns[1].label(
                        RichText::new(format!(
                            "{} {} · {}",
                            if passed { "✓" } else { "!" },
                            evidence.check,
                            evidence.details,
                        ))
                        .color(if passed { GOOD } else { BAD }),
                    );
                }
                if let Some(report) = &self.patch_verification_report {
                    egui::CollapsingHeader::new("Verification report JSON")
                        .show(&mut columns[1], |ui| ui.code(report));
                }
            }
        });
    }

    fn disassembly(&mut self, ui: &mut egui::Ui) {
        if self.disassembly_report.is_some() {
            self.full_disassembly(ui);
            return;
        }
        if self.native_decompilation.is_some() {
            let Some(native) = &self.native_decompilation else {
                ui.label(
                    RichText::new("Select a function or disassemble the whole ELF.").color(MUTED),
                );
                return;
            };
            let instructions = native
                .machine_ir
                .blocks
                .iter()
                .flat_map(|block| &block.instructions)
                .collect::<Vec<_>>();
            ui.label(
                RichText::new(format!(
                    "Native decoded function - {} instructions - source bytes preserved",
                    instructions.len()
                ))
                .size(11.0)
                .color(MUTED),
            );
            let mut clicked = None;
            let mut scroll = egui::ScrollArea::vertical().id_salt("native_bytes_view");
            if let Some(address) = self.pending_disassembly_scroll.take()
                && let Some(position) = instructions
                    .iter()
                    .position(|instruction| instruction.address.value.0 == address)
            {
                scroll = scroll.vertical_scroll_offset(position as f32 * 26.0);
            }
            scroll.show_rows(ui, 26.0, instructions.len(), |ui, range| {
                for position in range {
                    let instruction = instructions[position];
                    let opaque =
                        matches!(instruction.operation, MachineOperation::OpaqueEffect { .. });
                    let line = format!(
                        "{}:0x{:016x}  {:<20} {:<10} {:?}",
                        instruction.address.address_space,
                        instruction.address.value.0,
                        instruction.bytes_hex,
                        instruction.mnemonic,
                        instruction.operands
                    );
                    if ui
                        .selectable_label(
                            self.selected_address == Some(instruction.address.value.0),
                            RichText::new(line).monospace().size(11.0).color(if opaque {
                                BAD
                            } else {
                                TEXT
                            }),
                        )
                        .on_hover_text(format!(
                            "Operation: {:?}\nEffects: {:?}\nEdges: {:?}",
                            instruction.operation, instruction.effects, instruction.edges
                        ))
                        .clicked()
                    {
                        clicked = Some(instruction.address.value.0);
                    }
                }
            });
            if let Some(address) = clicked {
                self.selected_address = Some(address);
            }
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
        let mut scroll = egui::ScrollArea::vertical().id_salt("whole_elf_disassembly");
        if let Some(address) = self.pending_disassembly_scroll.take()
            && let Some(position) = instructions
                .iter()
                .position(|instruction| instruction.address.0 == address)
        {
            scroll = scroll.vertical_scroll_offset(position as f32 * 25.0);
        }
        scroll.show_rows(ui, 25.0, instructions.len(), |ui, range| {
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

    fn console_view(&mut self, ui: &mut egui::Ui, maximum_height: f32) {
        let (resize_rect, resize_response) =
            ui.allocate_exact_size(egui::vec2(ui.available_width(), 8.0), egui::Sense::drag());
        let resize_response = resize_response
            .on_hover_cursor(egui::CursorIcon::ResizeVertical)
            .on_hover_text("Drag to resize the console");
        if resize_response.dragged() {
            self.console_height = resized_console_height(
                self.console_height,
                resize_response.drag_delta().y,
                maximum_height,
            );
            ui.ctx().request_repaint();
        }
        let resize_color = if resize_response.dragged() || resize_response.hovered() {
            ACCENT
        } else {
            ui.visuals().widgets.noninteractive.bg_stroke.color
        };
        ui.painter().hline(
            resize_rect.x_range(),
            resize_rect.center().y,
            egui::Stroke::new(1.0, resize_color),
        );

        ui.horizontal(|ui| {
            ui.heading(RichText::new("Console").size(14.0));
            if ui
                .selectable_label(self.console_mode == ConsoleMode::Activity, "Activity")
                .clicked()
            {
                self.console_mode = ConsoleMode::Activity;
            }
            if ui
                .selectable_label(self.console_mode == ConsoleMode::Triton, "Triton REPL")
                .clicked()
            {
                self.console_mode = ConsoleMode::Triton;
            }
            if ui.button("Hide").clicked() {
                self.console_visible = false;
            }
            ui.label(
                RichText::new("DOCKED BOTTOM · drag the top border to resize")
                    .size(10.0)
                    .color(MUTED),
            );
            if self.console_mode == ConsoleMode::Activity
                && (self.disassembly_report.is_some() || self.triton_result.is_some())
            {
                if ui
                    .button(if self.console_json {
                        "Show activity"
                    } else {
                        "Show JSON"
                    })
                    .clicked()
                {
                    self.console_json = !self.console_json;
                }
                if ui.button("Copy JSON").clicked() {
                    if let Some(result) = &self.triton_result {
                        if let Ok(json) = serde_json::to_string_pretty(result) {
                            ui.ctx().copy_text(json);
                        }
                    } else if let Some(report) = &self.disassembly_report
                        && let Ok(json) = serde_json::to_string_pretty(report)
                    {
                        ui.ctx().copy_text(json);
                    }
                }
            } else if self.console_mode == ConsoleMode::Triton {
                if ui.button("Clear").clicked() {
                    self.triton_console_commands.clear();
                    self.triton_console_result = None;
                    self.triton_console_input.clear();
                    self.failure = None;
                }
                if ui.button("Copy transcript").clicked()
                    && let Some(result) = &self.triton_console_result
                    && let Ok(json) = serde_json::to_string_pretty(result)
                {
                    ui.ctx().copy_text(json);
                }
            }
        });
        if self.console_mode == ConsoleMode::Activity {
            let available = (ui.available_height() - 4.0).max(70.0);
            egui::ScrollArea::vertical()
                .id_salt("console_output")
                .max_height(available)
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    if self.console_json {
                        if let Some(result) = &self.triton_result
                            && let Ok(json) = serde_json::to_string_pretty(result)
                        {
                            ui.label(RichText::new("TRITON SYMBOLIC RESULT").color(ACCENT));
                            ui.code(json);
                        } else if let Some(report) = &self.disassembly_report
                            && let Ok(json) = serde_json::to_string_pretty(report)
                        {
                            ui.code(json);
                        }
                    } else {
                        if let Some(failure) = &self.failure {
                            ui.colored_label(BAD, failure);
                        } else {
                            ui.colored_label(
                                if self.busy || self.ghidra_busy {
                                    ACCENT
                                } else {
                                    GOOD
                                },
                                &self.status,
                            );
                        }
                        if let Some(report) = &self.disassembly_report {
                            for warning in report.warnings.iter().take(8) {
                                ui.colored_label(BAD, warning);
                            }
                        }
                        if let Some(result) = &self.triton_result {
                            let paths = result
                                .get("paths")
                                .and_then(serde_json::Value::as_array)
                                .map_or(0, Vec::len);
                            let rax = result
                                .get("final_registers")
                                .and_then(|registers| registers.get("rax"))
                                .and_then(serde_json::Value::as_str)
                                .unwrap_or("unavailable");
                            ui.label(
                                RichText::new(format!(
                                    "Triton: {paths} path(s), final rax = {rax}"
                                ))
                                .monospace()
                                .size(11.0)
                                .color(ACCENT),
                            );
                        }
                        for entry in self.history.iter().rev().take(8) {
                            ui.label(RichText::new(entry).size(11.0).color(MUTED));
                        }
                    }
                });
        } else {
            self.triton_console_body(ui);
        }
        ui.take_available_space();
    }

    fn triton_console_body(&mut self, ui: &mut egui::Ui) {
        ui.label(
            RichText::new(
                "Restricted Triton Python subset · one statement per line · no filesystem, shell, network, or arbitrary imports",
            )
            .size(10.0)
            .color(MUTED),
        );
        let transcript_height = (ui.available_height() - 42.0).max(70.0);
        egui::ScrollArea::vertical()
            .id_salt("triton_console_transcript")
            .max_height(transcript_height)
            .auto_shrink([false, false])
            .stick_to_bottom(true)
            .show(ui, |ui| {
                if let Some(result) = &self.triton_console_result {
                    if let Some(entries) =
                        result.get("entries").and_then(serde_json::Value::as_array)
                    {
                        for entry in entries {
                            let command = entry
                                .get("command")
                                .and_then(serde_json::Value::as_str)
                                .unwrap_or_default();
                            ui.label(
                                RichText::new(format!(">>> {command}"))
                                    .monospace()
                                    .color(ACCENT),
                            );
                            if let Some(output) =
                                entry.get("output").and_then(serde_json::Value::as_array)
                            {
                                for line in output.iter().filter_map(serde_json::Value::as_str) {
                                    ui.label(RichText::new(line).monospace().color(TEXT));
                                }
                            }
                        }
                    }
                } else {
                    ui.label(
                        RichText::new(
                            ">>> from triton import *\n>>> ctx = TritonContext(ARCH.X86_64)",
                        )
                        .monospace()
                        .color(MUTED),
                    );
                }
                if let Some(failure) = &self.failure {
                    ui.colored_label(BAD, failure);
                } else if self.busy {
                    ui.colored_label(ACCENT, "Evaluating Triton statement…");
                }
            });
        let mut submit = false;
        ui.horizontal(|ui| {
            ui.label(RichText::new(">>>").monospace().color(ACCENT));
            let editor = ui.add_enabled(
                !self.busy,
                egui::TextEdit::singleline(&mut self.triton_console_input)
                    .hint_text("ctx.getModel(rcx_expr.getAst() == 0xdead)")
                    .desired_width(f32::INFINITY),
            );
            submit = editor.lost_focus() && ui.input(|input| input.key_pressed(egui::Key::Enter));
            if ui
                .add_enabled(
                    !self.busy && !self.triton_console_input.trim().is_empty(),
                    egui::Button::new("Run"),
                )
                .clicked()
            {
                submit = true;
            }
        });
        if submit {
            self.submit_triton_console();
        }
    }

    fn submit_triton_console(&mut self) {
        let command = self.triton_console_input.trim().to_owned();
        if command.is_empty() {
            return;
        }
        if self.triton_console_commands.len() >= 64 {
            self.failure =
                Some("Triton console is limited to 64 statements; clear it first".to_owned());
            return;
        }
        let mut commands = self.triton_console_commands.clone();
        commands.push(command);
        self.triton_console_input.clear();
        self.enqueue(
            Task::TritonConsole { commands },
            "Evaluating restricted Triton statement…",
        );
    }

    fn graph_view(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label(RichText::new("GRAPH SCOPE").size(10.0).color(MUTED));
            if ui
                .selectable_label(
                    self.graph_mode == GraphMode::Function,
                    "Selected function CFG",
                )
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

        if self.graph_mode == GraphMode::Function && self.native_decompilation.is_some() {
            self.native_function_graph_view(ui);
            return;
        }
        if self.graph_mode == GraphMode::Program && self.function_index.is_some() {
            self.native_program_graph_view(ui);
            return;
        }

        let mut nodes: Vec<(NodeId, String, bool)> = Vec::new();
        let mut edges: Vec<(NodeId, NodeId)> = Vec::new();
        match self.graph_mode {
            GraphMode::Function => {
                let Some(cfg) = &self.cfg else {
                    ui.label(
                        RichText::new("Select a function to build its CFG graph.").color(MUTED),
                    );
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
                    ui.label(
                        RichText::new("Open an ELF to build its function graph.").color(MUTED),
                    );
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
                        RichText::new(
                            "Run Global effects / Analyze to populate bounded call edges.",
                        )
                        .color(MUTED),
                    );
                    return;
                };
                for summary in &report.functions {
                    for callee in &summary.direct_callees {
                        if spec
                            .functions
                            .iter()
                            .any(|function| function.name == *callee)
                        {
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
                        spec.functions
                            .iter()
                            .find(|function| function.address == address)
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
                    ui.label(
                        RichText::new("Load a Ghidra JSON export to show its graph.").color(MUTED),
                    );
                    return;
                };
                let selected = self
                    .symbol
                    .as_deref()
                    .and_then(|name| {
                        graph
                            .functions
                            .iter()
                            .find(|function| function.name == name)
                    })
                    .or_else(|| graph.functions.first());
                let Some(function) = selected else {
                    ui.label(
                        RichText::new("The Ghidra export contains no functions.").color(MUTED),
                    );
                    return;
                };
                let block_addresses: std::collections::HashSet<&str> = function
                    .blocks
                    .iter()
                    .map(|block| block.address.as_str())
                    .collect();
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
        let layout = layout_from_sizes(
            layout_nodes,
            edges.iter().copied(),
            GraphDirection::LeftToRight,
        );
        let min_x = layout
            .values()
            .map(|position| position.x)
            .fold(f32::INFINITY, f32::min);
        let min_y = layout
            .values()
            .map(|position| position.y)
            .fold(f32::INFINITY, f32::min);
        let max_x = layout
            .values()
            .map(|position| position.x)
            .fold(f32::NEG_INFINITY, f32::max);
        let max_y = layout
            .values()
            .map(|position| position.y)
            .fold(f32::NEG_INFINITY, f32::max);
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
                    let rect =
                        egui::Rect::from_min_size(position, egui::vec2(node_size[0], node_size[1]));
                    rects.insert(*id, rect);
                    painter.rect_filled(rect, 0.0, PANEL);
                    painter.rect_stroke(
                        rect,
                        0.0,
                        egui::Stroke::new(1.0, if *selected { ACCENT } else { MUTED }),
                        egui::StrokeKind::Outside,
                    );
                    painter.text(
                        rect.left_top() + egui::vec2(10.0, 9.0),
                        egui::Align2::LEFT_TOP,
                        label,
                        egui::FontId::monospace(11.0),
                        TEXT,
                    );
                    let response = ui.interact(
                        rect,
                        ui.id().with(("graph-node", id.value())),
                        egui::Sense::click(),
                    );
                    if response.clicked()
                        && self.graph_mode == GraphMode::Function
                        && let Some(address) = label
                            .strip_prefix("0x")
                            .and_then(|value| value.split('\n').next())
                            .and_then(|value| u64::from_str_radix(value, 16).ok())
                    {
                        self.selected_address = Some(address);
                    }
                }
                for (source, target) in &edges {
                    if let (Some(source_rect), Some(target_rect)) =
                        (rects.get(source), rects.get(target))
                    {
                        let start = source_rect.right_center();
                        let end = target_rect.left_center();
                        painter.line_segment([start, end], egui::Stroke::new(1.5, ACCENT));
                        let direction = (end - start).normalized();
                        let tip = end;
                        let left =
                            tip - direction * 10.0 + egui::vec2(-direction.y, direction.x) * 4.0;
                        let right =
                            tip - direction * 10.0 - egui::vec2(-direction.y, direction.x) * 4.0;
                        painter.add(egui::Shape::convex_polygon(
                            vec![tip, left, right],
                            ACCENT,
                            egui::Stroke::NONE,
                        ));
                    }
                }
            });
    }

    fn native_function_graph_view(&mut self, ui: &mut egui::Ui) {
        let Some(native) = &self.native_decompilation else {
            return;
        };
        ui.horizontal(|ui| {
            ui.label(RichText::new("ZOOM").size(10.0).color(MUTED));
            ui.add(egui::Slider::new(&mut self.graph_zoom, 0.6..=1.6).show_value(false));
            if ui.small_button("Reset").clicked() {
                self.graph_zoom = 1.0;
            }
            ui.label(
                RichText::new(format!(
                    "{} blocks / {} instructions",
                    native.machine_ir.blocks.len(),
                    native_instruction_count(native)
                ))
                .size(11.0)
                .color(MUTED),
            );
        });

        let mut nodes = Vec::<WorkbenchGraphNode>::new();
        let mut edges = Vec::<WorkbenchGraphEdge>::new();
        let mut block_ids = std::collections::BTreeMap::new();
        for block in &native.machine_ir.blocks {
            let id = NodeId::new((
                "native-block",
                block.address.address_space,
                block.address.value.0,
            ));
            block_ids.insert(block.address, id);
            let preview = block
                .instructions
                .iter()
                .take(3)
                .map(|instruction| instruction.mnemonic.as_str())
                .collect::<Vec<_>>()
                .join("; ");
            let truncated = if block.instructions.len() > 3 {
                "; ..."
            } else {
                ""
            };
            let opaque = block.instructions.iter().any(|instruction| {
                matches!(instruction.operation, MachineOperation::OpaqueEffect { .. })
            });
            nodes.push(WorkbenchGraphNode {
                id,
                label: format!(
                    "{}\n{}:0x{:x}\n{}{}",
                    block.label,
                    block.address.address_space,
                    block.address.value.0,
                    preview,
                    truncated
                ),
                tone: if self.selected_address == Some(block.address.value.0) {
                    GraphNodeTone::Selected
                } else if opaque {
                    GraphNodeTone::Opaque
                } else {
                    GraphNodeTone::Normal
                },
                action: Some(GraphNodeAction::Address(block.address.value.0)),
            });
        }

        let mut external_targets = std::collections::BTreeSet::new();
        for block in &native.machine_ir.blocks {
            let source = block_ids[&block.address];
            for (edge_index, edge) in block
                .instructions
                .iter()
                .flat_map(|instruction| &instruction.edges)
                .enumerate()
            {
                let (target, unresolved) = if let Some(location) = edge.target {
                    if let Some(target) = block_ids.get(&location) {
                        (*target, false)
                    } else {
                        let target = NodeId::new((
                            "native-external",
                            location.address_space,
                            location.value.0,
                        ));
                        if external_targets.insert(Some(location)) {
                            let indexed = self.function_index.as_ref().and_then(|index| {
                                index
                                    .functions
                                    .iter()
                                    .find(|function| function.entry == location)
                            });
                            nodes.push(WorkbenchGraphNode {
                                id: target,
                                label: indexed.map_or_else(
                                    || {
                                        format!(
                                            "external target\n{}:0x{:x}",
                                            location.address_space, location.value.0
                                        )
                                    },
                                    |function| {
                                        format!(
                                            "{}\n{}:0x{:x}",
                                            indexed_function_label(function),
                                            location.address_space,
                                            location.value.0
                                        )
                                    },
                                ),
                                tone: GraphNodeTone::External,
                                action: indexed.map(|function| {
                                    indexed_function_action(function, self.spec.as_ref())
                                }),
                            });
                        }
                        (target, false)
                    }
                } else {
                    let target = NodeId::new((
                        "native-unresolved",
                        block.address.address_space,
                        block.address.value.0,
                        edge_index,
                    ));
                    nodes.push(WorkbenchGraphNode {
                        id: target,
                        label: format!("unresolved\n{:?}", edge.kind),
                        tone: GraphNodeTone::Opaque,
                        action: None,
                    });
                    (target, true)
                };
                edges.push(WorkbenchGraphEdge {
                    source,
                    target,
                    label: format!("{:?}", edge.kind),
                    unresolved,
                });
            }
        }

        if let Some(action) = render_workbench_graph(
            ui,
            &nodes,
            &edges,
            self.graph_zoom,
            (
                "native_function_graph",
                native.machine_ir.function_id.as_str(),
            ),
        ) {
            self.apply_graph_action(action);
        }
    }

    fn native_program_graph_view(&mut self, ui: &mut egui::Ui) {
        let Some(index) = &self.function_index else {
            return;
        };
        ui.horizontal(|ui| {
            ui.label(RichText::new("FILTER").size(10.0).color(MUTED));
            ui.add(
                egui::TextEdit::singleline(&mut self.graph_filter)
                    .hint_text("Function name or stable ID")
                    .desired_width(240.0),
            );
            ui.label(RichText::new("ZOOM").size(10.0).color(MUTED));
            ui.add(egui::Slider::new(&mut self.graph_zoom, 0.6..=1.6).show_value(false));
        });

        let mut entries = std::collections::BTreeMap::new();
        for (position, function) in index.functions.iter().enumerate() {
            entries.entry(function.entry).or_insert(position);
        }
        let mut recovered_edges = std::collections::BTreeSet::new();
        for (source, function) in index.functions.iter().enumerate() {
            for target in &function.candidate_targets {
                if let Some(target) = entries.get(target).copied()
                    && source != target
                {
                    recovered_edges.insert((source, target, "candidate".to_owned()));
                }
            }
        }
        if let Some(native) = &self.native_decompilation
            && let Some(source) = index
                .functions
                .iter()
                .position(|function| function.id == native.machine_ir.function_id)
        {
            for call in &native.function_ir.calls {
                if let Some(target) = call.target.and_then(|target| entries.get(&target).copied())
                    && source != target
                {
                    recovered_edges.insert((
                        source,
                        target,
                        if call.tail_call { "tail call" } else { "call" }.to_owned(),
                    ));
                }
            }
        }

        let selected = self.selected_indexed_function().and_then(|selected| {
            index
                .functions
                .iter()
                .position(|function| function.id == selected.id)
        });
        let query = self.graph_filter.trim().to_lowercase();
        let mut visible = std::collections::BTreeSet::new();
        if index.functions.len() <= 180 && query.is_empty() {
            visible.extend(0..index.functions.len());
        } else {
            if query.is_empty() {
                visible.insert(selected.unwrap_or(0));
            } else {
                for (position, function) in index.functions.iter().enumerate() {
                    let label = indexed_function_label(function);
                    if label.to_lowercase().contains(&query)
                        || function.id.to_lowercase().contains(&query)
                    {
                        visible.insert(position);
                        if visible.len() >= 80 {
                            break;
                        }
                    }
                }
            }
            let seeds = visible.clone();
            for (source, target, _) in &recovered_edges {
                if seeds.contains(source) || seeds.contains(target) {
                    visible.insert(*source);
                    visible.insert(*target);
                    if visible.len() >= 220 {
                        break;
                    }
                }
            }
        }
        ui.label(
            RichText::new(format!(
                "Showing {} of {} functions and their evidence-backed direct neighbors",
                visible.len(),
                index.functions.len()
            ))
            .size(11.0)
            .color(MUTED),
        );

        let mut nodes = Vec::new();
        let mut ids = std::collections::BTreeMap::new();
        for position in &visible {
            let function = &index.functions[*position];
            let id = NodeId::new(("native-function", function.id.as_str()));
            ids.insert(*position, id);
            nodes.push(WorkbenchGraphNode {
                id,
                label: format!(
                    "{}\n{}:0x{:x}\n{:?}",
                    indexed_function_label(function),
                    function.entry.address_space,
                    function.entry.value.0,
                    function.state
                ),
                tone: if selected == Some(*position) {
                    GraphNodeTone::Selected
                } else if function.state == FunctionEvidenceState::Ambiguous {
                    GraphNodeTone::Opaque
                } else {
                    GraphNodeTone::Normal
                },
                action: Some(indexed_function_action(function, self.spec.as_ref())),
            });
        }
        let edges = recovered_edges
            .iter()
            .filter_map(|(source, target, label)| {
                Some(WorkbenchGraphEdge {
                    source: *ids.get(source)?,
                    target: *ids.get(target)?,
                    label: label.clone(),
                    unresolved: false,
                })
            })
            .collect::<Vec<_>>();
        if nodes.is_empty() {
            ui.colored_label(MUTED, "No functions match the graph filter.");
            return;
        }
        if let Some(action) =
            render_workbench_graph(ui, &nodes, &edges, self.graph_zoom, "native_program_graph")
        {
            self.apply_graph_action(action);
        }
    }

    fn apply_graph_action(&mut self, action: GraphNodeAction) {
        match action {
            GraphNodeAction::Address(address) => {
                self.selected_address = Some(address);
            }
            GraphNodeAction::Function {
                label,
                selector,
                entry,
                legacy_symbol,
            } => {
                self.graph_mode = GraphMode::Function;
                if legacy_symbol {
                    self.select(label);
                } else {
                    self.select_native(label, selector, entry);
                }
                self.selection_target_tab = Some(Tab::Graph);
            }
        }
    }

    fn cfg_view(&mut self, ui: &mut egui::Ui) {
        if self.native_decompilation.is_some() {
            let Some(native) = &self.native_decompilation else {
                ui.label(
                    RichText::new("Select a function to recover its control-flow graph.")
                        .color(MUTED),
                );
                return;
            };
            ui.label(
                RichText::new(format!(
                    "Native MachineFunctionIR control flow - {} blocks - {:?}",
                    native.machine_ir.blocks.len(),
                    native.machine_ir.structural_completeness
                ))
                .size(11.0)
                .color(MUTED),
            );
            let mut clicked = None;
            egui::ScrollArea::vertical()
                .id_salt("native_cfg_view")
                .show(ui, |ui| {
                    for block in &native.machine_ir.blocks {
                        let edges = block
                            .instructions
                            .iter()
                            .flat_map(|instruction| &instruction.edges)
                            .map(|edge| {
                                edge.target.map_or_else(
                                    || format!("{:?} -> unresolved", edge.kind),
                                    |target| {
                                        format!(
                                            "{:?} -> {}:0x{:x}",
                                            edge.kind, target.address_space, target.value.0
                                        )
                                    },
                                )
                            })
                            .collect::<Vec<_>>()
                            .join("   ");
                        let text = format!(
                            "{}:0x{:016x}  {:<18}  {}",
                            block.address.address_space, block.address.value.0, block.label, edges
                        );
                        if ui
                            .selectable_label(
                                self.selected_address == Some(block.address.value.0),
                                RichText::new(text).monospace().size(11.0),
                            )
                            .clicked()
                        {
                            clicked = Some(block.address.value.0);
                        }
                    }
                });
            if let Some(address) = clicked {
                self.selected_address = Some(address);
            }
            return;
        }
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
        let mut open_native = false;
        match self.c_output_source() {
            Some(COutputSource::Scalar(c)) => {
                ui.label(
                    RichText::new("SCALAR LLVM-TO-C · EXPLICIT CFG / SSA COPIES")
                        .size(11.0)
                        .color(ACCENT),
                );
                egui::ScrollArea::both().id_salt("c_view").show(ui, |ui| {
                    ui.code(c);
                });
            }
            Some(COutputSource::Native(native)) => {
                ui.label(
                    RichText::new("NATIVE LOW-LEVEL C · EXPLICIT MACHINE STATE")
                        .size(11.0)
                        .color(INFO),
                );
                if let Some(error) = self
                    .c_error
                    .as_deref()
                    .or(self.decompilation_error.as_deref())
                {
                    ui.label(
                        RichText::new(format!("Scalar C unavailable: {error}"))
                            .size(11.0)
                            .color(ACCENT),
                    );
                }
                let opaque = native_opaque_instruction_count(native);
                ui.label(
                    RichText::new(format!(
                        "Native fidelity: {:?} · {opaque} opaque instruction{} · rewrite ready: {}",
                        native.cir.semantic_fidelity,
                        if opaque == 1 { "" } else { "s" },
                        if native.cir.rewrite_ready {
                            "yes"
                        } else {
                            "no"
                        }
                    ))
                    .size(11.0)
                    .color(if opaque == 0 { MUTED } else { ACCENT }),
                );
                if ui.small_button("Open complete C and diagnostics").clicked() {
                    open_native = true;
                }
                ui.label(
                    RichText::new("Function excerpt; complete C is in the native view.")
                        .color(MUTED),
                );
                egui::ScrollArea::both()
                    .id_salt("c_view_native")
                    .show(ui, |ui| {
                        ui.code(native_function_excerpt(&native.low_level_c));
                    });
            }
            None => {
                if let Some(error) = &self.c_error {
                    ui.colored_label(BAD, error);
                    ui.label(
                        RichText::new("C generation and native decompilation are unavailable for this function.")
                            .color(MUTED),
                    );
                } else {
                    ui.label(RichText::new("Select a function to generate C.").color(MUTED));
                }
            }
        }
        if open_native {
            self.tab = Tab::Native;
        }
    }

    fn c_output_source(&self) -> Option<COutputSource<'_>> {
        self.c
            .as_deref()
            .or_else(|| {
                self.decompilation
                    .as_ref()
                    .map(|unit| unit.c_source.as_str())
            })
            .map(COutputSource::Scalar)
            .or_else(|| {
                self.native_decompilation
                    .as_ref()
                    .map(COutputSource::Native)
            })
    }

    fn native_view(&mut self, ui: &mut egui::Ui) {
        let Some(native) = &self.native_decompilation else {
            ui.colored_label(
                BAD,
                self.native_decompilation_error
                    .as_deref()
                    .unwrap_or("Select a native FunctionIndex entry to decompile it."),
            );
            ui.label(
                RichText::new(
                    "Native failures remain function-local; ProgramSpec and FunctionIndex artifacts are retained.",
                )
                .color(MUTED),
            );
            return;
        };
        ui.horizontal_wrapped(|ui| {
            field(ui, "FUNCTION ID", &native.machine_ir.function_id);
            field(
                ui,
                "ENTRY",
                &format!(
                    "{}:0x{:x}",
                    native.machine_ir.entry.address_space, native.machine_ir.entry.value.0
                ),
            );
            field(
                ui,
                "FIDELITY",
                &format!("{:?}", native.cir.semantic_fidelity),
            );
            field(
                ui,
                "REWRITE READY",
                if native.cir.rewrite_ready {
                    "yes"
                } else {
                    "no"
                },
            );
        });
        ui.separator();
        ui.label(
            RichText::new("LOW-LEVEL C11 · EXPLICIT STATE / UNKNOWN EFFECTS")
                .size(11.0)
                .strong()
                .color(ACCENT),
        );
        egui::ScrollArea::both()
            .id_salt("native_low_c")
            .max_height(340.0)
            .show(ui, |ui| ui.code(&native.low_level_c));
        if let Some(structured) = &native.structured_c {
            egui::CollapsingHeader::new("Structured C11")
                .default_open(true)
                .show(ui, |ui| {
                    egui::ScrollArea::both()
                        .id_salt("native_structured_c")
                        .max_height(300.0)
                        .show(ui, |ui| ui.code(structured));
                });
        }
        for (label, value) in [
            (
                "MachineFunctionIR v1",
                serde_json::to_string_pretty(&native.machine_ir),
            ),
            (
                "StateFunctionIR v1",
                serde_json::to_string_pretty(&native.state_ir),
            ),
            (
                "FunctionIR v1",
                serde_json::to_string_pretty(&native.function_ir),
            ),
            ("CIR v1", serde_json::to_string_pretty(&native.cir)),
        ] {
            egui::CollapsingHeader::new(label).show(ui, |ui| match value {
                Ok(value) => {
                    ui.code(value);
                }
                Err(error) => {
                    ui.colored_label(BAD, error.to_string());
                }
            });
        }
        if !native.diagnostics.is_empty() {
            egui::CollapsingHeader::new(format!("Diagnostics ({})", native.diagnostics.len()))
                .show(ui, |ui| {
                    for diagnostic in &native.diagnostics {
                        ui.colored_label(
                            if diagnostic.blocks_stable_operation {
                                BAD
                            } else {
                                MUTED
                            },
                            format!("{} · {}", diagnostic.code, diagnostic.message),
                        );
                    }
                });
        }
    }

    fn native_explorer_view(&mut self, ui: &mut egui::Ui) {
        if self.native_decompilation.is_none() {
            self.native_view(ui);
            return;
        }
        ui.horizontal_wrapped(|ui| {
            for (mode, label) in [
                (NativeViewMode::Summary, "Summary"),
                (NativeViewMode::TypedC, "Typed C"),
                (NativeViewMode::Types, "Types"),
                (NativeViewMode::LowLevelC, "Low-level C"),
                (NativeViewMode::StructuredC, "Structured C"),
                (NativeViewMode::MachineIr, "MachineIR"),
                (NativeViewMode::StateIr, "StateIR"),
                (NativeViewMode::FunctionIr, "FunctionIR"),
                (NativeViewMode::Cir, "CIR"),
                (NativeViewMode::Evidence, "Evidence"),
            ] {
                ui.selectable_value(&mut self.native_view_mode, mode, label);
            }
        });
        ui.separator();
        let Some(native) = &self.native_decompilation else {
            ui.colored_label(
                BAD,
                self.native_decompilation_error
                    .as_deref()
                    .unwrap_or("Select a native FunctionIndex entry to decompile it."),
            );
            ui.label(
                RichText::new(
                    "Native failures remain function-local; ProgramSpec and FunctionIndex artifacts are retained.",
                )
                .color(MUTED),
            );
            return;
        };

        let instruction_count = native_instruction_count(native);
        let opaque_count = native_opaque_instruction_count(native);
        ui.horizontal_wrapped(|ui| {
            field(ui, "FUNCTION ID", &native.machine_ir.function_id);
            field(
                ui,
                "ENTRY",
                &format!(
                    "{}:0x{:x}",
                    native.machine_ir.entry.address_space, native.machine_ir.entry.value.0
                ),
            );
            field(
                ui,
                "FIDELITY",
                &format!("{:?}", native.cir.semantic_fidelity),
            );
            field(
                ui,
                "REWRITE READY",
                if native.cir.rewrite_ready {
                    "yes"
                } else {
                    "no"
                },
            );
            field(ui, "BLOCKS", &native.machine_ir.blocks.len().to_string());
            field(ui, "INSTRUCTIONS", &instruction_count.to_string());
            field(ui, "OPAQUE", &opaque_count.to_string());
        });
        ui.separator();

        let clicked_address = match self.native_view_mode {
            NativeViewMode::Summary => {
                native_summary_view(ui, native);
                None
            }
            NativeViewMode::TypedC => {
                if let Some(typed) = &self.typed_native_view {
                    if let Some(c) = &typed.c {
                        code_artifact_view(
                            ui,
                            "TYPED C11 - BOUNDED SUPPORTED OPERATIONS",
                            c,
                            "native_typed_c",
                        );
                    } else {
                        ui.colored_label(
                            ACCENT,
                            typed
                                .diagnostic
                                .as_deref()
                                .unwrap_or("Typed C is unavailable for this function."),
                        );
                    }
                    ui.separator();
                    ui.label(
                        RichText::new(
                            "Source addresses (select an address, then open MachineIR or Evidence)",
                        )
                        .color(MUTED),
                    );
                    typed
                        .ir
                        .as_ref()
                        .and_then(|ir| typed_source_sites(ui, ir, self.selected_address))
                        .or_else(|| {
                            typed.cfg_ir.as_ref().and_then(|ir| {
                                typed_cfg_source_sites(ui, ir, self.selected_address)
                            })
                        })
                } else {
                    ui.colored_label(
                        ACCENT,
                        self.typed_native_error
                            .as_deref()
                            .unwrap_or("Typed model is unavailable."),
                    );
                    None
                }
            }
            NativeViewMode::Types => {
                if let Some(typed) = &self.typed_native_view {
                    typed_types_view(ui, &typed.model)
                } else {
                    ui.colored_label(
                        ACCENT,
                        self.typed_native_error
                            .as_deref()
                            .unwrap_or("Typed model is unavailable."),
                    );
                    None
                }
            }
            NativeViewMode::LowLevelC => {
                code_artifact_view(
                    ui,
                    "LOW-LEVEL C11 - EXPLICIT MACHINE STATE / UNKNOWN EFFECTS",
                    &native.low_level_c,
                    "native_low_c",
                );
                None
            }
            NativeViewMode::StructuredC => {
                if let Some(structured) = &native.structured_c {
                    code_artifact_view(
                        ui,
                        "STRUCTURED C11 - BEST EFFORT, SEMANTICS PRESERVED",
                        structured,
                        "native_structured_c",
                    );
                } else {
                    ui.colored_label(
                        ACCENT,
                        "This function cannot be structured safely; low-level C remains available.",
                    );
                    ui.label(
                        RichText::new(
                            "Irreducible or unresolved control flow stays explicit instead of being invented.",
                        )
                        .color(MUTED),
                    );
                }
                None
            }
            NativeViewMode::MachineIr => native_machine_ir_view(ui, native, self.selected_address),
            NativeViewMode::StateIr => {
                json_artifact_view(
                    ui,
                    "STATEFUNCTIONIR V1",
                    &native.state_ir,
                    "native_state_ir",
                );
                None
            }
            NativeViewMode::FunctionIr => {
                json_artifact_view(
                    ui,
                    "FUNCTIONIR V1",
                    &native.function_ir,
                    "native_function_ir",
                );
                None
            }
            NativeViewMode::Cir => {
                json_artifact_view(ui, "CIR V1", &native.cir, "native_cir");
                None
            }
            NativeViewMode::Evidence => native_evidence_view(ui, native, self.selected_address),
        };
        if let Some(address) = clicked_address {
            self.selected_address = Some(address);
        }
    }

    fn coverage_view(&mut self, ui: &mut egui::Ui) {
        let Some(report) = &self.native_coverage else {
            ui.heading(RichText::new("Native semantic coverage").size(20.0));
            ui.label(
                RichText::new(
                    self.native_coverage_error
                        .as_deref()
                        .unwrap_or("Run coverage to lift every discovered local function and inventory exact versus opaque semantics."),
                )
                .color(if self.native_coverage_error.is_some() { BAD } else { MUTED }),
            );
            ui.label(
                RichText::new(
                    "This is a bounded static analysis. It does not execute the input ELF, and a large binary can take time.",
                )
                .size(11.0)
                .color(MUTED),
            );
            if ui
                .add_enabled(
                    !self.busy && self.spec.is_some() && !self.remote,
                    egui::Button::new("Measure native coverage"),
                )
                .clicked()
            {
                self.enqueue(
                    Task::MeasureNativeCoverage,
                    "Lifting discovered functions and measuring native semantics...",
                );
            }
            return;
        };

        let total_instructions = report.exact_instructions + report.opaque_instructions;
        let exact_ratio = if total_instructions == 0 {
            0.0
        } else {
            report.exact_instructions as f32 / total_instructions as f32
        };
        let lift_ratio = if report.discovered_functions == 0 {
            0.0
        } else {
            report.lifted_functions as f32 / report.discovered_functions as f32
        };
        ui.heading(RichText::new("Native semantic coverage").size(20.0));
        ui.horizontal_wrapped(|ui| {
            metric_readout(
                ui,
                "DISCOVERED",
                &report.discovered_functions.to_string(),
                INFO,
            );
            metric_readout(ui, "LIFTED", &report.lifted_functions.to_string(), GOOD);
            metric_readout(
                ui,
                "EXACT FUNCTIONS",
                &report.exact_functions.to_string(),
                GOOD,
            );
            metric_readout(
                ui,
                "CONSERVATIVE",
                &report.conservative_functions.to_string(),
                ACCENT,
            );
            metric_readout(ui, "PARTIAL", &report.partial_functions.to_string(), BAD);
        });
        ui.add_space(8.0);
        let progress_width = ui.available_width();
        ui.add(
            egui::ProgressBar::new(lift_ratio)
                .text(format!("Function lift rate: {:.1}%", lift_ratio * 100.0))
                .desired_width(progress_width),
        );
        ui.add(
            egui::ProgressBar::new(exact_ratio)
                .text(format!(
                    "Exact instruction semantics: {:.1}% ({} exact / {} opaque)",
                    exact_ratio * 100.0,
                    report.exact_instructions,
                    report.opaque_instructions
                ))
                .desired_width(progress_width),
        );
        ui.add_space(10.0);

        ui.columns(2, |columns| {
            columns[0].heading(RichText::new("Exact semantic families").color(GOOD));
            egui::ScrollArea::vertical()
                .id_salt("coverage_exact_families")
                .max_height(420.0)
                .show(&mut columns[0], |ui| {
                    for (family, count) in &report.exact_families {
                        ui.horizontal(|ui| {
                            ui.label(RichText::new(family).monospace());
                            ui.with_layout(
                                egui::Layout::right_to_left(egui::Align::Center),
                                |ui| {
                                    ui.label(RichText::new(count.to_string()).color(GOOD));
                                },
                            );
                        });
                    }
                });

            columns[1].heading(RichText::new("Opaque semantic families").color(BAD));
            egui::ScrollArea::vertical()
                .id_salt("coverage_opaque_families")
                .max_height(420.0)
                .show(&mut columns[1], |ui| {
                    if report.opaque_families.is_empty() {
                        ui.colored_label(GOOD, "No opaque instruction occurrences measured.");
                    }
                    for (family, count) in &report.opaque_families {
                        ui.horizontal_wrapped(|ui| {
                            ui.label(RichText::new(family).monospace().color(BAD));
                            ui.label(format!("{count} occurrence(s)"));
                            if let Some(samples) = report.opaque_samples.get(family) {
                                for sample in samples {
                                    if ui
                                        .small_button(format!(
                                            "{}:0x{:x}",
                                            sample.address_space, sample.value.0
                                        ))
                                        .clicked()
                                    {
                                        self.selected_address = Some(sample.value.0);
                                    }
                                }
                            }
                        });
                    }
                });
        });
        if !report.diagnostics.is_empty() {
            ui.separator();
            egui::CollapsingHeader::new(format!(
                "Function-local diagnostics ({})",
                report.diagnostics.len()
            ))
            .default_open(true)
            .show(ui, |ui| {
                for diagnostic in &report.diagnostics {
                    ui.colored_label(BAD, diagnostic);
                }
            });
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

fn indexed_function_label(function: &IndexedFunction) -> String {
    function.name.clone().unwrap_or_else(|| {
        format!(
            "sub_{}_{}",
            function.entry.address_space, function.entry.value.0
        )
    })
}

fn indexed_function_action(
    function: &IndexedFunction,
    spec: Option<&ProgramSpec>,
) -> GraphNodeAction {
    let label = indexed_function_label(function);
    let legacy_symbol = spec.is_some_and(|spec| {
        spec.functions
            .iter()
            .any(|candidate| candidate.name == label && candidate.location == Some(function.entry))
    });
    GraphNodeAction::Function {
        label,
        selector: function.id.clone(),
        entry: function.entry,
        legacy_symbol,
    }
}

fn workbench_graph_layout(
    nodes: &[WorkbenchGraphNode],
    edges: &[WorkbenchGraphEdge],
    zoom: f32,
) -> (egui_graph::Layout, egui_graph::EdgeRoutes) {
    let node_size = [210.0_f32 * zoom, 72.0_f32 * zoom];
    layout_routed(
        nodes
            .iter()
            .map(|node| (node.id, LayoutNode::new(node_size))),
        edges
            .iter()
            .map(|edge| ((edge.source, 0), (edge.target, 0))),
        LayoutParams::new(GraphDirection::LeftToRight)
            .layer_gap(100.0 * zoom)
            .node_gap(40.0 * zoom),
    )
}

fn render_workbench_graph(
    ui: &mut egui::Ui,
    nodes: &[WorkbenchGraphNode],
    edges: &[WorkbenchGraphEdge],
    zoom: f32,
    canvas_salt: impl std::hash::Hash + std::fmt::Debug,
) -> Option<GraphNodeAction> {
    if nodes.is_empty() {
        ui.label(RichText::new("No graph nodes recovered.").color(MUTED));
        return None;
    }
    let node_size = [210.0_f32 * zoom, 72.0_f32 * zoom];
    let (layout, routes) = workbench_graph_layout(nodes, edges, zoom);
    let min_x = layout
        .values()
        .map(|position| position.x)
        .fold(f32::INFINITY, f32::min);
    let min_y = layout
        .values()
        .map(|position| position.y)
        .fold(f32::INFINITY, f32::min);
    let max_x = layout
        .values()
        .map(|position| position.x)
        .fold(f32::NEG_INFINITY, f32::max);
    let max_y = layout
        .values()
        .map(|position| position.y)
        .fold(f32::NEG_INFINITY, f32::max);
    let canvas_size = egui::vec2(
        (max_x - min_x + node_size[0] + 100.0).max(ui.available_width()),
        (max_y - min_y + node_size[1] + 100.0).max(300.0),
    );
    let mut clicked = None;
    egui::ScrollArea::both()
        .id_salt(canvas_salt)
        .show(ui, |ui| {
            let (canvas, _) = ui.allocate_exact_size(canvas_size, egui::Sense::hover());
            let painter = ui.painter_at(canvas);
            let offset = canvas.min + egui::vec2(50.0 - min_x, 50.0 - min_y);
            let rects = nodes
                .iter()
                .map(|node| {
                    let position = layout
                        .get(&node.id)
                        .map(|position| offset + egui::vec2(position.x, position.y))
                        .unwrap_or(canvas.min);
                    (
                        node.id,
                        egui::Rect::from_min_size(position, egui::vec2(node_size[0], node_size[1])),
                    )
                })
                .collect::<std::collections::HashMap<_, _>>();

            let mut occurrences = std::collections::HashMap::new();
            for edge in edges {
                let (Some(source_rect), Some(target_rect)) =
                    (rects.get(&edge.source), rects.get(&edge.target))
                else {
                    continue;
                };
                let start = source_rect.right_center();
                let end = target_rect.left_center();
                let color = if edge.unresolved { BAD } else { ACCENT };
                let occurrence = occurrences.entry((edge.source, edge.target)).or_insert(0);
                let mut points = vec![start];
                if let Some(waypoints) =
                    routes.route((edge.source, 0), (edge.target, 0), *occurrence)
                {
                    points.extend(
                        waypoints
                            .iter()
                            .map(|point| offset + egui::vec2(point.x, point.y)),
                    );
                }
                *occurrence += 1;
                points.push(end);
                for segment in points.windows(2) {
                    painter.line_segment([segment[0], segment[1]], egui::Stroke::new(1.5, color));
                }
                if let Some(direction) = points.windows(2).rev().find_map(|segment| {
                    let delta = segment[1] - segment[0];
                    (delta.length_sq() > 1.0).then(|| delta.normalized())
                }) {
                    let left = end - direction * 10.0 + egui::vec2(-direction.y, direction.x) * 4.0;
                    let right =
                        end - direction * 10.0 - egui::vec2(-direction.y, direction.x) * 4.0;
                    painter.add(egui::Shape::convex_polygon(
                        vec![end, left, right],
                        color,
                        egui::Stroke::NONE,
                    ));
                }
                if !edge.label.is_empty() {
                    let galley = painter.layout_no_wrap(
                        edge.label.clone(),
                        egui::FontId::monospace((10.0 * zoom).max(9.0)),
                        color,
                    );
                    let label_size = galley.size() + egui::vec2(8.0, 4.0);
                    let center = points
                        .windows(2)
                        .map(|segment| {
                            let delta = segment[1] - segment[0];
                            (delta.length_sq(), segment[0] + delta * 0.5)
                        })
                        .filter(|(_, center)| {
                            let label_rect = egui::Rect::from_center_size(*center, label_size);
                            !rects
                                .values()
                                .any(|rect| rect.expand(3.0).intersects(label_rect))
                        })
                        .max_by(|a, b| a.0.total_cmp(&b.0))
                        .map(|(_, center)| center);
                    if let Some(center) = center {
                        let label_rect = egui::Rect::from_center_size(center, label_size);
                        painter.rect_filled(label_rect, 0.0, BG);
                        painter.galley(label_rect.min + egui::vec2(4.0, 2.0), galley, color);
                    }
                }
            }

            for node in nodes {
                let rect = rects[&node.id];
                let stroke = match node.tone {
                    GraphNodeTone::Normal => MUTED,
                    GraphNodeTone::Selected => ACCENT,
                    GraphNodeTone::Opaque => BAD,
                    GraphNodeTone::External => INFO,
                };
                painter.rect_filled(rect, 0.0, PANEL);
                painter.rect_stroke(
                    rect,
                    0.0,
                    egui::Stroke::new(1.2, stroke),
                    egui::StrokeKind::Outside,
                );
                painter.text(
                    rect.left_top() + egui::vec2(10.0 * zoom, 8.0 * zoom),
                    egui::Align2::LEFT_TOP,
                    &node.label,
                    egui::FontId::monospace((10.5 * zoom).max(8.0)),
                    TEXT,
                );
                let response = ui.interact(
                    rect,
                    ui.id().with(("native-graph-node", node.id.value())),
                    if node.action.is_some() {
                        egui::Sense::click()
                    } else {
                        egui::Sense::hover()
                    },
                );
                if response.clicked()
                    && let Some(action) = &node.action
                {
                    clicked = Some(action.clone());
                }
            }
        });
    clicked
}

fn native_instruction_count(native: &NativeDecompilation) -> usize {
    native
        .machine_ir
        .blocks
        .iter()
        .map(|block| block.instructions.len())
        .sum()
}

fn native_opaque_instruction_count(native: &NativeDecompilation) -> usize {
    native
        .machine_ir
        .blocks
        .iter()
        .flat_map(|block| &block.instructions)
        .filter(|instruction| {
            matches!(instruction.operation, MachineOperation::OpaqueEffect { .. })
        })
        .count()
}

fn native_function_excerpt(source: &str) -> &str {
    source
        .rfind("\nvoid hydir_")
        .map_or(source, |start| &source[start + 1..])
}

fn code_artifact_view(ui: &mut egui::Ui, label: &str, source: &str, id: &str) {
    ui.horizontal(|ui| {
        ui.label(RichText::new(label).strong().color(ACCENT));
        if ui.button("Copy").clicked() {
            ui.ctx().copy_text(source.to_owned());
        }
    });
    egui::ScrollArea::both().id_salt(id).show(ui, |ui| {
        ui.code(source);
    });
}

fn json_artifact_view<T: serde::Serialize>(ui: &mut egui::Ui, label: &str, artifact: &T, id: &str) {
    match serde_json::to_string_pretty(artifact) {
        Ok(json) => code_artifact_view(ui, label, &json, id),
        Err(error) => {
            ui.colored_label(BAD, format!("Could not serialize {label}: {error}"));
        }
    }
}

fn native_summary_view(ui: &mut egui::Ui, native: &NativeDecompilation) {
    ui.columns(2, |columns| {
        columns[0].heading(RichText::new("Recovered ABI").color(ACCENT));
        field(
            &mut columns[0],
            "CALLING CONVENTION",
            &native.function_ir.calling_convention,
        );
        field(
            &mut columns[0],
            "PARAMETERS",
            &native.function_ir.parameters.len().to_string(),
        );
        for parameter in &native.function_ir.parameters {
            columns[0].label(
                RichText::new(format!(
                    "{}: {} @ {}{}",
                    parameter.name,
                    parameter.type_name,
                    parameter.location,
                    if parameter.inferred {
                        " (inferred)"
                    } else {
                        ""
                    }
                ))
                .monospace()
                .size(11.0),
            );
        }
        field(
            &mut columns[0],
            "RETURNS",
            &native.function_ir.returns.len().to_string(),
        );
        for value in &native.function_ir.returns {
            columns[0].label(
                RichText::new(format!(
                    "{}: {} @ {}",
                    value.name, value.type_name, value.location
                ))
                .monospace()
                .size(11.0),
            );
        }
        field(
            &mut columns[0],
            "STACK OBJECTS",
            &native.function_ir.stack_objects.len().to_string(),
        );
        field(
            &mut columns[0],
            "GLOBAL OBJECTS",
            &native.function_ir.global_objects.len().to_string(),
        );
        field(
            &mut columns[0],
            "ALIAS SETS",
            &native.function_ir.alias_sets.len().to_string(),
        );
        field(
            &mut columns[0],
            "POINTER ORIGINS",
            &native.function_ir.pointer_provenance.len().to_string(),
        );

        columns[1].heading(RichText::new("Calls and effects").color(INFO));
        if native.function_ir.calls.is_empty() {
            columns[1].label(RichText::new("No calls recovered.").color(MUTED));
        }
        for call in &native.function_ir.calls {
            let target = call.symbol.clone().or_else(|| {
                call.target
                    .map(|target| format!("{}:0x{:x}", target.address_space, target.value.0))
            });
            columns[1].label(
                RichText::new(format!(
                    "{}:0x{:x} -> {}{}{}",
                    call.site.address_space,
                    call.site.value.0,
                    target.as_deref().unwrap_or("unresolved"),
                    if call.indirect { " [indirect]" } else { "" },
                    if call.tail_call { " [tail]" } else { "" }
                ))
                .monospace()
                .size(11.0)
                .color(if call.target.is_some() || call.symbol.is_some() {
                    TEXT
                } else {
                    BAD
                }),
            );
            columns[1].label(RichText::new(&call.evidence).size(10.0).color(MUTED));
        }
        columns[1].separator();
        field(
            &mut columns[1],
            "STRUCTURE",
            &format!("{:?}", native.cir.structural_completeness),
        );
        field(
            &mut columns[1],
            "VERIFICATION",
            &format!("{:?}", native.cir.verification),
        );
        field(
            &mut columns[1],
            "DIAGNOSTICS",
            &native.diagnostics.len().to_string(),
        );
    });
}

fn native_machine_ir_view(
    ui: &mut egui::Ui,
    native: &NativeDecompilation,
    selected_address: Option<u64>,
) -> Option<u64> {
    let mut clicked_address = None;
    ui.horizontal(|ui| {
        ui.label(RichText::new("MACHINEFUNCTIONIR V1").strong().color(ACCENT));
        if ui.button("Copy JSON").clicked()
            && let Ok(json) = serde_json::to_string_pretty(&native.machine_ir)
        {
            ui.ctx().copy_text(json);
        }
    });
    egui::ScrollArea::both()
        .id_salt("native_machine_ir")
        .show(ui, |ui| {
            for block in &native.machine_ir.blocks {
                ui.label(
                    RichText::new(format!(
                        "{}  [{}:0x{:x}]",
                        block.label, block.address.address_space, block.address.value.0
                    ))
                    .monospace()
                    .strong()
                    .color(INFO),
                );
                for instruction in &block.instructions {
                    let opaque =
                        matches!(instruction.operation, MachineOperation::OpaqueEffect { .. });
                    let text = format!(
                        "{}:0x{:016x}  {:<20} {:<10} {:?}",
                        instruction.address.address_space,
                        instruction.address.value.0,
                        instruction.bytes_hex,
                        instruction.mnemonic,
                        instruction.operands
                    );
                    if ui
                        .selectable_label(
                            selected_address == Some(instruction.address.value.0),
                            RichText::new(text).monospace().size(11.0).color(if opaque {
                                BAD
                            } else {
                                TEXT
                            }),
                        )
                        .on_hover_text(format!(
                            "Effects: {:?}\nEdges: {:?}\nOperation: {:?}",
                            instruction.effects, instruction.edges, instruction.operation
                        ))
                        .clicked()
                    {
                        clicked_address = Some(instruction.address.value.0);
                    }
                }
                ui.add_space(5.0);
            }
        });
    clicked_address
}

fn native_evidence_view(
    ui: &mut egui::Ui,
    native: &NativeDecompilation,
    selected_address: Option<u64>,
) -> Option<u64> {
    let mut clicked_address = None;
    ui.heading(RichText::new("Diagnostics and address provenance").color(ACCENT));
    if native.diagnostics.is_empty() {
        ui.colored_label(GOOD, "No native decompilation diagnostics.");
    }
    for diagnostic in &native.diagnostics {
        ui.colored_label(
            if diagnostic.blocks_stable_operation {
                BAD
            } else {
                ACCENT
            },
            format!("{} - {}", diagnostic.code, diagnostic.message),
        );
    }
    for diagnostic in &native.machine_ir.diagnostics {
        let response = ui.colored_label(
            if diagnostic.blocks_stable_operation {
                BAD
            } else {
                ACCENT
            },
            format!("{} - {}", diagnostic.code, diagnostic.message),
        );
        if let Some(address) = diagnostic.address {
            response.on_hover_text(format!("{}:0x{:x}", address.address_space, address.value.0));
        }
    }
    ui.separator();
    egui::ScrollArea::vertical()
        .id_salt("native_provenance")
        .show(ui, |ui| {
            for block in &native.cir.blocks {
                ui.label(
                    RichText::new(format!(
                        "{}  <-  {}:0x{:x}",
                        block.label, block.address.address_space, block.address.value.0
                    ))
                    .monospace()
                    .strong()
                    .color(INFO),
                );
                for statement in &block.statements {
                    let (address, description) = match statement {
                        hydir_ir::CirStatement::Operation {
                            address, family, ..
                        } => (*address, format!("exact operation: {family}")),
                        hydir_ir::CirStatement::OpaqueEffect {
                            address, reason, ..
                        } => (*address, format!("opaque effect: {reason}")),
                    };
                    if ui
                        .selectable_label(
                            selected_address == Some(address.value.0),
                            RichText::new(format!(
                                "  {}:0x{:016x}  {}",
                                address.address_space, address.value.0, description
                            ))
                            .monospace()
                            .size(11.0),
                        )
                        .clicked()
                    {
                        clicked_address = Some(address.value.0);
                    }
                }
                ui.label(
                    RichText::new(format!("  terminator: {:?}", block.terminator))
                        .monospace()
                        .size(10.0)
                        .color(MUTED),
                );
            }
        });
    clicked_address
}

fn stage_status(ui: &mut egui::Ui, number: &str, title: &str, status: &str, ready: bool) {
    ui.add_space(8.0);
    ui.horizontal_wrapped(|ui| {
        ui.label(RichText::new(number).monospace().size(11.0).color(MUTED));
        ui.label(RichText::new(title).size(12.0).strong());
    });
    ui.label(
        RichText::new(status)
            .size(12.0)
            .color(if ready { GOOD } else { MUTED }),
    );
    ui.add_space(6.0);
    ui.separator();
}

fn metric_readout(ui: &mut egui::Ui, label: &str, value: &str, color: Color32) {
    ui.horizontal(|ui| {
        ui.label(RichText::new(label).monospace().size(11.0).color(MUTED));
        ui.label(
            RichText::new(value)
                .monospace()
                .size(12.0)
                .strong()
                .color(color),
        );
    });
    ui.add_space(8.0);
}

fn format_addresses(addresses: &[Address]) -> String {
    if addresses.is_empty() {
        "none".to_owned()
    } else {
        addresses
            .iter()
            .map(|address| format!("0x{:x}", address.0))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

fn physical_location_chips(ui: &mut egui::Ui, locations: &[hydir_core::PhysicalLocationSpec]) {
    if locations.is_empty() {
        ui.label(RichText::new("unresolved").color(BAD));
        return;
    }
    ui.horizontal_wrapped(|ui| {
        for (index, location) in locations.iter().enumerate() {
            if index > 0 {
                ui.label(RichText::new("·").color(MUTED));
            }
            ui.label(
                RichText::new(format!(
                    "{} · {:?} · {}b",
                    location.name, location.kind, location.width_bits
                ))
                .monospace()
                .size(11.0),
            );
        }
    });
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
        let dropped_path = ui.ctx().input(|input| {
            input
                .raw
                .dropped_files
                .iter()
                .map(|file| file.path().to_path_buf())
                .find(|path| !path.as_os_str().is_empty())
        });
        if self.workbench_loaded
            && !self.busy
            && let Some(path) = dropped_path
        {
            self.path_input = path.display().to_string();
            self.enqueue(Task::Open(path), "Importing dropped ELF...");
        }
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
        if self.console_visible {
            let maximum_height = (ui.available_height() - MAIN_VIEW_MIN_HEIGHT)
                .clamp(CONSOLE_MIN_HEIGHT, CONSOLE_MAX_HEIGHT);
            self.console_height = self
                .console_height
                .clamp(CONSOLE_MIN_HEIGHT, maximum_height);
            egui::Panel::bottom("console")
                .resizable(false)
                .exact_size(self.console_height)
                .show(ui, |ui| self.console_view(ui, maximum_height));
        }
        egui::CentralPanel::default().show(ui, |ui| {
            egui::Frame::new()
                .inner_margin(egui::Margin::same(12))
                .show(ui, |ui| self.main_view(ui));
        });
    }
}

fn main() -> eframe::Result<()> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    if arguments.as_slice() == ["--probe-triton-console"] {
        let commands = [
            "from triton import *",
            "ctx = TritonContext(ARCH.X86_64)",
            "ctx.setConcreteRegisterValue(ctx.registers.rip, 0x40000)",
            "ctx.symbolizeRegister(ctx.registers.rax, 'my_rax')",
            "ctx.processing(Instruction(b'\\x48\\x35\\x34\\x12\\x00\\x00'))",
            "ctx.processing(Instruction(b'\\x48\\x89\\xc1'))",
            "rcx_expr = ctx.getSymbolicRegister(ctx.registers.rcx)",
            "print(rcx_expr)",
            "ctx.getModel(rcx_expr.getAst() == 0xdead)",
            "hex(0xcc99 ^ 0x1234)",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
        match run_triton_console_cli(&commands) {
            Ok(result)
                if result
                    .get("entries")
                    .and_then(serde_json::Value::as_array)
                    .is_some_and(|entries| {
                        entries
                            .get(8)
                            .and_then(|entry| entry.get("output"))
                            .and_then(serde_json::Value::as_array)
                            .is_some_and(|output| {
                                output.iter().any(|line| {
                                    line.as_str()
                                        .is_some_and(|line| line.contains("my_rax:64 = 0xcc99"))
                                })
                            })
                    }) =>
            {
                println!("HydIR GUI Triton console probe passed");
                return Ok(());
            }
            Ok(_) => {
                eprintln!("HydIR GUI Triton console probe returned an unexpected model");
                std::process::exit(1);
            }
            Err(error) => {
                eprintln!("HydIR GUI Triton console probe failed: {error}");
                std::process::exit(1);
            }
        }
    }
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
            let idempotency_key = uuid::Uuid::new_v4().to_string();
            let (updated, overlaid, annotations) = add_local_annotation(
                &project,
                &bytes,
                &spec.binary_sha256,
                LocalAnnotationInput {
                    kind: AnnotationKind::Assumption,
                    address: None,
                    scope: "trusted fixture only",
                    value: statement,
                    idempotency_key: &idempotency_key,
                },
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
            let (cfg, ir, c, region, physical_ir, decompilation) =
                select_remote(&access, symbol).await;
            let cfg = cfg?;
            let ir = ir?;
            let c = c?;
            let region = region?;
            let physical_ir = physical_ir?;
            let decompilation = decompilation?;
            if !c.contains("uint64_t hydir_lifted(") {
                return Err(
                    "Remote C artifact did not contain the expected lifted function.".to_owned(),
                );
            }
            let analysis = analyze_remote(&access).await?;
            if analysis.binary_sha256 != spec.binary_sha256 {
                return Err("Remote analysis model digest differs from open project.".to_owned());
            }
            if region.binary_sha256 != spec.binary_sha256
                || physical_ir.region_bytes_sha256 != region.bytes_sha256
                || decompilation.region.bytes_sha256 != region.bytes_sha256
            {
                return Err("Remote Region Studio artifacts are not digest-bound.".to_owned());
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
    let open_recipe = if let [flag, _, recipe] = arguments.as_slice()
        && flag == "--open-recipe"
    {
        Some(PathBuf::from(recipe))
    } else {
        None
    };
    let open_local = if let [flag, path] = arguments.as_slice()
        && flag == "--open-local"
    {
        Some((PathBuf::from(path), None))
    } else if let [flag, path, symbol] = arguments.as_slice()
        && flag == "--open-local"
    {
        Some((PathBuf::from(path), Some(symbol.clone())))
    } else if let [flag, path, _] = arguments.as_slice()
        && flag == "--open-recipe"
    {
        Some((PathBuf::from(path), None))
    } else if arguments.is_empty() {
        None
    } else {
        eprintln!(
            "Usage: hydir [--open-local <elf> [function-symbol] | --open-recipe <elf> <recipe.json> | --probe-workbench <elf> (requires HYDIR_LOCAL_DB) | --probe-local-annotation <elf> (requires HYDIR_LOCAL_DB) | --probe-remote <endpoint> <token-file> <project-id> <symbol> | --probe-create-upload <endpoint> <token-file> <elf> | --probe-annotation <endpoint> <token-file> <elf> | --probe-transform <endpoint> <token-file> <elf> <symbol> | --probe-rebuild <endpoint> <token-file> <elf> <new-output-file> | --probe-local-pass <elf> <symbol> <new-output-dir> | --probe-local-rebuild <elf> <new-output-dir> | --probe-local-patch <elf> <symbol> <replacement> <new-output-file> | --probe-remote-patch <endpoint> <token-file> <elf> <symbol> <replacement> <new-output-file>]"
        );
        std::process::exit(2);
    };
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("HydIR · Region Studio")
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
            app.startup_recipe_path = open_recipe;
            Ok(Box::new(app))
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::{
        AnalystApp, COutputSource, Event, GraphNodeAction, GraphNodeTone, NativeViewMode, Tab,
        WorkbenchGraphEdge, WorkbenchGraphNode, captured_code_elf_address, indexed_function_action,
        ir_slice, local_region_artifacts, native_function_excerpt, native_instruction_count,
        native_opaque_instruction_count, pcode_display_lines, pcode_state_lines,
        preview_patch_local, resized_console_height, valid_bearer_token, validate_endpoint,
        workbench_graph_layout,
    };
    use egui_graph::NodeId;
    use hydir_backend::{import_elf, lift_symbol};
    use hydir_core::{
        AnalystAnnotation, AnnotationKind, FactProvenance, FactSource, ProgramSpec, RecoveryState,
    };
    use hydir_decompile::{
        decompile_function_at, decompile_symbol, discover_functions, measure_native_coverage,
    };
    use hydir_execution::StopPoint;
    use hydir_ir::pcode::{GhidraSnapshot, PcodeEffect};
    use std::sync::mpsc;

    #[test]
    fn ghidra_fixture_rows_keep_source_and_semantic_status() {
        let snapshot: GhidraSnapshot = serde_json::from_slice(include_bytes!(
            "../../../tests/fixtures/ghidra_prism_snapshot_v2.json"
        ))
        .unwrap();
        let semantics = snapshot.pcode_function_ir().unwrap().lower_semantics();
        let lines = pcode_display_lines(&snapshot, Some(&semantics));
        assert!(
            lines
                .iter()
                .any(|(_, line)| line.contains("ram:0x20137f #1:1"))
        );
        assert!(lines.iter().any(|(_, line)| line.contains("[exact ")));
        assert!(lines.iter().any(|(_, line)| line.contains("[opaque:")));
        let state_lines = pcode_state_lines(&semantics.lower_state());
        assert!(
            state_lines
                .iter()
                .any(|(address, line)| *address == Some(0x20137c)
                    && line.contains("Read 0:register:"))
        );
        assert!(
            state_lines
                .iter()
                .any(|(_, line)| line.contains("MayWrite"))
        );
        assert!(
            semantics
                .instructions
                .iter()
                .flat_map(|instruction| &instruction.operations)
                .any(|operation| matches!(operation.effect, PcodeEffect::Opaque { .. }))
        );
    }

    #[test]
    fn recipe_navigation_translates_only_verified_captured_pie_code() {
        let stop = StopPoint {
            runtime_pc: 0x7f00_1000,
            elf_vaddr: Some(0x1000),
            load_bias: Some(0x7f00_0000),
            symbol: None,
        };
        assert_eq!(
            captured_code_elf_address(&stop, 0x7f00_1000, 0x20, 0x7f00_101f),
            Some(0x101f)
        );
        assert_eq!(
            captured_code_elf_address(&stop, 0x7f00_1000, 0x20, 0x7f00_1020),
            None
        );
        assert_eq!(
            captured_code_elf_address(&stop, 0x7f00_1001, 0x20, 0x7f00_101f),
            None
        );
        let wrong_bias = StopPoint {
            load_bias: Some(0x7f00_0001),
            ..stop
        };
        assert_eq!(
            captured_code_elf_address(&wrong_bias, 0x7f00_1000, 0x20, 0x7f00_101f),
            None
        );
    }

    #[test]
    fn graph_layout_leaves_label_space_and_routes_long_edges_around_nodes() {
        let ids = [
            NodeId::new("entry"),
            NodeId::new("middle"),
            NodeId::new("exit"),
        ];
        let nodes = ids
            .iter()
            .map(|id| WorkbenchGraphNode {
                id: *id,
                label: String::new(),
                tone: GraphNodeTone::Normal,
                action: None,
            })
            .collect::<Vec<_>>();
        let edges = [(0, 1), (1, 2), (0, 2)]
            .into_iter()
            .map(|(source, target)| WorkbenchGraphEdge {
                source: ids[source],
                target: ids[target],
                label: "fallthrough".to_owned(),
                unresolved: false,
            })
            .collect::<Vec<_>>();

        let (layout, routes) = workbench_graph_layout(&nodes, &edges, 1.0);
        let label_gap = layout[&ids[1]].x - (layout[&ids[0]].x + 210.0);
        assert!(label_gap >= 99.0, "edge labels need space between layers");
        let route = routes
            .route((ids[0], 0), (ids[2], 0), 0)
            .expect("the long edge must route around the middle block");
        let middle = layout[&ids[1]];
        assert!(route.iter().all(|point| {
            point.x < middle.x
                || point.x > middle.x + 210.0
                || point.y < middle.y
                || point.y > middle.y + 72.0
        }));
    }

    #[test]
    fn annotation_refresh_overlays_once_and_rejects_stale_binary_events() {
        let mut app = AnalystApp::new(&eframe::egui::Context::default());
        let (sender, receiver) = mpsc::sync_channel(3);
        app.events = receiver;
        app.spec = Some(ProgramSpec {
            schema_version: hydir_core::PROGRAM_SPEC_VERSION,
            binary_sha256: "a".repeat(64),
            target_triple: "x86_64-unknown-elf".to_owned(),
            abi: "System V AMD64".to_owned(),
            file_kind: "executable".to_owned(),
            image_base: None,
            entry_point: None,
            entry_location: None,
            data_layout: None,
            program_headers: Vec::new(),
            dynamic_symbols: Vec::new(),
            runtime_ranges: Vec::new(),
            unwind_ranges: Vec::new(),
            pointer_arrays: Vec::new(),
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
            typed_model: Default::default(),
            memory_facts: Vec::new(),
            uncertainties: Vec::new(),
            provenance: Vec::new(),
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
    fn local_region_studio_artifacts_are_digest_bound_and_presentable() {
        let binary = include_bytes!("../../../fuzz/corpus/elf_import/max2.elf");
        let ir = lift_symbol(binary, "hydir_max2").map_err(|error| error.to_string());
        let artifacts = local_region_artifacts(binary, "hydir_max2", &ir);
        let region = artifacts.region.unwrap();
        let physical = artifacts.physical_ir.unwrap();
        let decompilation = artifacts.decompilation.unwrap();
        assert_eq!(physical.binary_sha256, region.binary_sha256);
        assert_eq!(physical.region_bytes_sha256, region.bytes_sha256);
        assert_eq!(decompilation.region.bytes_sha256, region.bytes_sha256);
        assert!(!physical.instructions.is_empty());
        assert!(decompilation.c_source.contains("uint64_t hydir_lifted("));
        let app = AnalystApp::new(&eframe::egui::Context::default());
        assert!(matches!(app.tab, Tab::Overview));
        assert!(!app.console_visible);
        assert_eq!(app.console_height, 220.0);
    }

    #[test]
    fn prism_syscall_helper_retains_native_c_when_structured_lift_refuses_it() {
        let binary = include_bytes!("../../../demo/hydir-prism.elf");
        let symbol = "prism_write_banner";
        let ir = lift_symbol(binary, symbol).map_err(|error| error.to_string());
        let artifacts = local_region_artifacts(binary, symbol, &ir);
        assert!(artifacts.decompilation.is_err());

        let native = decompile_symbol(binary, symbol).unwrap();
        assert!(native_opaque_instruction_count(&native) > 0);
        assert!(native.low_level_c.contains("hydir_opaque_effect"));
        assert!(native.low_level_c.contains("0x20141c"));
        assert!(native_function_excerpt(&native.low_level_c).starts_with("void hydir_"));
        assert!(native_function_excerpt(&native.low_level_c).contains("hydir_opaque_effect"));
        assert!(!native.cir.rewrite_ready);

        let mut app = AnalystApp::new(&eframe::egui::Context::default());
        app.c_error = Some("unsupported Syscall at 0x20141c".to_owned());
        app.native_decompilation = Some(native);
        assert!(matches!(
            app.c_output_source(),
            Some(COutputSource::Native(_))
        ));
        app.c = Some("return arg0;".to_owned());
        assert!(matches!(
            app.c_output_source(),
            Some(COutputSource::Scalar(_))
        ));
    }

    #[test]
    fn native_workbench_path_opens_stripped_unwind_functions_without_symbols() {
        let binary =
            include_bytes!("../../../fuzz/corpus/elf_import/unwind_discovery_stripped.elf");
        let index = discover_functions(binary).unwrap();
        assert_eq!(index.functions.len(), 2);
        assert!(
            index
                .functions
                .iter()
                .all(|function| function.name.is_none())
        );
        for function in index.functions {
            let native = decompile_function_at(binary, function.entry).unwrap();
            assert_eq!(native.machine_ir.function_id, function.id);
            assert!(native.low_level_c.contains("HydirMachineState"));
            assert!(native_instruction_count(&native) > 0);
        }
        let app = AnalystApp::new(&eframe::egui::Context::default());
        assert!(app.native_decompilation.is_none());
        assert!(matches!(app.native_view_mode, NativeViewMode::Summary));
    }

    #[test]
    fn native_program_graph_actions_keep_stripped_function_identity() {
        let binary =
            include_bytes!("../../../fuzz/corpus/elf_import/unwind_discovery_stripped.elf");
        let spec = import_elf(binary).unwrap();
        let index = discover_functions(binary).unwrap();
        let function = index.functions.first().unwrap();
        match indexed_function_action(function, Some(&spec)) {
            GraphNodeAction::Function {
                label,
                selector,
                entry,
                legacy_symbol,
            } => {
                assert!(label.starts_with("sub_"));
                assert_eq!(selector, function.id);
                assert_eq!(entry, function.entry);
                assert!(!legacy_symbol);
            }
            GraphNodeAction::Address(_) => panic!("function graph action became an address action"),
        }
    }

    #[test]
    fn native_coverage_event_opens_the_coverage_dashboard() {
        let binary = include_bytes!("../../../fuzz/corpus/elf_import/max2.elf");
        let spec = import_elf(binary).unwrap();
        let report = measure_native_coverage(binary).unwrap();
        let mut app = AnalystApp::new(&eframe::egui::Context::default());
        let (sender, receiver) = mpsc::sync_channel(1);
        app.events = receiver;
        app.spec = Some(spec);
        sender
            .send(Event::NativeCoverageMeasured(Ok(report)))
            .unwrap();
        app.poll();
        assert!(matches!(app.tab, Tab::Coverage));
        assert!(app.native_coverage.is_some());
        assert!(app.failure.is_none());
    }

    #[test]
    fn prism_coverage_completes_on_gui_worker_stack() {
        let binary = include_bytes!("../../../demo/hydir-prism.elf");
        let report = std::thread::spawn(move || measure_native_coverage(binary))
            .join()
            .expect("coverage worker should not panic")
            .expect("PRISM coverage should succeed");
        assert_eq!(report.discovered_functions, 13);
        assert_eq!(report.lifted_functions, 13);

        let context = eframe::egui::Context::default();
        let mut app = AnalystApp::new(&context);
        app.native_coverage = Some(report);
        let input = eframe::egui::RawInput {
            screen_rect: Some(eframe::egui::Rect::from_min_size(
                eframe::egui::Pos2::ZERO,
                eframe::egui::vec2(1200.0, 800.0),
            )),
            ..Default::default()
        };
        let mut output = context.run_ui(input, |ui| app.coverage_view(ui));
        output.textures_delta.clear();
    }

    #[test]
    fn triton_activity_opens_the_explicitly_hideable_console() {
        let mut app = AnalystApp::new(&eframe::egui::Context::default());
        app.console_height = 360.0;
        let (sender, receiver) = mpsc::sync_channel(1);
        app.events = receiver;
        sender
            .send(Event::TritonConsole {
                commands: vec!["1 + 1".to_owned()],
                result: Ok(serde_json::json!({"entries": []})),
            })
            .unwrap();
        app.poll();
        assert!(app.console_visible);
        assert_eq!(app.console_height, 360.0);
    }

    #[test]
    fn console_resize_tracks_drag_direction_and_keeps_the_released_height() {
        assert_eq!(resized_console_height(220.0, -80.0, 900.0), 300.0);
        assert_eq!(resized_console_height(300.0, 55.0, 900.0), 245.0);
        assert_eq!(resized_console_height(245.0, 0.0, 900.0), 245.0);
        assert_eq!(resized_console_height(120.0, 80.0, 900.0), 100.0);
        assert_eq!(resized_console_height(860.0, -80.0, 900.0), 900.0);
    }

    #[test]
    fn remote_endpoint_allows_tls_and_only_loopback_plaintext() {
        assert!(validate_endpoint("http://127.0.0.1:50051").is_ok());
        assert!(validate_endpoint("http://[::1]:50051").is_ok());
        assert!(validate_endpoint("http://0.0.0.0:50051").is_err());
        assert!(validate_endpoint("http://192.0.2.1:50051").is_err());
        assert!(validate_endpoint("https://hydir.example:443").is_ok());
        assert!(validate_endpoint("https://hydir.example/api").is_err());
        assert!(validate_endpoint("https://user@hydir.example").is_err());
    }

    #[test]
    fn remote_credentials_accept_static_tokens_and_compact_jwts() {
        assert!(valid_bearer_token(&"a".repeat(64)));
        assert!(valid_bearer_token("eyJhbGciOiJSUzI1NiJ9.e30.signature"));
        assert!(!valid_bearer_token("header.payload."));
        assert!(!valid_bearer_token("header.pay load.signature"));
    }

    #[test]
    fn local_patch_preview_exposes_verified_trampoline_plan_without_writing() {
        let binary = include_bytes!("../../../fuzz/corpus/elf_import/frame.elf");
        let (bundle, report) = preview_patch_local(
            binary,
            "hydir_nop_identity",
            "u64 sum = arg0 + arg1;\nsum = sum - arg1;\nreturn sum;",
        )
        .unwrap();
        assert_eq!(
            bundle.placement_plan.strategy,
            hydir_patch::PlacementStrategy::EntryTrampoline
        );
        assert!(bundle.placement_plan.executable_segment.is_some());
        assert!(bundle.typed_patch_ir.resolved_return.is_some());
        assert!(report.contains("Structural verification passed"));
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
