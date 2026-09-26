//! Authenticated local-or-TLS HydIR RPC slice. No sample execution endpoint.

mod interchange;

use aws_sdk_s3::primitives::ByteStream;
use hydir_analysis::{analyze_elf, analyze_spec_elf};
use hydir_api::v1::{
    AnnotationRequest, ArtifactReply, ArtifactRequest, CreateProjectRequest, DiscoverReply,
    DiscoverRequest, FunctionRequest, JobEvent, JobEventRequest, JobReply, JobRequest, JsonReply,
    PatchReply, PatchRequest, ProjectReply, ProjectRequest, RebuildReply, RebuildRequest,
    SourceReply, SourceRequest, StartLiftJobRequest, TransformReply, TransformRequest,
    UploadBinaryRequest,
    hydir_server::{Hydir, HydirServer},
};
use hydir_api::v2 as api_v2;
use hydir_api::v2::hydir_v2_server::HydirV2Server;
use hydir_api::v3 as api_v3;
use hydir_api::v3::hydir_v3_server::HydirV3Server;
use hydir_backend::{
    MAX_BINARY_BYTES, import_elf, lift_physical_region, lift_symbol, recover_symbol_cfg,
    region_contract,
};
use hydir_c::{build_decompilation_unit, emit_structured_c};
use hydir_core::{
    Address, AnalystAnnotation, AnnotationKind, DECOMPILATION_UNIT_VERSION, FactProvenance,
    FactSource, Location, PATCH_BUNDLE_VERSION, PROGRAM_SPEC_VERSION, ProgramSpec,
    REGION_SPEC_VERSION, annotation_address_in_spec, overlay_analyst_assumptions,
    parse_annotation_address, parse_program_spec_json, validate_analyst_annotation,
};
use hydir_decompile::{
    decompile_function_unit_at, decompile_indexed_function, discover_functions,
    export_function_ir_llvm, lift_machine_function_at, lower_cir, lower_function_ir,
    lower_state_ir, measure_native_coverage,
};
use hydir_hlc::{emit_typed_c, emit_typed_cfg_c, lower_high_level_cfg_cir, lower_high_level_cir};
use hydir_ir::pcode::{
    MAX_GHIDRA_SNAPSHOT_BYTES, PcodeAddress, PcodeSliceTarget, parse_ghidra_snapshot,
};
use hydir_ir::{
    CIR_VERSION, FUNCTION_INDEX_VERSION, FUNCTION_IR_VERSION, MACHINE_FUNCTION_IR_VERSION,
    STATE_FUNCTION_IR_VERSION,
};
use hydir_model::{import_dwarf, infer_model, init_model};
use hydir_patch::{
    MAX_PATCH_BYTES, compile_patch_binary, parse_patch_bundle_json, parse_patch_document,
    parse_patch_json, patch_binary,
};
use hydir_recompile::rebuild_bytes;
use hydir_transform::{parse_passes, transform};
use jsonwebtoken::{
    Algorithm, DecodingKey, Validation, decode, decode_header,
    jwk::{AlgorithmParameters, JwkSet, KeyAlgorithm, KeyOperations, PublicKeyUse},
};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
#[cfg(not(test))]
use std::process::Stdio;
use std::{
    collections::{HashMap, HashSet},
    env,
    error::Error,
    ffi::OsString,
    io::{Read, Write},
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
#[cfg(not(test))]
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    process::Command,
};
use tokio_stream::{StreamExt, wrappers::ReceiverStream};
use tonic::{
    Request, Response, Status,
    transport::{Identity, Server, ServerTlsConfig},
};
use tonic_health::ServingStatus;
use uuid::Uuid;

include!(concat!(env!("OUT_DIR"), "/source_offer.rs"));

const MAX_WORKER_OUTPUT: usize = 16 * 1024 * 1024;
const MAX_ACTIVE_JOBS_PER_IDENTITY: i64 = 2;
const MAX_TLS_MATERIAL_BYTES: u64 = 1024 * 1024;
const MAX_STORED_OBJECT_BYTES: usize = MAX_BINARY_BYTES;
#[cfg(not(test))]
const WORKER_DEADLINE: Duration = Duration::from_secs(30);

#[derive(Debug)]
struct WorkerLaunchSpec {
    program: PathBuf,
    arguments: Vec<OsString>,
}

fn worker_launch_spec(
    executable: &Path,
    action: &str,
    symbol: Option<&str>,
    isolation: &str,
    bubblewrap: Option<&Path>,
) -> Result<WorkerLaunchSpec, String> {
    let mut worker_arguments = vec![OsString::from("worker"), OsString::from(action)];
    if let Some(symbol) = symbol {
        worker_arguments.push(OsString::from(symbol));
    }
    match isolation {
        "process" => Ok(WorkerLaunchSpec {
            program: executable.to_owned(),
            arguments: worker_arguments,
        }),
        "bubblewrap" => {
            if !cfg!(target_os = "linux") {
                return Err("bubblewrap worker isolation requires Linux".to_owned());
            }
            let bubblewrap = bubblewrap
                .ok_or("HYDIR_BWRAP_PATH must be an absolute path in bubblewrap isolation mode")?;
            if !bubblewrap.is_absolute() || !executable.is_absolute() {
                return Err("worker and bubblewrap executable paths must be absolute".to_owned());
            }
            let mut arguments = [
                "--die-with-parent",
                "--new-session",
                "--unshare-all",
                "--cap-drop",
                "ALL",
                "--clearenv",
                "--ro-bind",
                "/usr",
                "/usr",
                "--symlink",
                "usr/lib",
                "/lib",
                "--symlink",
                "usr/lib64",
                "/lib64",
                "--proc",
                "/proc",
                "--dev",
                "/dev",
                "--tmpfs",
                "/tmp",
                "--dir",
                "/work",
                "--chdir",
                "/work",
                "--setenv",
                "PATH",
                "/usr/bin",
                "--ro-bind",
            ]
            .into_iter()
            .map(OsString::from)
            .collect::<Vec<_>>();
            arguments.push(executable.as_os_str().to_owned());
            arguments.push(OsString::from("/hydird"));
            arguments.push(OsString::from("--"));
            arguments.push(OsString::from("/hydird"));
            arguments.extend(worker_arguments);
            Ok(WorkerLaunchSpec {
                program: bubblewrap.to_owned(),
                arguments,
            })
        }
        _ => Err("HYDIR_WORKER_ISOLATION must be `process` or `bubblewrap`".to_owned()),
    }
}

#[cfg(all(not(test), target_os = "linux"))]
struct WorkerProcessGroup {
    pid: i32,
}

#[cfg(all(not(test), target_os = "linux"))]
impl WorkerProcessGroup {
    fn disarm(&mut self) {
        self.pid = 0;
    }
}

#[cfg(all(not(test), target_os = "linux"))]
impl Drop for WorkerProcessGroup {
    fn drop(&mut self) {
        if self.pid > 0 {
            // SAFETY: the worker is placed in its own process group before
            // exec, and a negative PID targets only that group.
            unsafe { libc::kill(-self.pid, libc::SIGKILL) };
        }
    }
}

const SCHEMA: &str = "
BEGIN IMMEDIATE;
CREATE TABLE IF NOT EXISTS identities (
    principal TEXT PRIMARY KEY,
    token_sha256 TEXT NOT NULL UNIQUE
);
CREATE TABLE IF NOT EXISTS projects (
    id TEXT PRIMARY KEY,
    owner TEXT NOT NULL REFERENCES identities(principal),
    name TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    current_revision INTEGER NOT NULL DEFAULT 0,
    UNIQUE(owner, idempotency_key)
);
CREATE TABLE IF NOT EXISTS binaries (
    sha256 TEXT PRIMARY KEY,
    content BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS project_revisions (
    project_id TEXT NOT NULL REFERENCES projects(id),
    revision INTEGER NOT NULL,
    binary_sha256 TEXT NOT NULL REFERENCES binaries(sha256),
    PRIMARY KEY(project_id, revision)
);
CREATE TABLE IF NOT EXISTS artifacts (
    project_id TEXT NOT NULL REFERENCES projects(id),
    revision INTEGER NOT NULL,
    sha256 TEXT NOT NULL,
    media_type TEXT NOT NULL,
    content BLOB NOT NULL,
    PRIMARY KEY(project_id, revision, sha256)
);
PRAGMA user_version=1;
COMMIT;
";

const JOBS_MIGRATION: &str = "
BEGIN IMMEDIATE;
CREATE TABLE jobs (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id),
    revision INTEGER NOT NULL,
    kind TEXT NOT NULL,
    symbol TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('queued','running','succeeded','failed','cancelled','interrupted')),
    artifact_sha256 TEXT NOT NULL DEFAULT '',
    diagnostic TEXT NOT NULL DEFAULT '',
    created_at_ms INTEGER NOT NULL DEFAULT (unixepoch('subsec') * 1000),
    UNIQUE(project_id, idempotency_key)
);
CREATE INDEX jobs_project_state ON jobs(project_id, state);
CREATE TABLE job_events (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id TEXT NOT NULL REFERENCES jobs(id),
    state TEXT NOT NULL,
    message TEXT NOT NULL,
    artifact_sha256 TEXT NOT NULL DEFAULT ''
);
CREATE INDEX job_events_job_sequence ON job_events(job_id, sequence);
PRAGMA user_version=2;
COMMIT;
";

const PATCH_MIGRATION: &str = "
BEGIN IMMEDIATE;
CREATE TABLE patch_requests (
    project_id TEXT NOT NULL REFERENCES projects(id),
    idempotency_key TEXT NOT NULL,
    expected_revision INTEGER NOT NULL,
    patch_sha256 TEXT NOT NULL,
    new_revision INTEGER NOT NULL,
    binary_sha256 TEXT NOT NULL,
    PRIMARY KEY(project_id, idempotency_key)
);
PRAGMA user_version=3;
COMMIT;
";

const TRANSFORM_MIGRATION: &str = "
BEGIN IMMEDIATE;
CREATE TABLE transform_requests (
    project_id TEXT NOT NULL REFERENCES projects(id),
    idempotency_key TEXT NOT NULL,
    expected_revision INTEGER NOT NULL,
    request_sha256 TEXT NOT NULL,
    new_revision INTEGER NOT NULL,
    raw_sha256 TEXT NOT NULL,
    before_sha256 TEXT NOT NULL,
    after_sha256 TEXT NOT NULL,
    report_sha256 TEXT NOT NULL,
    ir_text_changed INTEGER NOT NULL,
    report_json TEXT NOT NULL,
    PRIMARY KEY(project_id, idempotency_key)
);
PRAGMA user_version=4;
COMMIT;
";

const REBUILD_MIGRATION: &str = "
BEGIN IMMEDIATE;
CREATE TABLE rebuild_requests (
    project_id TEXT NOT NULL REFERENCES projects(id),
    idempotency_key TEXT NOT NULL,
    expected_revision INTEGER NOT NULL,
    new_revision INTEGER NOT NULL,
    binary_sha256 TEXT NOT NULL,
    ir_sha256 TEXT NOT NULL,
    report_sha256 TEXT NOT NULL,
    report_json TEXT NOT NULL,
    PRIMARY KEY(project_id, idempotency_key)
);
PRAGMA user_version=5;
COMMIT;
";

const ANNOTATION_MIGRATION: &str = "
BEGIN IMMEDIATE;
CREATE TABLE analyst_annotations (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id),
    created_revision INTEGER NOT NULL,
    binary_sha256 TEXT NOT NULL REFERENCES binaries(sha256),
    kind TEXT NOT NULL CHECK(kind IN ('name','comment','assumption')),
    address TEXT,
    value TEXT NOT NULL,
    scope TEXT NOT NULL,
    UNIQUE(project_id, created_revision)
);
CREATE INDEX analyst_annotations_scope
    ON analyst_annotations(project_id, binary_sha256, created_revision);
CREATE TABLE annotation_requests (
    project_id TEXT NOT NULL REFERENCES projects(id),
    idempotency_key TEXT NOT NULL,
    expected_revision INTEGER NOT NULL,
    request_sha256 TEXT NOT NULL,
    new_revision INTEGER NOT NULL,
    annotation_id TEXT NOT NULL REFERENCES analyst_annotations(id),
    PRIMARY KEY(project_id, idempotency_key)
);
PRAGMA user_version=6;
COMMIT;
";

const PROJECT_ACCESS_MIGRATION: &str = "
BEGIN IMMEDIATE;
CREATE TABLE project_acls (
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    principal TEXT NOT NULL REFERENCES identities(principal),
    role TEXT NOT NULL CHECK(role IN ('viewer','analyst','operator','admin')),
    granted_by TEXT NOT NULL REFERENCES identities(principal),
    created_at_ms INTEGER NOT NULL DEFAULT (unixepoch('subsec') * 1000),
    PRIMARY KEY(project_id, principal)
);
CREATE INDEX project_acls_principal ON project_acls(principal, project_id);
INSERT INTO project_acls(project_id,principal,role,granted_by)
    SELECT id,owner,'admin',owner FROM projects;
ALTER TABLE jobs ADD COLUMN requested_by TEXT REFERENCES identities(principal);
UPDATE jobs SET requested_by=(SELECT owner FROM projects WHERE projects.id=jobs.project_id)
    WHERE requested_by IS NULL;
CREATE TABLE audit_events (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    occurred_at_ms INTEGER NOT NULL DEFAULT (unixepoch('subsec') * 1000),
    principal TEXT NOT NULL,
    action TEXT NOT NULL,
    project_id TEXT,
    details_json TEXT NOT NULL
);
PRAGMA user_version=7;
COMMIT;
";

const OIDC_IDENTITY_MIGRATION: &str = "
BEGIN IMMEDIATE;
CREATE TABLE oidc_identities (
    principal TEXT PRIMARY KEY REFERENCES identities(principal),
    issuer TEXT NOT NULL,
    subject TEXT NOT NULL,
    UNIQUE(issuer, subject)
);
PRAGMA user_version=8;
COMMIT;
";

const CONTENT_STORAGE_MIGRATION: &str = "
BEGIN IMMEDIATE;
ALTER TABLE binaries ADD COLUMN storage_kind TEXT NOT NULL DEFAULT 'inline'
    CHECK(storage_kind IN ('inline','filesystem-cas'));
ALTER TABLE binaries ADD COLUMN storage_key TEXT NOT NULL DEFAULT '';
ALTER TABLE binaries ADD COLUMN content_size INTEGER NOT NULL DEFAULT 0;
UPDATE binaries SET content_size=length(content);
ALTER TABLE artifacts ADD COLUMN storage_kind TEXT NOT NULL DEFAULT 'inline'
    CHECK(storage_kind IN ('inline','filesystem-cas'));
ALTER TABLE artifacts ADD COLUMN storage_key TEXT NOT NULL DEFAULT '';
ALTER TABLE artifacts ADD COLUMN content_size INTEGER NOT NULL DEFAULT 0;
UPDATE artifacts SET content_size=length(content);
PRAGMA user_version=9;
COMMIT;
";

const S3_STORAGE_MIGRATION: &str = "
PRAGMA foreign_keys=OFF;
BEGIN IMMEDIATE;
CREATE TABLE binaries_v10 (
    sha256 TEXT PRIMARY KEY,
    content BLOB NOT NULL,
    storage_kind TEXT NOT NULL DEFAULT 'inline' CHECK(storage_kind IN ('inline','filesystem-cas','s3')),
    storage_key TEXT NOT NULL DEFAULT '',
    content_size INTEGER NOT NULL DEFAULT 0
);
INSERT INTO binaries_v10 SELECT sha256,content,storage_kind,storage_key,content_size FROM binaries;
DROP TABLE binaries;
ALTER TABLE binaries_v10 RENAME TO binaries;
CREATE TABLE artifacts_v10 (
    project_id TEXT NOT NULL REFERENCES projects(id),
    revision INTEGER NOT NULL,
    sha256 TEXT NOT NULL,
    media_type TEXT NOT NULL,
    content BLOB NOT NULL,
    storage_kind TEXT NOT NULL DEFAULT 'inline' CHECK(storage_kind IN ('inline','filesystem-cas','s3')),
    storage_key TEXT NOT NULL DEFAULT '',
    content_size INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY(project_id, revision, sha256)
);
INSERT INTO artifacts_v10 SELECT project_id,revision,sha256,media_type,content,storage_kind,storage_key,content_size FROM artifacts;
DROP TABLE artifacts;
ALTER TABLE artifacts_v10 RENAME TO artifacts;
PRAGMA user_version=10;
COMMIT;
PRAGMA foreign_keys=ON;
";

const GHIDRA_SNAPSHOT_MIGRATION: &str = "
BEGIN IMMEDIATE;
CREATE TABLE ghidra_snapshots (
    project_id TEXT NOT NULL REFERENCES projects(id),
    binary_sha256 TEXT NOT NULL REFERENCES binaries(sha256),
    worker_key TEXT NOT NULL,
    created_revision INTEGER NOT NULL,
    content_sha256 TEXT NOT NULL,
    content BLOB NOT NULL,
    PRIMARY KEY(project_id,binary_sha256,worker_key)
);
PRAGMA user_version=11;
COMMIT;
";

#[derive(Clone)]
enum ContentStorage {
    Inline,
    FilesystemCas(Arc<FilesystemCas>),
    S3(Arc<S3ContentStore>),
}

#[derive(Debug)]
struct FilesystemCas {
    root: PathBuf,
}

#[derive(Debug)]
struct S3ContentStore {
    client: aws_sdk_s3::Client,
    bucket: String,
    prefix: String,
}

#[derive(Debug)]
struct StagedContent {
    digest: String,
    inline: Vec<u8>,
    storage_kind: &'static str,
    storage_key: String,
    content_size: i64,
}

impl ContentStorage {
    async fn stage(&self, content: &[u8]) -> Result<StagedContent, Status> {
        if content.len() > MAX_STORED_OBJECT_BYTES {
            return Err(Status::resource_exhausted(
                "stored object exceeds size limit",
            ));
        }
        let digest = sha256(content);
        let content_size = i64::try_from(content.len())
            .map_err(|_| Status::resource_exhausted("stored object exceeds size limit"))?;
        match self {
            Self::Inline => Ok(StagedContent {
                digest,
                inline: content.to_vec(),
                storage_kind: "inline",
                storage_key: String::new(),
                content_size,
            }),
            Self::FilesystemCas(storage) => {
                let storage = storage.clone();
                let stored_digest = digest.clone();
                let stored_content = content.to_vec();
                tokio::task::spawn_blocking(move || storage.put(&stored_digest, &stored_content))
                    .await
                    .map_err(|_| Status::internal("filesystem CAS task failed"))?
                    .map_err(Status::internal)?;
                Ok(StagedContent {
                    storage_key: digest.clone(),
                    digest,
                    inline: Vec::new(),
                    storage_kind: "filesystem-cas",
                    content_size,
                })
            }
            Self::S3(storage) => {
                storage
                    .put(&digest, content.to_vec())
                    .await
                    .map_err(Status::internal)?;
                Ok(StagedContent {
                    storage_key: storage.object_key(&digest)?,
                    digest,
                    inline: Vec::new(),
                    storage_kind: "s3",
                    content_size,
                })
            }
        }
    }

    async fn load(
        &self,
        digest: &str,
        inline: Vec<u8>,
        storage_kind: &str,
        storage_key: &str,
        content_size: i64,
    ) -> Result<Vec<u8>, Status> {
        if content_size < 0 || content_size as usize > MAX_STORED_OBJECT_BYTES {
            return Err(Status::data_loss("stored object size is invalid"));
        }
        let content = match storage_kind {
            "inline" => inline,
            "filesystem-cas" => match self {
                Self::FilesystemCas(storage) => {
                    let storage = storage.clone();
                    let storage_key = storage_key.to_owned();
                    tokio::task::spawn_blocking(move || storage.get(&storage_key))
                        .await
                        .map_err(|_| Status::internal("filesystem CAS task failed"))?
                        .map_err(Status::internal)?
                }
                _ => {
                    return Err(Status::failed_precondition(
                        "database references filesystem CAS objects; start hydird with that store",
                    ));
                }
            },
            "s3" => match self {
                Self::S3(storage) => storage
                    .get(storage_key, digest)
                    .await
                    .map_err(Status::internal)?,
                _ => {
                    return Err(Status::failed_precondition(
                        "database references S3 objects; start hydird with that store",
                    ));
                }
            },
            _ => return Err(Status::data_loss("unknown stored object backend")),
        };
        if content.len() != content_size as usize || sha256(&content) != digest {
            return Err(Status::data_loss(
                "stored object failed size or digest validation",
            ));
        }
        Ok(content)
    }
}

impl S3ContentStore {
    fn object_key(&self, digest: &str) -> Result<String, Status> {
        if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(Status::data_loss("S3 object digest is invalid"));
        }
        let suffix = format!("sha256/{}/{}/{}", &digest[..2], &digest[2..4], digest);
        Ok(if self.prefix.is_empty() {
            suffix
        } else {
            format!("{}/{suffix}", self.prefix)
        })
    }

    async fn put(&self, digest: &str, content: Vec<u8>) -> Result<(), String> {
        let key = self.object_key(digest).map_err(|error| error.to_string())?;
        let result = self
            .client
            .put_object()
            .bucket(&self.bucket)
            .key(&key)
            .metadata("hydir-sha256", digest)
            .if_none_match("*")
            .body(ByteStream::from(content))
            .send()
            .await;
        if result.is_err() && self.get(&key, digest).await.is_err() {
            return Err("S3 object write failed".to_owned());
        }
        Ok(())
    }

    async fn get(&self, key: &str, digest: &str) -> Result<Vec<u8>, String> {
        if self.object_key(digest).map_err(|error| error.to_string())? != key {
            return Err("S3 object key does not match its digest".to_owned());
        }
        let output = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
            .map_err(|_| "S3 object read failed".to_owned())?;
        if output.content_length().unwrap_or_default() < 0
            || output.content_length().unwrap_or_default() as usize > MAX_STORED_OBJECT_BYTES
        {
            return Err("S3 object exceeds size limit".to_owned());
        }
        let content_length = output.content_length().unwrap_or_default() as usize;
        let mut body = output.body;
        let mut content = Vec::with_capacity(content_length);
        while let Some(chunk) = body
            .try_next()
            .await
            .map_err(|_| "S3 object stream failed".to_owned())?
        {
            if content.len().saturating_add(chunk.len()) > MAX_STORED_OBJECT_BYTES {
                return Err("S3 object exceeds size limit".to_owned());
            }
            content.extend_from_slice(&chunk);
        }
        if sha256(&content) != digest {
            return Err("S3 object digest mismatch".to_owned());
        }
        Ok(content)
    }
}

impl FilesystemCas {
    fn open(root: &Path) -> Result<Self, Box<dyn Error>> {
        if !root.is_absolute() {
            return Err("filesystem CAS root must be absolute".into());
        }
        std::fs::create_dir_all(root)?;
        let metadata = std::fs::symlink_metadata(root)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err("filesystem CAS root must be a real directory".into());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o022 != 0 {
                return Err("filesystem CAS root must not be group/world writable".into());
            }
        }
        Ok(Self {
            root: root.to_owned(),
        })
    }

    fn object_path(&self, digest: &str) -> Result<PathBuf, String> {
        if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err("filesystem CAS key must be SHA-256 hex".to_owned());
        }
        Ok(self
            .root
            .join(&digest[..2])
            .join(&digest[2..4])
            .join(digest))
    }

    fn put(&self, digest: &str, content: &[u8]) -> Result<(), String> {
        if sha256(content) != digest {
            return Err("filesystem CAS write digest mismatch".to_owned());
        }
        let destination = self.object_path(digest)?;
        if destination.exists() {
            return self.verify_existing(&destination, digest, content.len());
        }
        let parent = destination
            .parent()
            .ok_or_else(|| "filesystem CAS object has no parent".to_owned())?;
        std::fs::create_dir_all(parent).map_err(|error| error.to_string())?;
        let temporary = parent.join(format!(".{}.{}.tmp", digest, Uuid::new_v4().simple()));
        let write_result = (|| -> Result<(), String> {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temporary)
                .map_err(|error| error.to_string())?;
            file.write_all(content).map_err(|error| error.to_string())?;
            file.sync_all().map_err(|error| error.to_string())?;
            match std::fs::rename(&temporary, &destination) {
                Ok(()) => Ok(()),
                Err(_) if destination.exists() => {
                    std::fs::remove_file(&temporary).map_err(|error| error.to_string())?;
                    Ok(())
                }
                Err(error) => Err(error.to_string()),
            }
        })();
        if write_result.is_err() {
            let _ = std::fs::remove_file(&temporary);
        }
        write_result?;
        self.verify_existing(&destination, digest, content.len())
    }

    fn get(&self, key: &str) -> Result<Vec<u8>, String> {
        let path = self.object_path(key)?;
        let metadata = std::fs::symlink_metadata(&path).map_err(|error| error.to_string())?;
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.len() > MAX_STORED_OBJECT_BYTES as u64
        {
            return Err("filesystem CAS object is not a bounded regular file".to_owned());
        }
        let content = std::fs::read(path).map_err(|error| error.to_string())?;
        if sha256(&content) != key {
            return Err("filesystem CAS object digest mismatch".to_owned());
        }
        Ok(content)
    }

    fn verify_existing(&self, path: &Path, digest: &str, size: usize) -> Result<(), String> {
        let metadata = std::fs::symlink_metadata(path).map_err(|error| error.to_string())?;
        if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() != size as u64
        {
            return Err("filesystem CAS object metadata mismatch".to_owned());
        }
        let content = std::fs::read(path).map_err(|error| error.to_string())?;
        if sha256(&content) != digest {
            return Err("filesystem CAS object digest mismatch".to_owned());
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum ProjectRole {
    Viewer,
    Analyst,
    Operator,
    Admin,
}

impl ProjectRole {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "viewer" => Ok(Self::Viewer),
            "analyst" => Ok(Self::Analyst),
            "operator" => Ok(Self::Operator),
            "admin" => Ok(Self::Admin),
            _ => Err("project role must be viewer, analyst, operator, or admin".to_owned()),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Viewer => "viewer",
            Self::Analyst => "analyst",
            Self::Operator => "operator",
            Self::Admin => "admin",
        }
    }
}

#[derive(Clone)]
enum AuthenticationMode {
    StaticTokens,
    Oidc(Arc<OidcVerifier>),
}

struct OidcVerifier {
    issuer: String,
    audience: String,
    keys: JwkSet,
}

#[derive(Debug, Deserialize)]
struct OidcClaims {
    sub: String,
}

struct OidcIdentity {
    principal: String,
    subject: String,
}

struct OidcIdentityRecord {
    principal: String,
    issuer: String,
    subject: String,
}

impl OidcVerifier {
    fn new(issuer: String, audience: String, keys: JwkSet) -> Result<Self, String> {
        let uri: tonic::codegen::http::Uri = issuer
            .parse()
            .map_err(|_| "OIDC issuer must be a valid HTTPS URI")?;
        if uri.scheme_str() != Some("https") || uri.authority().is_none() || uri.query().is_some() {
            return Err("OIDC issuer must be an absolute HTTPS URI".to_owned());
        }
        if audience.is_empty() || audience.len() > 256 || audience.chars().any(char::is_control) {
            return Err("OIDC audience must be 1..=256 non-control characters".to_owned());
        }
        if keys.keys.is_empty() || keys.keys.len() > 128 {
            return Err("OIDC JWKS must contain 1..=128 keys".to_owned());
        }
        let mut key_ids = HashSet::new();
        for key in &keys.keys {
            let key_id = key
                .common
                .key_id
                .as_deref()
                .filter(|key_id| !key_id.is_empty() && key_id.len() <= 128)
                .ok_or("every OIDC JWK requires a 1..=128 byte kid")?;
            if !key_ids.insert(key_id) {
                return Err("OIDC JWKS contains duplicate kid values".to_owned());
            }
            if !matches!(key.algorithm, AlgorithmParameters::RSA(_))
                || key.common.key_algorithm != Some(KeyAlgorithm::RS256)
                || key
                    .common
                    .public_key_use
                    .as_ref()
                    .is_some_and(|usage| usage != &PublicKeyUse::Signature)
                || key
                    .common
                    .key_operations
                    .as_ref()
                    .is_some_and(|operations| !operations.contains(&KeyOperations::Verify))
                || (key.common.public_key_use.is_some() && key.common.key_operations.is_some())
            {
                return Err(
                    "OIDC JWKS keys must be RSA verification keys with alg RS256".to_owned(),
                );
            }
            DecodingKey::from_jwk(key)
                .map_err(|error| format!("OIDC JWK `{key_id}` is invalid: {error}"))?;
        }
        Ok(Self {
            issuer,
            audience,
            keys,
        })
    }

    fn verify(&self, token: &str) -> Result<OidcIdentity, String> {
        if token.len() > 16 * 1024
            || token.bytes().any(|byte| !byte.is_ascii_graphic())
            || token.split('.').count() != 3
        {
            return Err("OIDC bearer token is not a bounded compact JWT".to_owned());
        }
        let header = decode_header(token).map_err(|_| "OIDC JWT header is invalid")?;
        if header.alg != Algorithm::RS256 {
            return Err("OIDC JWT algorithm must be RS256".to_owned());
        }
        let key_id = header.kid.as_deref().ok_or("OIDC JWT header has no kid")?;
        let key = self
            .keys
            .find(key_id)
            .ok_or("OIDC JWT kid is not present in the pinned JWKS")?;
        let decoding_key = DecodingKey::from_jwk(key).map_err(|_| "OIDC JWT key is invalid")?;
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_audience(&[self.audience.as_str()]);
        validation.set_issuer(&[self.issuer.as_str()]);
        validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
        validation.validate_nbf = true;
        validation.leeway = 30;
        let claims = decode::<OidcClaims>(token, &decoding_key, &validation)
            .map_err(|_| "OIDC JWT signature or claims are invalid")?
            .claims;
        if claims.sub.is_empty()
            || claims.sub.len() > 512
            || claims.sub.chars().any(char::is_control)
        {
            return Err("OIDC subject must be 1..=512 non-control characters".to_owned());
        }
        let principal = format!(
            "oidc-{:x}",
            Sha256::digest(format!("{}\0{}", self.issuer, claims.sub))
        );
        Ok(OidcIdentity {
            principal,
            subject: claims.sub,
        })
    }
}

fn require_project_role_in(
    connection: &Connection,
    principal: &str,
    id: &str,
    required: ProjectRole,
) -> Result<ProjectRole, Status> {
    let role: Option<String> = connection
        .query_row(
            "SELECT role FROM project_acls WHERE project_id=?1 AND principal=?2",
            params![id, principal],
            |row| row.get(0),
        )
        .optional()
        .map_err(internal)?;
    let role = role
        .as_deref()
        .map(ProjectRole::parse)
        .transpose()
        .map_err(Status::internal)?
        .ok_or_else(|| Status::not_found("project not found"))?;
    if role < required {
        return Err(Status::permission_denied(format!(
            "project operation requires {} role",
            required.as_str()
        )));
    }
    Ok(role)
}

#[derive(Clone)]
struct Store {
    db: Arc<Mutex<Connection>>,
    workers: Arc<Mutex<HashMap<String, JoinHandle<()>>>>,
    authentication: AuthenticationMode,
    content_storage: ContentStorage,
}

impl Store {
    fn open(path: &Path) -> Result<Self, Box<dyn Error>> {
        Self::open_with_options(
            path,
            AuthenticationMode::StaticTokens,
            ContentStorage::Inline,
        )
    }

    fn open_with_auth(
        path: &Path,
        authentication: AuthenticationMode,
    ) -> Result<Self, Box<dyn Error>> {
        Self::open_with_options(path, authentication, ContentStorage::Inline)
    }

    fn open_with_options(
        path: &Path,
        authentication: AuthenticationMode,
        content_storage: ContentStorage,
    ) -> Result<Self, Box<dyn Error>> {
        #[cfg(unix)]
        if path != Path::new(":memory:") {
            use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
            match std::fs::symlink_metadata(path) {
                Ok(metadata) => {
                    if !metadata.file_type().is_file() || metadata.permissions().mode() & 0o077 != 0
                    {
                        return Err(
                            "database must be a regular, owner-private file (chmod 600)".into()
                        );
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    std::fs::OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .mode(0o600)
                        .open(path)?;
                }
                Err(error) => return Err(error.into()),
            }
        }
        let connection = Connection::open(path)?;
        connection.execute_batch("PRAGMA foreign_keys=ON;")?;
        let version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        if version > 11 {
            return Err("database schema is newer than this hydird build".into());
        }
        if version == 0 {
            connection.execute_batch(SCHEMA)?;
        }
        if version <= 1 {
            connection.execute_batch(JOBS_MIGRATION)?;
        }
        if version <= 2 {
            connection.execute_batch(PATCH_MIGRATION)?;
        }
        if version <= 3 {
            connection.execute_batch(TRANSFORM_MIGRATION)?;
        }
        if version <= 4 {
            connection.execute_batch(REBUILD_MIGRATION)?;
        }
        if version <= 5 {
            connection.execute_batch(ANNOTATION_MIGRATION)?;
        }
        if version <= 6 {
            connection.execute_batch(PROJECT_ACCESS_MIGRATION)?;
        }
        if version <= 7 {
            connection.execute_batch(OIDC_IDENTITY_MIGRATION)?;
        }
        if version <= 8 {
            connection.execute_batch(CONTENT_STORAGE_MIGRATION)?;
        }
        if version <= 9 {
            connection.execute_batch(S3_STORAGE_MIGRATION)?;
        }
        if version <= 10 {
            connection.execute_batch(GHIDRA_SNAPSHOT_MIGRATION)?;
        }
        connection.execute_batch("BEGIN IMMEDIATE;
          INSERT INTO job_events(job_id,state,message) SELECT id,'interrupted','server restarted before completion'
          FROM jobs WHERE state IN ('queued','running');
          UPDATE jobs SET state='interrupted',diagnostic='server restarted before completion'
          WHERE state IN ('queued','running');
          COMMIT;")?;
        Ok(Self {
            db: Arc::new(Mutex::new(connection)),
            workers: Arc::new(Mutex::new(HashMap::new())),
            authentication,
            content_storage,
        })
    }

    fn connection(&self) -> Result<std::sync::MutexGuard<'_, Connection>, Status> {
        self.db
            .lock()
            .map_err(|_| Status::internal("database lock poisoned"))
    }

    fn create_identity(&self, principal: &str) -> Result<String, Box<dyn Error>> {
        if principal.is_empty()
            || principal.len() > 128
            || principal.starts_with("oidc-")
            || !principal
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        {
            return Err(
                "principal must be 1..=128 ASCII letters, digits, underscore, or hyphen and must not use the reserved oidc- prefix".into(),
            );
        }
        let token = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
        let digest = sha256(token.as_bytes());
        self.db
            .lock()
            .map_err(|_| "database lock poisoned")?
            .execute(
                "INSERT INTO identities(principal, token_sha256) VALUES(?1, ?2)",
                params![principal, digest],
            )?;
        Ok(token)
    }

    fn rotate_identity(&self, principal: &str) -> Result<String, Box<dyn Error>> {
        if principal.starts_with("oidc-") {
            return Err("OIDC identities cannot receive static credentials".into());
        }
        let token = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
        let digest = sha256(token.as_bytes());
        let changed = self
            .db
            .lock()
            .map_err(|_| "database lock poisoned")?
            .execute(
                "UPDATE identities SET token_sha256=?1 WHERE principal=?2",
                params![digest, principal],
            )?;
        if changed != 1 {
            return Err("principal does not exist".into());
        }
        Ok(token)
    }

    fn oidc_identities(&self) -> Result<Vec<OidcIdentityRecord>, Box<dyn Error>> {
        let connection = self.db.lock().map_err(|_| "database lock poisoned")?;
        let mut statement = connection.prepare(
            "SELECT principal,issuer,subject FROM oidc_identities ORDER BY issuer,subject",
        )?;
        Ok(statement
            .query_map([], |row| {
                Ok(OidcIdentityRecord {
                    principal: row.get(0)?,
                    issuer: row.get(1)?,
                    subject: row.get(2)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?)
    }

    fn principal<T>(&self, request: &Request<T>) -> Result<String, Status> {
        let bearer = request
            .metadata()
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
            .ok_or_else(|| Status::unauthenticated("missing or invalid bearer credential"))?;
        self.authenticate_bearer(bearer)
    }

    fn authenticate_bearer(&self, bearer: &str) -> Result<String, Status> {
        match &self.authentication {
            AuthenticationMode::StaticTokens => {
                if bearer.len() != 64 || !bearer.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                    return Err(Status::unauthenticated("invalid static bearer credential"));
                }
                let digest = sha256(bearer.as_bytes());
                self.connection()?
                    .query_row(
                        "SELECT principal FROM identities WHERE token_sha256=?1",
                        [digest],
                        |row| row.get(0),
                    )
                    .optional()
                    .map_err(internal)?
                    .ok_or_else(|| Status::unauthenticated("invalid bearer credential"))
            }
            AuthenticationMode::Oidc(verifier) => {
                let identity = verifier.verify(bearer).map_err(Status::unauthenticated)?;
                let disabled_static_digest =
                    sha256(format!("oidc-static-disabled\0{}", identity.principal).as_bytes());
                let mut connection = self.connection()?;
                let transaction = connection.transaction().map_err(internal)?;
                let registered: Option<(String, String)> = transaction
                    .query_row(
                        "SELECT issuer,subject FROM oidc_identities WHERE principal=?1",
                        [&identity.principal],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )
                    .optional()
                    .map_err(internal)?;
                if let Some(registered) = registered {
                    if registered != (verifier.issuer.clone(), identity.subject) {
                        return Err(Status::unauthenticated("OIDC identity mapping collision"));
                    }
                } else {
                    let principal_exists: bool = transaction
                        .query_row(
                            "SELECT EXISTS(SELECT 1 FROM identities WHERE principal=?1)",
                            [&identity.principal],
                            |row| row.get(0),
                        )
                        .map_err(internal)?;
                    if principal_exists {
                        return Err(Status::unauthenticated(
                            "OIDC principal collides with an existing local identity",
                        ));
                    }
                    transaction
                        .execute(
                            "INSERT INTO identities(principal,token_sha256) VALUES(?1,?2)",
                            params![identity.principal, disabled_static_digest],
                        )
                        .map_err(internal)?;
                    transaction
                        .execute(
                            "INSERT INTO oidc_identities(principal,issuer,subject) VALUES(?1,?2,?3)",
                            params![identity.principal, verifier.issuer, identity.subject],
                        )
                        .map_err(internal)?;
                }
                transaction.commit().map_err(internal)?;
                Ok(identity.principal)
            }
        }
    }

    fn require_project_role(
        &self,
        principal: &str,
        id: &str,
        required: ProjectRole,
    ) -> Result<ProjectRole, Status> {
        let connection = self.connection()?;
        require_project_role_in(&connection, principal, id, required)
    }

    fn set_project_role(
        &self,
        actor: &str,
        project_id: &str,
        principal: &str,
        role: Option<ProjectRole>,
    ) -> Result<(), Box<dyn Error>> {
        let mut connection = self.db.lock().map_err(|_| "database lock poisoned")?;
        let transaction = connection.transaction()?;
        let actor_role: Option<String> = transaction
            .query_row(
                "SELECT role FROM project_acls WHERE project_id=?1 AND principal=?2",
                params![project_id, actor],
                |row| row.get(0),
            )
            .optional()?;
        if actor_role.as_deref() != Some("admin") {
            return Err("actor is not a project admin".into());
        }
        let owner: String = transaction
            .query_row(
                "SELECT owner FROM projects WHERE id=?1",
                [project_id],
                |row| row.get(0),
            )
            .map_err(|_| "project does not exist")?;
        if principal == owner && role != Some(ProjectRole::Admin) {
            return Err("the project owner must retain the admin role".into());
        }
        let identity_exists: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM identities WHERE principal=?1)",
            [principal],
            |row| row.get(0),
        )?;
        if !identity_exists {
            return Err("target principal does not exist".into());
        }
        let (action, details) = if let Some(role) = role {
            transaction.execute(
                "INSERT INTO project_acls(project_id,principal,role,granted_by) VALUES(?1,?2,?3,?4) \
                 ON CONFLICT(project_id,principal) DO UPDATE SET role=excluded.role,granted_by=excluded.granted_by,created_at_ms=(unixepoch('subsec') * 1000)",
                params![project_id, principal, role.as_str(), actor],
            )?;
            (
                "project.role.set",
                serde_json::to_string(&json!({"principal": principal, "role": role.as_str()}))?,
            )
        } else {
            if transaction.execute(
                "DELETE FROM project_acls WHERE project_id=?1 AND principal=?2",
                params![project_id, principal],
            )? == 0
            {
                return Err("target principal has no project role".into());
            }
            (
                "project.role.revoke",
                serde_json::to_string(&json!({"principal": principal}))?,
            )
        };
        transaction.execute(
            "INSERT INTO audit_events(principal,action,project_id,details_json) VALUES(?1,?2,?3,?4)",
            params![actor, action, project_id, details],
        )?;
        transaction.commit()?;
        Ok(())
    }

    fn project_access(
        &self,
        actor: &str,
        project_id: &str,
    ) -> Result<Vec<(String, ProjectRole)>, Box<dyn Error>> {
        let connection = self.db.lock().map_err(|_| "database lock poisoned")?;
        let actor_role: Option<String> = connection
            .query_row(
                "SELECT role FROM project_acls WHERE project_id=?1 AND principal=?2",
                params![project_id, actor],
                |row| row.get(0),
            )
            .optional()?;
        if actor_role.as_deref() != Some("admin") {
            return Err("actor is not a project admin".into());
        }
        let mut statement = connection.prepare(
            "SELECT principal,role FROM project_acls WHERE project_id=?1 ORDER BY principal",
        )?;
        let records = statement
            .query_map([project_id], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        records
            .into_iter()
            .map(|(principal, role)| {
                ProjectRole::parse(&role)
                    .map(|role| (principal, role))
                    .map_err(Into::into)
            })
            .collect()
    }

    fn project(&self, principal: &str, id: &str) -> Result<ProjectReply, Status> {
        self.require_project_role(principal, id, ProjectRole::Viewer)?;
        let conn = self.connection()?;
        let row: Option<(String, String, i64, Option<String>)> = conn
            .query_row(
                "SELECT p.id,p.name,p.current_revision,r.binary_sha256 \
             FROM projects p LEFT JOIN project_revisions r \
             ON r.project_id=p.id AND r.revision=p.current_revision \
             WHERE p.id=?1",
                params![id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()
            .map_err(internal)?;
        let (id, name, revision, binary_sha) =
            row.ok_or_else(|| Status::not_found("project not found"))?;
        Ok(ProjectReply {
            project_id: id,
            name,
            revision: revision as u64,
            binary_sha256: binary_sha.unwrap_or_default(),
        })
    }

    async fn current_binary(
        &self,
        principal: &str,
        id: &str,
        revision: u64,
    ) -> Result<Vec<u8>, Status> {
        let project = self.project(principal, id)?;
        if project.revision != revision {
            return Err(Status::aborted("stale project revision"));
        }
        if project.binary_sha256.is_empty() {
            return Err(Status::failed_precondition(
                "project has no uploaded binary",
            ));
        }
        let stored: (String, Vec<u8>, String, String, i64) = self.connection()?.query_row(
            "SELECT b.sha256,b.content,b.storage_kind,b.storage_key,b.content_size FROM project_revisions r JOIN binaries b ON b.sha256=r.binary_sha256 \
             WHERE r.project_id=?1 AND r.revision=?2",
            params![id, revision as i64],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
        ).map_err(internal)?;
        self.content_storage
            .load(&stored.0, stored.1, &stored.2, &stored.3, stored.4)
            .await
    }

    async fn binary_at_revision(
        &self,
        principal: &str,
        id: &str,
        revision: u64,
    ) -> Result<Vec<u8>, Status> {
        self.require_project_role(principal, id, ProjectRole::Viewer)?;
        let stored: Option<(String, Vec<u8>, String, String, i64)> = self.connection()?
            .query_row(
                "SELECT b.sha256,b.content,b.storage_kind,b.storage_key,b.content_size FROM project_revisions r \
                 JOIN binaries b ON b.sha256=r.binary_sha256 \
                 WHERE r.project_id=?1 AND r.revision=?2",
                params![id, revision as i64],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
            )
            .optional()
            .map_err(internal)?;
        let stored = stored.ok_or_else(|| Status::not_found("project revision not found"))?;
        self.content_storage
            .load(&stored.0, stored.1, &stored.2, &stored.3, stored.4)
            .await
    }

    async fn store_artifact(
        &self,
        project_id: &str,
        revision: u64,
        media_type: &str,
        content: &[u8],
    ) -> Result<String, Status> {
        let staged = self.content_storage.stage(content).await?;
        let connection = self.connection()?;
        insert_artifact(
            &connection,
            project_id,
            revision as i64,
            media_type,
            &staged,
        )?;
        Ok(staged.digest)
    }

    async fn commit_patch_mutation(
        &self,
        principal: &str,
        project_id: &str,
        expected_revision: u64,
        idempotency_key: &str,
        patch_digest: &str,
        patched: Vec<u8>,
    ) -> Result<PatchReply, Status> {
        self.require_project_role(principal, project_id, ProjectRole::Operator)?;
        let expected = i64::try_from(expected_revision)
            .map_err(|_| Status::invalid_argument("revision too large"))?;
        let next = expected
            .checked_add(1)
            .ok_or_else(|| Status::out_of_range("project revision overflow"))?;
        let staged_binary = self.content_storage.stage(&patched).await?;
        let binary_sha256 = staged_binary.digest.clone();
        let mut conn = self.connection()?;
        let tx = conn.transaction().map_err(internal)?;
        require_project_role_in(&tx, principal, project_id, ProjectRole::Operator)?;
        let prior: Option<(i64, String, i64, String)> = tx
            .query_row(
                "SELECT expected_revision,patch_sha256,new_revision,binary_sha256 FROM patch_requests WHERE project_id=?1 AND idempotency_key=?2",
                params![project_id, idempotency_key],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()
            .map_err(internal)?;
        if let Some((prior_expected, prior_digest, revision, prior_binary_sha)) = prior {
            if prior_expected != expected || prior_digest != patch_digest {
                return Err(Status::already_exists(
                    "idempotency key belongs to a different patch request",
                ));
            }
            return Ok(PatchReply {
                project_id: project_id.to_owned(),
                revision: revision as u64,
                artifact_sha256: prior_binary_sha.clone(),
                binary_sha256: prior_binary_sha,
            });
        }
        let current: i64 = tx
            .query_row(
                "SELECT current_revision FROM projects WHERE id=?1",
                params![project_id],
                |row| row.get(0),
            )
            .map_err(internal)?;
        if current != expected {
            return Err(Status::aborted("stale project revision"));
        }
        insert_binary(&tx, &staged_binary)?;
        tx.execute(
            "INSERT INTO project_revisions(project_id,revision,binary_sha256) VALUES(?1,?2,?3)",
            params![project_id, next, binary_sha256],
        )
        .map_err(internal)?;
        tx.execute(
            "UPDATE projects SET current_revision=?1 WHERE id=?2",
            params![next, project_id],
        )
        .map_err(internal)?;
        insert_artifact(&tx, project_id, next, "application/x-elf", &staged_binary)?;
        tx.execute(
            "INSERT INTO patch_requests(project_id,idempotency_key,expected_revision,patch_sha256,new_revision,binary_sha256) VALUES(?1,?2,?3,?4,?5,?6)",
            params![project_id, idempotency_key, expected, patch_digest, next, binary_sha256],
        )
        .map_err(internal)?;
        tx.commit().map_err(internal)?;
        Ok(PatchReply {
            project_id: project_id.to_owned(),
            revision: next as u64,
            artifact_sha256: binary_sha256.clone(),
            binary_sha256,
        })
    }

    fn job(&self, principal: &str, project_id: &str, job_id: &str) -> Result<JobReply, Status> {
        self.require_project_role(principal, project_id, ProjectRole::Viewer)?;
        let row = self
            .connection()?
            .query_row(
                "SELECT j.project_id,j.id,j.revision,j.kind,j.state,j.artifact_sha256,j.diagnostic \
             FROM jobs j WHERE j.id=?1 AND j.project_id=?2",
                params![job_id, project_id],
                |row| {
                    Ok(JobReply {
                        project_id: row.get(0)?,
                        job_id: row.get(1)?,
                        project_revision: row.get::<_, i64>(2)? as u64,
                        kind: row.get(3)?,
                        state: row.get(4)?,
                        artifact_sha256: row.get(5)?,
                        diagnostic: row.get(6)?,
                    })
                },
            )
            .optional()
            .map_err(internal)?;
        row.ok_or_else(|| Status::not_found("job not found"))
    }

    fn transition_job(
        &self,
        job_id: &str,
        from: &str,
        to: &str,
        message: &str,
    ) -> Result<bool, Status> {
        let mut conn = self.connection()?;
        let tx = conn.transaction().map_err(internal)?;
        let changed = tx
            .execute(
                "UPDATE jobs SET state=?1 WHERE id=?2 AND state=?3",
                params![to, job_id, from],
            )
            .map_err(internal)?;
        if changed == 1 {
            insert_event(&tx, job_id, to, message, "")?;
        }
        tx.commit().map_err(internal)?;
        Ok(changed == 1)
    }

    async fn finish_lift_job(
        &self,
        job_id: &str,
        project_id: &str,
        revision: u64,
        result: Result<Vec<u8>, Status>,
    ) -> Result<(), Status> {
        let prepared = match result {
            Ok(content) => Ok(self.content_storage.stage(&content).await?),
            Err(error) => Err(error.message().chars().take(4096).collect::<String>()),
        };
        let mut conn = self.connection()?;
        let tx = conn.transaction().map_err(internal)?;
        let state: Option<String> = tx
            .query_row("SELECT state FROM jobs WHERE id=?1", [job_id], |row| {
                row.get(0)
            })
            .optional()
            .map_err(internal)?;
        if state.as_deref() != Some("running") {
            tx.commit().map_err(internal)?;
            return Ok(());
        }
        match prepared {
            Ok(staged) => {
                let digest = staged.digest.clone();
                insert_artifact(&tx, project_id, revision as i64, "text/x-llvm-ir", &staged)?;
                tx.execute(
                    "UPDATE jobs SET state='succeeded',artifact_sha256=?1 WHERE id=?2",
                    params![digest, job_id],
                )
                .map_err(internal)?;
                insert_event(&tx, job_id, "succeeded", "LLVM IR artifact ready", &digest)?;
            }
            Err(diagnostic) => {
                tx.execute(
                    "UPDATE jobs SET state='failed',diagnostic=?1 WHERE id=?2",
                    params![diagnostic, job_id],
                )
                .map_err(internal)?;
                insert_event(&tx, job_id, "failed", &diagnostic, "")?;
            }
        }
        tx.commit().map_err(internal)?;
        Ok(())
    }

    async fn execute_lift_job(
        self,
        job_id: String,
        project_id: String,
        revision: u64,
        symbol: String,
        bytes: Vec<u8>,
    ) {
        match self.transition_job(&job_id, "queued", "running", "worker started") {
            Ok(true) => {}
            Ok(false) => return,
            Err(error) => {
                eprintln!("hydird job transition failed: {error}");
                return;
            }
        }
        let result = run_worker("lift", Some(&symbol), bytes).await;
        if let Err(error) = self
            .finish_lift_job(&job_id, &project_id, revision, result)
            .await
        {
            eprintln!("hydird job completion failed: {error}");
        }
        if let Ok(mut workers) = self.workers.lock() {
            workers.remove(&job_id);
        }
    }

    async fn finish_native_analysis_job(
        &self,
        job_id: &str,
        project_id: &str,
        revision: u64,
        result: Result<Vec<u8>, Status>,
    ) -> Result<(), Status> {
        let prepared = match result {
            Ok(content) => Ok(self.content_storage.stage(&content).await?),
            Err(error) => Err(error.message().chars().take(4096).collect::<String>()),
        };
        let mut conn = self.connection()?;
        let tx = conn.transaction().map_err(internal)?;
        let state: Option<String> = tx
            .query_row("SELECT state FROM jobs WHERE id=?1", [job_id], |row| {
                row.get(0)
            })
            .optional()
            .map_err(internal)?;
        if state.as_deref() != Some("running") {
            tx.commit().map_err(internal)?;
            return Ok(());
        }
        match prepared {
            Ok(staged) => {
                let digest = staged.digest.clone();
                insert_artifact(
                    &tx,
                    project_id,
                    revision as i64,
                    "application/vnd.hydir.native-analysis+json;version=1",
                    &staged,
                )?;
                tx.execute(
                    "UPDATE jobs SET state='succeeded',artifact_sha256=?1 WHERE id=?2",
                    params![digest, job_id],
                )
                .map_err(internal)?;
                insert_event(
                    &tx,
                    job_id,
                    "succeeded",
                    "native program analysis artifact ready",
                    &digest,
                )?;
            }
            Err(diagnostic) => {
                tx.execute(
                    "UPDATE jobs SET state='failed',diagnostic=?1 WHERE id=?2",
                    params![diagnostic, job_id],
                )
                .map_err(internal)?;
                insert_event(&tx, job_id, "failed", &diagnostic, "")?;
            }
        }
        tx.commit().map_err(internal)?;
        Ok(())
    }

    async fn execute_native_analysis_job(
        self,
        job_id: String,
        project_id: String,
        revision: u64,
        bytes: Vec<u8>,
    ) {
        match self.transition_job(&job_id, "queued", "running", "native worker started") {
            Ok(true) => {}
            Ok(false) => return,
            Err(error) => {
                eprintln!("hydird native job transition failed: {error}");
                return;
            }
        }
        let result = run_worker("native-analysis", None, bytes).await;
        if let Err(error) = self
            .finish_native_analysis_job(&job_id, &project_id, revision, result)
            .await
        {
            eprintln!("hydird native job completion failed: {error}");
        }
        if let Ok(mut workers) = self.workers.lock() {
            workers.remove(&job_id);
        }
    }
}

fn insert_event(
    tx: &rusqlite::Transaction<'_>,
    job_id: &str,
    state: &str,
    message: &str,
    artifact_sha256: &str,
) -> Result<(), Status> {
    tx.execute(
        "INSERT INTO job_events(job_id,state,message,artifact_sha256) VALUES(?1,?2,?3,?4)",
        params![job_id, state, message, artifact_sha256],
    )
    .map_err(internal)?;
    Ok(())
}

fn insert_binary(connection: &Connection, content: &StagedContent) -> Result<(), Status> {
    connection
        .execute(
            "INSERT OR IGNORE INTO binaries(sha256,content,storage_kind,storage_key,content_size) \
             VALUES(?1,?2,?3,?4,?5)",
            params![
                content.digest,
                content.inline,
                content.storage_kind,
                content.storage_key,
                content.content_size
            ],
        )
        .map_err(internal)?;
    Ok(())
}

fn insert_artifact(
    connection: &Connection,
    project_id: &str,
    revision: i64,
    media_type: &str,
    content: &StagedContent,
) -> Result<(), Status> {
    connection
        .execute(
            "INSERT OR IGNORE INTO artifacts(project_id,revision,sha256,media_type,content,storage_kind,storage_key,content_size) \
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
            params![
                project_id,
                revision,
                content.digest,
                media_type,
                content.inline,
                content.storage_kind,
                content.storage_key,
                content.content_size
            ],
        )
        .map_err(internal)?;
    Ok(())
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn patch_worker_envelope(patch_json: &[u8], binary: &[u8]) -> Result<Vec<u8>, Status> {
    if patch_json.is_empty() || patch_json.len() > MAX_PATCH_BYTES {
        return Err(Status::invalid_argument(
            "patch document must be 1..=4096 bytes",
        ));
    }
    let patch_length = u32::try_from(patch_json.len())
        .map_err(|_| Status::invalid_argument("patch document too long"))?;
    let mut envelope = Vec::with_capacity(4 + patch_json.len() + binary.len());
    envelope.extend_from_slice(&patch_length.to_le_bytes());
    envelope.extend_from_slice(patch_json);
    envelope.extend_from_slice(binary);
    Ok(envelope)
}

fn validate_v2_patch_request(input: &api_v2::PatchRequest) -> Result<(), Status> {
    if !input.trusted_fixture || !input.assume_u64x2 || !input.assume_entry_only {
        return Err(Status::invalid_argument(
            "patch requires trusted-fixture, u64x2, and entry-only assertions",
        ));
    }
    if input.idempotency_key.is_empty()
        || input.idempotency_key.len() > 128
        || input.idempotency_key.chars().any(char::is_control)
    {
        return Err(Status::invalid_argument(
            "patch idempotency key must be 1..=128 non-control bytes",
        ));
    }
    if input.patch_json.is_empty() || input.patch_json.len() > MAX_PATCH_BYTES {
        return Err(Status::invalid_argument(
            "patch document must be 1..=4096 bytes",
        ));
    }
    Ok(())
}

fn internal(error: rusqlite::Error) -> Status {
    // SQL details and path data must not be exposed to remote clients.
    eprintln!("hydird database error: {error}");
    Status::internal("database operation failed")
}

fn valid_symbol(symbol: &str) -> Result<(), Status> {
    if symbol.is_empty() || symbol.len() > 256 || symbol.chars().any(char::is_control) {
        return Err(Status::invalid_argument(
            "function symbol must be 1..=256 non-control bytes",
        ));
    }
    Ok(())
}

fn valid_worker_argument(action: &str, argument: &str) -> Result<(), Status> {
    if matches!(action, "native-artifact" | "ghidra-snapshot-artifact") {
        if argument.is_empty() || argument.len() > 1024 || argument.chars().any(char::is_control) {
            return Err(Status::invalid_argument(
                "worker artifact selector must be 1..=1024 non-control bytes",
            ));
        }
        Ok(())
    } else {
        valid_symbol(argument)
    }
}

fn annotation_kind(value: &str) -> Result<AnnotationKind, Status> {
    AnnotationKind::parse(value).map_err(Status::invalid_argument)
}

fn annotation_address(value: &str) -> Result<Option<Address>, Status> {
    parse_annotation_address(value).map_err(Status::invalid_argument)
}

fn validate_annotation(
    input: &AnnotationRequest,
) -> Result<(AnnotationKind, Option<Address>), Status> {
    let kind = annotation_kind(&input.kind)?;
    let address = annotation_address(&input.address)?;
    validate_analyst_annotation(
        kind,
        address,
        &input.value,
        &input.scope,
        &input.idempotency_key,
    )
    .map_err(Status::invalid_argument)?;
    Ok((kind, address))
}

fn analyst_provenance() -> FactProvenance {
    FactProvenance {
        source: FactSource::AnalystAssertion,
        scope: "authenticated project annotation; not independently validated".to_owned(),
    }
}

fn annotations_for(
    conn: &Connection,
    project_id: &str,
    revision: u64,
    binary_sha256: &str,
) -> Result<Vec<AnalystAnnotation>, Status> {
    let mut statement = conn
        .prepare(
            "SELECT id,created_revision,kind,address,value,scope FROM analyst_annotations \
             WHERE project_id=?1 AND binary_sha256=?2 AND created_revision<=?3 \
             ORDER BY created_revision LIMIT 513",
        )
        .map_err(internal)?;
    let rows = statement
        .query_map(params![project_id, binary_sha256, revision as i64], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Option<String>>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
            ))
        })
        .map_err(internal)?;
    let mut annotations = Vec::new();
    for row in rows {
        let (id, created_revision, kind, address, value, scope) = row.map_err(internal)?;
        let kind = annotation_kind(&kind)
            .map_err(|_| Status::internal("invalid stored annotation kind"))?;
        let address = annotation_address(address.as_deref().unwrap_or(""))
            .map_err(|_| Status::internal("invalid stored annotation address"))?;
        annotations.push(AnalystAnnotation {
            id,
            binary_sha256: binary_sha256.to_owned(),
            created_revision: created_revision as u64,
            kind,
            address,
            value,
            scope,
            provenance: analyst_provenance(),
        });
    }
    if annotations.len() > 512 {
        return Err(Status::resource_exhausted(
            "annotation list exceeds 512 facts",
        ));
    }
    Ok(annotations)
}

fn annotation_replay(
    conn: &Connection,
    project_id: &str,
    key: &str,
    expected: i64,
    request_sha256: &str,
) -> Result<Option<(u64, String)>, Status> {
    let prior: Option<(i64, String, i64, String)> = conn
        .query_row(
            "SELECT a.expected_revision,a.request_sha256,a.new_revision,r.binary_sha256 \
             FROM annotation_requests a JOIN project_revisions r \
             ON r.project_id=a.project_id AND r.revision=a.new_revision \
             WHERE a.project_id=?1 AND a.idempotency_key=?2",
            params![project_id, key],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()
        .map_err(internal)?;
    match prior {
        Some((prior_expected, prior_digest, revision, binary_sha256)) => {
            if prior_expected != expected || prior_digest != request_sha256 {
                Err(Status::already_exists(
                    "idempotency key belongs to a different annotation request",
                ))
            } else {
                Ok(Some((revision as u64, binary_sha256)))
            }
        }
        None => Ok(None),
    }
}

struct TransformRecord {
    expected: i64,
    request_sha256: String,
    revision: i64,
    raw_sha256: String,
    before_sha256: String,
    after_sha256: String,
    report_sha256: String,
    changed: i64,
    report_json: String,
}

fn transform_replay(
    conn: &Connection,
    project_id: &str,
    key: &str,
    expected: i64,
    request_sha256: &str,
) -> Result<Option<TransformReply>, Status> {
    let prior: Option<TransformRecord> = conn
        .query_row(
            "SELECT expected_revision,request_sha256,new_revision,raw_sha256,before_sha256,after_sha256,report_sha256,ir_text_changed,report_json FROM transform_requests WHERE project_id=?1 AND idempotency_key=?2",
            params![project_id, key],
            |row| Ok(TransformRecord {
                expected: row.get(0)?,
                request_sha256: row.get(1)?,
                revision: row.get(2)?,
                raw_sha256: row.get(3)?,
                before_sha256: row.get(4)?,
                after_sha256: row.get(5)?,
                report_sha256: row.get(6)?,
                changed: row.get(7)?,
                report_json: row.get(8)?,
            }),
        )
        .optional()
        .map_err(internal)?;
    let Some(prior) = prior else {
        return Ok(None);
    };
    if prior.expected != expected || prior.request_sha256 != request_sha256 {
        return Err(Status::already_exists(
            "idempotency key belongs to a different transform request",
        ));
    }
    Ok(Some(TransformReply {
        project_id: project_id.to_owned(),
        project_revision: prior.revision as u64,
        raw_sha256: prior.raw_sha256,
        before_sha256: prior.before_sha256,
        after_sha256: prior.after_sha256,
        report_sha256: prior.report_sha256,
        ir_text_changed: prior.changed != 0,
        report_json: prior.report_json,
    }))
}

struct RebuildRecord {
    expected: i64,
    revision: i64,
    binary_sha256: String,
    ir_sha256: String,
    report_sha256: String,
    report_json: String,
}

fn rebuild_replay(
    conn: &Connection,
    project_id: &str,
    key: &str,
    expected: i64,
) -> Result<Option<RebuildReply>, Status> {
    let prior: Option<RebuildRecord> = conn
        .query_row(
            "SELECT expected_revision,new_revision,binary_sha256,ir_sha256,report_sha256,report_json FROM rebuild_requests WHERE project_id=?1 AND idempotency_key=?2",
            params![project_id, key],
            |row| Ok(RebuildRecord {
                expected: row.get(0)?,
                revision: row.get(1)?,
                binary_sha256: row.get(2)?,
                ir_sha256: row.get(3)?,
                report_sha256: row.get(4)?,
                report_json: row.get(5)?,
            }),
        )
        .optional()
        .map_err(internal)?;
    let Some(prior) = prior else {
        return Ok(None);
    };
    if prior.expected != expected {
        return Err(Status::already_exists(
            "idempotency key belongs to a different rebuild request",
        ));
    }
    Ok(Some(RebuildReply {
        project_id: project_id.to_owned(),
        revision: prior.revision as u64,
        binary_sha256: prior.binary_sha256,
        ir_sha256: prior.ir_sha256,
        report_sha256: prior.report_sha256,
        report_json: prior.report_json,
    }))
}

fn pack_worker_parts(parts: &[&[u8]]) -> Result<Vec<u8>, String> {
    let total = parts
        .len()
        .checked_mul(4)
        .ok_or("worker header overflow")?
        .checked_add(parts.iter().map(|part| part.len()).sum::<usize>())
        .ok_or("worker output size overflow")?;
    if total > MAX_WORKER_OUTPUT {
        return Err("artifacts exceed 16 MiB worker output limit".to_owned());
    }
    let mut packed = Vec::with_capacity(total);
    for part in parts {
        let size = u32::try_from(part.len()).map_err(|_| "worker artifact too large")?;
        packed.extend_from_slice(&size.to_le_bytes());
    }
    for part in parts {
        packed.extend_from_slice(part);
    }
    Ok(packed)
}

fn unpack_worker_parts<const N: usize>(bytes: &[u8]) -> Result<[&[u8]; N], Status> {
    let mut cursor = N * 4;
    let mut parts = [&[][..]; N];
    for (index, part) in parts.iter_mut().enumerate() {
        let offset = index * 4;
        let size = u32::from_le_bytes(
            bytes
                .get(offset..offset + 4)
                .ok_or_else(|| Status::internal("worker returned a short artifact header"))?
                .try_into()
                .map_err(|_| Status::internal("worker returned a bad artifact header"))?,
        ) as usize;
        let end = cursor
            .checked_add(size)
            .ok_or_else(|| Status::internal("worker artifact length overflow"))?;
        *part = bytes
            .get(cursor..end)
            .ok_or_else(|| Status::internal("worker returned a truncated artifact"))?;
        cursor = end;
    }
    if cursor != bytes.len() {
        return Err(Status::internal("worker returned trailing artifact bytes"));
    }
    Ok(parts)
}

#[derive(Debug, Deserialize, Serialize)]
struct NativeArtifactSelector {
    stage: String,
    #[serde(default)]
    function: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct GhidraSnapshotArtifactSelector {
    stage: String,
    binary_sha256: String,
    #[serde(default)]
    start_address: String,
    #[serde(default)]
    instruction_index: Option<u32>,
    #[serde(default)]
    operation_index: Option<u32>,
    #[serde(default)]
    input_index: Option<u32>,
}

fn ghidra_snapshot_artifact_media_type(stage: &str) -> Option<&'static str> {
    match stage {
        "snapshot" => Some("application/vnd.hydir.ghidra-snapshot+json;version=2"),
        "pcode" => Some("application/vnd.hydir.pcode-ir+json;version=1"),
        "semantics" => Some("application/vnd.hydir.pcode-semantic-ir+json;version=1"),
        "state" => Some("application/vnd.hydir.pcode-state-ir+json;version=1"),
        "cfg" => Some("application/vnd.hydir.pcode-cfg-ir+json;version=1"),
        "coverage" => Some("application/vnd.hydir.pcode-coverage+json;version=1"),
        "llvm-cfg" => Some("application/vnd.hydir.pcode-cfg-llvm+json;version=2"),
        "slice" => Some("application/vnd.hydir.pcode-slice+json;version=1"),
        _ => None,
    }
}

fn validate_ghidra_slice_target(
    stage: &str,
    instruction_index: Option<u32>,
    operation_index: Option<u32>,
    input_index: Option<u32>,
) -> Result<Option<PcodeSliceTarget>, String> {
    if stage != "slice" {
        if instruction_index.is_some() || operation_index.is_some() || input_index.is_some() {
            return Err("operation selector is supported only for slice".to_owned());
        }
        return Ok(None);
    }
    let instruction_index =
        instruction_index.ok_or("slice requires instruction_index and operation_index")?;
    let operation_index =
        operation_index.ok_or("slice requires instruction_index and operation_index")?;
    Ok(Some(PcodeSliceTarget {
        instruction_index,
        operation_index,
        input_index,
    }))
}

fn validate_ghidra_start_address(stage: &str, address: &str) -> Result<(), String> {
    if address.is_empty() {
        return Ok(());
    }
    if stage != "llvm-cfg" {
        return Err("start address is supported only for llvm-cfg".to_owned());
    }
    let digits = address
        .strip_prefix("0x")
        .ok_or("start address must be 0x-prefixed hexadecimal")?;
    if digits.is_empty()
        || digits.len() > 16
        || !digits
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err("start address must contain 1..=16 lowercase hexadecimal digits".to_owned());
    }
    Ok(())
}

fn ghidra_selected_entry(address: &str, automatic: bool) -> Result<Option<u64>, String> {
    if address.is_empty() {
        return Ok(None);
    }
    if !automatic {
        return Err("selected_function_entry requires automatic Ghidra analysis".to_owned());
    }
    let digits = address
        .strip_prefix("0x")
        .ok_or("selected_function_entry must be 0x-prefixed hexadecimal")?;
    if digits.is_empty()
        || digits.len() > 16
        || !digits
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(
            "selected_function_entry must contain 1..=16 lowercase hexadecimal digits".to_owned(),
        );
    }
    u64::from_str_radix(digits, 16)
        .map(Some)
        .map_err(|_| "selected_function_entry is out of range".to_owned())
}

async fn automatic_ghidra_snapshot(
    binary: Vec<u8>,
    selected_entry: Option<u64>,
) -> Result<Vec<u8>, Status> {
    tokio::task::spawn_blocking(move || -> Result<Vec<u8>, String> {
        let scratch = tempfile::tempdir()
            .map_err(|error| format!("cannot create Ghidra input scratch: {error}"))?;
        let input = scratch.path().join("binary.elf");
        let output = scratch.path().join("snapshot.json");
        std::fs::write(&input, binary)
            .map_err(|error| format!("cannot stage Ghidra input: {error}"))?;
        hydir_ghidra_worker::analyze(&input, selected_entry, &output)?;
        std::fs::read(output)
            .map_err(|error| format!("cannot read automatic Ghidra snapshot: {error}"))
    })
    .await
    .map_err(|error| Status::internal(format!("Ghidra worker task failed: {error}")))?
    .map_err(|error| {
        Status::failed_precondition(format!("automatic Ghidra analysis failed: {error}"))
    })
}

fn cached_ghidra_snapshot(
    connection: &Connection,
    project_id: &str,
    binary_digest: &str,
    worker_key: &str,
    selected_entry: Option<u64>,
) -> Result<Option<Vec<u8>>, Status> {
    let row: Option<(String, Vec<u8>)> = connection
        .query_row(
            "SELECT content_sha256,content FROM ghidra_snapshots \
             WHERE project_id=?1 AND binary_sha256=?2 AND worker_key=?3",
            params![project_id, binary_digest, worker_key],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(internal)?;
    let Some((stored_digest, content)) = row else {
        return Ok(None);
    };
    if content.is_empty()
        || content.len() > MAX_GHIDRA_SNAPSHOT_BYTES
        || sha256(&content) != stored_digest
        || hydir_ghidra_worker::validate_cached_snapshot(&content, binary_digest, selected_entry)
            .is_err()
    {
        return Ok(None);
    }
    Ok(Some(content))
}

fn save_ghidra_snapshot(
    connection: &Connection,
    project_id: &str,
    binary_digest: &str,
    revision: u64,
    worker_key: &str,
    selected_entry: Option<u64>,
    content: &[u8],
) -> Result<(), Status> {
    if content.is_empty() || content.len() > MAX_GHIDRA_SNAPSHOT_BYTES {
        return Err(Status::resource_exhausted(
            "automatic Ghidra snapshot exceeds 16 MiB",
        ));
    }
    hydir_ghidra_worker::validate_cached_snapshot(content, binary_digest, selected_entry)
        .map_err(|error| Status::invalid_argument(format!("invalid Ghidra snapshot: {error}")))?;
    connection
        .execute(
            "INSERT INTO ghidra_snapshots(project_id,binary_sha256,worker_key,created_revision,content_sha256,content) \
             VALUES(?1,?2,?3,?4,?5,?6) ON CONFLICT(project_id,binary_sha256,worker_key) \
             DO UPDATE SET created_revision=excluded.created_revision, \
             content_sha256=excluded.content_sha256,content=excluded.content",
            params![
                project_id,
                binary_digest,
                worker_key,
                revision as i64,
                sha256(content),
                content
            ],
        )
        .map_err(internal)?;
    Ok(())
}

fn ghidra_snapshot_artifact(bytes: &[u8], selector_json: &str) -> Result<Vec<u8>, String> {
    let selector: GhidraSnapshotArtifactSelector = serde_json::from_str(selector_json)
        .map_err(|error| format!("invalid Ghidra artifact selector: {error}"))?;
    ghidra_snapshot_artifact_media_type(&selector.stage)
        .ok_or_else(|| "unsupported Ghidra artifact stage".to_owned())?;
    validate_ghidra_start_address(&selector.stage, &selector.start_address)?;
    let slice_target = validate_ghidra_slice_target(
        &selector.stage,
        selector.instruction_index,
        selector.operation_index,
        selector.input_index,
    )?;
    let snapshot = parse_ghidra_snapshot(bytes, &selector.binary_sha256)?;
    let raw = snapshot.pcode_function_ir()?;
    let content = match selector.stage.as_str() {
        "snapshot" => serde_json::to_vec(&snapshot),
        "pcode" => serde_json::to_vec(&raw),
        "semantics" => serde_json::to_vec(&raw.lower_semantics()),
        "state" => serde_json::to_vec(&raw.lower_state()),
        "cfg" => serde_json::to_vec(&snapshot.pcode_cfg_ir()?),
        "coverage" => serde_json::to_vec(&snapshot.pcode_coverage_report()?),
        "slice" => serde_json::to_vec(
            &snapshot
                .backward_pcode_slice(slice_target.expect("slice selector validated above"))?,
        ),
        "llvm-cfg" => {
            let start = (!selector.start_address.is_empty()).then(|| PcodeAddress {
                space: snapshot.selected_function.entry.space.clone(),
                offset: selector.start_address,
            });
            serde_json::to_vec(&hydir_decompile::emit_pcode_cfg_llvm(
                &snapshot,
                start.as_ref(),
            )?)
        }
        _ => unreachable!("stage was checked above"),
    };
    content.map_err(|error| error.to_string())
}

fn native_artifact_media_type(stage: &str) -> Option<&'static str> {
    match stage {
        "program_spec" => Some("application/vnd.hydir.program-spec+json;version=5"),
        "function_index" => Some("application/vnd.hydir.function-index+json;version=1"),
        "coverage" => Some("application/vnd.hydir.coverage+json;version=1"),
        "machine" => Some("application/vnd.hydir.machine-ir+json;version=1"),
        "state" => Some("application/vnd.hydir.state-ir+json;version=1"),
        "function" => Some("application/vnd.hydir.function-ir+json;version=1"),
        "cir" => Some("application/vnd.hydir.cir+json;version=1"),
        "llvm" => Some("text/x-llvm-ir"),
        "unit" => Some("application/vnd.hydir.decompilation-unit+json;version=2"),
        "analysis_model" => Some("application/vnd.hydir.analysis-model+json;version=1"),
        "high_level_cir" => Some("application/vnd.hydir.high-level-cir+json;version=1"),
        "high_level_cfg_cir" => Some("application/vnd.hydir.high-level-cfg-cir+json;version=3"),
        "typed_c" => Some("text/x-c;view=typed"),
        _ => None,
    }
}

fn automatic_analysis_model(bytes: &[u8]) -> Result<hydir_model::AnalysisModel, String> {
    let mut model = init_model(bytes)?;
    import_dwarf(bytes, &mut model)?;
    let index = discover_functions(bytes)?;
    let native = index
        .functions
        .iter()
        .take(256)
        .filter_map(|row| decompile_indexed_function(bytes, &index, &row.id).ok())
        .collect::<Vec<_>>();
    let inputs = native
        .iter()
        .map(|unit| (&unit.machine_ir, &unit.function_ir))
        .collect::<Vec<_>>();
    infer_model(&mut model, &inputs)?;
    Ok(model)
}

fn native_function_entry(bytes: &[u8], selector: &str) -> Result<Location, String> {
    if selector.is_empty() {
        return Err("function-scoped native artifact requires a function selector".to_owned());
    }
    let index = discover_functions(bytes)?;
    let mut matches = index
        .functions
        .iter()
        .filter(|function| function.id == selector || function.name.as_deref() == Some(selector));
    let function = matches
        .next()
        .ok_or_else(|| format!("native function selector {selector:?} was not discovered"))?;
    let entry = function.entry;
    if matches.next().is_some() {
        return Err(format!(
            "native function selector {selector:?} is ambiguous; use the FunctionIndex id"
        ));
    }
    Ok(entry)
}

fn native_artifact(bytes: &[u8], selector_json: &str) -> Result<Vec<u8>, String> {
    let selector: NativeArtifactSelector = serde_json::from_str(selector_json)
        .map_err(|error| format!("invalid selector: {error}"))?;
    if selector.stage.len() > 32
        || selector.stage.chars().any(char::is_control)
        || selector.function.len() > 256
        || selector.function.chars().any(char::is_control)
    {
        return Err("native artifact selector fields exceed their bounds".to_owned());
    }
    native_artifact_media_type(&selector.stage)
        .ok_or_else(|| format!("unsupported native artifact stage {:?}", selector.stage))?;
    match selector.stage.as_str() {
        "program_spec" => {
            serde_json::to_vec(&hydir_loader::import_elf(bytes).map_err(|error| error.to_string())?)
                .map_err(|error| error.to_string())
        }
        "function_index" => {
            serde_json::to_vec(&discover_functions(bytes)?).map_err(|error| error.to_string())
        }
        "coverage" => {
            serde_json::to_vec(&measure_native_coverage(bytes)?).map_err(|error| error.to_string())
        }
        "analysis_model" => {
            let model = automatic_analysis_model(bytes)?;
            serde_json::to_vec(&model).map_err(|error| error.to_string())
        }
        stage => {
            let entry = native_function_entry(bytes, &selector.function)?;
            if stage == "unit" {
                return serde_json::to_vec(&decompile_function_unit_at(bytes, entry)?)
                    .map_err(|error| error.to_string());
            }
            let machine = lift_machine_function_at(bytes, entry)?;
            if stage == "machine" {
                return serde_json::to_vec(&machine).map_err(|error| error.to_string());
            }
            let state = lower_state_ir(&machine)?;
            if stage == "state" {
                return serde_json::to_vec(&state).map_err(|error| error.to_string());
            }
            let function = lower_function_ir(&machine, &state)?;
            if stage == "function" {
                return serde_json::to_vec(&function).map_err(|error| error.to_string());
            }
            if matches!(stage, "high_level_cir" | "high_level_cfg_cir" | "typed_c") {
                let model = automatic_analysis_model(bytes)?;
                if stage == "high_level_cfg_cir" {
                    let high = lower_high_level_cfg_cir(&machine, &function, &model)?;
                    return serde_json::to_vec(&high).map_err(|error| error.to_string());
                }
                return match lower_high_level_cir(&machine, &function, &model) {
                    Ok(high) if stage == "typed_c" => {
                        emit_typed_c(&high, &model).map(String::into_bytes)
                    }
                    Ok(high) => serde_json::to_vec(&high).map_err(|error| error.to_string()),
                    Err(_) if stage == "typed_c" => {
                        let high = lower_high_level_cfg_cir(&machine, &function, &model)?;
                        emit_typed_cfg_c(&high, &model).map(String::into_bytes)
                    }
                    Err(error) => Err(error),
                };
            }
            if stage == "llvm" {
                return export_function_ir_llvm(&function).map(String::into_bytes);
            }
            let cir = lower_cir(&machine, &function)?;
            serde_json::to_vec(&cir).map_err(|error| error.to_string())
        }
    }
}

fn native_analysis_bundle(bytes: &[u8]) -> Result<Vec<u8>, String> {
    let program_spec = hydir_loader::import_elf(bytes).map_err(|error| error.to_string())?;
    let function_index = discover_functions(bytes)?;
    let coverage = measure_native_coverage(bytes)?;
    serde_json::to_vec(&json!({
        "schema_version": 1,
        "binary_sha256": program_spec.binary_sha256,
        "program_spec": program_spec,
        "function_index": function_index,
        "coverage": coverage,
    }))
    .map_err(|error| error.to_string())
}

fn worker_operation(action: &str, symbol: Option<&str>, bytes: &[u8]) -> Result<Vec<u8>, String> {
    match (action, symbol) {
        ("native-analysis", None) => native_analysis_bundle(bytes),
        ("native-artifact", Some(selector)) => native_artifact(bytes, selector),
        ("ghidra-snapshot-artifact", Some(selector)) => ghidra_snapshot_artifact(bytes, selector),
        ("inspect", None) => import_elf(bytes)
            .map_err(|error| error.to_string())
            .and_then(|spec| serde_json::to_vec(&spec).map_err(|error| error.to_string())),
        ("analyze", None) => analyze_elf(bytes)
            .map_err(|error| error.to_string())
            .and_then(|report| serde_json::to_vec(&report).map_err(|error| error.to_string())),
        ("analyze-spec", None) => analyze_spec_elf(bytes)
            .map_err(|error| error.to_string())
            .and_then(|spec| serde_json::to_vec(&spec).map_err(|error| error.to_string())),
        ("cfg", Some(symbol)) => recover_symbol_cfg(bytes, symbol)
            .map_err(|error| error.to_string())
            .and_then(|cfg| serde_json::to_vec(&cfg).map_err(|error| error.to_string())),
        ("region", Some(symbol)) => region_contract(bytes, symbol)
            .map_err(|error| error.to_string())
            .and_then(|region| serde_json::to_vec(&region).map_err(|error| error.to_string())),
        ("physical-region-ir", Some(symbol)) => {
            let region = region_contract(bytes, symbol).map_err(|error| error.to_string())?;
            let ir = lift_physical_region(&region).map_err(|error| error.to_string())?;
            serde_json::to_vec(&ir).map_err(|error| error.to_string())
        }
        ("lift", Some(symbol)) => lift_symbol(bytes, symbol)
            .map(String::into_bytes)
            .map_err(|error| error.to_string()),
        ("decompile", Some(symbol)) => lift_symbol(bytes, symbol)
            .map_err(|error| error.to_string())
            .and_then(|ir| emit_structured_c(&ir))
            .map(String::into_bytes),
        ("decompile-unit", Some(symbol)) => {
            let region = region_contract(bytes, symbol).map_err(|error| error.to_string())?;
            let ir = lift_symbol(bytes, symbol).map_err(|error| error.to_string())?;
            let unit =
                build_decompilation_unit(region, ir, concat!("hydir/", env!("CARGO_PKG_VERSION")))?;
            serde_json::to_vec(&unit).map_err(|error| error.to_string())
        }
        ("transform", Some(symbol)) => {
            let pass_length = *bytes.first().ok_or("transform worker lacks pass list")? as usize;
            let pass_bytes = bytes
                .get(1..1 + pass_length)
                .ok_or("transform worker pass list is truncated")?;
            let passes =
                std::str::from_utf8(pass_bytes).map_err(|_| "transform pass list is not UTF-8")?;
            parse_passes(passes)?;
            let binary = bytes
                .get(1 + pass_length..)
                .ok_or("transform worker lacks binary")?;
            let raw_ir = lift_symbol(binary, symbol).map_err(|error| error.to_string())?;
            let result = transform(&raw_ir, passes, Path::new("/usr/bin/opt-14"))?;
            let report = json!({
                "scope": "trusted function fixture; LLVM verification only, not behavioral equivalence",
                "binary_sha256": sha256(binary),
                "function": symbol,
                "prototype_assertion": "u64(u64,u64) System V AMD64",
                "pipeline": result.pipeline,
                "llvm_version": result.llvm_version,
                "raw_ir_sha256": sha256(&result.raw),
                "before_ir_sha256": sha256(&result.before),
                "after_ir_sha256": sha256(&result.after),
                "ir_text_changed": result.before != result.after,
                "llvm_verified": true,
            });
            let report = serde_json::to_vec_pretty(&report).map_err(|error| error.to_string())?;
            pack_worker_parts(&[&result.raw, &result.before, &result.after, &report])
        }
        ("rebuild", None) => {
            let result = rebuild_bytes(
                bytes,
                Path::new("/usr/bin/clang-14"),
                Path::new("/usr/bin/opt-14"),
            )
            .map_err(|error| error.to_string())?;
            pack_worker_parts(&[&result.ir, &result.executable, &result.report_json])
        }
        ("patch", None) => {
            let length_bytes: [u8; 4] = bytes
                .get(..4)
                .ok_or("patch worker input lacks a length prefix")?
                .try_into()
                .map_err(|_| "invalid patch length prefix")?;
            let patch_length = u32::from_le_bytes(length_bytes) as usize;
            if patch_length == 0 || patch_length > MAX_PATCH_BYTES {
                return Err("patch document exceeds worker limit".to_owned());
            }
            let end = 4usize
                .checked_add(patch_length)
                .ok_or("patch envelope length overflow")?;
            let patch_json = bytes.get(4..end).ok_or("patch envelope is truncated")?;
            let binary = bytes.get(end..).ok_or("patch envelope lacks binary")?;
            let patch = parse_patch_json(patch_json)?;
            patch_binary(binary, &patch).map(|result| result.content)
        }
        ("patch-v2", None) => {
            let length_bytes: [u8; 4] = bytes
                .get(..4)
                .ok_or("patch worker input lacks a length prefix")?
                .try_into()
                .map_err(|_| "invalid patch length prefix")?;
            let patch_length = u32::from_le_bytes(length_bytes) as usize;
            if patch_length == 0 || patch_length > MAX_PATCH_BYTES {
                return Err("patch document exceeds worker limit".to_owned());
            }
            let end = 4usize
                .checked_add(patch_length)
                .ok_or("patch envelope length overflow")?;
            let patch_json = bytes.get(4..end).ok_or("patch envelope is truncated")?;
            let binary = bytes.get(end..).ok_or("patch envelope lacks binary")?;
            let (document, _) = parse_patch_document(patch_json)?;
            let result = compile_patch_binary(binary, &document)?;
            let bundle = serde_json::to_vec(&result.bundle).map_err(|error| error.to_string())?;
            pack_worker_parts(&[&result.content, &bundle])
        }
        _ => Err("unsupported worker operation".to_owned()),
    }
}

#[cfg(test)]
async fn run_worker(action: &str, symbol: Option<&str>, bytes: Vec<u8>) -> Result<Vec<u8>, Status> {
    if let Some(symbol) = symbol {
        valid_worker_argument(action, symbol)?;
    }
    let output = worker_operation(action, symbol, &bytes).map_err(|error| {
        Status::invalid_argument(format!("analysis worker rejected input: {error}"))
    })?;
    if output.len() > MAX_WORKER_OUTPUT {
        return Err(Status::resource_exhausted("worker output exceeds 16 MiB"));
    }
    Ok(output)
}

#[cfg(not(test))]
async fn run_worker(action: &str, symbol: Option<&str>, bytes: Vec<u8>) -> Result<Vec<u8>, Status> {
    let executable =
        env::current_exe().map_err(|_| Status::internal("worker executable unavailable"))?;
    if let Some(symbol) = symbol {
        valid_worker_argument(action, symbol)?;
    }
    let isolation = env::var("HYDIR_WORKER_ISOLATION").unwrap_or_else(|_| "process".to_owned());
    let bubblewrap = env::var_os("HYDIR_BWRAP_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/usr/bin/bwrap"));
    let launch = worker_launch_spec(&executable, action, symbol, &isolation, Some(&bubblewrap))
        .map_err(Status::failed_precondition)?;
    let mut command = Command::new(launch.program);
    command.args(launch.arguments).env_clear();
    #[cfg(target_os = "linux")]
    // SAFETY: the closure runs after fork and before exec, uses only libc's
    // async-signal-safe setrlimit calls, and captures no process state.
    unsafe {
        command.pre_exec(|| {
            if libc::setpgid(0, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            for (resource, value) in [
                (libc::RLIMIT_AS, 2 * 1024 * 1024 * 1024),
                (libc::RLIMIT_CPU, 25),
                (libc::RLIMIT_FSIZE, 16 * 1024 * 1024),
                (libc::RLIMIT_NOFILE, 64),
                (libc::RLIMIT_NPROC, 32),
                (libc::RLIMIT_STACK, 16 * 1024 * 1024),
                (libc::RLIMIT_CORE, 0),
            ] {
                let limit = libc::rlimit {
                    rlim_cur: value,
                    rlim_max: value,
                };
                if libc::setrlimit(resource, &limit) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
                || libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) != 0
            {
                return Err(std::io::Error::last_os_error());
            }
            libc::umask(0o077);
            Ok(())
        });
    }
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .map_err(|_| Status::internal("analysis worker could not start"))?;
    #[cfg(target_os = "linux")]
    let mut process_group = WorkerProcessGroup {
        pid: i32::try_from(
            child
                .id()
                .ok_or_else(|| Status::internal("worker PID unavailable"))?,
        )
        .map_err(|_| Status::internal("worker PID overflow"))?,
    };
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| Status::internal("worker stdin unavailable"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| Status::internal("worker stdout unavailable"))?;
    let writer = tokio::spawn(async move { stdin.write_all(&bytes).await });
    let mut output = Vec::new();
    let result = tokio::time::timeout(WORKER_DEADLINE, async {
        stdout
            .take((MAX_WORKER_OUTPUT + 1) as u64)
            .read_to_end(&mut output)
            .await
            .map_err(|_| Status::internal("worker output read failed"))?;
        if output.len() > MAX_WORKER_OUTPUT {
            return Err(Status::resource_exhausted("worker output exceeds 16 MiB"));
        }
        let status = child
            .wait()
            .await
            .map_err(|_| Status::internal("worker wait failed"))?;
        if !status.success() {
            let diagnostic = String::from_utf8_lossy(&output[..output.len().min(4096)]);
            return Err(Status::invalid_argument(format!(
                "analysis worker rejected input (exit {status}): {}",
                diagnostic.trim()
            )));
        }
        Ok(output)
    })
    .await;
    writer.abort();
    match result {
        Ok(Ok(output)) => {
            #[cfg(target_os = "linux")]
            process_group.disarm();
            Ok(output)
        }
        Ok(Err(error)) => Err(error),
        Err(_) => Err(Status::deadline_exceeded(
            "analysis worker exceeded 30-second deadline",
        )),
    }
}

fn worker_main(arguments: &[String]) -> Result<(), Box<dyn Error>> {
    let mut bytes = Vec::new();
    std::io::stdin()
        .take((MAX_BINARY_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.is_empty() || bytes.len() > MAX_BINARY_BYTES {
        return Err("worker input must be 1..=64 MiB".into());
    }
    let result = match arguments {
        [action] => worker_operation(action, None, &bytes),
        [action, symbol] => worker_operation(action, Some(symbol), &bytes),
        _ => Err("unsupported worker operation".to_owned()),
    };
    match result {
        Ok(output) if output.len() <= MAX_WORKER_OUTPUT => std::io::stdout().write_all(&output)?,
        Ok(_) => {
            std::io::stdout().write_all(b"worker output exceeds 16 MiB")?;
            std::process::exit(1);
        }
        Err(error) => {
            std::io::stdout().write_all(error.as_bytes())?;
            std::process::exit(1);
        }
    }
    Ok(())
}

#[tonic::async_trait]
impl Hydir for Store {
    async fn discover(
        &self,
        request: Request<DiscoverRequest>,
    ) -> Result<Response<DiscoverReply>, Status> {
        self.principal(&request)?;
        Ok(Response::new(DiscoverReply {
            api_version: 1,
            hydir_version: env!("CARGO_PKG_VERSION").to_owned(),
            license: "AGPL-3.0-only".to_owned(),
            source_status: if SOURCE_ARCHIVE.is_empty() {
                "No matching source archive embedded in this development build".to_owned()
            } else {
                format!(
                    "Matching committed source archive available via GetSource for revision {SOURCE_REVISION}"
                )
            },
            native_elf_import: true,
            scalar_direct_cfg_lift: true,
            execution_validation: false,
            max_binary_bytes: MAX_BINARY_BYTES as u64,
            durable_lift_jobs: true,
            reconnectable_job_events: true,
            job_cancellation: true,
            conservative_global_effect_analysis: true,
            scalar_c_output: true,
            source_revision: SOURCE_REVISION.to_owned(),
            source_sha256: if SOURCE_ARCHIVE.is_empty() {
                String::new()
            } else {
                sha256(SOURCE_ARCHIVE)
            },
            named_pass_transform: cfg!(all(target_os = "linux", target_arch = "x86_64"))
                && Path::new("/usr/bin/opt-14").is_file(),
            scalar_patch_v1: true,
            whole_rebuild: cfg!(all(target_os = "linux", target_arch = "x86_64"))
                && Path::new("/usr/bin/opt-14").is_file()
                && Path::new("/usr/bin/clang-14").is_file(),
            analyzed_program_spec: true,
            revisioned_annotations: true,
        }))
    }

    async fn get_source(
        &self,
        request: Request<SourceRequest>,
    ) -> Result<Response<SourceReply>, Status> {
        self.principal(&request)?;
        if SOURCE_ARCHIVE.is_empty() {
            return Err(Status::unavailable(
                "this development build has no embedded source archive",
            ));
        }
        Ok(Response::new(SourceReply {
            revision: SOURCE_REVISION.to_owned(),
            sha256: sha256(SOURCE_ARCHIVE),
            content: SOURCE_ARCHIVE.to_vec(),
        }))
    }

    async fn create_project(
        &self,
        request: Request<CreateProjectRequest>,
    ) -> Result<Response<ProjectReply>, Status> {
        let principal = self.principal(&request)?;
        let input = request.into_inner();
        if input.name.is_empty()
            || input.name.len() > 128
            || input.name.chars().any(char::is_control)
        {
            return Err(Status::invalid_argument(
                "project name must be 1..=128 non-control characters",
            ));
        }
        if input.idempotency_key.is_empty() || input.idempotency_key.len() > 128 {
            return Err(Status::invalid_argument(
                "idempotency key must be 1..=128 bytes",
            ));
        }
        let id = {
            let mut conn = self.connection()?;
            let transaction = conn.transaction().map_err(internal)?;
            let prior: Option<String> = transaction
                .query_row(
                    "SELECT id FROM projects WHERE owner=?1 AND idempotency_key=?2",
                    params![principal, input.idempotency_key],
                    |row| row.get(0),
                )
                .optional()
                .map_err(internal)?;
            let id = if let Some(id) = prior {
                id
            } else {
                let id = Uuid::new_v4().to_string();
                transaction
                    .execute(
                        "INSERT INTO projects(id,owner,name,idempotency_key) VALUES(?1,?2,?3,?4)",
                        params![id, principal, input.name, input.idempotency_key],
                    )
                    .map_err(internal)?;
                transaction
                    .execute(
                        "INSERT INTO project_acls(project_id,principal,role,granted_by) VALUES(?1,?2,'admin',?2)",
                        params![id, principal],
                    )
                    .map_err(internal)?;
                transaction
                    .execute(
                        "INSERT INTO audit_events(principal,action,project_id,details_json) VALUES(?1,'project.create',?2,?3)",
                        params![principal, id, serde_json::to_string(&json!({"name": input.name})).map_err(|error| Status::internal(format!("audit serialization failed: {error}")))?],
                    )
                    .map_err(internal)?;
                id
            };
            transaction.commit().map_err(internal)?;
            id
        };
        Ok(Response::new(self.project(&principal, &id)?))
    }

    async fn get_project(
        &self,
        request: Request<ProjectRequest>,
    ) -> Result<Response<ProjectReply>, Status> {
        let principal = self.principal(&request)?;
        Ok(Response::new(
            self.project(&principal, &request.get_ref().project_id)?,
        ))
    }

    async fn upload_binary(
        &self,
        request: Request<UploadBinaryRequest>,
    ) -> Result<Response<ProjectReply>, Status> {
        let principal = self.principal(&request)?;
        let input = request.into_inner();
        self.require_project_role(&principal, &input.project_id, ProjectRole::Operator)?;
        if input.content.is_empty() || input.content.len() > MAX_BINARY_BYTES {
            return Err(Status::invalid_argument("binary must be 1..=64 MiB"));
        }
        let digest = sha256(&input.content);
        if digest != input.content_sha256 {
            return Err(Status::invalid_argument(
                "binary SHA-256 does not match upload",
            ));
        }
        run_worker("inspect", None, input.content.clone()).await?;
        let staged_binary = self.content_storage.stage(&input.content).await?;
        let expected = i64::try_from(input.expected_revision)
            .map_err(|_| Status::invalid_argument("revision too large"))?;
        {
            let mut conn = self.connection()?;
            let tx = conn.transaction().map_err(internal)?;
            require_project_role_in(&tx, &principal, &input.project_id, ProjectRole::Operator)?;
            let current: Option<i64> = tx
                .query_row(
                    "SELECT current_revision FROM projects WHERE id=?1",
                    params![input.project_id],
                    |row| row.get(0),
                )
                .optional()
                .map_err(internal)?;
            let current = current.ok_or_else(|| Status::not_found("project not found"))?;
            if current != expected {
                let previous_retry: Option<String> = tx.query_row(
                    "SELECT binary_sha256 FROM project_revisions WHERE project_id=?1 AND revision=?2",
                    params![input.project_id, expected.checked_add(1).ok_or_else(|| Status::out_of_range("project revision overflow"))?],
                    |row| row.get(0),
                ).optional().map_err(internal)?;
                if current == expected + 1 && previous_retry.as_deref() == Some(digest.as_str()) {
                    drop(tx);
                    drop(conn);
                    return Ok(Response::new(self.project(&principal, &input.project_id)?));
                }
                return Err(Status::aborted("stale project revision"));
            }
            let next = current
                .checked_add(1)
                .ok_or_else(|| Status::out_of_range("project revision overflow"))?;
            insert_binary(&tx, &staged_binary)?;
            tx.execute(
                "INSERT INTO project_revisions(project_id,revision,binary_sha256) VALUES(?1,?2,?3)",
                params![input.project_id, next, digest],
            )
            .map_err(internal)?;
            tx.execute(
                "UPDATE projects SET current_revision=?1 WHERE id=?2",
                params![next, input.project_id],
            )
            .map_err(internal)?;
            tx.commit().map_err(internal)?;
        }
        Ok(Response::new(self.project(&principal, &input.project_id)?))
    }

    async fn inspect(
        &self,
        request: Request<ProjectRequest>,
    ) -> Result<Response<JsonReply>, Status> {
        let principal = self.principal(&request)?;
        let input = request.into_inner();
        self.require_project_role(&principal, &input.project_id, ProjectRole::Analyst)?;
        let bytes = self
            .current_binary(&principal, &input.project_id, input.expected_revision)
            .await?;
        let raw = run_worker("inspect", None, bytes).await?;
        let mut spec: ProgramSpec = parse_program_spec_json(&raw)
            .map_err(|_| Status::internal("worker returned invalid program model"))?;
        let annotations = annotations_for(
            &*self.connection()?,
            &input.project_id,
            input.expected_revision,
            &spec.binary_sha256,
        )?;
        overlay_analyst_assumptions(&mut spec, &annotations);
        let json = serde_json::to_string(&spec)
            .map_err(|_| Status::internal("program model serialization failed"))?;
        Ok(Response::new(JsonReply { json }))
    }

    async fn analyze(
        &self,
        request: Request<ProjectRequest>,
    ) -> Result<Response<JsonReply>, Status> {
        let principal = self.principal(&request)?;
        let input = request.into_inner();
        self.require_project_role(&principal, &input.project_id, ProjectRole::Analyst)?;
        let bytes = self
            .current_binary(&principal, &input.project_id, input.expected_revision)
            .await?;
        let report = run_worker("analyze", None, bytes).await?;
        Ok(Response::new(JsonReply {
            json: String::from_utf8(report)
                .map_err(|_| Status::internal("worker returned non-UTF-8 analysis"))?,
        }))
    }

    async fn analyze_spec(
        &self,
        request: Request<ProjectRequest>,
    ) -> Result<Response<JsonReply>, Status> {
        let principal = self.principal(&request)?;
        let input = request.into_inner();
        self.require_project_role(&principal, &input.project_id, ProjectRole::Analyst)?;
        let bytes = self
            .current_binary(&principal, &input.project_id, input.expected_revision)
            .await?;
        let raw = run_worker("analyze-spec", None, bytes).await?;
        let mut spec: ProgramSpec = parse_program_spec_json(&raw)
            .map_err(|_| Status::internal("worker returned invalid analyzed model"))?;
        let annotations = annotations_for(
            &*self.connection()?,
            &input.project_id,
            input.expected_revision,
            &spec.binary_sha256,
        )?;
        overlay_analyst_assumptions(&mut spec, &annotations);
        let json = serde_json::to_string(&spec)
            .map_err(|_| Status::internal("analyzed model serialization failed"))?;
        Ok(Response::new(JsonReply { json }))
    }

    async fn list_annotations(
        &self,
        request: Request<ProjectRequest>,
    ) -> Result<Response<JsonReply>, Status> {
        let principal = self.principal(&request)?;
        let input = request.into_inner();
        let project = self.project(&principal, &input.project_id)?;
        if project.revision != input.expected_revision {
            return Err(Status::aborted("stale project revision"));
        }
        if project.binary_sha256.is_empty() {
            return Err(Status::failed_precondition(
                "project has no uploaded binary",
            ));
        }
        let annotations = annotations_for(
            &*self.connection()?,
            &input.project_id,
            project.revision,
            &project.binary_sha256,
        )?;
        let json = serde_json::to_string(&json!({
            "schema_version": 1,
            "project_id": input.project_id,
            "revision": project.revision,
            "binary_sha256": project.binary_sha256,
            "annotations": annotations,
        }))
        .map_err(|_| Status::internal("annotation serialization failed"))?;
        Ok(Response::new(JsonReply { json }))
    }

    async fn add_annotation(
        &self,
        request: Request<AnnotationRequest>,
    ) -> Result<Response<ProjectReply>, Status> {
        let principal = self.principal(&request)?;
        let input = request.into_inner();
        self.require_project_role(&principal, &input.project_id, ProjectRole::Analyst)?;
        let (kind, address) = validate_annotation(&input)?;
        let expected = i64::try_from(input.expected_revision)
            .map_err(|_| Status::invalid_argument("revision too large"))?;
        let request_json = serde_json::to_vec(&(
            input.expected_revision,
            &input.kind,
            address.map(|address| address.0),
            &input.value,
            &input.scope,
        ))
        .map_err(|_| Status::internal("annotation request serialization failed"))?;
        let request_sha256 = sha256(&request_json);
        let project = self.project(&principal, &input.project_id)?;
        if let Some((revision, binary_sha256)) = annotation_replay(
            &*self.connection()?,
            &input.project_id,
            &input.idempotency_key,
            expected,
            &request_sha256,
        )? {
            return Ok(Response::new(ProjectReply {
                project_id: input.project_id,
                name: project.name,
                revision,
                binary_sha256,
            }));
        }
        let bytes = self
            .current_binary(&principal, &input.project_id, input.expected_revision)
            .await?;
        if let Some(address) = address {
            let raw = run_worker("inspect", None, bytes).await?;
            let spec: ProgramSpec = parse_program_spec_json(&raw)
                .map_err(|_| Status::internal("worker returned invalid program model"))?;
            if !annotation_address_in_spec(&spec, address) {
                return Err(Status::invalid_argument(
                    "annotation address is outside linked ELF load mappings",
                ));
            }
        }
        let next = expected
            .checked_add(1)
            .ok_or_else(|| Status::out_of_range("project revision overflow"))?;
        let id = Uuid::new_v4().to_string();
        let kind_label = match kind {
            AnnotationKind::Name => "name",
            AnnotationKind::Comment => "comment",
            AnnotationKind::Assumption => "assumption",
        };
        let address_label = address.map(|address| format!("0x{:016x}", address.0));
        {
            let mut conn = self.connection()?;
            let tx = conn.transaction().map_err(internal)?;
            require_project_role_in(&tx, &principal, &input.project_id, ProjectRole::Analyst)?;
            if let Some((revision, binary_sha256)) = annotation_replay(
                &tx,
                &input.project_id,
                &input.idempotency_key,
                expected,
                &request_sha256,
            )? {
                return Ok(Response::new(ProjectReply {
                    project_id: input.project_id,
                    name: project.name,
                    revision,
                    binary_sha256,
                }));
            }
            let current: i64 = tx
                .query_row(
                    "SELECT current_revision FROM projects WHERE id=?1",
                    params![input.project_id],
                    |row| row.get(0),
                )
                .map_err(internal)?;
            if current != expected {
                return Err(Status::aborted("stale project revision"));
            }
            let count: i64 = tx
                .query_row(
                    "SELECT COUNT(*) FROM analyst_annotations WHERE project_id=?1 AND binary_sha256=?2",
                    params![input.project_id, project.binary_sha256],
                    |row| row.get(0),
                )
                .map_err(internal)?;
            if count >= 512 {
                return Err(Status::resource_exhausted(
                    "project has reached 512 annotations for this binary",
                ));
            }
            tx.execute(
                "INSERT INTO project_revisions(project_id,revision,binary_sha256) VALUES(?1,?2,?3)",
                params![input.project_id, next, project.binary_sha256],
            )
            .map_err(internal)?;
            tx.execute(
                "INSERT INTO analyst_annotations(id,project_id,created_revision,binary_sha256,kind,address,value,scope) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
                params![id, input.project_id, next, project.binary_sha256, kind_label, address_label, input.value, input.scope],
            )
            .map_err(internal)?;
            tx.execute(
                "INSERT INTO annotation_requests(project_id,idempotency_key,expected_revision,request_sha256,new_revision,annotation_id) VALUES(?1,?2,?3,?4,?5,?6)",
                params![input.project_id, input.idempotency_key, expected, request_sha256, next, id],
            )
            .map_err(internal)?;
            tx.execute(
                "UPDATE projects SET current_revision=?1 WHERE id=?2",
                params![next, input.project_id],
            )
            .map_err(internal)?;
            tx.commit().map_err(internal)?;
        }
        Ok(Response::new(ProjectReply {
            project_id: input.project_id,
            name: project.name,
            revision: next as u64,
            binary_sha256: project.binary_sha256,
        }))
    }

    async fn recover_cfg(
        &self,
        request: Request<FunctionRequest>,
    ) -> Result<Response<JsonReply>, Status> {
        let principal = self.principal(&request)?;
        let input = request.into_inner();
        self.require_project_role(&principal, &input.project_id, ProjectRole::Analyst)?;
        valid_symbol(&input.function_symbol)?;
        let bytes = self
            .current_binary(&principal, &input.project_id, input.expected_revision)
            .await?;
        let cfg = run_worker("cfg", Some(&input.function_symbol), bytes).await?;
        Ok(Response::new(JsonReply {
            json: String::from_utf8(cfg)
                .map_err(|_| Status::internal("worker returned non-UTF-8 CFG"))?,
        }))
    }

    async fn lift(
        &self,
        request: Request<FunctionRequest>,
    ) -> Result<Response<ArtifactReply>, Status> {
        let principal = self.principal(&request)?;
        let input = request.into_inner();
        self.require_project_role(&principal, &input.project_id, ProjectRole::Analyst)?;
        if !input.assume_u64x2 {
            return Err(Status::invalid_argument(
                "explicit u64(u64,u64) prototype assertion required",
            ));
        }
        valid_symbol(&input.function_symbol)?;
        let bytes = self
            .current_binary(&principal, &input.project_id, input.expected_revision)
            .await?;
        let content = run_worker("lift", Some(&input.function_symbol), bytes).await?;
        let digest = self
            .store_artifact(
                &input.project_id,
                input.expected_revision,
                "text/x-llvm-ir",
                &content,
            )
            .await?;
        Ok(Response::new(ArtifactReply {
            sha256: digest,
            media_type: "text/x-llvm-ir".to_owned(),
            content,
            project_revision: input.expected_revision,
        }))
    }

    async fn decompile(
        &self,
        request: Request<FunctionRequest>,
    ) -> Result<Response<ArtifactReply>, Status> {
        let principal = self.principal(&request)?;
        let input = request.into_inner();
        self.require_project_role(&principal, &input.project_id, ProjectRole::Analyst)?;
        if !input.assume_u64x2 {
            return Err(Status::invalid_argument(
                "explicit u64(u64,u64) prototype assertion required",
            ));
        }
        valid_symbol(&input.function_symbol)?;
        let bytes = self
            .current_binary(&principal, &input.project_id, input.expected_revision)
            .await?;
        let content = run_worker("decompile", Some(&input.function_symbol), bytes).await?;
        let digest = self
            .store_artifact(
                &input.project_id,
                input.expected_revision,
                "text/x-csrc",
                &content,
            )
            .await?;
        Ok(Response::new(ArtifactReply {
            sha256: digest,
            media_type: "text/x-csrc".to_owned(),
            content,
            project_revision: input.expected_revision,
        }))
    }

    async fn transform(
        &self,
        request: Request<TransformRequest>,
    ) -> Result<Response<TransformReply>, Status> {
        let principal = self.principal(&request)?;
        let input = request.into_inner();
        self.require_project_role(&principal, &input.project_id, ProjectRole::Operator)?;
        if !input.assume_u64x2 || !input.trusted_fixture {
            return Err(Status::invalid_argument(
                "transform requires u64x2 and trusted-fixture assertions",
            ));
        }
        valid_symbol(&input.function_symbol)?;
        parse_passes(&input.passes).map_err(Status::invalid_argument)?;
        if input.idempotency_key.is_empty()
            || input.idempotency_key.len() > 128
            || input.idempotency_key.chars().any(char::is_control)
        {
            return Err(Status::invalid_argument(
                "transform idempotency key must be 1..=128 non-control bytes",
            ));
        }
        let expected = i64::try_from(input.expected_revision)
            .map_err(|_| Status::invalid_argument("revision too large"))?;
        self.project(&principal, &input.project_id)?;
        let request_sha256 =
            sha256(format!("{}\0{}", input.function_symbol, input.passes).as_bytes());
        let prior = {
            let conn = self.connection()?;
            transform_replay(
                &conn,
                &input.project_id,
                &input.idempotency_key,
                expected,
                &request_sha256,
            )?
        };
        if let Some(prior) = prior {
            return Ok(Response::new(prior));
        }
        let pass_length = u8::try_from(input.passes.len())
            .map_err(|_| Status::invalid_argument("pass list is too long"))?;
        let binary = self
            .current_binary(&principal, &input.project_id, input.expected_revision)
            .await?;
        let binary_sha256 = sha256(&binary);
        let mut envelope = Vec::with_capacity(1 + input.passes.len() + binary.len());
        envelope.push(pass_length);
        envelope.extend_from_slice(input.passes.as_bytes());
        envelope.extend_from_slice(&binary);
        let packed = run_worker("transform", Some(&input.function_symbol), envelope).await?;
        let parts = unpack_worker_parts::<4>(&packed)?;
        let report_json = String::from_utf8(parts[3].to_vec())
            .map_err(|_| Status::internal("transform report is not UTF-8"))?;
        let mut staged_parts = Vec::with_capacity(parts.len());
        for part in &parts {
            staged_parts.push(self.content_storage.stage(part).await?);
        }
        let digests = staged_parts
            .iter()
            .map(|part| part.digest.clone())
            .collect::<Vec<_>>();
        let next = expected
            .checked_add(1)
            .ok_or_else(|| Status::out_of_range("project revision overflow"))?;
        {
            let mut conn = self.connection()?;
            let tx = conn.transaction().map_err(internal)?;
            require_project_role_in(&tx, &principal, &input.project_id, ProjectRole::Operator)?;
            if let Some(prior) = transform_replay(
                &tx,
                &input.project_id,
                &input.idempotency_key,
                expected,
                &request_sha256,
            )? {
                return Ok(Response::new(prior));
            }
            let current: i64 = tx
                .query_row(
                    "SELECT current_revision FROM projects WHERE id=?1",
                    params![input.project_id],
                    |row| row.get(0),
                )
                .map_err(internal)?;
            if current != expected {
                return Err(Status::aborted("stale project revision"));
            }
            tx.execute(
                "INSERT INTO project_revisions(project_id,revision,binary_sha256) VALUES(?1,?2,?3)",
                params![input.project_id, next, binary_sha256],
            )
            .map_err(internal)?;
            tx.execute(
                "UPDATE projects SET current_revision=?1 WHERE id=?2",
                params![next, input.project_id],
            )
            .map_err(internal)?;
            for (media_type, staged) in [
                "text/x-llvm-ir",
                "text/x-llvm-ir",
                "text/x-llvm-ir",
                "application/json",
            ]
            .into_iter()
            .zip(&staged_parts)
            {
                insert_artifact(&tx, &input.project_id, next, media_type, staged)?;
            }
            tx.execute(
                "INSERT INTO transform_requests(project_id,idempotency_key,expected_revision,request_sha256,new_revision,raw_sha256,before_sha256,after_sha256,report_sha256,ir_text_changed,report_json) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
                params![input.project_id, input.idempotency_key, expected, request_sha256, next, digests[0], digests[1], digests[2], digests[3], i64::from(parts[1] != parts[2]), report_json],
            ).map_err(internal)?;
            tx.commit().map_err(internal)?;
        }
        Ok(Response::new(TransformReply {
            project_id: input.project_id,
            project_revision: next as u64,
            raw_sha256: digests[0].clone(),
            before_sha256: digests[1].clone(),
            after_sha256: digests[2].clone(),
            report_sha256: digests[3].clone(),
            ir_text_changed: parts[1] != parts[2],
            report_json,
        }))
    }

    async fn rebuild(
        &self,
        request: Request<RebuildRequest>,
    ) -> Result<Response<RebuildReply>, Status> {
        let principal = self.principal(&request)?;
        let input = request.into_inner();
        self.require_project_role(&principal, &input.project_id, ProjectRole::Operator)?;
        if !input.trusted_fixture {
            return Err(Status::invalid_argument(
                "rebuild requires an explicit trusted-fixture assertion",
            ));
        }
        if input.idempotency_key.is_empty()
            || input.idempotency_key.len() > 128
            || input.idempotency_key.chars().any(char::is_control)
        {
            return Err(Status::invalid_argument(
                "rebuild idempotency key must be 1..=128 non-control bytes",
            ));
        }
        let expected = i64::try_from(input.expected_revision)
            .map_err(|_| Status::invalid_argument("revision too large"))?;
        self.project(&principal, &input.project_id)?;
        let prior = {
            let conn = self.connection()?;
            rebuild_replay(&conn, &input.project_id, &input.idempotency_key, expected)?
        };
        if let Some(prior) = prior {
            return Ok(Response::new(prior));
        }
        let binary = self
            .current_binary(&principal, &input.project_id, input.expected_revision)
            .await?;
        let packed = run_worker("rebuild", None, binary).await?;
        let parts = unpack_worker_parts::<3>(&packed)?;
        run_worker("inspect", None, parts[1].to_vec()).await?;
        let report_json = String::from_utf8(parts[2].to_vec())
            .map_err(|_| Status::internal("rebuild report is not UTF-8"))?;
        let staged_ir = self.content_storage.stage(parts[0]).await?;
        let staged_binary = self.content_storage.stage(parts[1]).await?;
        let staged_report = self.content_storage.stage(parts[2]).await?;
        let ir_sha256 = staged_ir.digest.clone();
        let binary_sha256 = staged_binary.digest.clone();
        let report_sha256 = staged_report.digest.clone();
        let next = expected
            .checked_add(1)
            .ok_or_else(|| Status::out_of_range("project revision overflow"))?;
        {
            let mut conn = self.connection()?;
            let tx = conn.transaction().map_err(internal)?;
            require_project_role_in(&tx, &principal, &input.project_id, ProjectRole::Operator)?;
            if let Some(prior) =
                rebuild_replay(&tx, &input.project_id, &input.idempotency_key, expected)?
            {
                return Ok(Response::new(prior));
            }
            let current: i64 = tx
                .query_row(
                    "SELECT current_revision FROM projects WHERE id=?1",
                    params![input.project_id],
                    |row| row.get(0),
                )
                .map_err(internal)?;
            if current != expected {
                return Err(Status::aborted("stale project revision"));
            }
            insert_binary(&tx, &staged_binary)?;
            tx.execute(
                "INSERT INTO project_revisions(project_id,revision,binary_sha256) VALUES(?1,?2,?3)",
                params![input.project_id, next, binary_sha256],
            )
            .map_err(internal)?;
            tx.execute(
                "UPDATE projects SET current_revision=?1 WHERE id=?2",
                params![next, input.project_id],
            )
            .map_err(internal)?;
            for (media_type, staged) in [
                ("text/x-llvm-ir", &staged_ir),
                ("application/x-elf", &staged_binary),
                ("application/json", &staged_report),
            ] {
                insert_artifact(&tx, &input.project_id, next, media_type, staged)?;
            }
            tx.execute(
                "INSERT INTO rebuild_requests(project_id,idempotency_key,expected_revision,new_revision,binary_sha256,ir_sha256,report_sha256,report_json) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
                params![input.project_id, input.idempotency_key, expected, next, binary_sha256, ir_sha256, report_sha256, report_json],
            )
            .map_err(internal)?;
            tx.commit().map_err(internal)?;
        }
        Ok(Response::new(RebuildReply {
            project_id: input.project_id,
            revision: next as u64,
            binary_sha256,
            ir_sha256,
            report_sha256,
            report_json,
        }))
    }

    async fn apply_patch(
        &self,
        request: Request<PatchRequest>,
    ) -> Result<Response<PatchReply>, Status> {
        let principal = self.principal(&request)?;
        let input = request.into_inner();
        self.require_project_role(&principal, &input.project_id, ProjectRole::Operator)?;
        if !input.trusted_fixture || !input.assume_u64x2 || !input.assume_entry_only {
            return Err(Status::invalid_argument(
                "patch requires trusted-fixture, u64x2, and entry-only assertions",
            ));
        }
        if input.patch_json.is_empty() || input.patch_json.len() > MAX_PATCH_BYTES {
            return Err(Status::invalid_argument(
                "patch document must be 1..=4096 bytes",
            ));
        }
        if input.idempotency_key.is_empty()
            || input.idempotency_key.len() > 128
            || input.idempotency_key.chars().any(char::is_control)
        {
            return Err(Status::invalid_argument(
                "patch idempotency key must be 1..=128 non-control bytes",
            ));
        }
        let expected = i64::try_from(input.expected_revision)
            .map_err(|_| Status::invalid_argument("revision too large"))?;
        self.project(&principal, &input.project_id)?;
        let patch_digest = sha256(&input.patch_json);
        let prior: Option<(i64, String, i64, String)> = self
            .connection()?
            .query_row(
                "SELECT expected_revision,patch_sha256,new_revision,binary_sha256 FROM patch_requests WHERE project_id=?1 AND idempotency_key=?2",
                params![input.project_id, input.idempotency_key],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()
            .map_err(internal)?;
        if let Some((prior_expected, prior_digest, revision, binary_sha256)) = prior {
            if prior_expected != expected || prior_digest != patch_digest {
                return Err(Status::already_exists(
                    "idempotency key belongs to a different patch request",
                ));
            }
            return Ok(Response::new(PatchReply {
                project_id: input.project_id,
                revision: revision as u64,
                artifact_sha256: binary_sha256.clone(),
                binary_sha256,
            }));
        }
        let binary = self
            .current_binary(&principal, &input.project_id, input.expected_revision)
            .await?;
        if binary.len() > MAX_WORKER_OUTPUT {
            return Err(Status::resource_exhausted(
                "remote patch binary exceeds 16 MiB worker output limit",
            ));
        }
        let patch_length = u32::try_from(input.patch_json.len())
            .map_err(|_| Status::invalid_argument("patch document too long"))?;
        let mut envelope = Vec::with_capacity(4 + input.patch_json.len() + binary.len());
        envelope.extend_from_slice(&patch_length.to_le_bytes());
        envelope.extend_from_slice(&input.patch_json);
        envelope.extend_from_slice(&binary);
        let patched = run_worker("patch", None, envelope).await?;
        if patched.len() != binary.len() {
            return Err(Status::internal("patch worker changed ELF file size"));
        }
        Ok(Response::new(
            self.commit_patch_mutation(
                &principal,
                &input.project_id,
                input.expected_revision,
                &input.idempotency_key,
                &patch_digest,
                patched,
            )
            .await?,
        ))
    }

    async fn get_artifact(
        &self,
        request: Request<ArtifactRequest>,
    ) -> Result<Response<ArtifactReply>, Status> {
        let principal = self.principal(&request)?;
        let input = request.into_inner();
        self.require_project_role(&principal, &input.project_id, ProjectRole::Viewer)?;
        if input.sha256.len() != 64 || !input.sha256.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(Status::invalid_argument(
                "artifact digest must be SHA-256 hex",
            ));
        }
        let record: Option<(i64, String, Vec<u8>, String, String, i64)> = self
            .connection()?
            .query_row(
                "SELECT a.revision,a.media_type,a.content,a.storage_kind,a.storage_key,a.content_size FROM artifacts a \
             WHERE a.project_id=?1 AND a.sha256=?2 \
             ORDER BY a.revision DESC LIMIT 1",
                params![input.project_id, input.sha256],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?)),
            )
            .optional()
            .map_err(internal)?;
        let (revision, media_type, inline, storage_kind, storage_key, content_size) =
            record.ok_or_else(|| Status::not_found("artifact not found"))?;
        let content = self
            .content_storage
            .load(
                &input.sha256,
                inline,
                &storage_kind,
                &storage_key,
                content_size,
            )
            .await?;
        Ok(Response::new(ArtifactReply {
            sha256: input.sha256,
            media_type,
            content,
            project_revision: revision as u64,
        }))
    }

    async fn start_lift_job(
        &self,
        request: Request<StartLiftJobRequest>,
    ) -> Result<Response<JobReply>, Status> {
        let principal = self.principal(&request)?;
        let input = request.into_inner();
        self.require_project_role(&principal, &input.project_id, ProjectRole::Analyst)?;
        valid_symbol(&input.function_symbol)?;
        if !input.assume_u64x2 {
            return Err(Status::invalid_argument(
                "explicit u64(u64,u64) prototype assertion required",
            ));
        }
        if input.idempotency_key.is_empty()
            || input.idempotency_key.len() > 128
            || input.idempotency_key.chars().any(char::is_control)
        {
            return Err(Status::invalid_argument(
                "job idempotency key must be 1..=128 non-control bytes",
            ));
        }
        let expected = i64::try_from(input.expected_revision)
            .map_err(|_| Status::invalid_argument("revision too large"))?;
        self.project(&principal, &input.project_id)?;
        let prior: Option<(String, i64, String)> = self
            .connection()?
            .query_row(
                "SELECT id,revision,symbol FROM jobs WHERE project_id=?1 AND idempotency_key=?2",
                params![input.project_id, input.idempotency_key],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(internal)?;
        if let Some((id, revision, symbol)) = prior {
            if revision != expected || symbol != input.function_symbol {
                return Err(Status::already_exists(
                    "idempotency key belongs to a different lift request",
                ));
            }
            return Ok(Response::new(self.job(
                &principal,
                &input.project_id,
                &id,
            )?));
        }
        let bytes = self
            .current_binary(&principal, &input.project_id, input.expected_revision)
            .await?;
        let id = Uuid::new_v4().to_string();
        {
            let mut conn = self.connection()?;
            let tx = conn.transaction().map_err(internal)?;
            require_project_role_in(&tx, &principal, &input.project_id, ProjectRole::Analyst)?;
            let retry: Option<(String, i64, String)> = tx.query_row(
                "SELECT id,revision,symbol FROM jobs WHERE project_id=?1 AND idempotency_key=?2",
                params![input.project_id, input.idempotency_key],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            ).optional().map_err(internal)?;
            if let Some((existing, revision, symbol)) = retry {
                drop(tx);
                drop(conn);
                if revision != expected || symbol != input.function_symbol {
                    return Err(Status::already_exists(
                        "idempotency key belongs to a different lift request",
                    ));
                }
                return Ok(Response::new(self.job(
                    &principal,
                    &input.project_id,
                    &existing,
                )?));
            }
            let current: i64 = tx
                .query_row(
                    "SELECT current_revision FROM projects WHERE id=?1",
                    params![input.project_id],
                    |row| row.get(0),
                )
                .map_err(internal)?;
            if current != expected {
                return Err(Status::aborted("stale project revision"));
            }
            let active: i64 = tx
                .query_row(
                    "SELECT COUNT(*) FROM jobs \
                 WHERE requested_by=?1 AND state IN ('queued','running')",
                    [principal.as_str()],
                    |row| row.get(0),
                )
                .map_err(internal)?;
            if active >= MAX_ACTIVE_JOBS_PER_IDENTITY {
                return Err(Status::resource_exhausted("identity has two active jobs"));
            }
            tx.execute(
                "INSERT INTO jobs(id,project_id,revision,kind,symbol,idempotency_key,state,requested_by) \
                 VALUES(?1,?2,?3,'lift',?4,?5,'queued',?6)",
                params![
                    id,
                    input.project_id,
                    expected,
                    input.function_symbol,
                    input.idempotency_key,
                    principal
                ],
            )
            .map_err(internal)?;
            insert_event(&tx, &id, "queued", "lift queued", "")?;
            tx.commit().map_err(internal)?;
        }
        let (start_sender, start_receiver) = oneshot::channel();
        let runner = self.clone();
        let runner_id = id.clone();
        let project_id = input.project_id.clone();
        let symbol = input.function_symbol.clone();
        let handle = tokio::spawn(async move {
            if start_receiver.await.is_ok() {
                runner
                    .execute_lift_job(
                        runner_id,
                        project_id,
                        input.expected_revision,
                        symbol,
                        bytes,
                    )
                    .await;
            }
        });
        self.workers
            .lock()
            .map_err(|_| Status::internal("worker registry lock poisoned"))?
            .insert(id.clone(), handle);
        let _ = start_sender.send(());
        Ok(Response::new(self.job(
            &principal,
            &input.project_id,
            &id,
        )?))
    }

    async fn get_job(&self, request: Request<JobRequest>) -> Result<Response<JobReply>, Status> {
        let principal = self.principal(&request)?;
        let input = request.into_inner();
        Ok(Response::new(self.job(
            &principal,
            &input.project_id,
            &input.job_id,
        )?))
    }

    async fn cancel_job(&self, request: Request<JobRequest>) -> Result<Response<JobReply>, Status> {
        let principal = self.principal(&request)?;
        let input = request.into_inner();
        let role =
            self.require_project_role(&principal, &input.project_id, ProjectRole::Analyst)?;
        self.job(&principal, &input.project_id, &input.job_id)?;
        let requested_by: Option<String> = self
            .connection()?
            .query_row(
                "SELECT requested_by FROM jobs WHERE id=?1 AND project_id=?2",
                params![input.job_id, input.project_id],
                |row| row.get(0),
            )
            .map_err(internal)?;
        if role < ProjectRole::Operator && requested_by.as_deref() != Some(principal.as_str()) {
            return Err(Status::permission_denied(
                "analysts may cancel only jobs they requested",
            ));
        }
        let changed = {
            let mut conn = self.connection()?;
            let tx = conn.transaction().map_err(internal)?;
            let changed = tx
                .execute(
                    "UPDATE jobs SET state='cancelled',diagnostic='cancelled by user' \
                 WHERE id=?1 AND project_id=?2 AND state IN ('queued','running')",
                    params![input.job_id, input.project_id],
                )
                .map_err(internal)?;
            if changed == 1 {
                insert_event(&tx, &input.job_id, "cancelled", "cancelled by user", "")?;
            }
            tx.commit().map_err(internal)?;
            changed == 1
        };
        let handle = if changed {
            self.workers
                .lock()
                .map_err(|_| Status::internal("worker registry lock poisoned"))?
                .remove(&input.job_id)
        } else {
            None
        };
        if let Some(handle) = handle {
            handle.abort();
            let _ = tokio::time::timeout(Duration::from_secs(5), handle)
                .await
                .map_err(|_| Status::deadline_exceeded("worker cancellation was not confirmed"))?;
        }
        Ok(Response::new(self.job(
            &principal,
            &input.project_id,
            &input.job_id,
        )?))
    }

    type StreamJobEventsStream = ReceiverStream<Result<JobEvent, Status>>;

    async fn stream_job_events(
        &self,
        request: Request<JobEventRequest>,
    ) -> Result<Response<Self::StreamJobEventsStream>, Status> {
        let principal = self.principal(&request)?;
        let bearer = request
            .metadata()
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
            .ok_or_else(|| Status::unauthenticated("credential missing"))?
            .to_owned();
        let input = request.into_inner();
        self.job(&principal, &input.project_id, &input.job_id)?;
        let mut cursor = i64::try_from(input.after_sequence)
            .map_err(|_| Status::invalid_argument("event sequence too large"))?;
        let store = self.clone();
        let (sender, receiver) = mpsc::channel(32);
        tokio::spawn(async move {
            loop {
                let snapshot: Result<(Vec<JobEvent>, bool), Status> = (|| {
                    if store.authenticate_bearer(&bearer)? != principal {
                        return Err(Status::unauthenticated("credential was revoked"));
                    }
                    let conn = store.connection()?;
                    let state: String = conn
                        .query_row(
                            "SELECT j.state FROM jobs j JOIN project_acls a ON a.project_id=j.project_id \
                         WHERE j.id=?1 AND j.project_id=?2 AND a.principal=?3",
                            params![input.job_id, input.project_id, principal],
                            |row| row.get(0),
                        )
                        .optional()
                        .map_err(internal)?
                        .ok_or_else(|| Status::permission_denied("project access was revoked"))?;
                    let mut statement = conn
                        .prepare(
                            "SELECT sequence,state,message,artifact_sha256 FROM job_events \
                         WHERE job_id=?1 AND sequence>?2 ORDER BY sequence LIMIT 32",
                        )
                        .map_err(internal)?;
                    let events = statement
                        .query_map(params![input.job_id, cursor], |row| {
                            Ok(JobEvent {
                                sequence: row.get::<_, i64>(0)? as u64,
                                job_id: input.job_id.clone(),
                                state: row.get(1)?,
                                message: row.get(2)?,
                                artifact_sha256: row.get(3)?,
                            })
                        })
                        .map_err(internal)?
                        .collect::<Result<Vec<_>, _>>()
                        .map_err(internal)?;
                    let terminal = matches!(
                        state.as_str(),
                        "succeeded" | "failed" | "cancelled" | "interrupted"
                    );
                    Ok((events, terminal))
                })();
                let (events, terminal) = match snapshot {
                    Ok(value) => value,
                    Err(error) => {
                        let _ = sender.send(Err(error)).await;
                        return;
                    }
                };
                let empty = events.is_empty();
                for event in events {
                    cursor = event.sequence as i64;
                    if sender.send(Ok(event)).await.is_err() {
                        return;
                    }
                }
                if terminal && empty {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        });
        Ok(Response::new(ReceiverStream::new(receiver)))
    }
}

fn v3_job_reply(job: JobReply) -> api_v3::JobReply {
    api_v3::JobReply {
        project_id: job.project_id,
        job_id: job.job_id,
        project_revision: job.project_revision,
        kind: job.kind,
        state: job.state,
        artifact_sha256: job.artifact_sha256,
        diagnostic: job.diagnostic,
    }
}

fn require_native_job(job: JobReply) -> Result<api_v3::JobReply, Status> {
    if job.kind != "native-analysis" {
        return Err(Status::not_found("native analysis job not found"));
    }
    Ok(v3_job_reply(job))
}

#[tonic::async_trait]
impl api_v3::hydir_v3_server::HydirV3 for Store {
    async fn discover(
        &self,
        request: Request<api_v3::DiscoverRequest>,
    ) -> Result<Response<api_v3::DiscoverReply>, Status> {
        self.principal(&request)?;
        Ok(Response::new(api_v3::DiscoverReply {
            api_version: 3,
            program_spec_version: PROGRAM_SPEC_VERSION,
            function_index_version: FUNCTION_INDEX_VERSION,
            machine_ir_version: MACHINE_FUNCTION_IR_VERSION,
            state_ir_version: STATE_FUNCTION_IR_VERSION,
            function_ir_version: FUNCTION_IR_VERSION,
            cir_version: CIR_VERSION,
            decompilation_unit_version: DECOMPILATION_UNIT_VERSION,
            stable_contract: "native bounded ELF analysis with explicit unknown effects; LLVM is an optional export; partial artifacts are never rewrite-ready".to_owned(),
            isolated_analysis_jobs: true,
            analyst_fact_updates: true,
            ghidra_snapshot_analysis: true,
            automatic_ghidra_analysis: true,
        }))
    }

    async fn start_program_analysis(
        &self,
        request: Request<api_v3::StartProgramAnalysisRequest>,
    ) -> Result<Response<api_v3::JobReply>, Status> {
        let principal = self.principal(&request)?;
        let input = request.into_inner();
        self.require_project_role(&principal, &input.project_id, ProjectRole::Analyst)?;
        if input.idempotency_key.is_empty()
            || input.idempotency_key.len() > 128
            || input.idempotency_key.chars().any(char::is_control)
        {
            return Err(Status::invalid_argument(
                "job idempotency key must be 1..=128 non-control bytes",
            ));
        }
        let expected = i64::try_from(input.expected_revision)
            .map_err(|_| Status::invalid_argument("revision too large"))?;
        self.project(&principal, &input.project_id)?;
        let prior: Option<(String, i64, String)> = self
            .connection()?
            .query_row(
                "SELECT id,revision,kind FROM jobs WHERE project_id=?1 AND idempotency_key=?2",
                params![input.project_id, input.idempotency_key],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(internal)?;
        if let Some((id, revision, kind)) = prior {
            if revision != expected || kind != "native-analysis" {
                return Err(Status::already_exists(
                    "idempotency key belongs to a different analysis request",
                ));
            }
            return Ok(Response::new(require_native_job(self.job(
                &principal,
                &input.project_id,
                &id,
            )?)?));
        }
        let bytes = self
            .current_binary(&principal, &input.project_id, input.expected_revision)
            .await?;
        let id = Uuid::new_v4().to_string();
        {
            let mut conn = self.connection()?;
            let tx = conn.transaction().map_err(internal)?;
            require_project_role_in(&tx, &principal, &input.project_id, ProjectRole::Analyst)?;
            let retry: Option<(String, i64, String)> = tx
                .query_row(
                    "SELECT id,revision,kind FROM jobs WHERE project_id=?1 AND idempotency_key=?2",
                    params![input.project_id, input.idempotency_key],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .optional()
                .map_err(internal)?;
            if let Some((existing, revision, kind)) = retry {
                drop(tx);
                drop(conn);
                if revision != expected || kind != "native-analysis" {
                    return Err(Status::already_exists(
                        "idempotency key belongs to a different analysis request",
                    ));
                }
                return Ok(Response::new(require_native_job(self.job(
                    &principal,
                    &input.project_id,
                    &existing,
                )?)?));
            }
            let current: i64 = tx
                .query_row(
                    "SELECT current_revision FROM projects WHERE id=?1",
                    params![input.project_id],
                    |row| row.get(0),
                )
                .map_err(internal)?;
            if current != expected {
                return Err(Status::aborted("stale project revision"));
            }
            let active: i64 = tx
                .query_row(
                    "SELECT COUNT(*) FROM jobs WHERE requested_by=?1 AND state IN ('queued','running')",
                    [principal.as_str()],
                    |row| row.get(0),
                )
                .map_err(internal)?;
            if active >= MAX_ACTIVE_JOBS_PER_IDENTITY {
                return Err(Status::resource_exhausted("identity has two active jobs"));
            }
            tx.execute(
                "INSERT INTO jobs(id,project_id,revision,kind,symbol,idempotency_key,state,requested_by) \
                 VALUES(?1,?2,?3,'native-analysis','',?4,'queued',?5)",
                params![
                    id,
                    input.project_id,
                    expected,
                    input.idempotency_key,
                    principal
                ],
            )
            .map_err(internal)?;
            insert_event(&tx, &id, "queued", "native program analysis queued", "")?;
            tx.commit().map_err(internal)?;
        }
        let (start_sender, start_receiver) = oneshot::channel();
        let runner = self.clone();
        let runner_id = id.clone();
        let project_id = input.project_id.clone();
        let handle = tokio::spawn(async move {
            if start_receiver.await.is_ok() {
                runner
                    .execute_native_analysis_job(
                        runner_id,
                        project_id,
                        input.expected_revision,
                        bytes,
                    )
                    .await;
            }
        });
        self.workers
            .lock()
            .map_err(|_| Status::internal("worker registry lock poisoned"))?
            .insert(id.clone(), handle);
        let _ = start_sender.send(());
        Ok(Response::new(require_native_job(self.job(
            &principal,
            &input.project_id,
            &id,
        )?)?))
    }

    async fn get_analysis_job(
        &self,
        request: Request<api_v3::JobRequest>,
    ) -> Result<Response<api_v3::JobReply>, Status> {
        let principal = self.principal(&request)?;
        let input = request.into_inner();
        Ok(Response::new(require_native_job(self.job(
            &principal,
            &input.project_id,
            &input.job_id,
        )?)?))
    }

    async fn cancel_analysis_job(
        &self,
        request: Request<api_v3::JobRequest>,
    ) -> Result<Response<api_v3::JobReply>, Status> {
        let metadata = request.metadata().clone();
        let input = request.into_inner();
        let mut legacy = Request::new(JobRequest {
            project_id: input.project_id,
            job_id: input.job_id,
        });
        *legacy.metadata_mut() = metadata;
        let principal = self.principal(&legacy)?;
        require_native_job(self.job(
            &principal,
            &legacy.get_ref().project_id,
            &legacy.get_ref().job_id,
        )?)?;
        let job = <Store as Hydir>::cancel_job(self, legacy)
            .await?
            .into_inner();
        Ok(Response::new(require_native_job(job)?))
    }

    type StreamAnalysisEventsStream = ReceiverStream<Result<api_v3::JobEvent, Status>>;

    async fn stream_analysis_events(
        &self,
        request: Request<api_v3::JobEventRequest>,
    ) -> Result<Response<Self::StreamAnalysisEventsStream>, Status> {
        let metadata = request.metadata().clone();
        let input = request.into_inner();
        let mut legacy = Request::new(JobEventRequest {
            project_id: input.project_id,
            job_id: input.job_id,
            after_sequence: input.after_sequence,
        });
        *legacy.metadata_mut() = metadata;
        let principal = self.principal(&legacy)?;
        require_native_job(self.job(
            &principal,
            &legacy.get_ref().project_id,
            &legacy.get_ref().job_id,
        )?)?;
        let mut stream = <Store as Hydir>::stream_job_events(self, legacy)
            .await?
            .into_inner();
        let (sender, receiver) = mpsc::channel(32);
        tokio::spawn(async move {
            while let Some(event) = stream.next().await {
                let mapped = event.map(|event| api_v3::JobEvent {
                    sequence: event.sequence,
                    job_id: event.job_id,
                    state: event.state,
                    message: event.message,
                    artifact_sha256: event.artifact_sha256,
                });
                if sender.send(mapped).await.is_err() {
                    break;
                }
            }
        });
        Ok(Response::new(ReceiverStream::new(receiver)))
    }

    async fn get_program_artifact(
        &self,
        request: Request<api_v3::ProgramArtifactRequest>,
    ) -> Result<Response<api_v3::ArtifactReply>, Status> {
        let principal = self.principal(&request)?;
        let input = request.into_inner();
        self.require_project_role(&principal, &input.project_id, ProjectRole::Analyst)?;
        let media_type = native_artifact_media_type(&input.stage)
            .ok_or_else(|| Status::invalid_argument("unsupported native artifact stage"))?;
        if matches!(
            input.stage.as_str(),
            "machine"
                | "state"
                | "function"
                | "cir"
                | "llvm"
                | "unit"
                | "high_level_cir"
                | "high_level_cfg_cir"
                | "typed_c"
        ) {
            valid_symbol(&input.function_selector)?;
        } else if !input.function_selector.is_empty() {
            return Err(Status::invalid_argument(
                "program-scoped artifact must not include a function selector",
            ));
        }
        let binary = self
            .current_binary(&principal, &input.project_id, input.expected_revision)
            .await?;
        let selector = serde_json::to_string(&NativeArtifactSelector {
            stage: input.stage,
            function: input.function_selector,
        })
        .map_err(|_| Status::internal("native artifact selector serialization failed"))?;
        let content = run_worker("native-artifact", Some(&selector), binary).await?;
        let digest = self
            .store_artifact(
                &input.project_id,
                input.expected_revision,
                media_type,
                &content,
            )
            .await?;
        Ok(Response::new(api_v3::ArtifactReply {
            sha256: digest,
            media_type: media_type.to_owned(),
            content,
            project_revision: input.expected_revision,
        }))
    }

    async fn analyze_ghidra_snapshot(
        &self,
        request: Request<api_v3::GhidraSnapshotArtifactRequest>,
    ) -> Result<Response<api_v3::ArtifactReply>, Status> {
        let principal = self.principal(&request)?;
        let input = request.into_inner();
        self.require_project_role(&principal, &input.project_id, ProjectRole::Analyst)?;
        let media_type = ghidra_snapshot_artifact_media_type(&input.stage)
            .ok_or_else(|| Status::invalid_argument("unsupported Ghidra artifact stage"))?;
        validate_ghidra_start_address(&input.stage, &input.start_address)
            .map_err(Status::invalid_argument)?;
        validate_ghidra_slice_target(
            &input.stage,
            input.instruction_index,
            input.operation_index,
            input.input_index,
        )
        .map_err(Status::invalid_argument)?;
        let automatic = input.automatic;
        if automatic && !input.snapshot_json.is_empty() {
            return Err(Status::invalid_argument(
                "automatic Ghidra analysis cannot include snapshot_json",
            ));
        }
        if !automatic && input.snapshot_json.is_empty() {
            return Err(Status::invalid_argument(
                "Ghidra snapshot is empty; set automatic to run the managed worker",
            ));
        }
        let selected_entry = ghidra_selected_entry(&input.selected_function_entry, automatic)
            .map_err(Status::invalid_argument)?;
        if input.snapshot_json.len() > MAX_GHIDRA_SNAPSHOT_BYTES {
            return Err(Status::resource_exhausted("Ghidra snapshot exceeds 16 MiB"));
        }
        let project = self.project(&principal, &input.project_id)?;
        if project.revision != input.expected_revision {
            return Err(Status::aborted("stale project revision"));
        }
        if project.binary_sha256.is_empty() {
            return Err(Status::failed_precondition(
                "project has no uploaded binary",
            ));
        }
        let selector = serde_json::to_string(&GhidraSnapshotArtifactSelector {
            stage: input.stage,
            binary_sha256: project.binary_sha256.clone(),
            start_address: input.start_address,
            instruction_index: input.instruction_index,
            operation_index: input.operation_index,
            input_index: input.input_index,
        })
        .map_err(|_| Status::internal("Ghidra artifact selector serialization failed"))?;
        let snapshot_json = if automatic {
            let worker_key =
                hydir_ghidra_worker::analysis_cache_key(&project.binary_sha256, selected_entry);
            let cached = {
                let connection = self.connection()?;
                cached_ghidra_snapshot(
                    &connection,
                    &input.project_id,
                    &project.binary_sha256,
                    &worker_key,
                    selected_entry,
                )?
            };
            if let Some(cached) = cached {
                cached
            } else {
                let binary = self
                    .current_binary(&principal, &input.project_id, input.expected_revision)
                    .await?;
                let produced = automatic_ghidra_snapshot(binary, selected_entry).await?;
                {
                    let connection = self.connection()?;
                    save_ghidra_snapshot(
                        &connection,
                        &input.project_id,
                        &project.binary_sha256,
                        input.expected_revision,
                        &worker_key,
                        selected_entry,
                        &produced,
                    )?;
                }
                produced
            }
        } else {
            input.snapshot_json
        };
        let content =
            run_worker("ghidra-snapshot-artifact", Some(&selector), snapshot_json).await?;
        // Do not attach an artifact to a revision that ceased to be current
        // while the isolated worker was processing the snapshot.
        let current = self.project(&principal, &input.project_id)?;
        if current.revision != input.expected_revision
            || current.binary_sha256 != project.binary_sha256
        {
            return Err(Status::aborted("stale project revision"));
        }
        let staged = self.content_storage.stage(&content).await?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction().map_err(internal)?;
        let stored: (i64, String) = transaction
            .query_row(
                "SELECT p.current_revision,r.binary_sha256 FROM projects p \
                 JOIN project_revisions r ON r.project_id=p.id AND r.revision=p.current_revision \
                 WHERE p.id=?1",
                params![input.project_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(internal)?;
        if stored.0 != input.expected_revision as i64 || stored.1 != project.binary_sha256 {
            return Err(Status::aborted("stale project revision"));
        }
        insert_artifact(
            &transaction,
            &input.project_id,
            input.expected_revision as i64,
            media_type,
            &staged,
        )?;
        transaction.commit().map_err(internal)?;
        Ok(Response::new(api_v3::ArtifactReply {
            sha256: staged.digest,
            media_type: media_type.to_owned(),
            content,
            project_revision: input.expected_revision,
        }))
    }

    async fn update_analyst_fact(
        &self,
        request: Request<api_v3::AnalystFactRequest>,
    ) -> Result<Response<api_v3::MutationReply>, Status> {
        let metadata = request.metadata().clone();
        let input = request.into_inner();
        let mut legacy = Request::new(AnnotationRequest {
            project_id: input.project_id,
            expected_revision: input.expected_revision,
            idempotency_key: input.idempotency_key,
            kind: input.kind,
            address: input.address,
            value: input.value,
            scope: input.scope,
        });
        *legacy.metadata_mut() = metadata;
        let project = <Store as Hydir>::add_annotation(self, legacy)
            .await?
            .into_inner();
        Ok(Response::new(api_v3::MutationReply {
            project_id: project.project_id,
            revision: project.revision,
            binary_sha256: project.binary_sha256,
        }))
    }
}

#[tonic::async_trait]
impl api_v2::hydir_v2_server::HydirV2 for Store {
    async fn discover(
        &self,
        request: Request<api_v2::DiscoverRequest>,
    ) -> Result<Response<api_v2::DiscoverReply>, Status> {
        self.principal(&request)?;
        Ok(Response::new(api_v2::DiscoverReply {
            api_version: 2,
            program_spec_version: PROGRAM_SPEC_VERSION,
            region_spec_version: REGION_SPEC_VERSION,
            decompilation_unit_version: DECOMPILATION_UNIT_VERSION,
            patch_bundle_version: PATCH_BUNDLE_VERSION,
            stable_contract:
                "versioned region artifacts are available; full HydIR region parity remains gated"
                    .to_owned(),
            compile_patch: true,
            structural_patch_verification: true,
            behavior_patch_verification: false,
            physical_region_ir: true,
        }))
    }

    async fn get_region(
        &self,
        request: Request<api_v2::RegionRequest>,
    ) -> Result<Response<api_v2::ArtifactReply>, Status> {
        let principal = self.principal(&request)?;
        let input = request.into_inner();
        self.require_project_role(&principal, &input.project_id, ProjectRole::Analyst)?;
        if !input.assume_u64x2 {
            return Err(Status::invalid_argument(
                "explicit u64(u64,u64) prototype assertion required",
            ));
        }
        valid_symbol(&input.function_symbol)?;
        let binary = self
            .current_binary(&principal, &input.project_id, input.expected_revision)
            .await?;
        let content = run_worker("region", Some(&input.function_symbol), binary).await?;
        let digest = self
            .store_artifact(
                &input.project_id,
                input.expected_revision,
                "application/vnd.hydir.region-spec+json;version=3",
                &content,
            )
            .await?;
        Ok(Response::new(api_v2::ArtifactReply {
            sha256: digest,
            media_type: "application/vnd.hydir.region-spec+json;version=3".to_owned(),
            content,
            project_revision: input.expected_revision,
        }))
    }

    async fn decompile_region(
        &self,
        request: Request<api_v2::RegionRequest>,
    ) -> Result<Response<api_v2::ArtifactReply>, Status> {
        let principal = self.principal(&request)?;
        let input = request.into_inner();
        self.require_project_role(&principal, &input.project_id, ProjectRole::Analyst)?;
        if !input.assume_u64x2 {
            return Err(Status::invalid_argument(
                "explicit u64(u64,u64) prototype assertion required",
            ));
        }
        valid_symbol(&input.function_symbol)?;
        let binary = self
            .current_binary(&principal, &input.project_id, input.expected_revision)
            .await?;
        let content = run_worker("decompile-unit", Some(&input.function_symbol), binary).await?;
        let digest = self
            .store_artifact(
                &input.project_id,
                input.expected_revision,
                "application/vnd.hydir.decompilation-unit+json;version=1",
                &content,
            )
            .await?;
        Ok(Response::new(api_v2::ArtifactReply {
            sha256: digest,
            media_type: "application/vnd.hydir.decompilation-unit+json;version=1".to_owned(),
            content,
            project_revision: input.expected_revision,
        }))
    }

    async fn lift_region(
        &self,
        request: Request<api_v2::RegionRequest>,
    ) -> Result<Response<api_v2::ArtifactReply>, Status> {
        let principal = self.principal(&request)?;
        let input = request.into_inner();
        self.require_project_role(&principal, &input.project_id, ProjectRole::Analyst)?;
        if !input.assume_u64x2 {
            return Err(Status::invalid_argument(
                "explicit u64(u64,u64) prototype assertion required",
            ));
        }
        valid_symbol(&input.function_symbol)?;
        let binary = self
            .current_binary(&principal, &input.project_id, input.expected_revision)
            .await?;
        let content =
            run_worker("physical-region-ir", Some(&input.function_symbol), binary).await?;
        let media_type = "application/vnd.hydir.physical-region-ir+json;version=1";
        let digest = self
            .store_artifact(
                &input.project_id,
                input.expected_revision,
                media_type,
                &content,
            )
            .await?;
        Ok(Response::new(api_v2::ArtifactReply {
            sha256: digest,
            media_type: media_type.to_owned(),
            content,
            project_revision: input.expected_revision,
        }))
    }

    async fn compile_patch(
        &self,
        request: Request<api_v2::PatchRequest>,
    ) -> Result<Response<api_v2::ArtifactReply>, Status> {
        let principal = self.principal(&request)?;
        let input = request.into_inner();
        self.require_project_role(&principal, &input.project_id, ProjectRole::Analyst)?;
        validate_v2_patch_request(&input)?;
        let binary = self
            .current_binary(&principal, &input.project_id, input.expected_revision)
            .await?;
        let envelope = patch_worker_envelope(&input.patch_json, &binary)?;
        let packed = run_worker("patch-v2", None, envelope).await?;
        let [_patched, bundle] = unpack_worker_parts::<2>(&packed)?;
        parse_patch_bundle_json(bundle).map_err(Status::invalid_argument)?;
        let digest = self
            .store_artifact(
                &input.project_id,
                input.expected_revision,
                "application/vnd.hydir.patch-bundle+json;version=2",
                bundle,
            )
            .await?;
        Ok(Response::new(api_v2::ArtifactReply {
            sha256: digest,
            media_type: "application/vnd.hydir.patch-bundle+json;version=2".to_owned(),
            content: bundle.to_vec(),
            project_revision: input.expected_revision,
        }))
    }

    async fn apply_patch(
        &self,
        request: Request<api_v2::PatchRequest>,
    ) -> Result<Response<api_v2::MutationReply>, Status> {
        let principal = self.principal(&request)?;
        let input = request.into_inner();
        self.require_project_role(&principal, &input.project_id, ProjectRole::Operator)?;
        validate_v2_patch_request(&input)?;
        let binary = self
            .binary_at_revision(&principal, &input.project_id, input.expected_revision)
            .await?;
        let envelope = patch_worker_envelope(&input.patch_json, &binary)?;
        let packed = run_worker("patch-v2", None, envelope).await?;
        let [patched, bundle] = unpack_worker_parts::<2>(&packed)?;
        let parsed_bundle = parse_patch_bundle_json(bundle).map_err(Status::invalid_argument)?;
        if sha256(patched) != parsed_bundle.patched_sha256 {
            return Err(Status::internal(
                "v2 patch worker output differs from its PatchBundle digest",
            ));
        }
        let bundle_digest = self
            .store_artifact(
                &input.project_id,
                input.expected_revision,
                "application/vnd.hydir.patch-bundle+json;version=2",
                bundle,
            )
            .await?;
        let patch_digest = sha256(&input.patch_json);
        let reply = self
            .commit_patch_mutation(
                &principal,
                &input.project_id,
                input.expected_revision,
                &input.idempotency_key,
                &patch_digest,
                patched.to_vec(),
            )
            .await?;
        Ok(Response::new(api_v2::MutationReply {
            project_id: reply.project_id,
            revision: reply.revision,
            binary_sha256: reply.binary_sha256,
            patch_bundle_sha256: bundle_digest,
        }))
    }

    async fn verify_patch(
        &self,
        request: Request<api_v2::VerifyPatchRequest>,
    ) -> Result<Response<api_v2::VerificationReply>, Status> {
        let principal = self.principal(&request)?;
        let input = request.into_inner();
        self.current_binary(&principal, &input.project_id, input.expected_revision)
            .await?;
        if input.patch_bundle_json.is_empty() || input.patch_bundle_json.len() > 2 * 1024 * 1024 {
            return Err(Status::invalid_argument("PatchBundle must be 1..=2 MiB"));
        }
        let bundle =
            parse_patch_bundle_json(&input.patch_bundle_json).map_err(Status::invalid_argument)?;
        let belongs_to_project: bool = self
            .connection()?
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM project_revisions r \
                 WHERE r.project_id=?1 AND r.binary_sha256=?2)",
                params![input.project_id, bundle.original_sha256],
                |row| row.get(0),
            )
            .map_err(internal)?;
        if !belongs_to_project {
            return Err(Status::failed_precondition(
                "PatchBundle original binary is not in project history",
            ));
        }
        let report_json = serde_json::to_string(&json!({
            "schema_version": 1,
            "structurally_valid": true,
            "behavior_verified": false,
            "stable_verified": bundle.stable_verified,
            "verification_evidence": bundle.verification_evidence,
            "scope": "digest, schema, embedded bytes, placement, and project-history checks only; no sample execution",
        }))
        .map_err(|error| Status::internal(format!("verification report serialization: {error}")))?;
        Ok(Response::new(api_v2::VerificationReply {
            structurally_valid: true,
            behavior_verified: false,
            report_json,
        }))
    }
}

fn read_tls_material(path: &Path, label: &str, private: bool) -> Result<Vec<u8>, Box<dyn Error>> {
    #[cfg(not(unix))]
    let _ = private;
    if !path.is_absolute() {
        return Err(format!("{label} path must be absolute").into());
    }
    let metadata = std::fs::metadata(path)?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_TLS_MATERIAL_BYTES {
        return Err(format!("{label} must be a non-empty regular file of at most 1 MiB").into());
    }
    #[cfg(unix)]
    if private {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(format!("{label} must not be group/world accessible (chmod 600)").into());
        }
    }
    let bytes = std::fs::read(path)?;
    if bytes.contains(&0) {
        return Err(format!("{label} must be PEM text without NUL bytes").into());
    }
    Ok(bytes)
}

fn tls_config(certificate: &Path, private_key: &Path) -> Result<ServerTlsConfig, Box<dyn Error>> {
    let certificate = read_tls_material(certificate, "TLS certificate", false)?;
    let private_key = read_tls_material(private_key, "TLS private key", true)?;
    Ok(ServerTlsConfig::new()
        .identity(Identity::from_pem(certificate, private_key))
        .timeout(Duration::from_secs(10)))
}

fn oidc_verifier(
    issuer: &str,
    audience: &str,
    jwks_path: &Path,
) -> Result<OidcVerifier, Box<dyn Error>> {
    let bytes = read_tls_material(jwks_path, "OIDC JWKS", false)?;
    let keys: JwkSet =
        serde_json::from_slice(&bytes).map_err(|error| format!("OIDC JWKS JSON: {error}"))?;
    OidcVerifier::new(issuer.to_owned(), audience.to_owned(), keys).map_err(Into::into)
}

fn filesystem_content_storage(root: &Path) -> Result<ContentStorage, Box<dyn Error>> {
    Ok(ContentStorage::FilesystemCas(Arc::new(
        FilesystemCas::open(root)?,
    )))
}

async fn s3_content_storage(
    endpoint: &str,
    region: &str,
    bucket: &str,
    prefix: &str,
) -> Result<ContentStorage, Box<dyn Error>> {
    if region.is_empty()
        || region.len() > 64
        || !region
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err("S3 region must be 1..=64 ASCII letters, digits, or hyphens".into());
    }
    if bucket.len() < 3
        || bucket.len() > 63
        || bucket.starts_with(['.', '-'])
        || bucket.ends_with(['.', '-'])
        || bucket.contains("..")
        || !bucket
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || b".-".contains(&byte))
    {
        return Err("S3 bucket name is invalid".into());
    }
    let prefix = if prefix == "-" {
        String::new()
    } else {
        let trimmed = prefix.trim_matches('/');
        if trimmed.is_empty()
            || trimmed.len() > 256
            || trimmed
                .split('/')
                .any(|part| part.is_empty() || part == "..")
            || !trimmed.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'/')
            })
        {
            return Err("S3 prefix must be `-` or a bounded safe object-key prefix".into());
        }
        trimmed.to_owned()
    };
    let custom_endpoint = if endpoint == "-" {
        None
    } else {
        let parsed = url::Url::parse(endpoint)?;
        if parsed.scheme() != "https"
            || parsed.host_str().is_none()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.query().is_some()
            || parsed.fragment().is_some()
            || parsed.path() != "/"
        {
            return Err("custom S3 endpoint must be an origin-only HTTPS URL".into());
        }
        Some(endpoint.to_owned())
    };
    let shared = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(aws_sdk_s3::config::Region::new(region.to_owned()))
        .load()
        .await;
    let mut builder = aws_sdk_s3::config::Builder::from(&shared);
    if let Some(endpoint) = custom_endpoint {
        builder = builder.endpoint_url(endpoint).force_path_style(true);
    }
    Ok(ContentStorage::S3(Arc::new(S3ContentStore {
        client: aws_sdk_s3::Client::from_conf(builder.build()),
        bucket: bucket.to_owned(),
        prefix,
    })))
}

async fn serve_rpc(
    store: Store,
    address: SocketAddr,
    tls: Option<ServerTlsConfig>,
) -> Result<(), Box<dyn Error>> {
    let (health_reporter, health_service) = tonic_health::server::health_reporter();
    health_reporter
        .set_service_status("", ServingStatus::Serving)
        .await;
    let mut server = Server::builder();
    if let Some(tls) = tls {
        server = server.tls_config(tls)?;
    }
    server
        .add_service(health_service)
        .add_service(
            HydirServer::new(store.clone())
                .max_decoding_message_size(MAX_BINARY_BYTES + 1024)
                .max_encoding_message_size(MAX_BINARY_BYTES + 1024),
        )
        .add_service(
            HydirV2Server::new(store.clone())
                .max_decoding_message_size(MAX_BINARY_BYTES + 1024)
                .max_encoding_message_size(MAX_BINARY_BYTES + 1024),
        )
        .add_service(
            HydirV3Server::new(store)
                .max_decoding_message_size(MAX_BINARY_BYTES + 1024)
                .max_encoding_message_size(MAX_BINARY_BYTES + 1024),
        )
        .add_service(interchange::interchange_service())
        .add_service(interchange::patch_service())
        .serve(address)
        .await?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let arguments: Vec<String> = env::args().skip(1).collect();
    match arguments.as_slice() {
        [worker, action] if worker == "worker" => worker_main(std::slice::from_ref(action))?,
        [worker, action, symbol] if worker == "worker" => {
            worker_main(&[action.clone(), symbol.clone()])?
        }
        [identity, create, database, principal] if identity == "identity" && create == "create" => {
            let store = Store::open(Path::new(database))?;
            let token = store.create_identity(principal)?;
            println!("principal: {principal}\ncredential (save securely; shown once): {token}");
        }
        [identity, rotate, database, principal] if identity == "identity" && rotate == "rotate" => {
            let store = Store::open(Path::new(database))?;
            let token = store.rotate_identity(principal)?;
            println!("principal: {principal}\nnew credential (save securely; shown once): {token}");
        }
        [identity, list, database] if identity == "identity" && list == "list-oidc" => {
            let store = Store::open(Path::new(database))?;
            let identities = store
                .oidc_identities()?
                .into_iter()
                .map(|identity| {
                    json!({
                        "principal": identity.principal,
                        "issuer": identity.issuer,
                        "subject": identity.subject,
                    })
                })
                .collect::<Vec<_>>();
            println!("{}", serde_json::to_string_pretty(&identities)?);
        }
        [access, grant, database, project, actor, principal, role]
            if access == "access" && grant == "grant" =>
        {
            let store = Store::open(Path::new(database))?;
            let role = ProjectRole::parse(role)?;
            store.set_project_role(actor, project, principal, Some(role))?;
            println!("granted {} role on {project} to {principal}", role.as_str());
        }
        [access, revoke, database, project, actor, principal]
            if access == "access" && revoke == "revoke" =>
        {
            let store = Store::open(Path::new(database))?;
            store.set_project_role(actor, project, principal, None)?;
            println!("revoked access to {project} from {principal}");
        }
        [access, list, database, project, actor] if access == "access" && list == "list" => {
            let store = Store::open(Path::new(database))?;
            let records = store
                .project_access(actor, project)?
                .into_iter()
                .map(|(principal, role)| json!({"principal": principal, "role": role.as_str()}))
                .collect::<Vec<_>>();
            println!("{}", serde_json::to_string_pretty(&records)?);
        }
        [serve, database, bind] if serve == "serve" => {
            if database == ":memory:" {
                return Err("hydird serve requires a persistent SQLite database file".into());
            }
            let address: SocketAddr = bind.parse()?;
            if !address.ip().is_loopback() {
                return Err("hydird currently supports only authenticated loopback binding; TLS/non-loopback mode is not implemented".into());
            }
            let store = Store::open(Path::new(database))?;
            println!("hydird local RPC listening on {address}");
            serve_rpc(store, address, None).await?;
        }
        [serve, database, bind, certificate, private_key] if serve == "serve-tls" => {
            if database == ":memory:" {
                return Err("hydird serve-tls requires a persistent SQLite database file".into());
            }
            let address: SocketAddr = bind.parse()?;
            let tls = tls_config(Path::new(certificate), Path::new(private_key))?;
            let store = Store::open(Path::new(database))?;
            println!("hydird TLS RPC listening on {address}");
            serve_rpc(store, address, Some(tls)).await?;
        }
        [serve, database, bind, certificate, private_key, issuer, audience, jwks]
            if serve == "serve-oidc" =>
        {
            if database == ":memory:" {
                return Err("hydird serve-oidc requires a persistent SQLite database file".into());
            }
            let address: SocketAddr = bind.parse()?;
            let tls = tls_config(Path::new(certificate), Path::new(private_key))?;
            let verifier = oidc_verifier(issuer, audience, Path::new(jwks))?;
            let store = Store::open_with_auth(
                Path::new(database),
                AuthenticationMode::Oidc(Arc::new(verifier)),
            )?;
            println!("hydird TLS/OIDC RPC listening on {address}");
            serve_rpc(store, address, Some(tls)).await?;
        }
        [serve, database, bind, certificate, private_key, issuer, audience, jwks, object_root]
            if serve == "serve-oidc-cas" =>
        {
            if database == ":memory:" {
                return Err("hydird serve-oidc-cas requires a persistent SQLite database file".into());
            }
            let address: SocketAddr = bind.parse()?;
            let tls = tls_config(Path::new(certificate), Path::new(private_key))?;
            let verifier = oidc_verifier(issuer, audience, Path::new(jwks))?;
            let content_storage = filesystem_content_storage(Path::new(object_root))?;
            let store = Store::open_with_options(
                Path::new(database),
                AuthenticationMode::Oidc(Arc::new(verifier)),
                content_storage,
            )?;
            println!("hydird TLS/OIDC RPC with filesystem CAS listening on {address}");
            serve_rpc(store, address, Some(tls)).await?;
        }
        [serve, database, bind, certificate, private_key, issuer, audience, jwks, endpoint, region, bucket, prefix]
            if serve == "serve-oidc-s3" =>
        {
            if database == ":memory:" {
                return Err("hydird serve-oidc-s3 requires a persistent SQLite database file".into());
            }
            let address: SocketAddr = bind.parse()?;
            let tls = tls_config(Path::new(certificate), Path::new(private_key))?;
            let verifier = oidc_verifier(issuer, audience, Path::new(jwks))?;
            let content_storage = s3_content_storage(endpoint, region, bucket, prefix).await?;
            let store = Store::open_with_options(
                Path::new(database),
                AuthenticationMode::Oidc(Arc::new(verifier)),
                content_storage,
            )?;
            println!("hydird TLS/OIDC RPC with S3 content storage listening on {address}");
            serve_rpc(store, address, Some(tls)).await?;
        }
        _ => return Err("Usage: hydird identity create|rotate <database.sqlite> <principal> | hydird identity list-oidc <database.sqlite> | hydird access grant <database.sqlite> <project-id> <admin-principal> <principal> <viewer|analyst|operator|admin> | hydird access revoke <database.sqlite> <project-id> <admin-principal> <principal> | hydird access list <database.sqlite> <project-id> <admin-principal> | hydird serve <database.sqlite> <loopback-host:port> | hydird serve-tls <database.sqlite> <host:port> <absolute-cert.pem> <absolute-key.pem> | hydird serve-oidc <database.sqlite> <host:port> <absolute-cert.pem> <absolute-key.pem> <https-issuer> <audience> <absolute-jwks.json> | hydird serve-oidc-cas <database.sqlite> <host:port> <absolute-cert.pem> <absolute-key.pem> <https-issuer> <audience> <absolute-jwks.json> <absolute-object-root> | hydird serve-oidc-s3 <database.sqlite> <host:port> <absolute-cert.pem> <absolute-key.pem> <https-issuer> <audience> <absolute-jwks.json> <-|https-endpoint> <region> <bucket> <-|prefix>".into()),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires HYDIR_GHIDRA_HOME pointing to Ghidra 12.1.4 or Docker"]
    async fn automatic_ghidra_worker_exports_selected_real_elf() {
        use api_v3::hydir_v3_server::HydirV3;

        let store = Store::open(Path::new(":memory:")).unwrap();
        let token = store.create_identity("auto-ghidra-analyst").unwrap();
        let project = store
            .create_project(authorized(
                CreateProjectRequest {
                    name: "Automatic Ghidra fixture".to_owned(),
                    idempotency_key: "auto-ghidra-fixture".to_owned(),
                },
                &token,
            ))
            .await
            .unwrap()
            .into_inner();
        let binary = include_bytes!("../../../tests/fixtures/ghidra_prototype.elf").to_vec();
        let uploaded = store
            .upload_binary(authorized(
                UploadBinaryRequest {
                    project_id: project.project_id.clone(),
                    expected_revision: 0,
                    content_sha256: sha256(&binary),
                    content: binary.clone(),
                },
                &token,
            ))
            .await
            .unwrap()
            .into_inner();
        let request = api_v3::GhidraSnapshotArtifactRequest {
            project_id: project.project_id.clone(),
            expected_revision: uploaded.revision,
            snapshot_json: Vec::new(),
            stage: "snapshot".to_owned(),
            start_address: String::new(),
            instruction_index: None,
            operation_index: None,
            input_index: None,
            selected_function_entry: "0x101320".to_owned(),
            automatic: true,
        };
        let result = HydirV3::analyze_ghidra_snapshot(&store, authorized(request.clone(), &token))
            .await
            .unwrap()
            .into_inner();
        let bytes = result.content;
        let snapshot = parse_ghidra_snapshot(&bytes, &sha256(&binary)).unwrap();
        assert_eq!(snapshot.selected_function.entry.offset, "0x101320");
        assert!(!snapshot.selected_function.instructions.is_empty());
        assert!(!snapshot.functions.is_empty());
        let worker_key =
            hydir_ghidra_worker::analysis_cache_key(&uploaded.binary_sha256, Some(0x101320));
        assert!(
            cached_ghidra_snapshot(
                &store.connection().unwrap(),
                &project.project_id,
                &uploaded.binary_sha256,
                &worker_key,
                Some(0x101320),
            )
            .unwrap()
            .is_some()
        );
        let replay = HydirV3::analyze_ghidra_snapshot(&store, authorized(request, &token))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(replay.sha256, result.sha256);
        assert_eq!(replay.content, bytes);
    }

    #[test]
    fn pinned_oidc_jwks_verifies_claims_and_provisions_stable_principal() {
        use jsonwebtoken::{EncodingKey, Header, encode, jwk::Jwk};
        use rand::rngs::OsRng;
        use rsa::{RsaPrivateKey, pkcs1::EncodeRsaPrivateKey};
        use serde::Serialize;

        #[derive(Serialize)]
        struct Claims<'a> {
            sub: &'a str,
            iss: &'a str,
            aud: &'a str,
            exp: u64,
            nbf: u64,
        }

        let private_key = RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
        let private_der = private_key.to_pkcs1_der().unwrap();
        let encoding_key = EncodingKey::from_rsa_der(private_der.as_bytes());
        let mut jwk = Jwk::from_encoding_key(&encoding_key, Algorithm::RS256).unwrap();
        jwk.common.key_id = Some("test-key".to_owned());
        jwk.common.public_key_use = Some(PublicKeyUse::Signature);
        let verifier = Arc::new(
            OidcVerifier::new(
                "https://identity.example/tenant".to_owned(),
                "hydir-api".to_owned(),
                JwkSet { keys: vec![jwk] },
            )
            .unwrap(),
        );
        let now = jsonwebtoken::get_current_timestamp();
        let claims = Claims {
            sub: "analyst@example",
            iss: "https://identity.example/tenant",
            aud: "hydir-api",
            exp: now + 300,
            nbf: now.saturating_sub(1),
        };
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some("test-key".to_owned());
        let token = encode(&header, &claims, &encoding_key).unwrap();
        let store = Store::open_with_auth(
            Path::new(":memory:"),
            AuthenticationMode::Oidc(verifier.clone()),
        )
        .unwrap();
        let principal = store.authenticate_bearer(&token).unwrap();
        assert!(principal.starts_with("oidc-"));
        assert!(store.rotate_identity(&principal).is_err());
        assert_eq!(store.authenticate_bearer(&token).unwrap(), principal);
        let registered: (String, String) = store
            .connection()
            .unwrap()
            .query_row(
                "SELECT issuer,subject FROM oidc_identities WHERE principal=?1",
                [&principal],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(
            registered,
            (
                "https://identity.example/tenant".to_owned(),
                "analyst@example".to_owned()
            )
        );

        let wrong_audience = encode(
            &header,
            &Claims {
                aud: "another-api",
                ..claims
            },
            &encoding_key,
        )
        .unwrap();
        assert!(store.authenticate_bearer(&wrong_audience).is_err());
        let expired = encode(
            &header,
            &Claims {
                exp: now.saturating_sub(31),
                ..claims
            },
            &encoding_key,
        )
        .unwrap();
        assert!(store.authenticate_bearer(&expired).is_err());
        let mut unknown_header = Header::new(Algorithm::RS256);
        unknown_header.kid = Some("unknown-key".to_owned());
        let unknown_key = encode(&unknown_header, &claims, &encoding_key).unwrap();
        assert!(store.authenticate_bearer(&unknown_key).is_err());
        assert!(verifier.verify("not.a.jwt").is_err());
    }

    #[test]
    fn tls_material_requires_absolute_bounded_pem_text() {
        let directory = tempfile::tempdir().unwrap();
        let certificate = directory.path().join("server.pem");
        std::fs::write(&certificate, b"-----BEGIN CERTIFICATE-----\nfixture\n").unwrap();
        assert_eq!(
            read_tls_material(&certificate, "certificate", false).unwrap(),
            b"-----BEGIN CERTIFICATE-----\nfixture\n"
        );
        assert!(read_tls_material(Path::new("server.pem"), "certificate", false).is_err());
        std::fs::write(&certificate, b"pem\0text").unwrap();
        assert!(read_tls_material(&certificate, "certificate", false).is_err());
    }

    #[tokio::test]
    async fn s3_configuration_rejects_unsafe_names_and_endpoints_before_network_use() {
        assert!(
            s3_content_storage("-", "../region", "hydir-artifacts", "-")
                .await
                .is_err()
        );
        assert!(
            s3_content_storage("-", "us-east-1", "Hydir_Artifacts", "-")
                .await
                .is_err()
        );
        assert!(
            s3_content_storage("-", "us-east-1", "hydir-artifacts", "../../escape")
                .await
                .is_err()
        );
        assert!(
            s3_content_storage(
                "http://objects.example",
                "us-east-1",
                "hydir-artifacts",
                "hydir"
            )
            .await
            .is_err()
        );
        assert!(
            s3_content_storage(
                "https://user:secret@objects.example/?query=x",
                "us-east-1",
                "hydir-artifacts",
                "hydir"
            )
            .await
            .is_err()
        );
    }

    #[test]
    fn schema_eleven_accepts_s3_metadata_and_preserves_foreign_keys() {
        let store = Store::open(Path::new(":memory:")).unwrap();
        let connection = store.connection().unwrap();
        let version: i64 = connection
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(version, 11);
        connection
            .execute(
                "INSERT INTO binaries(sha256,content,storage_kind,storage_key,content_size) VALUES(?1,x'','s3',?2,1)",
                params!["0".repeat(64), "sha256/00/00/fixture"],
            )
            .unwrap();
        let foreign_key_errors: i64 = connection
            .query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(foreign_key_errors, 0);
    }

    #[test]
    fn schema_ten_migrates_to_snapshot_cache_without_losing_projects() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("v10.sqlite");
        let store = Store::open(&path).unwrap();
        {
            let connection = store.connection().unwrap();
            connection
                .execute_batch(
                    "INSERT INTO identities(principal,token_sha256) VALUES('owner','digest');
                     INSERT INTO projects(id,owner,name,idempotency_key)
                     VALUES('project','owner','existing','create-key');
                     DROP TABLE ghidra_snapshots;
                     PRAGMA user_version=10;",
                )
                .unwrap();
        }
        drop(store);
        let reopened = Store::open(&path).unwrap();
        let connection = reopened.connection().unwrap();
        let version: i64 = connection
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(version, 11);
        let name: String = connection
            .query_row("SELECT name FROM projects WHERE id='project'", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(name, "existing");
        let foreign_key_errors: i64 = connection
            .query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(foreign_key_errors, 0);
        let binary = include_bytes!("../../../demo/hydir-prism.elf");
        let snapshot = include_bytes!("../../../tests/fixtures/ghidra_prism_snapshot_v2.json");
        let digest = sha256(binary);
        connection
            .execute(
                "INSERT INTO binaries(sha256,content,storage_kind,storage_key,content_size) \
                 VALUES(?1,?2,'inline','',?3)",
                params![digest, binary.as_slice(), binary.len() as i64],
            )
            .unwrap();
        let worker_key = hydir_ghidra_worker::analysis_cache_key(&digest, None);
        save_ghidra_snapshot(
            &connection,
            "project",
            &digest,
            0,
            &worker_key,
            None,
            snapshot,
        )
        .unwrap();
        drop(connection);
        drop(reopened);
        let after_restart = Store::open(&path).unwrap();
        assert_eq!(
            cached_ghidra_snapshot(
                &after_restart.connection().unwrap(),
                "project",
                &digest,
                &worker_key,
                None,
            )
            .unwrap(),
            Some(snapshot.to_vec())
        );
    }

    #[test]
    fn worker_launch_mode_is_explicit_and_argument_separated() {
        let executable = Path::new(if cfg!(windows) {
            "C:\\hydir\\hydird.exe"
        } else {
            "/opt/hydir/hydird"
        });
        let direct =
            worker_launch_spec(executable, "lift", Some("hydir_symbol"), "process", None).unwrap();
        assert_eq!(direct.program, executable);
        assert_eq!(
            direct.arguments,
            ["worker", "lift", "hydir_symbol"].map(OsString::from)
        );
        assert!(
            worker_launch_spec(executable, "lift", None, "unknown", None)
                .unwrap_err()
                .contains("process` or `bubblewrap")
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn bubblewrap_worker_has_no_network_and_minimal_read_only_mounts() {
        let launch = worker_launch_spec(
            Path::new("/opt/hydir/hydird"),
            "inspect",
            None,
            "bubblewrap",
            Some(Path::new("/usr/bin/bwrap")),
        )
        .unwrap();
        let arguments = launch
            .arguments
            .iter()
            .map(|value| value.to_string_lossy())
            .collect::<Vec<_>>();
        assert!(arguments.iter().any(|value| value == "--unshare-all"));
        assert!(arguments.iter().any(|value| value == "--clearenv"));
        assert!(
            arguments
                .windows(3)
                .any(|window| window == ["--cap-drop", "ALL", "--clearenv"])
        );
        assert_eq!(arguments.last().map(AsRef::as_ref), Some("inspect"));
    }

    #[test]
    fn annotation_inputs_are_bounded_and_names_cannot_spoof_display_lines() {
        let input = AnnotationRequest {
            project_id: "project".to_owned(),
            expected_revision: 1,
            idempotency_key: "key".to_owned(),
            kind: "name".to_owned(),
            address: "0x401000".to_owned(),
            value: "entry".to_owned(),
            scope: "analyst review".to_owned(),
        };
        assert_eq!(
            validate_annotation(&input).unwrap().1,
            Some(Address(0x401000))
        );
        assert_eq!(
            validate_annotation(&AnnotationRequest {
                value: "entry\nverified".to_owned(),
                ..input.clone()
            })
            .unwrap_err()
            .code(),
            tonic::Code::InvalidArgument
        );
        assert_eq!(
            validate_annotation(&AnnotationRequest {
                value: "x".repeat(129),
                ..input.clone()
            })
            .unwrap_err()
            .code(),
            tonic::Code::InvalidArgument
        );
        assert_eq!(
            validate_annotation(&AnnotationRequest {
                address: "0x10000000000000000".to_owned(),
                ..input
            })
            .unwrap_err()
            .code(),
            tonic::Code::InvalidArgument
        );
    }

    fn authorized<T>(value: T, token: &str) -> Request<T> {
        let mut request = Request::new(value);
        request
            .metadata_mut()
            .insert("authorization", format!("Bearer {token}").parse().unwrap());
        request
    }

    #[tokio::test]
    async fn filesystem_cas_is_digest_verified_and_survives_restart() {
        let directory = tempfile::tempdir().unwrap();
        let database = directory.path().join("cas.sqlite");
        let object_root = directory.path().join("objects");
        let storage = filesystem_content_storage(&object_root).unwrap();
        let store =
            Store::open_with_options(&database, AuthenticationMode::StaticTokens, storage.clone())
                .unwrap();
        let token = store.create_identity("cas-analyst").unwrap();
        let project = store
            .create_project(authorized(
                CreateProjectRequest {
                    name: "CAS project".to_owned(),
                    idempotency_key: "cas-project".to_owned(),
                },
                &token,
            ))
            .await
            .unwrap()
            .into_inner();
        let binary = b"digest-bound-binary";
        let staged = store.content_storage.stage(binary).await.unwrap();
        {
            let connection = store.connection().unwrap();
            insert_binary(&connection, &staged).unwrap();
            connection
                .execute(
                    "INSERT INTO project_revisions(project_id,revision,binary_sha256) VALUES(?1,1,?2)",
                    params![project.project_id, staged.digest],
                )
                .unwrap();
            connection
                .execute(
                    "UPDATE projects SET current_revision=1 WHERE id=?1",
                    [&project.project_id],
                )
                .unwrap();
        }
        let artifact = b"content-addressed artifact";
        let artifact_digest = store
            .store_artifact(&project.project_id, 1, "application/test", artifact)
            .await
            .unwrap();
        let inline_bytes: i64 = store
            .connection()
            .unwrap()
            .query_row(
                "SELECT length(content) FROM artifacts WHERE sha256=?1",
                [&artifact_digest],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(inline_bytes, 0);
        assert_eq!(
            store
                .current_binary("cas-analyst", &project.project_id, 1)
                .await
                .unwrap(),
            binary
        );
        drop(store);

        let reopened =
            Store::open_with_options(&database, AuthenticationMode::StaticTokens, storage).unwrap();
        let found = reopened
            .get_artifact(authorized(
                ArtifactRequest {
                    project_id: project.project_id.clone(),
                    sha256: artifact_digest.clone(),
                },
                &token,
            ))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(found.content, artifact);

        let object_path = object_root
            .join(&artifact_digest[..2])
            .join(&artifact_digest[2..4])
            .join(&artifact_digest);
        std::fs::write(&object_path, b"corrupt").unwrap();
        assert_eq!(
            reopened
                .get_artifact(authorized(
                    ArtifactRequest {
                        project_id: project.project_id,
                        sha256: artifact_digest,
                    },
                    &token,
                ))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::Internal
        );
    }

    #[tokio::test]
    async fn v2_region_decompile_compile_verify_and_apply_are_digest_bound() {
        let store = Store::open(Path::new(":memory:")).unwrap();
        let token = store.create_identity("v2-analyst").unwrap();
        let project = store
            .create_project(authorized(
                CreateProjectRequest {
                    name: "v2 workflow".to_owned(),
                    idempotency_key: "create-v2".to_owned(),
                },
                &token,
            ))
            .await
            .unwrap()
            .into_inner();
        let binary = include_bytes!("../../../fuzz/corpus/elf_import/max2.elf").to_vec();
        let uploaded = store
            .upload_binary(authorized(
                UploadBinaryRequest {
                    project_id: project.project_id.clone(),
                    expected_revision: 0,
                    content_sha256: sha256(&binary),
                    content: binary.clone(),
                },
                &token,
            ))
            .await
            .unwrap()
            .into_inner();
        let region_request = api_v2::RegionRequest {
            project_id: project.project_id.clone(),
            expected_revision: uploaded.revision,
            function_symbol: "hydir_max2".to_owned(),
            assume_u64x2: true,
        };
        let region = api_v2::hydir_v2_server::HydirV2::get_region(
            &store,
            authorized(region_request.clone(), &token),
        )
        .await
        .unwrap()
        .into_inner();
        let parsed_region = hydir_core::parse_region_spec_json(&region.content).unwrap();
        assert_eq!(parsed_region.schema_version, REGION_SPEC_VERSION);

        let physical_ir = api_v2::hydir_v2_server::HydirV2::lift_region(
            &store,
            authorized(region_request.clone(), &token),
        )
        .await
        .unwrap()
        .into_inner();
        assert_eq!(
            physical_ir.media_type,
            "application/vnd.hydir.physical-region-ir+json;version=1"
        );
        let physical_ir: hydir_core::PhysicalRegionIr =
            serde_json::from_slice(&physical_ir.content).unwrap();
        hydir_core::validate_physical_region_ir(&physical_ir, &parsed_region).unwrap();

        let decompilation = api_v2::hydir_v2_server::HydirV2::decompile_region(
            &store,
            authorized(region_request, &token),
        )
        .await
        .unwrap()
        .into_inner();
        let unit: hydir_core::DecompilationUnit =
            serde_json::from_slice(&decompilation.content).unwrap();
        hydir_core::validate_decompilation_unit(&unit).unwrap();

        let patch_json = serde_json::to_vec(&hydir_patch::PatchDocument {
            schema_version: hydir_patch::PATCH_SCHEMA_VERSION,
            binary_sha256: sha256(&binary),
            function_symbol: "hydir_max2".to_owned(),
            prototype: "u64(u64,u64)".to_owned(),
            replacement: "u64 sum = arg0 + arg1;\nsum = sum - arg1;\nreturn sum;".to_owned(),
        })
        .unwrap();
        let patch_request = api_v2::PatchRequest {
            project_id: project.project_id.clone(),
            expected_revision: uploaded.revision,
            idempotency_key: "v2-patch".to_owned(),
            patch_json,
            trusted_fixture: true,
            assume_u64x2: true,
            assume_entry_only: true,
        };
        let compiled = api_v2::hydir_v2_server::HydirV2::compile_patch(
            &store,
            authorized(patch_request.clone(), &token),
        )
        .await
        .unwrap()
        .into_inner();
        let bundle = parse_patch_bundle_json(&compiled.content).unwrap();
        assert!(!bundle.stable_verified);
        assert!(bundle.typed_patch_ir.expression.is_none());
        assert!(bundle.typed_patch_ir.resolved_return.is_some());
        let verified = api_v2::hydir_v2_server::HydirV2::verify_patch(
            &store,
            authorized(
                api_v2::VerifyPatchRequest {
                    project_id: project.project_id.clone(),
                    expected_revision: uploaded.revision,
                    patch_bundle_json: compiled.content,
                },
                &token,
            ),
        )
        .await
        .unwrap()
        .into_inner();
        assert!(verified.structurally_valid);
        assert!(!verified.behavior_verified);

        let applied = api_v2::hydir_v2_server::HydirV2::apply_patch(
            &store,
            authorized(patch_request.clone(), &token),
        )
        .await
        .unwrap()
        .into_inner();
        assert_eq!(applied.revision, uploaded.revision + 1);
        assert_eq!(applied.patch_bundle_sha256, compiled.sha256);
        let replay = api_v2::hydir_v2_server::HydirV2::apply_patch(
            &store,
            authorized(patch_request, &token),
        )
        .await
        .unwrap()
        .into_inner();
        assert_eq!(replay.revision, applied.revision);
        assert_eq!(replay.binary_sha256, applied.binary_sha256);
    }

    #[tokio::test]
    async fn v3_ghidra_snapshot_artifacts_are_binary_and_revision_bound() {
        use api_v3::hydir_v3_server::HydirV3;

        let store = Store::open(Path::new(":memory:")).unwrap();
        let token = store.create_identity("ghidra-analyst").unwrap();
        let project = store
            .create_project(authorized(
                CreateProjectRequest {
                    name: "Ghidra imported analysis".to_owned(),
                    idempotency_key: "create-ghidra-import".to_owned(),
                },
                &token,
            ))
            .await
            .unwrap()
            .into_inner();
        let binary = include_bytes!("../../../demo/hydir-prism.elf").to_vec();
        let uploaded = store
            .upload_binary(authorized(
                UploadBinaryRequest {
                    project_id: project.project_id.clone(),
                    expected_revision: 0,
                    content_sha256: sha256(&binary),
                    content: binary,
                },
                &token,
            ))
            .await
            .unwrap()
            .into_inner();
        let snapshot =
            include_bytes!("../../../tests/fixtures/ghidra_prism_snapshot_v2.json").to_vec();
        let request = |stage: &str, bytes: Vec<u8>| api_v3::GhidraSnapshotArtifactRequest {
            project_id: project.project_id.clone(),
            expected_revision: uploaded.revision,
            snapshot_json: bytes,
            stage: stage.to_owned(),
            start_address: String::new(),
            instruction_index: None,
            operation_index: None,
            input_index: None,
            selected_function_entry: String::new(),
            automatic: false,
        };
        let worker_key = hydir_ghidra_worker::analysis_cache_key(&uploaded.binary_sha256, None);
        {
            let connection = store.connection().unwrap();
            assert!(
                cached_ghidra_snapshot(
                    &connection,
                    &project.project_id,
                    &uploaded.binary_sha256,
                    &worker_key,
                    None,
                )
                .unwrap()
                .is_none()
            );
            save_ghidra_snapshot(
                &connection,
                &project.project_id,
                &uploaded.binary_sha256,
                uploaded.revision,
                &worker_key,
                None,
                &snapshot,
            )
            .unwrap();
            assert_eq!(
                cached_ghidra_snapshot(
                    &connection,
                    &project.project_id,
                    &uploaded.binary_sha256,
                    &worker_key,
                    None,
                )
                .unwrap(),
                Some(snapshot.clone())
            );
            assert!(
                cached_ghidra_snapshot(
                    &connection,
                    &project.project_id,
                    &"0".repeat(64),
                    &worker_key,
                    None,
                )
                .unwrap()
                .is_none()
            );
            assert!(
                cached_ghidra_snapshot(
                    &connection,
                    &project.project_id,
                    &uploaded.binary_sha256,
                    &worker_key,
                    Some(0xdead),
                )
                .unwrap()
                .is_none()
            );
        }
        let automatic_request = api_v3::GhidraSnapshotArtifactRequest {
            automatic: true,
            ..request("snapshot", Vec::new())
        };
        let automatic_artifact =
            HydirV3::analyze_ghidra_snapshot(&store, authorized(automatic_request, &token))
                .await
                .unwrap()
                .into_inner();
        assert_eq!(
            automatic_artifact.media_type,
            ghidra_snapshot_artifact_media_type("snapshot").unwrap()
        );
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&automatic_artifact.content).unwrap()["selected_function"]
                ["entry"]["offset"],
            "0x20137c"
        );
        {
            let connection = store.connection().unwrap();
            connection
                .execute(
                    "UPDATE ghidra_snapshots SET content=x'7b7d' WHERE project_id=?1",
                    params![project.project_id],
                )
                .unwrap();
            assert!(
                cached_ghidra_snapshot(
                    &connection,
                    &project.project_id,
                    &uploaded.binary_sha256,
                    &worker_key,
                    None,
                )
                .unwrap()
                .is_none()
            );
        }
        for stage in [
            "snapshot",
            "pcode",
            "semantics",
            "state",
            "cfg",
            "coverage",
            "llvm-cfg",
            "slice",
        ] {
            let mut stage_request = request(stage, snapshot.clone());
            if stage == "llvm-cfg" {
                stage_request.start_address = "0x20137c".to_owned();
            } else if stage == "slice" {
                stage_request.instruction_index = Some(1);
                stage_request.operation_index = Some(9);
                stage_request.input_index = Some(0);
            }
            let artifact =
                HydirV3::analyze_ghidra_snapshot(&store, authorized(stage_request, &token))
                    .await
                    .unwrap()
                    .into_inner();
            assert_eq!(artifact.project_revision, uploaded.revision);
            assert_eq!(artifact.sha256, sha256(&artifact.content));
            assert_eq!(
                artifact.media_type,
                ghidra_snapshot_artifact_media_type(stage).unwrap()
            );
            let json: serde_json::Value = serde_json::from_slice(&artifact.content).unwrap();
            assert_eq!(json["binary_sha256"], uploaded.binary_sha256);
            assert_eq!(
                json["schema_version"],
                if stage == "llvm-cfg" || stage == "snapshot" {
                    2
                } else {
                    1
                }
            );
            if stage == "slice" {
                assert_eq!(json["target"]["instruction_index"], 1);
                assert_eq!(json["target"]["operation_index"], 9);
                assert_eq!(json["target"]["input_index"], 0);
                assert_eq!(json["steps"][0]["source"]["mnemonic"], "INT_EQUAL");
                assert_eq!(json["path_proven"], false);
            } else if stage == "snapshot" {
                assert!(
                    json["functions"]
                        .as_array()
                        .is_some_and(|rows| !rows.is_empty())
                );
            } else if stage != "cfg" {
                assert_eq!(json["semantic_fidelity"], "unknown");
                assert_eq!(json["verification"], "not_run");
            } else {
                assert_eq!(json["state"]["semantic_fidelity"], "unknown");
            }
            if stage == "llvm-cfg" {
                assert_eq!(json["start"]["offset"], "0x20137c");
            }
        }

        let stale = api_v3::GhidraSnapshotArtifactRequest {
            expected_revision: 0,
            ..request("pcode", snapshot.clone())
        };
        assert_eq!(
            HydirV3::analyze_ghidra_snapshot(&store, authorized(stale, &token))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::Aborted
        );

        let mut wrong: serde_json::Value = serde_json::from_slice(&snapshot).unwrap();
        wrong["binary_sha256"] = json!("0".repeat(64));
        assert_eq!(
            HydirV3::analyze_ghidra_snapshot(
                &store,
                authorized(
                    request("pcode", serde_json::to_vec(&wrong).unwrap()),
                    &token
                ),
            )
            .await
            .unwrap_err()
            .code(),
            tonic::Code::InvalidArgument
        );

        let oversized = request("pcode", vec![b' '; MAX_GHIDRA_SNAPSHOT_BYTES + 1]);
        assert_eq!(
            HydirV3::analyze_ghidra_snapshot(&store, authorized(oversized, &token))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::ResourceExhausted
        );
        let missing_snapshot = request("pcode", Vec::new());
        assert_eq!(
            HydirV3::analyze_ghidra_snapshot(&store, authorized(missing_snapshot, &token))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::InvalidArgument
        );
        let conflicting_automatic = api_v3::GhidraSnapshotArtifactRequest {
            automatic: true,
            ..request("pcode", snapshot.clone())
        };
        assert_eq!(
            HydirV3::analyze_ghidra_snapshot(&store, authorized(conflicting_automatic, &token))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::InvalidArgument
        );
        let selected_without_automatic = api_v3::GhidraSnapshotArtifactRequest {
            selected_function_entry: "0x20137c".to_owned(),
            ..request("pcode", snapshot.clone())
        };
        assert_eq!(
            HydirV3::analyze_ghidra_snapshot(
                &store,
                authorized(selected_without_automatic, &token)
            )
            .await
            .unwrap_err()
            .code(),
            tonic::Code::InvalidArgument
        );
        assert_eq!(ghidra_selected_entry("0x20137c", true), Ok(Some(0x20137c)));
        assert!(ghidra_selected_entry("0xGG", true).is_err());
        let invalid_start = api_v3::GhidraSnapshotArtifactRequest {
            start_address: "0x20137c".to_owned(),
            ..request("pcode", snapshot.clone())
        };
        assert_eq!(
            HydirV3::analyze_ghidra_snapshot(&store, authorized(invalid_start, &token))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::InvalidArgument
        );
        let missing_slice_target = request("slice", snapshot.clone());
        assert_eq!(
            HydirV3::analyze_ghidra_snapshot(&store, authorized(missing_slice_target, &token))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::InvalidArgument
        );
        let wrong_stage_target = api_v3::GhidraSnapshotArtifactRequest {
            instruction_index: Some(0),
            operation_index: Some(0),
            ..request("cfg", snapshot.clone())
        };
        assert_eq!(
            HydirV3::analyze_ghidra_snapshot(&store, authorized(wrong_stage_target, &token))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::InvalidArgument
        );
        let out_of_range_slice = api_v3::GhidraSnapshotArtifactRequest {
            instruction_index: Some(999),
            operation_index: Some(0),
            ..request("slice", snapshot.clone())
        };
        assert_eq!(
            HydirV3::analyze_ghidra_snapshot(&store, authorized(out_of_range_slice, &token))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::InvalidArgument
        );
        assert_eq!(
            HydirV3::analyze_ghidra_snapshot(
                &store,
                Request::new(request("pcode", snapshot.clone())),
            )
            .await
            .unwrap_err()
            .code(),
            tonic::Code::Unauthenticated
        );
        assert_eq!(
            HydirV3::analyze_ghidra_snapshot(
                &store,
                authorized(request("invalid", snapshot), &token),
            )
            .await
            .unwrap_err()
            .code(),
            tonic::Code::InvalidArgument
        );
    }

    #[tokio::test]
    async fn v3_native_artifacts_jobs_and_fact_updates_are_revision_bound() {
        use api_v3::hydir_v3_server::HydirV3;

        let store = Store::open(Path::new(":memory:")).unwrap();
        let token = store.create_identity("v3-analyst").unwrap();
        let project = store
            .create_project(authorized(
                CreateProjectRequest {
                    name: "v3 native workflow".to_owned(),
                    idempotency_key: "create-v3".to_owned(),
                },
                &token,
            ))
            .await
            .unwrap()
            .into_inner();
        let binary = include_bytes!("../../../fuzz/corpus/elf_import/max2.elf").to_vec();
        let uploaded = store
            .upload_binary(authorized(
                UploadBinaryRequest {
                    project_id: project.project_id.clone(),
                    expected_revision: 0,
                    content_sha256: sha256(&binary),
                    content: binary,
                },
                &token,
            ))
            .await
            .unwrap()
            .into_inner();

        let discover = HydirV3::discover(&store, authorized(api_v3::DiscoverRequest {}, &token))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(discover.api_version, 3);
        assert_eq!(discover.program_spec_version, PROGRAM_SPEC_VERSION);
        assert_eq!(discover.function_index_version, FUNCTION_INDEX_VERSION);

        let index_artifact = HydirV3::get_program_artifact(
            &store,
            authorized(
                api_v3::ProgramArtifactRequest {
                    project_id: project.project_id.clone(),
                    expected_revision: uploaded.revision,
                    stage: "function_index".to_owned(),
                    function_selector: String::new(),
                },
                &token,
            ),
        )
        .await
        .unwrap()
        .into_inner();
        let index: hydir_ir::FunctionIndex =
            serde_json::from_slice(&index_artifact.content).unwrap();
        hydir_ir::validate_function_index(&index).unwrap();
        let selector = index
            .functions
            .iter()
            .find(|function| function.name.as_deref() == Some("hydir_max2"))
            .unwrap()
            .id
            .clone();

        for stage in [
            "program_spec",
            "analysis_model",
            "coverage",
            "machine",
            "state",
            "function",
            "cir",
            "llvm",
            "unit",
        ] {
            let function_selector = if matches!(
                stage,
                "machine" | "state" | "function" | "cir" | "llvm" | "unit"
            ) {
                selector.clone()
            } else {
                String::new()
            };
            let artifact = HydirV3::get_program_artifact(
                &store,
                authorized(
                    api_v3::ProgramArtifactRequest {
                        project_id: project.project_id.clone(),
                        expected_revision: uploaded.revision,
                        stage: stage.to_owned(),
                        function_selector,
                    },
                    &token,
                ),
            )
            .await
            .unwrap()
            .into_inner();
            assert_eq!(artifact.sha256, sha256(&artifact.content));
            assert!(!artifact.content.is_empty(), "{stage} artifact is empty");
        }

        let request = api_v3::StartProgramAnalysisRequest {
            project_id: project.project_id.clone(),
            expected_revision: uploaded.revision,
            idempotency_key: "native-analysis-1".to_owned(),
        };
        let started = HydirV3::start_program_analysis(&store, authorized(request.clone(), &token))
            .await
            .unwrap()
            .into_inner();
        let replay = HydirV3::start_program_analysis(&store, authorized(request, &token))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(started.job_id, replay.job_id);
        let completed = tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let job = HydirV3::get_analysis_job(
                    &store,
                    authorized(
                        api_v3::JobRequest {
                            project_id: project.project_id.clone(),
                            job_id: started.job_id.clone(),
                        },
                        &token,
                    ),
                )
                .await
                .unwrap()
                .into_inner();
                if matches!(job.state.as_str(), "succeeded" | "failed") {
                    break job;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(completed.state, "succeeded", "{}", completed.diagnostic);
        assert!(!completed.artifact_sha256.is_empty());

        let mutation = HydirV3::update_analyst_fact(
            &store,
            authorized(
                api_v3::AnalystFactRequest {
                    project_id: project.project_id.clone(),
                    expected_revision: uploaded.revision,
                    idempotency_key: "v3-fact-1".to_owned(),
                    kind: "comment".to_owned(),
                    address: String::new(),
                    value: "native analysis reviewed".to_owned(),
                    scope: "whole binary".to_owned(),
                },
                &token,
            ),
        )
        .await
        .unwrap()
        .into_inner();
        assert_eq!(mutation.revision, uploaded.revision + 1);
        assert_eq!(mutation.binary_sha256, uploaded.binary_sha256);
    }

    #[test]
    fn v3_typed_artifact_stages_emit_versioned_model_ir_and_c() {
        use std::process::Command;
        let directory = tempfile::tempdir().unwrap();
        let fixture =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/typed_pair.c");
        let object = directory.path().join("typed_pair.o");
        let output = Command::new("clang")
            .args(["--target=x86_64-unknown-linux-gnu", "-g", "-O2", "-c"])
            .arg(&fixture)
            .arg("-o")
            .arg(&object)
            .output();
        let Ok(output) = output else {
            return;
        };
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let binary = std::fs::read(object).unwrap();
        let mut model_revision = None;
        for (stage, selector) in [
            ("analysis_model", ""),
            ("high_level_cir", "hydir_pair_sum"),
            ("typed_c", "hydir_pair_sum"),
        ] {
            let request = serde_json::to_string(&NativeArtifactSelector {
                stage: stage.to_owned(),
                function: selector.to_owned(),
            })
            .unwrap();
            let content = native_artifact(&binary, &request).unwrap();
            if stage == "typed_c" {
                assert!(String::from_utf8(content).unwrap().contains("->left"));
            } else {
                let artifact: serde_json::Value = serde_json::from_slice(&content).unwrap();
                assert_eq!(artifact["schema_version"], 1);
                if stage == "analysis_model" {
                    model_revision = artifact["revision"].as_u64();
                } else {
                    assert_eq!(artifact["model_revision"].as_u64(), model_revision);
                }
            }
            assert!(native_artifact_media_type(stage).is_some());
        }
    }

    #[test]
    fn v3_cfg_artifact_and_typed_c_cover_scalar_and_memory_loops() {
        use std::process::Command;
        let directory = tempfile::tempdir().unwrap();
        let fixture =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/typed_cfg.S");
        let object = directory.path().join("typed_cfg.o");
        let output = Command::new("clang")
            .args(["--target=x86_64-unknown-linux-gnu", "-c"])
            .arg(fixture)
            .arg("-o")
            .arg(&object)
            .output();
        let Ok(output) = output else { return };
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let binary = std::fs::read(object).unwrap();
        let json = serde_json::to_string(&NativeArtifactSelector {
            stage: "high_level_cfg_cir".to_owned(),
            function: "hydir_cfg_sum".to_owned(),
        })
        .unwrap();
        let content = native_artifact(&binary, &json).unwrap();
        let artifact: serde_json::Value = serde_json::from_slice(&content).unwrap();
        assert_eq!(artifact["schema_version"], 3);
        assert!(artifact["blocks"].as_array().unwrap().len() > 2);
        assert_eq!(
            native_artifact_media_type("high_level_cfg_cir"),
            Some("application/vnd.hydir.high-level-cfg-cir+json;version=3")
        );
        let json = serde_json::to_string(&NativeArtifactSelector {
            stage: "typed_c".to_owned(),
            function: "hydir_cfg_sum".to_owned(),
        })
        .unwrap();
        let c = String::from_utf8(native_artifact(&binary, &json).unwrap()).unwrap();
        assert!(!c.contains("goto hydir_bb_") && c.contains("while ("));
        let json = serde_json::to_string(&NativeArtifactSelector {
            stage: "high_level_cfg_cir".to_owned(),
            function: "hydir_cfg_array_sum".to_owned(),
        })
        .unwrap();
        let artifact: serde_json::Value =
            serde_json::from_slice(&native_artifact(&binary, &json).unwrap()).unwrap();
        assert_eq!(artifact["schema_version"], 3);
        assert!(artifact["blocks"].as_array().unwrap().iter().any(|block| {
            block["statements"].as_array().is_some_and(|statements| {
                statements
                    .iter()
                    .any(|statement| statement["kind"] == "load")
            })
        }));
        let json = serde_json::to_string(&NativeArtifactSelector {
            stage: "typed_c".to_owned(),
            function: "hydir_cfg_array_sum".to_owned(),
        })
        .unwrap();
        let c = String::from_utf8(native_artifact(&binary, &json).unwrap()).unwrap();
        assert!(c.contains("hydir_load_u64") && c.contains("return hydir_rax"));
    }

    #[cfg(unix)]
    #[test]
    fn database_requires_private_regular_file() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        let database = directory.path().join("projects.sqlite");
        let store = Store::open(&database).unwrap();
        drop(store);
        assert_eq!(
            std::fs::metadata(&database).unwrap().permissions().mode() & 0o077,
            0
        );
        std::fs::set_permissions(&database, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(Store::open(&database).is_err());
    }

    #[tokio::test]
    async fn identity_and_project_isolation_survive_restart() {
        let directory = tempfile::tempdir().unwrap();
        let database = directory.path().join("projects.sqlite");
        let store = Store::open(&database).unwrap();
        let alice = store.create_identity("alice").unwrap();
        let bob = store.create_identity("bob").unwrap();
        let project = store
            .create_project(authorized(
                CreateProjectRequest {
                    name: "A".to_owned(),
                    idempotency_key: "request-1".to_owned(),
                },
                &alice,
            ))
            .await
            .unwrap()
            .into_inner();
        let retry = store
            .create_project(authorized(
                CreateProjectRequest {
                    name: "A".to_owned(),
                    idempotency_key: "request-1".to_owned(),
                },
                &alice,
            ))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(project.project_id, retry.project_id);
        assert_eq!(project.revision, 0);
        let denied = store
            .get_project(authorized(
                ProjectRequest {
                    project_id: project.project_id.clone(),
                    expected_revision: 0,
                },
                &bob,
            ))
            .await
            .unwrap_err();
        assert_eq!(denied.code(), tonic::Code::NotFound);
        let unauthenticated = store
            .get_project(Request::new(ProjectRequest {
                project_id: project.project_id.clone(),
                expected_revision: 0,
            }))
            .await
            .unwrap_err();
        assert_eq!(unauthenticated.code(), tonic::Code::Unauthenticated);
        drop(store);
        let reopened = Store::open(&database).unwrap();
        let found = reopened
            .get_project(authorized(
                ProjectRequest {
                    project_id: project.project_id.clone(),
                    expected_revision: 0,
                },
                &alice,
            ))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(found.project_id, project.project_id);
    }

    #[tokio::test]
    async fn annotations_are_revisioned_private_idempotent_and_recover_after_restart() {
        let directory = tempfile::tempdir().unwrap();
        let database = directory.path().join("annotations.sqlite");
        let store = Store::open(&database).unwrap();
        let alice = store.create_identity("alice").unwrap();
        let bob = store.create_identity("bob").unwrap();
        let project = store
            .create_project(authorized(
                CreateProjectRequest {
                    name: "notes".to_owned(),
                    idempotency_key: "notes-project".to_owned(),
                },
                &alice,
            ))
            .await
            .unwrap()
            .into_inner();
        let fake_binary = b"test-binary";
        let binary_sha256 = sha256(fake_binary);
        {
            let conn = store.connection().unwrap();
            conn.execute(
                "INSERT INTO binaries(sha256,content,content_size) VALUES(?1,?2,?3)",
                params![binary_sha256, fake_binary, fake_binary.len() as i64],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO project_revisions(project_id,revision,binary_sha256) VALUES(?1,1,?2)",
                params![project.project_id, binary_sha256],
            )
            .unwrap();
            conn.execute(
                "UPDATE projects SET current_revision=1 WHERE id=?1",
                [&project.project_id],
            )
            .unwrap();
        }
        let request = AnnotationRequest {
            project_id: project.project_id.clone(),
            expected_revision: 1,
            idempotency_key: "note-1".to_owned(),
            kind: "assumption".to_owned(),
            address: String::new(),
            value: "The entry follows a trusted caller contract".to_owned(),
            scope: "whole uploaded binary".to_owned(),
        };
        let created = store
            .add_annotation(authorized(request.clone(), &alice))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(created.revision, 2);
        assert_eq!(created.binary_sha256, binary_sha256);
        let denied = store
            .list_annotations(authorized(
                ProjectRequest {
                    project_id: project.project_id.clone(),
                    expected_revision: 2,
                },
                &bob,
            ))
            .await
            .unwrap_err();
        assert_eq!(denied.code(), tonic::Code::NotFound);
        let stale = store
            .list_annotations(authorized(
                ProjectRequest {
                    project_id: project.project_id.clone(),
                    expected_revision: 1,
                },
                &alice,
            ))
            .await
            .unwrap_err();
        assert_eq!(stale.code(), tonic::Code::Aborted);
        drop(store);
        let reopened = Store::open(&database).unwrap();
        let replay = reopened
            .add_annotation(authorized(request.clone(), &alice))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(replay.revision, 2);
        let conflict = reopened
            .add_annotation(authorized(
                AnnotationRequest {
                    value: "changed".to_owned(),
                    ..request.clone()
                },
                &alice,
            ))
            .await
            .unwrap_err();
        assert_eq!(conflict.code(), tonic::Code::AlreadyExists);
        let list = reopened
            .list_annotations(authorized(
                ProjectRequest {
                    project_id: project.project_id.clone(),
                    expected_revision: 2,
                },
                &alice,
            ))
            .await
            .unwrap()
            .into_inner();
        let parsed: serde_json::Value = serde_json::from_str(&list.json).unwrap();
        assert_eq!(parsed["annotations"].as_array().unwrap().len(), 1);
        assert_eq!(parsed["annotations"][0]["kind"], "assumption");
        assert_eq!(
            parsed["annotations"][0]["provenance"]["source"],
            "analyst_assertion"
        );
        let denied = reopened
            .add_annotation(authorized(
                AnnotationRequest {
                    idempotency_key: "bob-note".to_owned(),
                    expected_revision: 2,
                    ..request
                },
                &bob,
            ))
            .await
            .unwrap_err();
        assert_eq!(denied.code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn patch_requires_assertions_and_project_ownership() {
        let store = Store::open(Path::new(":memory:")).unwrap();
        let alice = store.create_identity("alice").unwrap();
        let bob = store.create_identity("bob").unwrap();
        let project = store
            .create_project(authorized(
                CreateProjectRequest {
                    name: "patch target".to_owned(),
                    idempotency_key: "patch-project".to_owned(),
                },
                &alice,
            ))
            .await
            .unwrap()
            .into_inner();
        let request = PatchRequest {
            project_id: project.project_id,
            expected_revision: 0,
            patch_json: b"{}".to_vec(),
            idempotency_key: "patch-1".to_owned(),
            trusted_fixture: false,
            assume_u64x2: true,
            assume_entry_only: true,
        };
        let denied = store
            .apply_patch(authorized(request.clone(), &alice))
            .await
            .unwrap_err();
        assert_eq!(denied.code(), tonic::Code::InvalidArgument);
        let denied = store
            .apply_patch(authorized(
                PatchRequest {
                    trusted_fixture: true,
                    ..request
                },
                &bob,
            ))
            .await
            .unwrap_err();
        assert_eq!(denied.code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn transform_requires_assertions_and_project_ownership() {
        let store = Store::open(Path::new(":memory:")).unwrap();
        let alice = store.create_identity("alice").unwrap();
        let bob = store.create_identity("bob").unwrap();
        let project = store
            .create_project(authorized(
                CreateProjectRequest {
                    name: "transform target".to_owned(),
                    idempotency_key: "transform-project".to_owned(),
                },
                &alice,
            ))
            .await
            .unwrap()
            .into_inner();
        let request = TransformRequest {
            project_id: project.project_id,
            expected_revision: 0,
            function_symbol: "function".to_owned(),
            assume_u64x2: true,
            trusted_fixture: false,
            passes: "dce".to_owned(),
            idempotency_key: "transform-1".to_owned(),
        };
        let denied = store
            .transform(authorized(request.clone(), &alice))
            .await
            .unwrap_err();
        assert_eq!(denied.code(), tonic::Code::InvalidArgument);
        let denied = store
            .transform(authorized(
                TransformRequest {
                    trusted_fixture: true,
                    ..request
                },
                &bob,
            ))
            .await
            .unwrap_err();
        assert_eq!(denied.code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn rebuild_requires_assertion_and_project_ownership() {
        let store = Store::open(Path::new(":memory:")).unwrap();
        let alice = store.create_identity("alice").unwrap();
        let bob = store.create_identity("bob").unwrap();
        let project = store
            .create_project(authorized(
                CreateProjectRequest {
                    name: "rebuild target".to_owned(),
                    idempotency_key: "rebuild-project".to_owned(),
                },
                &alice,
            ))
            .await
            .unwrap()
            .into_inner();
        let request = RebuildRequest {
            project_id: project.project_id,
            expected_revision: 0,
            trusted_fixture: false,
            idempotency_key: "rebuild-1".to_owned(),
        };
        let denied = store
            .rebuild(authorized(request.clone(), &alice))
            .await
            .unwrap_err();
        assert_eq!(denied.code(), tonic::Code::InvalidArgument);
        let denied = store
            .rebuild(authorized(
                RebuildRequest {
                    trusted_fixture: true,
                    ..request
                },
                &bob,
            ))
            .await
            .unwrap_err();
        assert_eq!(denied.code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn malformed_upload_and_unasserted_lift_are_denied() {
        let store = Store::open(Path::new(":memory:")).unwrap();
        let token = store.create_identity("analyst").unwrap();
        let project = store
            .create_project(authorized(
                CreateProjectRequest {
                    name: "sample".to_owned(),
                    idempotency_key: "first".to_owned(),
                },
                &token,
            ))
            .await
            .unwrap()
            .into_inner();
        let bad_hash = store
            .upload_binary(authorized(
                UploadBinaryRequest {
                    project_id: project.project_id.clone(),
                    expected_revision: 0,
                    content_sha256: "0".repeat(64),
                    content: b"not an ELF".to_vec(),
                },
                &token,
            ))
            .await
            .unwrap_err();
        assert_eq!(bad_hash.code(), tonic::Code::InvalidArgument);
        let bad_elf = store
            .upload_binary(authorized(
                UploadBinaryRequest {
                    project_id: project.project_id.clone(),
                    expected_revision: 0,
                    content_sha256: sha256(b"not an ELF"),
                    content: b"not an ELF".to_vec(),
                },
                &token,
            ))
            .await
            .unwrap_err();
        assert_eq!(bad_elf.code(), tonic::Code::InvalidArgument);
        let bad_lift = store
            .lift(authorized(
                FunctionRequest {
                    project_id: project.project_id,
                    expected_revision: 0,
                    function_symbol: "f".to_owned(),
                    assume_u64x2: false,
                },
                &token,
            ))
            .await
            .unwrap_err();
        assert_eq!(bad_lift.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn token_rotation_revokes_old_credential() {
        let store = Store::open(Path::new(":memory:")).unwrap();
        let original = store.create_identity("analyst").unwrap();
        let replacement = store.rotate_identity("analyst").unwrap();
        assert_ne!(original, replacement);
        let denied = store
            .discover(authorized(DiscoverRequest {}, &original))
            .await
            .unwrap_err();
        assert_eq!(denied.code(), tonic::Code::Unauthenticated);
        store
            .discover(authorized(DiscoverRequest {}, &replacement))
            .await
            .unwrap();
    }

    #[test]
    fn newer_database_version_is_rejected() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("newer.sqlite");
        drop(Store::open(&path).unwrap());
        Connection::open(&path)
            .unwrap()
            .execute_batch("PRAGMA user_version=12;")
            .unwrap();
        let error = Store::open(&path).err().unwrap().to_string();
        assert!(error.contains("newer"));
    }

    #[cfg(unix)]
    #[test]
    fn version_one_database_migrates_without_losing_projects() {
        use std::os::unix::fs::OpenOptionsExt;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("v1.sqlite");
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        let connection = Connection::open(&path).unwrap();
        connection.execute_batch(SCHEMA).unwrap();
        connection
            .execute(
                "INSERT INTO identities(principal,token_sha256) VALUES('alice','digest')",
                [],
            )
            .unwrap();
        connection.execute("INSERT INTO projects(id,owner,name,idempotency_key) VALUES('p','alice','existing','key')", []).unwrap();
        drop(connection);
        let store = Store::open(&path).unwrap();
        let version: i64 = store
            .connection()
            .unwrap()
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(version, 11);
        let foreign_key_errors: i64 = store
            .connection()
            .unwrap()
            .query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(foreign_key_errors, 0);
        store
            .connection()
            .unwrap()
            .execute(
                "INSERT INTO binaries(sha256,content,storage_kind,storage_key,content_size) VALUES(?1,x'','s3',?2,1)",
                params!["0".repeat(64), "sha256/00/00/fixture"],
            )
            .unwrap();
        assert_eq!(store.project("alice", "p").unwrap().name, "existing");
        assert_eq!(
            store
                .require_project_role("alice", "p", ProjectRole::Admin)
                .unwrap(),
            ProjectRole::Admin
        );
    }

    #[tokio::test]
    async fn project_roles_are_ordered_persistent_and_audited() {
        let directory = tempfile::tempdir().unwrap();
        let database = directory.path().join("roles.sqlite");
        let store = Store::open(&database).unwrap();
        let alice = store.create_identity("alice").unwrap();
        let bob = store.create_identity("bob").unwrap();
        store.create_identity("carol").unwrap();
        let project = store
            .create_project(authorized(
                CreateProjectRequest {
                    name: "shared".to_owned(),
                    idempotency_key: "shared-1".to_owned(),
                },
                &alice,
            ))
            .await
            .unwrap()
            .into_inner();

        store
            .set_project_role(
                "alice",
                &project.project_id,
                "bob",
                Some(ProjectRole::Viewer),
            )
            .unwrap();
        assert!(store.project("bob", &project.project_id).is_ok());
        assert!(
            store
                .get_project(authorized(
                    ProjectRequest {
                        project_id: project.project_id.clone(),
                        expected_revision: 0,
                    },
                    &bob,
                ))
                .await
                .is_ok()
        );
        let denied_upload = store
            .upload_binary(authorized(
                UploadBinaryRequest {
                    project_id: project.project_id.clone(),
                    expected_revision: 0,
                    content: b"not an ELF".to_vec(),
                    content_sha256: sha256(b"not an ELF"),
                },
                &bob,
            ))
            .await
            .unwrap_err();
        assert_eq!(denied_upload.code(), tonic::Code::PermissionDenied);
        let denied_analysis = store
            .inspect(authorized(
                ProjectRequest {
                    project_id: project.project_id.clone(),
                    expected_revision: 0,
                },
                &bob,
            ))
            .await
            .unwrap_err();
        assert_eq!(denied_analysis.code(), tonic::Code::PermissionDenied);
        assert_eq!(
            store
                .require_project_role("bob", &project.project_id, ProjectRole::Analyst)
                .unwrap_err()
                .code(),
            tonic::Code::PermissionDenied
        );
        store
            .set_project_role(
                "alice",
                &project.project_id,
                "bob",
                Some(ProjectRole::Analyst),
            )
            .unwrap();
        assert!(
            store
                .require_project_role("bob", &project.project_id, ProjectRole::Analyst)
                .is_ok()
        );
        let analysis_without_binary = store
            .inspect(authorized(
                ProjectRequest {
                    project_id: project.project_id.clone(),
                    expected_revision: 0,
                },
                &bob,
            ))
            .await
            .unwrap_err();
        assert_eq!(
            analysis_without_binary.code(),
            tonic::Code::FailedPrecondition
        );
        assert!(
            store
                .set_project_role(
                    "bob",
                    &project.project_id,
                    "carol",
                    Some(ProjectRole::Viewer)
                )
                .is_err()
        );
        assert!(
            store
                .set_project_role("alice", &project.project_id, "alice", None)
                .is_err()
        );
        assert_eq!(
            store
                .project_access("alice", &project.project_id)
                .unwrap()
                .len(),
            2
        );
        let audit_count: i64 = store
            .connection()
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM audit_events WHERE project_id=?1",
                [&project.project_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(audit_count, 3);
        drop(store);

        let reopened = Store::open(&database).unwrap();
        assert_eq!(
            reopened
                .require_project_role("bob", &project.project_id, ProjectRole::Analyst)
                .unwrap(),
            ProjectRole::Analyst
        );
    }

    #[tokio::test]
    async fn lift_jobs_are_idempotent_replayable_and_isolated() {
        use tokio_stream::StreamExt;
        let store = Store::open(Path::new(":memory:")).unwrap();
        let alice = store.create_identity("alice").unwrap();
        let bob = store.create_identity("bob").unwrap();
        let project = store
            .create_project(authorized(
                CreateProjectRequest {
                    name: "jobs".to_owned(),
                    idempotency_key: "project-1".to_owned(),
                },
                &alice,
            ))
            .await
            .unwrap()
            .into_inner();
        let bytes = b"not an ELF";
        {
            let conn = store.connection().unwrap();
            conn.execute(
                "INSERT INTO binaries(sha256,content,content_size) VALUES(?1,?2,?3)",
                params![sha256(bytes), bytes, bytes.len() as i64],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO project_revisions(project_id,revision,binary_sha256) VALUES(?1,1,?2)",
                params![project.project_id, sha256(bytes)],
            )
            .unwrap();
            conn.execute(
                "UPDATE projects SET current_revision=1 WHERE id=?1",
                [&project.project_id],
            )
            .unwrap();
        }
        let request = StartLiftJobRequest {
            project_id: project.project_id.clone(),
            expected_revision: 1,
            function_symbol: "f".to_owned(),
            assume_u64x2: true,
            idempotency_key: "lift-1".to_owned(),
        };
        let job = store
            .start_lift_job(authorized(request.clone(), &alice))
            .await
            .unwrap()
            .into_inner();
        let retry = store
            .start_lift_job(authorized(request, &alice))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(job.job_id, retry.job_id);
        let conflict = store
            .start_lift_job(authorized(
                StartLiftJobRequest {
                    function_symbol: "other".to_owned(),
                    ..StartLiftJobRequest {
                        project_id: project.project_id.clone(),
                        expected_revision: 1,
                        function_symbol: "f".to_owned(),
                        assume_u64x2: true,
                        idempotency_key: "lift-1".to_owned(),
                    }
                },
                &alice,
            ))
            .await
            .unwrap_err();
        assert_eq!(conflict.code(), tonic::Code::AlreadyExists);
        let denied = store
            .get_job(authorized(
                JobRequest {
                    project_id: project.project_id.clone(),
                    job_id: job.job_id.clone(),
                },
                &bob,
            ))
            .await
            .unwrap_err();
        assert_eq!(denied.code(), tonic::Code::NotFound);
        let mut stream = store
            .stream_job_events(authorized(
                JobEventRequest {
                    project_id: project.project_id.clone(),
                    job_id: job.job_id.clone(),
                    after_sequence: 0,
                },
                &alice,
            ))
            .await
            .unwrap()
            .into_inner();
        let mut states = Vec::new();
        while let Some(event) = tokio::time::timeout(Duration::from_secs(5), stream.next())
            .await
            .unwrap()
        {
            states.push(event.unwrap().state);
        }
        assert_eq!(states.first().unwrap(), "queued");
        assert_eq!(states.last().unwrap(), "failed");
        let terminal = store
            .get_job(authorized(
                JobRequest {
                    project_id: project.project_id.clone(),
                    job_id: job.job_id.clone(),
                },
                &alice,
            ))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(terminal.state, "failed");
        let replay = store
            .stream_job_events(authorized(
                JobEventRequest {
                    project_id: project.project_id.clone(),
                    job_id: job.job_id,
                    after_sequence: 0,
                },
                &alice,
            ))
            .await
            .unwrap()
            .into_inner()
            .collect::<Vec<_>>()
            .await;
        assert_eq!(replay.len(), states.len());
    }

    #[tokio::test]
    async fn cancelled_job_is_not_resurrected_and_restart_interrupts_running() {
        let directory = tempfile::tempdir().unwrap();
        let database = directory.path().join("jobs.sqlite");
        let store = Store::open(&database).unwrap();
        let token = store.create_identity("alice").unwrap();
        let project = store
            .create_project(authorized(
                CreateProjectRequest {
                    name: "recovery".to_owned(),
                    idempotency_key: "recovery-1".to_owned(),
                },
                &token,
            ))
            .await
            .unwrap()
            .into_inner();
        {
            let conn = store.connection().unwrap();
            conn.execute("INSERT INTO jobs(id,project_id,revision,kind,symbol,idempotency_key,state) VALUES('cancel-me',?1,0,'lift','f','key-a','queued')", [&project.project_id]).unwrap();
            conn.execute("INSERT INTO jobs(id,project_id,revision,kind,symbol,idempotency_key,state) VALUES('interrupt-me',?1,0,'lift','f','key-b','running')", [&project.project_id]).unwrap();
        }
        let handle = tokio::spawn(std::future::pending::<()>());
        let observer = handle.abort_handle();
        store
            .workers
            .lock()
            .unwrap()
            .insert("cancel-me".to_owned(), handle);
        let cancelled = store
            .cancel_job(authorized(
                JobRequest {
                    project_id: project.project_id.clone(),
                    job_id: "cancel-me".to_owned(),
                },
                &token,
            ))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(cancelled.state, "cancelled");
        assert!(observer.is_finished());
        assert!(
            !store
                .transition_job("cancel-me", "queued", "running", "late worker")
                .unwrap()
        );
        drop(store);
        let reopened = Store::open(&database).unwrap();
        assert_eq!(
            reopened
                .job("alice", &project.project_id, "cancel-me")
                .unwrap()
                .state,
            "cancelled"
        );
        assert_eq!(
            reopened
                .job("alice", &project.project_id, "interrupt-me")
                .unwrap()
                .state,
            "interrupted"
        );
    }
}
