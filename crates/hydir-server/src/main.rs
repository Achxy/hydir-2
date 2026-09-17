//! Local-only, authenticated HydIR RPC slice. No sample execution endpoint.

use hydir_analysis::analyze_elf;
use hydir_api::v1::{
    ArtifactReply, ArtifactRequest, CreateProjectRequest, DiscoverReply, DiscoverRequest,
    FunctionRequest, JobEvent, JobEventRequest, JobReply, JobRequest, JsonReply, PatchReply,
    PatchRequest, ProjectReply, ProjectRequest, RebuildReply, RebuildRequest, SourceReply,
    SourceRequest, StartLiftJobRequest, TransformReply, TransformRequest, UploadBinaryRequest,
    hydir_server::{Hydir, HydirServer},
};
use hydir_backend::{MAX_BINARY_BYTES, import_elf, lift_symbol, recover_symbol_cfg};
use hydir_c::emit_c;
use hydir_patch::{MAX_PATCH_BYTES, parse_patch_json, patch_binary};
use hydir_recompile::rebuild_bytes;
use hydir_transform::{parse_passes, transform};
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::json;
use sha2::{Digest, Sha256};
#[cfg(not(test))]
use std::process::Stdio;
use std::{
    collections::HashMap,
    env,
    error::Error,
    io::{Read, Write},
    net::SocketAddr,
    path::Path,
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
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status, transport::Server};
use uuid::Uuid;

include!(concat!(env!("OUT_DIR"), "/source_offer.rs"));

const MAX_WORKER_OUTPUT: usize = 16 * 1024 * 1024;
const MAX_ACTIVE_JOBS_PER_IDENTITY: i64 = 2;
#[cfg(not(test))]
const WORKER_DEADLINE: Duration = Duration::from_secs(30);

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

#[derive(Clone)]
struct Store {
    db: Arc<Mutex<Connection>>,
    workers: Arc<Mutex<HashMap<String, JoinHandle<()>>>>,
}

impl Store {
    fn open(path: &Path) -> Result<Self, Box<dyn Error>> {
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
        if version > 5 {
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
        connection.execute_batch("BEGIN IMMEDIATE;
          INSERT INTO job_events(job_id,state,message) SELECT id,'interrupted','server restarted before completion'
          FROM jobs WHERE state IN ('queued','running');
          UPDATE jobs SET state='interrupted',diagnostic='server restarted before completion'
          WHERE state IN ('queued','running');
          COMMIT;")?;
        Ok(Self {
            db: Arc::new(Mutex::new(connection)),
            workers: Arc::new(Mutex::new(HashMap::new())),
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
            || !principal
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        {
            return Err(
                "principal must be 1..=128 ASCII letters, digits, underscore, or hyphen".into(),
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

    fn principal<T>(&self, request: &Request<T>) -> Result<String, Status> {
        let bearer = request
            .metadata()
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
            .filter(|value| value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit()))
            .ok_or_else(|| Status::unauthenticated("missing or invalid bearer credential"))?;
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

    fn project(&self, principal: &str, id: &str) -> Result<ProjectReply, Status> {
        let conn = self.connection()?;
        let row: Option<(String, String, i64, Option<String>)> = conn
            .query_row(
                "SELECT p.id,p.name,p.current_revision,r.binary_sha256 \
             FROM projects p LEFT JOIN project_revisions r \
             ON r.project_id=p.id AND r.revision=p.current_revision \
             WHERE p.id=?1 AND p.owner=?2",
                params![id, principal],
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

    fn current_binary(&self, principal: &str, id: &str, revision: u64) -> Result<Vec<u8>, Status> {
        let project = self.project(principal, id)?;
        if project.revision != revision {
            return Err(Status::aborted("stale project revision"));
        }
        if project.binary_sha256.is_empty() {
            return Err(Status::failed_precondition(
                "project has no uploaded binary",
            ));
        }
        self.connection()?.query_row(
            "SELECT b.content FROM project_revisions r JOIN binaries b ON b.sha256=r.binary_sha256 \
             WHERE r.project_id=?1 AND r.revision=?2",
            params![id, revision as i64],
            |row| row.get(0),
        ).map_err(internal)
    }

    fn job(&self, principal: &str, project_id: &str, job_id: &str) -> Result<JobReply, Status> {
        let row = self
            .connection()?
            .query_row(
                "SELECT j.project_id,j.id,j.revision,j.kind,j.state,j.artifact_sha256,j.diagnostic \
             FROM jobs j JOIN projects p ON p.id=j.project_id \
             WHERE j.id=?1 AND j.project_id=?2 AND p.owner=?3",
                params![job_id, project_id, principal],
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

    fn finish_lift_job(
        &self,
        job_id: &str,
        project_id: &str,
        revision: u64,
        result: Result<Vec<u8>, Status>,
    ) -> Result<(), Status> {
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
        match result {
            Ok(content) => {
                let digest = sha256(&content);
                tx.execute(
                    "INSERT OR IGNORE INTO artifacts(project_id,revision,sha256,media_type,content) VALUES(?1,?2,?3,'text/x-llvm-ir',?4)",
                    params![project_id, revision as i64, digest, content],
                ).map_err(internal)?;
                tx.execute(
                    "UPDATE jobs SET state='succeeded',artifact_sha256=?1 WHERE id=?2",
                    params![digest, job_id],
                )
                .map_err(internal)?;
                insert_event(&tx, job_id, "succeeded", "LLVM IR artifact ready", &digest)?;
            }
            Err(error) => {
                let diagnostic: String = error.message().chars().take(4096).collect();
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
        if let Err(error) = self.finish_lift_job(&job_id, &project_id, revision, result) {
            eprintln!("hydird job completion failed: {error}");
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

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
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

fn worker_operation(action: &str, symbol: Option<&str>, bytes: &[u8]) -> Result<Vec<u8>, String> {
    match (action, symbol) {
        ("inspect", None) => import_elf(bytes)
            .map_err(|error| error.to_string())
            .and_then(|spec| serde_json::to_vec(&spec).map_err(|error| error.to_string())),
        ("analyze", None) => analyze_elf(bytes)
            .map_err(|error| error.to_string())
            .and_then(|report| serde_json::to_vec(&report).map_err(|error| error.to_string())),
        ("cfg", Some(symbol)) => recover_symbol_cfg(bytes, symbol)
            .map_err(|error| error.to_string())
            .and_then(|cfg| serde_json::to_vec(&cfg).map_err(|error| error.to_string())),
        ("lift", Some(symbol)) => lift_symbol(bytes, symbol)
            .map(String::into_bytes)
            .map_err(|error| error.to_string()),
        ("decompile", Some(symbol)) => lift_symbol(bytes, symbol)
            .map_err(|error| error.to_string())
            .and_then(|ir| emit_c(&ir))
            .map(String::into_bytes),
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
        _ => Err("unsupported worker operation".to_owned()),
    }
}

#[cfg(test)]
async fn run_worker(action: &str, symbol: Option<&str>, bytes: Vec<u8>) -> Result<Vec<u8>, Status> {
    if let Some(symbol) = symbol {
        valid_symbol(symbol)?;
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
    let mut command = Command::new(executable);
    command.arg("worker").arg(action);
    command.env_clear();
    if let Some(symbol) = symbol {
        valid_symbol(symbol)?;
        command.arg(symbol);
    }
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
            let id =
                if let Some(id) = prior {
                    id
                } else {
                    let id = Uuid::new_v4().to_string();
                    transaction.execute(
                    "INSERT INTO projects(id,owner,name,idempotency_key) VALUES(?1,?2,?3,?4)",
                    params![id, principal, input.name, input.idempotency_key],
                ).map_err(internal)?;
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
        let expected = i64::try_from(input.expected_revision)
            .map_err(|_| Status::invalid_argument("revision too large"))?;
        {
            let mut conn = self.connection()?;
            let tx = conn.transaction().map_err(internal)?;
            let current: Option<i64> = tx
                .query_row(
                    "SELECT current_revision FROM projects WHERE id=?1 AND owner=?2",
                    params![input.project_id, principal],
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
            tx.execute(
                "INSERT OR IGNORE INTO binaries(sha256,content) VALUES(?1,?2)",
                params![digest, input.content],
            )
            .map_err(internal)?;
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
        let bytes = self.current_binary(&principal, &input.project_id, input.expected_revision)?;
        let spec = run_worker("inspect", None, bytes).await?;
        Ok(Response::new(JsonReply {
            json: String::from_utf8(spec)
                .map_err(|_| Status::internal("worker returned non-UTF-8 program model"))?,
        }))
    }

    async fn analyze(
        &self,
        request: Request<ProjectRequest>,
    ) -> Result<Response<JsonReply>, Status> {
        let principal = self.principal(&request)?;
        let input = request.into_inner();
        let bytes = self.current_binary(&principal, &input.project_id, input.expected_revision)?;
        let report = run_worker("analyze", None, bytes).await?;
        Ok(Response::new(JsonReply {
            json: String::from_utf8(report)
                .map_err(|_| Status::internal("worker returned non-UTF-8 analysis"))?,
        }))
    }

    async fn recover_cfg(
        &self,
        request: Request<FunctionRequest>,
    ) -> Result<Response<JsonReply>, Status> {
        let principal = self.principal(&request)?;
        let input = request.into_inner();
        valid_symbol(&input.function_symbol)?;
        let bytes = self.current_binary(&principal, &input.project_id, input.expected_revision)?;
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
        if !input.assume_u64x2 {
            return Err(Status::invalid_argument(
                "explicit u64(u64,u64) prototype assertion required",
            ));
        }
        valid_symbol(&input.function_symbol)?;
        let bytes = self.current_binary(&principal, &input.project_id, input.expected_revision)?;
        let content = run_worker("lift", Some(&input.function_symbol), bytes).await?;
        let digest = sha256(&content);
        self.connection()?.execute(
            "INSERT OR IGNORE INTO artifacts(project_id,revision,sha256,media_type,content) VALUES(?1,?2,?3,?4,?5)",
            params![input.project_id, input.expected_revision as i64, digest, "text/x-llvm-ir", content],
        ).map_err(internal)?;
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
        if !input.assume_u64x2 {
            return Err(Status::invalid_argument(
                "explicit u64(u64,u64) prototype assertion required",
            ));
        }
        valid_symbol(&input.function_symbol)?;
        let bytes = self.current_binary(&principal, &input.project_id, input.expected_revision)?;
        let content = run_worker("decompile", Some(&input.function_symbol), bytes).await?;
        let digest = sha256(&content);
        self.connection()?.execute(
            "INSERT OR IGNORE INTO artifacts(project_id,revision,sha256,media_type,content) VALUES(?1,?2,?3,?4,?5)",
            params![input.project_id, input.expected_revision as i64, digest, "text/x-csrc", content],
        ).map_err(internal)?;
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
        let binary = self.current_binary(&principal, &input.project_id, input.expected_revision)?;
        let binary_sha256 = sha256(&binary);
        let mut envelope = Vec::with_capacity(1 + input.passes.len() + binary.len());
        envelope.push(pass_length);
        envelope.extend_from_slice(input.passes.as_bytes());
        envelope.extend_from_slice(&binary);
        let packed = run_worker("transform", Some(&input.function_symbol), envelope).await?;
        let parts = unpack_worker_parts::<4>(&packed)?;
        let report_json = String::from_utf8(parts[3].to_vec())
            .map_err(|_| Status::internal("transform report is not UTF-8"))?;
        let digests = parts.map(sha256);
        let next = expected
            .checked_add(1)
            .ok_or_else(|| Status::out_of_range("project revision overflow"))?;
        {
            let mut conn = self.connection()?;
            let tx = conn.transaction().map_err(internal)?;
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
                    "SELECT current_revision FROM projects WHERE id=?1 AND owner=?2",
                    params![input.project_id, principal],
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
            for (index, (media_type, part)) in [
                ("text/x-llvm-ir", parts[0]),
                ("text/x-llvm-ir", parts[1]),
                ("text/x-llvm-ir", parts[2]),
                ("application/json", parts[3]),
            ]
            .into_iter()
            .enumerate()
            {
                tx.execute(
                    "INSERT OR IGNORE INTO artifacts(project_id,revision,sha256,media_type,content) VALUES(?1,?2,?3,?4,?5)",
                    params![input.project_id, next, digests[index], media_type, part],
                ).map_err(internal)?;
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
        let binary = self.current_binary(&principal, &input.project_id, input.expected_revision)?;
        let packed = run_worker("rebuild", None, binary).await?;
        let parts = unpack_worker_parts::<3>(&packed)?;
        run_worker("inspect", None, parts[1].to_vec()).await?;
        let report_json = String::from_utf8(parts[2].to_vec())
            .map_err(|_| Status::internal("rebuild report is not UTF-8"))?;
        let ir_sha256 = sha256(parts[0]);
        let binary_sha256 = sha256(parts[1]);
        let report_sha256 = sha256(parts[2]);
        let next = expected
            .checked_add(1)
            .ok_or_else(|| Status::out_of_range("project revision overflow"))?;
        {
            let mut conn = self.connection()?;
            let tx = conn.transaction().map_err(internal)?;
            if let Some(prior) =
                rebuild_replay(&tx, &input.project_id, &input.idempotency_key, expected)?
            {
                return Ok(Response::new(prior));
            }
            let current: i64 = tx
                .query_row(
                    "SELECT current_revision FROM projects WHERE id=?1 AND owner=?2",
                    params![input.project_id, principal],
                    |row| row.get(0),
                )
                .map_err(internal)?;
            if current != expected {
                return Err(Status::aborted("stale project revision"));
            }
            tx.execute(
                "INSERT OR IGNORE INTO binaries(sha256,content) VALUES(?1,?2)",
                params![binary_sha256, parts[1]],
            )
            .map_err(internal)?;
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
            for (digest, media_type, content) in [
                (&ir_sha256, "text/x-llvm-ir", parts[0]),
                (&binary_sha256, "application/x-elf", parts[1]),
                (&report_sha256, "application/json", parts[2]),
            ] {
                tx.execute(
                    "INSERT OR IGNORE INTO artifacts(project_id,revision,sha256,media_type,content) VALUES(?1,?2,?3,?4,?5)",
                    params![input.project_id, next, digest, media_type, content],
                )
                .map_err(internal)?;
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
        let binary = self.current_binary(&principal, &input.project_id, input.expected_revision)?;
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
        let binary_sha256 = sha256(&patched);
        let next = expected
            .checked_add(1)
            .ok_or_else(|| Status::out_of_range("project revision overflow"))?;
        {
            let mut conn = self.connection()?;
            let tx = conn.transaction().map_err(internal)?;
            let raced: Option<(i64, String, i64, String)> = tx
                .query_row(
                    "SELECT expected_revision,patch_sha256,new_revision,binary_sha256 FROM patch_requests WHERE project_id=?1 AND idempotency_key=?2",
                    params![input.project_id, input.idempotency_key],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )
                .optional()
                .map_err(internal)?;
            if let Some((prior_expected, prior_digest, revision, prior_binary_sha)) = raced {
                if prior_expected != expected || prior_digest != patch_digest {
                    return Err(Status::already_exists(
                        "idempotency key belongs to a different patch request",
                    ));
                }
                return Ok(Response::new(PatchReply {
                    project_id: input.project_id,
                    revision: revision as u64,
                    artifact_sha256: prior_binary_sha.clone(),
                    binary_sha256: prior_binary_sha,
                }));
            }
            let current: i64 = tx
                .query_row(
                    "SELECT current_revision FROM projects WHERE id=?1 AND owner=?2",
                    params![input.project_id, principal],
                    |row| row.get(0),
                )
                .map_err(internal)?;
            if current != expected {
                return Err(Status::aborted("stale project revision"));
            }
            tx.execute(
                "INSERT OR IGNORE INTO binaries(sha256,content) VALUES(?1,?2)",
                params![binary_sha256, patched],
            )
            .map_err(internal)?;
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
            tx.execute(
                "INSERT INTO artifacts(project_id,revision,sha256,media_type,content) SELECT ?1,?2,sha256,'application/x-elf',content FROM binaries WHERE sha256=?3",
                params![input.project_id, next, binary_sha256],
            )
            .map_err(internal)?;
            tx.execute(
                "INSERT INTO patch_requests(project_id,idempotency_key,expected_revision,patch_sha256,new_revision,binary_sha256) VALUES(?1,?2,?3,?4,?5,?6)",
                params![input.project_id, input.idempotency_key, expected, patch_digest, next, binary_sha256],
            )
            .map_err(internal)?;
            tx.commit().map_err(internal)?;
        }
        Ok(Response::new(PatchReply {
            project_id: input.project_id,
            revision: next as u64,
            artifact_sha256: binary_sha256.clone(),
            binary_sha256,
        }))
    }

    async fn get_artifact(
        &self,
        request: Request<ArtifactRequest>,
    ) -> Result<Response<ArtifactReply>, Status> {
        let principal = self.principal(&request)?;
        let input = request.into_inner();
        if input.sha256.len() != 64 || !input.sha256.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(Status::invalid_argument(
                "artifact digest must be SHA-256 hex",
            ));
        }
        let record: Option<(i64, String, Vec<u8>)> = self
            .connection()?
            .query_row(
                "SELECT a.revision,a.media_type,a.content FROM artifacts a \
             JOIN projects p ON p.id=a.project_id \
             WHERE a.project_id=?1 AND a.sha256=?2 AND p.owner=?3 \
             ORDER BY a.revision DESC LIMIT 1",
                params![input.project_id, input.sha256, principal],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(internal)?;
        let (revision, media_type, content) =
            record.ok_or_else(|| Status::not_found("artifact not found"))?;
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
        let bytes = self.current_binary(&principal, &input.project_id, input.expected_revision)?;
        let id = Uuid::new_v4().to_string();
        {
            let mut conn = self.connection()?;
            let tx = conn.transaction().map_err(internal)?;
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
                    "SELECT current_revision FROM projects WHERE id=?1 AND owner=?2",
                    params![input.project_id, principal],
                    |row| row.get(0),
                )
                .map_err(internal)?;
            if current != expected {
                return Err(Status::aborted("stale project revision"));
            }
            let active: i64 = tx
                .query_row(
                    "SELECT COUNT(*) FROM jobs j JOIN projects p ON p.id=j.project_id \
                 WHERE p.owner=?1 AND j.state IN ('queued','running')",
                    [principal.as_str()],
                    |row| row.get(0),
                )
                .map_err(internal)?;
            if active >= MAX_ACTIVE_JOBS_PER_IDENTITY {
                return Err(Status::resource_exhausted("identity has two active jobs"));
            }
            tx.execute(
                "INSERT INTO jobs(id,project_id,revision,kind,symbol,idempotency_key,state) \
                 VALUES(?1,?2,?3,'lift',?4,?5,'queued')",
                params![
                    id,
                    input.project_id,
                    expected,
                    input.function_symbol,
                    input.idempotency_key
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
        self.job(&principal, &input.project_id, &input.job_id)?;
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
        let token = request
            .metadata()
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            .ok_or_else(|| Status::unauthenticated("credential missing"))?;
        let token_digest = sha256(token.strip_prefix("Bearer ").unwrap_or_default().as_bytes());
        let input = request.into_inner();
        self.job(&principal, &input.project_id, &input.job_id)?;
        let mut cursor = i64::try_from(input.after_sequence)
            .map_err(|_| Status::invalid_argument("event sequence too large"))?;
        let store = self.clone();
        let (sender, receiver) = mpsc::channel(32);
        tokio::spawn(async move {
            loop {
                let snapshot: Result<(Vec<JobEvent>, bool), Status> = (|| {
                    let conn = store.connection()?;
                    let credential_valid: bool = conn.query_row(
                        "SELECT EXISTS(SELECT 1 FROM identities WHERE principal=?1 AND token_sha256=?2)",
                        params![principal, token_digest],
                        |row| row.get(0),
                    ).map_err(internal)?;
                    if !credential_valid {
                        return Err(Status::unauthenticated("credential was revoked"));
                    }
                    let state: String = conn
                        .query_row(
                            "SELECT j.state FROM jobs j JOIN projects p ON p.id=j.project_id \
                         WHERE j.id=?1 AND j.project_id=?2 AND p.owner=?3",
                            params![input.job_id, input.project_id, principal],
                            |row| row.get(0),
                        )
                        .map_err(internal)?;
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
            Server::builder()
                .add_service(HydirServer::new(store).max_decoding_message_size(MAX_BINARY_BYTES + 1024).max_encoding_message_size(MAX_BINARY_BYTES + 1024))
                .serve(address)
                .await?;
        }
        _ => return Err("Usage: hydird identity create|rotate <database.sqlite> <principal> | hydird serve <database.sqlite> <loopback-host:port>".into()),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn authorized<T>(value: T, token: &str) -> Request<T> {
        let mut request = Request::new(value);
        request
            .metadata_mut()
            .insert("authorization", format!("Bearer {token}").parse().unwrap());
        request
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
            .execute_batch("PRAGMA user_version=6;")
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
        assert_eq!(version, 5);
        assert_eq!(store.project("alice", "p").unwrap().name, "existing");
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
                "INSERT INTO binaries(sha256,content) VALUES(?1,?2)",
                params![sha256(bytes), bytes],
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
