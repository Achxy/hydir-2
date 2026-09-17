//! Local-only, authenticated HydIR RPC slice. No sample execution endpoint.

use hydir_api::v1::{
    ArtifactReply, ArtifactRequest, CreateProjectRequest, DiscoverReply, DiscoverRequest,
    FunctionRequest, JsonReply, ProjectReply, ProjectRequest, UploadBinaryRequest,
    hydir_server::{Hydir, HydirServer},
};
use hydir_backend::{MAX_BINARY_BYTES, import_elf, lift_symbol, recover_symbol_cfg};
use rusqlite::{Connection, OptionalExtension, params};
use sha2::{Digest, Sha256};
use std::{
    env,
    error::Error,
    io::{Read, Write},
    net::SocketAddr,
    path::Path,
    sync::{Arc, Mutex},
};
#[cfg(not(test))]
use std::{process::Stdio, time::Duration};
#[cfg(not(test))]
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    process::Command,
};
use tonic::{Request, Response, Status, transport::Server};
use uuid::Uuid;

const MAX_WORKER_OUTPUT: usize = 16 * 1024 * 1024;
#[cfg(not(test))]
const WORKER_DEADLINE: Duration = Duration::from_secs(30);

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

#[derive(Clone)]
struct Store(Arc<Mutex<Connection>>);

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
        if version > 1 {
            return Err("database schema is newer than this hydird build".into());
        }
        if version == 0 {
            connection.execute_batch(SCHEMA)?;
        }
        Ok(Self(Arc::new(Mutex::new(connection))))
    }

    fn connection(&self) -> Result<std::sync::MutexGuard<'_, Connection>, Status> {
        self.0
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
        self.0
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
            .0
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

fn worker_operation(action: &str, symbol: Option<&str>, bytes: &[u8]) -> Result<Vec<u8>, String> {
    match (action, symbol) {
        ("inspect", None) => import_elf(bytes)
            .map_err(|error| error.to_string())
            .and_then(|spec| serde_json::to_vec(&spec).map_err(|error| error.to_string())),
        ("cfg", Some(symbol)) => recover_symbol_cfg(bytes, symbol)
            .map_err(|error| error.to_string())
            .and_then(|cfg| serde_json::to_vec(&cfg).map_err(|error| error.to_string())),
        ("lift", Some(symbol)) => lift_symbol(bytes, symbol)
            .map(String::into_bytes)
            .map_err(|error| error.to_string()),
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
    if let Some(symbol) = symbol {
        valid_symbol(symbol)?;
        command.arg(symbol);
    }
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .map_err(|_| Status::internal("analysis worker could not start"))?;
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
                "analysis worker rejected input: {}",
                diagnostic.trim()
            )));
        }
        Ok(output)
    })
    .await;
    writer.abort();
    match result {
        Ok(result) => result,
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
            source_status: "Local source checkout only; no public release or remote source offer"
                .to_owned(),
            native_elf_import: true,
            scalar_direct_cfg_lift: true,
            execution_validation: false,
            max_binary_bytes: MAX_BINARY_BYTES as u64,
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
        Connection::open(&path)
            .unwrap()
            .execute_batch("PRAGMA user_version=2;")
            .unwrap();
        assert!(Store::open(&path).is_err());
    }
}
