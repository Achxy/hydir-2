//! Private, path-bound local projects. Original ELF bytes are never stored or modified here.

use hydir_core::{
    Address, AnalystAnnotation, AnnotationKind, FactProvenance, FactSource, ProgramSpec,
    annotation_address_in_spec, parse_annotation_address, validate_analyst_annotation,
};
use hydir_model::{AnalysisModel, MAX_MODEL_BYTES, parse_model, validate_model};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
    time::Duration,
};
use uuid::Uuid;

const MAX_BINARY_BYTES: usize = 64 * 1024 * 1024;

const SCHEMA: &str = "CREATE TABLE local_projects (
    id TEXT PRIMARY KEY,
    canonical_path TEXT NOT NULL UNIQUE,
    current_revision INTEGER NOT NULL CHECK(current_revision >= 1),
    binary_sha256 TEXT NOT NULL
);
CREATE TABLE local_revisions (
    project_id TEXT NOT NULL REFERENCES local_projects(id),
    revision INTEGER NOT NULL,
    binary_sha256 TEXT NOT NULL,
    PRIMARY KEY(project_id, revision)
);
CREATE TABLE local_annotations (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES local_projects(id),
    created_revision INTEGER NOT NULL,
    binary_sha256 TEXT NOT NULL,
    kind TEXT NOT NULL,
    address TEXT,
    value TEXT NOT NULL,
    scope TEXT NOT NULL
);
CREATE INDEX local_annotations_digest
    ON local_annotations(project_id, binary_sha256, created_revision);
CREATE TABLE annotation_requests (
    project_id TEXT NOT NULL REFERENCES local_projects(id),
    idempotency_key TEXT NOT NULL,
    expected_revision INTEGER NOT NULL,
    request_sha256 TEXT NOT NULL,
    new_revision INTEGER NOT NULL,
    PRIMARY KEY(project_id, idempotency_key)
);
CREATE TABLE workbench_settings (
    id INTEGER PRIMARY KEY CHECK(id=1),
    navigator_width REAL NOT NULL,
    inspector_width REAL NOT NULL,
    recent_local_path TEXT
);
CREATE TABLE local_models (
    project_id TEXT NOT NULL REFERENCES local_projects(id),
    created_revision INTEGER NOT NULL,
    binary_sha256 TEXT NOT NULL,
    model_sha256 TEXT NOT NULL,
    model_json BLOB NOT NULL,
    PRIMARY KEY(project_id, created_revision)
);
CREATE INDEX local_models_digest
    ON local_models(project_id, binary_sha256, created_revision);
CREATE TABLE model_requests (
    project_id TEXT NOT NULL REFERENCES local_projects(id),
    idempotency_key TEXT NOT NULL,
    expected_revision INTEGER NOT NULL,
    request_sha256 TEXT NOT NULL,
    new_revision INTEGER NOT NULL,
    PRIMARY KEY(project_id, idempotency_key)
);
PRAGMA user_version=3;";

const MIGRATE_V1_TO_V2: &str = "CREATE TABLE workbench_settings (
    id INTEGER PRIMARY KEY CHECK(id=1),
    navigator_width REAL NOT NULL,
    inspector_width REAL NOT NULL,
    recent_local_path TEXT
);
PRAGMA user_version=2;";

const MIGRATE_V2_TO_V3: &str = "CREATE TABLE IF NOT EXISTS local_models (
    project_id TEXT NOT NULL REFERENCES local_projects(id),
    created_revision INTEGER NOT NULL,
    binary_sha256 TEXT NOT NULL,
    model_sha256 TEXT NOT NULL,
    model_json BLOB NOT NULL,
    PRIMARY KEY(project_id, created_revision)
);
CREATE INDEX IF NOT EXISTS local_models_digest
    ON local_models(project_id, binary_sha256, created_revision);
CREATE TABLE IF NOT EXISTS model_requests (
    project_id TEXT NOT NULL REFERENCES local_projects(id),
    idempotency_key TEXT NOT NULL,
    expected_revision INTEGER NOT NULL,
    request_sha256 TEXT NOT NULL,
    new_revision INTEGER NOT NULL,
    PRIMARY KEY(project_id, idempotency_key)
);
PRAGMA user_version=3;";

#[derive(Clone, Debug, PartialEq)]
pub struct WorkbenchSettings {
    pub navigator_width: f32,
    pub inspector_width: f32,
    pub recent_local_path: Option<PathBuf>,
}

impl Default for WorkbenchSettings {
    fn default() -> Self {
        Self {
            navigator_width: 260.0,
            inspector_width: 290.0,
            recent_local_path: None,
        }
    }
}

impl WorkbenchSettings {
    fn validate(&self) -> Result<(), String> {
        if !self.navigator_width.is_finite()
            || !(180.0..=800.0).contains(&self.navigator_width)
            || !self.inspector_width.is_finite()
            || !(220.0..=800.0).contains(&self.inspector_width)
        {
            return Err("Workbench pane widths are outside the supported range".to_owned());
        }
        if let Some(path) = &self.recent_local_path
            && (!path.is_absolute() || path.to_str().is_none_or(|value| value.len() > 4096))
        {
            return Err("Recent local ELF path must be absolute UTF-8 and bounded".to_owned());
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct LocalProject {
    pub id: String,
    pub path: PathBuf,
    pub revision: u64,
    pub binary_sha256: String,
}

#[derive(Clone, Copy, Debug)]
pub struct LocalAnnotationInput<'a> {
    pub kind: AnnotationKind,
    pub address: Option<Address>,
    pub value: &'a str,
    pub scope: &'a str,
    pub idempotency_key: &'a str,
}

pub struct LocalProjectStore {
    conn: Connection,
}

pub fn default_db_path() -> Result<PathBuf, String> {
    if let Some(configured) = std::env::var_os("HYDIR_LOCAL_DB") {
        let path = PathBuf::from(configured);
        if !path.is_absolute() {
            return Err("HYDIR_LOCAL_DB must be an absolute path".to_owned());
        }
        return Ok(path);
    }
    #[cfg(target_os = "macos")]
    {
        return std::env::home_dir()
            .map(|home| home.join("Library/Application Support/HydIR/analyst.sqlite"))
            .ok_or("Cannot determine the macOS user data directory".to_owned());
    }
    #[cfg(target_os = "linux")]
    {
        let base = std::env::var_os("XDG_DATA_HOME")
            .map(PathBuf::from)
            .filter(|path| path.is_absolute())
            .or_else(|| std::env::home_dir().map(|home| home.join(".local/share")))
            .ok_or("Cannot determine the Linux user data directory".to_owned())?;
        return Ok(base.join("hydir/analyst.sqlite"));
    }
    #[cfg(target_os = "windows")]
    {
        std::env::var_os("APPDATA")
            .map(PathBuf::from)
            .map(|base| base.join("HydIR/data/analyst.sqlite"))
            .ok_or("Cannot determine the Windows user data directory".to_owned())
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    Err("Set HYDIR_LOCAL_DB to an absolute local project database path".to_owned())
}

impl LocalProjectStore {
    pub fn open_default() -> Result<Self, String> {
        Self::open(&default_db_path()?)
    }

    pub fn open(path: &Path) -> Result<Self, String> {
        if !path.is_absolute() {
            return Err("Local project database path must be absolute".to_owned());
        }
        let parent = path
            .parent()
            .ok_or("Local project database needs a parent directory")?;
        if !parent.exists() {
            fs::create_dir_all(parent)
                .map_err(|error| format!("Cannot create local project directory: {error}"))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
                    .map_err(|error| format!("Cannot protect local project directory: {error}"))?;
            }
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
            let check_existing = || {
                let metadata = fs::symlink_metadata(path)
                    .map_err(|error| format!("Cannot inspect local project database: {error}"))?;
                if !metadata.file_type().is_file() || metadata.permissions().mode() & 0o077 != 0 {
                    return Err(
                        "Local project database must be a regular owner-private file".to_owned(),
                    );
                }
                Ok(())
            };
            match fs::symlink_metadata(path) {
                Ok(_) => check_existing()?,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    match fs::OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .mode(0o600)
                        .open(path)
                    {
                        Ok(_) => {}
                        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                            check_existing()?;
                        }
                        Err(error) => {
                            return Err(format!("Cannot create local project database: {error}"));
                        }
                    }
                }
                Err(error) => {
                    return Err(format!("Cannot inspect local project database: {error}"));
                }
            }
        }
        let mut conn = Connection::open(path)
            .map_err(|error| format!("Cannot open local project database: {error}"))?;
        conn.busy_timeout(Duration::from_secs(5))
            .map_err(db_error)?;
        conn.execute_batch("PRAGMA foreign_keys=ON;")
            .map_err(db_error)?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(db_error)?;
        let version: i64 = tx
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .map_err(db_error)?;
        match version {
            0 => tx.execute_batch(SCHEMA).map_err(db_error)?,
            1 => {
                tx.execute_batch(MIGRATE_V1_TO_V2).map_err(db_error)?;
                tx.execute_batch(MIGRATE_V2_TO_V3).map_err(db_error)?;
            }
            2 => tx.execute_batch(MIGRATE_V2_TO_V3).map_err(db_error)?,
            3 => {}
            _ => {
                return Err(
                    "Local project database schema is not supported by this build".to_owned(),
                );
            }
        }
        tx.commit().map_err(db_error)?;
        Ok(Self { conn })
    }

    pub fn load_workbench_settings(&self) -> Result<WorkbenchSettings, String> {
        let settings: Option<(f32, f32, Option<String>)> = self
            .conn
            .query_row(
                "SELECT navigator_width,inspector_width,recent_local_path FROM workbench_settings WHERE id=1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(db_error)?;
        let settings =
            settings.map_or_else(WorkbenchSettings::default, |value| WorkbenchSettings {
                navigator_width: value.0,
                inspector_width: value.1,
                recent_local_path: value.2.map(PathBuf::from),
            });
        settings.validate()?;
        Ok(settings)
    }

    pub fn save_workbench_settings(&mut self, settings: &WorkbenchSettings) -> Result<(), String> {
        settings.validate()?;
        let path = settings
            .recent_local_path
            .as_ref()
            .map(|path| path.to_str().ok_or("Non-UTF-8 recent local ELF path"))
            .transpose()?;
        self.conn
            .execute(
                "INSERT INTO workbench_settings(id,navigator_width,inspector_width,recent_local_path) \
                 VALUES(1,?1,?2,?3) ON CONFLICT(id) DO UPDATE SET \
                 navigator_width=excluded.navigator_width, \
                 inspector_width=excluded.inspector_width, \
                 recent_local_path=excluded.recent_local_path",
                params![settings.navigator_width, settings.inspector_width, path],
            )
            .map_err(db_error)?;
        Ok(())
    }

    pub fn open_binary(&mut self, path: &Path, spec: &ProgramSpec) -> Result<LocalProject, String> {
        let canonical = fs::canonicalize(path)
            .map_err(|error| format!("Cannot resolve local ELF path: {error}"))?;
        if !fs::metadata(&canonical)
            .map_err(|error| error.to_string())?
            .is_file()
        {
            return Err("Local ELF path is not a regular file".to_owned());
        }
        if binary_digest(&canonical)? != spec.binary_sha256 {
            return Err("Local ELF changed after import; reopen it before editing".to_owned());
        }
        let path_text = canonical
            .to_str()
            .ok_or("Non-UTF-8 local ELF paths are not yet supported")?;
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(db_error)?;
        let previous: Option<(String, i64, String)> = tx.query_row(
            "SELECT id,current_revision,binary_sha256 FROM local_projects WHERE canonical_path=?1",
            [path_text],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        ).optional().map_err(db_error)?;
        let (id, revision) = match previous {
            Some((id, revision, digest)) if digest == spec.binary_sha256 => (id, revision),
            Some((id, revision, _)) => {
                let next = revision
                    .checked_add(1)
                    .ok_or("Local project revision overflow")?;
                tx.execute("INSERT INTO local_revisions(project_id,revision,binary_sha256) VALUES(?1,?2,?3)",
                    params![id, next, spec.binary_sha256]).map_err(db_error)?;
                tx.execute(
                    "UPDATE local_projects SET current_revision=?1,binary_sha256=?2 WHERE id=?3",
                    params![next, spec.binary_sha256, id],
                )
                .map_err(db_error)?;
                (id, next)
            }
            None => {
                let id = Uuid::new_v4().to_string();
                tx.execute("INSERT INTO local_projects(id,canonical_path,current_revision,binary_sha256) VALUES(?1,?2,1,?3)",
                    params![id, path_text, spec.binary_sha256]).map_err(db_error)?;
                tx.execute("INSERT INTO local_revisions(project_id,revision,binary_sha256) VALUES(?1,1,?2)",
                    params![id, spec.binary_sha256]).map_err(db_error)?;
                (id, 1)
            }
        };
        tx.commit().map_err(db_error)?;
        Ok(LocalProject {
            id,
            path: canonical,
            revision: revision as u64,
            binary_sha256: spec.binary_sha256.clone(),
        })
    }

    pub fn list_annotations(
        &self,
        project: &LocalProject,
    ) -> Result<Vec<AnalystAnnotation>, String> {
        self.verify_current(project)?;
        let mut statement = self
            .conn
            .prepare(
                "SELECT id,created_revision,kind,address,value,scope FROM local_annotations \
             WHERE project_id=?1 AND binary_sha256=?2 AND created_revision<=?3 \
             ORDER BY created_revision LIMIT 513",
            )
            .map_err(db_error)?;
        let rows = statement
            .query_map(
                params![project.id, project.binary_sha256, project.revision as i64],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, Option<String>>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                    ))
                },
            )
            .map_err(db_error)?;
        let mut annotations = Vec::new();
        for row in rows {
            let (id, revision, kind, address, value, scope) = row.map_err(db_error)?;
            annotations.push(AnalystAnnotation {
                id,
                binary_sha256: project.binary_sha256.clone(),
                created_revision: revision as u64,
                kind: AnnotationKind::parse(&kind).map_err(str::to_owned)?,
                address: parse_annotation_address(address.as_deref().unwrap_or(""))
                    .map_err(str::to_owned)?,
                value,
                scope,
                provenance: FactProvenance {
                    source: FactSource::AnalystAssertion,
                    scope: "local project annotation; not independently validated".to_owned(),
                },
            });
        }
        if annotations.len() > 512 {
            return Err("Local project exceeds 512 annotations for this binary".to_owned());
        }
        Ok(annotations)
    }

    pub fn add_annotation(
        &mut self,
        project: &LocalProject,
        spec: &ProgramSpec,
        input: LocalAnnotationInput<'_>,
    ) -> Result<LocalProject, String> {
        let LocalAnnotationInput {
            kind,
            address,
            value,
            scope,
            idempotency_key,
        } = input;
        validate_analyst_annotation(kind, address, value, scope, idempotency_key)?;
        if spec.binary_sha256 != project.binary_sha256 {
            return Err("Annotation binary digest differs from open local project".to_owned());
        }
        if binary_digest(&project.path)? != project.binary_sha256 {
            return Err("Local ELF changed after import; reopen it before editing".to_owned());
        }
        if let Some(address) = address
            && !annotation_address_in_spec(spec, address)
        {
            return Err("Annotation address is outside linked ELF load mappings".to_owned());
        }
        let expected =
            i64::try_from(project.revision).map_err(|_| "Local project revision overflow")?;
        let request_json = serde_json::to_vec(&(
            project.revision,
            kind.as_str(),
            address.map(|a| a.0),
            value,
            scope,
        ))
        .map_err(|error| error.to_string())?;
        let request_sha256 = format!("{:x}", Sha256::digest(request_json));
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(db_error)?;
        if let Some((prior_expected, prior_sha, new_revision, prior_digest)) = tx
            .query_row(
                "SELECT a.expected_revision,a.request_sha256,a.new_revision,r.binary_sha256 \
             FROM annotation_requests a JOIN local_revisions r \
             ON r.project_id=a.project_id AND r.revision=a.new_revision \
             WHERE a.project_id=?1 AND a.idempotency_key=?2",
                params![project.id, idempotency_key],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, String>(3)?,
                    ))
                },
            )
            .optional()
            .map_err(db_error)?
        {
            if prior_expected != expected || prior_sha != request_sha256 {
                return Err("Idempotency key belongs to a different annotation request".to_owned());
            }
            return Ok(LocalProject {
                revision: new_revision as u64,
                binary_sha256: prior_digest,
                ..project.clone()
            });
        }
        let (current, digest): (i64, String) = tx
            .query_row(
                "SELECT current_revision,binary_sha256 FROM local_projects WHERE id=?1",
                [&project.id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(db_error)?;
        if current != expected || digest != project.binary_sha256 {
            return Err("Stale local project revision; reopen the ELF before editing".to_owned());
        }
        let count: i64 = tx
            .query_row(
                "SELECT COUNT(*) FROM local_annotations WHERE project_id=?1 AND binary_sha256=?2",
                params![project.id, project.binary_sha256],
                |row| row.get(0),
            )
            .map_err(db_error)?;
        if count >= 512 {
            return Err("Local project has reached 512 annotations for this binary".to_owned());
        }
        let next = expected
            .checked_add(1)
            .ok_or("Local project revision overflow")?;
        let id = Uuid::new_v4().to_string();
        let address_label = address.map(|address| format!("0x{:016x}", address.0));
        tx.execute(
            "INSERT INTO local_revisions(project_id,revision,binary_sha256) VALUES(?1,?2,?3)",
            params![project.id, next, project.binary_sha256],
        )
        .map_err(db_error)?;
        tx.execute("INSERT INTO local_annotations(id,project_id,created_revision,binary_sha256,kind,address,value,scope) \
                    VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
            params![id, project.id, next, project.binary_sha256, kind.as_str(), address_label, value, scope]).map_err(db_error)?;
        tx.execute("INSERT INTO annotation_requests(project_id,idempotency_key,expected_revision,request_sha256,new_revision) \
                    VALUES(?1,?2,?3,?4,?5)",
            params![project.id, idempotency_key, expected, request_sha256, next]).map_err(db_error)?;
        tx.execute(
            "UPDATE local_projects SET current_revision=?1 WHERE id=?2",
            params![next, project.id],
        )
        .map_err(db_error)?;
        tx.commit().map_err(db_error)?;
        Ok(LocalProject {
            revision: next as u64,
            ..project.clone()
        })
    }

    pub fn load_model(&self, project: &LocalProject) -> Result<Option<AnalysisModel>, String> {
        self.verify_current(project)?;
        let row: Option<(String, Vec<u8>)> = self
            .conn
            .query_row(
                "SELECT model_sha256,model_json FROM local_models \
             WHERE project_id=?1 AND binary_sha256=?2 AND created_revision<=?3 \
             ORDER BY created_revision DESC LIMIT 1",
                params![project.id, project.binary_sha256, project.revision as i64],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(db_error)?;
        let Some((digest, json)) = row else {
            return Ok(None);
        };
        if digest != format!("{:x}", Sha256::digest(&json)) {
            return Err("Stored analysis model digest does not match content".to_owned());
        }
        let model = parse_model(&json)?;
        let bytes =
            fs::read(&project.path).map_err(|error| format!("Cannot read local ELF: {error}"))?;
        validate_model(&bytes, &model)?;
        Ok(Some(model))
    }

    pub fn save_model(
        &mut self,
        project: &LocalProject,
        model: &AnalysisModel,
        idempotency_key: &str,
    ) -> Result<LocalProject, String> {
        if idempotency_key.is_empty()
            || idempotency_key.len() > 128
            || !idempotency_key
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        {
            return Err(
                "Model idempotency key must be 1..=128 ASCII letters, digits, '-', '_' or '.'"
                    .to_owned(),
            );
        }
        if binary_digest(&project.path)? != project.binary_sha256 {
            return Err("Local ELF changed after import; reopen it before editing".to_owned());
        }
        let bytes =
            fs::read(&project.path).map_err(|error| format!("Cannot read local ELF: {error}"))?;
        validate_model(&bytes, model)?;
        let expected =
            i64::try_from(project.revision).map_err(|_| "Local project revision overflow")?;
        let request = serde_json::to_vec(model).map_err(|error| error.to_string())?;
        if request.len() > MAX_MODEL_BYTES {
            return Err("Analysis model exceeds 16 MiB".to_owned());
        }
        let request_sha256 = format!("{:x}", Sha256::digest(&request));
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(db_error)?;
        if let Some((prior_expected, prior_sha, new_revision, prior_digest)) = tx
            .query_row(
                "SELECT m.expected_revision,m.request_sha256,m.new_revision,r.binary_sha256 \
             FROM model_requests m JOIN local_revisions r \
             ON r.project_id=m.project_id AND r.revision=m.new_revision \
             WHERE m.project_id=?1 AND m.idempotency_key=?2",
                params![project.id, idempotency_key],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, String>(3)?,
                    ))
                },
            )
            .optional()
            .map_err(db_error)?
        {
            if prior_expected != expected || prior_sha != request_sha256 {
                return Err("Idempotency key belongs to a different model request".to_owned());
            }
            return Ok(LocalProject {
                revision: new_revision as u64,
                binary_sha256: prior_digest,
                ..project.clone()
            });
        }
        let (current, digest): (i64, String) = tx
            .query_row(
                "SELECT current_revision,binary_sha256 FROM local_projects WHERE id=?1",
                [&project.id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(db_error)?;
        if current != expected || digest != project.binary_sha256 {
            return Err("Stale local project revision; reopen the ELF before editing".to_owned());
        }
        let next = expected
            .checked_add(1)
            .ok_or("Local project revision overflow")?;
        let mut stored_model = model.clone();
        stored_model.revision = next as u64;
        let json = serde_json::to_vec(&stored_model).map_err(|error| error.to_string())?;
        if json.len() > MAX_MODEL_BYTES {
            return Err("Analysis model exceeds 16 MiB".to_owned());
        }
        let model_sha256 = format!("{:x}", Sha256::digest(&json));
        tx.execute(
            "INSERT INTO local_revisions(project_id,revision,binary_sha256) VALUES(?1,?2,?3)",
            params![project.id, next, project.binary_sha256],
        )
        .map_err(db_error)?;
        tx.execute("INSERT INTO local_models(project_id,created_revision,binary_sha256,model_sha256,model_json) VALUES(?1,?2,?3,?4,?5)", params![project.id, next, project.binary_sha256, model_sha256, json]).map_err(db_error)?;
        tx.execute("INSERT INTO model_requests(project_id,idempotency_key,expected_revision,request_sha256,new_revision) VALUES(?1,?2,?3,?4,?5)", params![project.id, idempotency_key, expected, request_sha256, next]).map_err(db_error)?;
        tx.execute(
            "UPDATE local_projects SET current_revision=?1 WHERE id=?2",
            params![next, project.id],
        )
        .map_err(db_error)?;
        tx.commit().map_err(db_error)?;
        Ok(LocalProject {
            revision: next as u64,
            ..project.clone()
        })
    }

    fn verify_current(&self, project: &LocalProject) -> Result<(), String> {
        if binary_digest(&project.path)? != project.binary_sha256 {
            return Err(
                "Local ELF changed after import; reopen it before reading annotations".to_owned(),
            );
        }
        let current: Option<(i64, String)> = self.conn.query_row(
            "SELECT current_revision,binary_sha256 FROM local_projects WHERE id=?1 AND canonical_path=?2",
            params![project.id, project.path.to_str().ok_or("Non-UTF-8 local project path")?],
            |row| Ok((row.get(0)?, row.get(1)?)),
        ).optional().map_err(db_error)?;
        match current {
            Some((revision, digest))
                if revision == project.revision as i64 && digest == project.binary_sha256 =>
            {
                Ok(())
            }
            _ => Err("Stale local project revision; reopen the ELF".to_owned()),
        }
    }
}

fn db_error(error: rusqlite::Error) -> String {
    format!("Local project database error: {error}")
}

fn binary_digest(path: &Path) -> Result<String, String> {
    let metadata = fs::metadata(path).map_err(|error| format!("Cannot stat local ELF: {error}"))?;
    if !metadata.is_file() || metadata.len() > MAX_BINARY_BYTES as u64 {
        return Err("Local ELF must be a regular file no larger than 64 MiB".to_owned());
    }
    let mut bytes = Vec::new();
    fs::File::open(path)
        .map_err(|error| format!("Cannot open local ELF: {error}"))?
        .take((MAX_BINARY_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("Cannot read local ELF: {error}"))?;
    if bytes.len() > MAX_BINARY_BYTES {
        return Err("Local ELF changed while reading and exceeded 64 MiB".to_owned());
    }
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hydir_core::{MappedSegmentSpec, RecoveryState};

    fn spec(bytes: &[u8]) -> ProgramSpec {
        ProgramSpec {
            schema_version: hydir_core::PROGRAM_SPEC_VERSION,
            binary_sha256: format!("{:x}", Sha256::digest(bytes)),
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
            mapped_segments: vec![MappedSegmentSpec {
                id: "load-0".to_owned(),
                address_space: 0,
                virtual_address: Address(0x401000),
                memory_size: 0x100,
                file_offset: Address(0),
                file_size: 0x100,
                alignment: 0x1000,
                readable: true,
                writable: false,
                executable: true,
                provenance: FactProvenance {
                    source: FactSource::ElfMetadata,
                    scope: "test mapping".to_owned(),
                },
            }],
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
        }
    }

    fn annotation<'a>(
        kind: AnnotationKind,
        address: Option<Address>,
        value: &'a str,
        scope: &'a str,
        idempotency_key: &'a str,
    ) -> LocalAnnotationInput<'a> {
        LocalAnnotationInput {
            kind,
            address,
            value,
            scope,
            idempotency_key,
        }
    }

    #[test]
    fn local_annotations_are_private_revisioned_idempotent_and_digest_bound() {
        let directory = tempfile::tempdir().unwrap();
        let binary = directory.path().join("sample.elf");
        let database = directory.path().join("analyst.sqlite");
        fs::write(&binary, b"first binary").unwrap();
        let first_spec = spec(b"first binary");
        let mut store = LocalProjectStore::open(&database).unwrap();
        let first = store.open_binary(&binary, &first_spec).unwrap();
        assert_eq!(first.revision, 1);
        let second = store
            .add_annotation(
                &first,
                &first_spec,
                annotation(
                    AnnotationKind::Assumption,
                    None,
                    "trusted caller contract",
                    "whole binary",
                    "local-key-1",
                ),
            )
            .unwrap();
        assert_eq!(second.revision, 2);
        let replay = store
            .add_annotation(
                &first,
                &first_spec,
                annotation(
                    AnnotationKind::Assumption,
                    None,
                    "trusted caller contract",
                    "whole binary",
                    "local-key-1",
                ),
            )
            .unwrap();
        assert_eq!(replay.revision, 2);
        assert!(
            store
                .add_annotation(
                    &first,
                    &first_spec,
                    annotation(
                        AnnotationKind::Assumption,
                        None,
                        "changed statement",
                        "whole binary",
                        "local-key-1",
                    ),
                )
                .unwrap_err()
                .contains("different annotation request")
        );
        assert!(
            store
                .list_annotations(&first)
                .unwrap_err()
                .contains("Stale")
        );
        let facts = store.list_annotations(&second).unwrap();
        assert_eq!(facts.len(), 1);
        assert_eq!(facts[0].provenance.source, FactSource::AnalystAssertion);
        let mut overlaid = first_spec.clone();
        hydir_core::overlay_analyst_assumptions(&mut overlaid, &facts);
        assert_eq!(overlaid.assumptions[0].statement, "trusted caller contract");
        drop(store);

        let mut reopened = LocalProjectStore::open(&database).unwrap();
        let reopened_project = reopened.open_binary(&binary, &first_spec).unwrap();
        assert_eq!(reopened_project.revision, 2);
        assert_eq!(
            reopened.list_annotations(&reopened_project).unwrap().len(),
            1
        );
        fs::write(&binary, b"different binary").unwrap();
        assert!(
            reopened
                .list_annotations(&reopened_project)
                .unwrap_err()
                .contains("changed")
        );
        let changed_spec = spec(b"different binary");
        let changed = reopened.open_binary(&binary, &changed_spec).unwrap();
        assert_eq!(changed.id, reopened_project.id);
        assert_eq!(changed.revision, 3);
        assert!(reopened.list_annotations(&changed).unwrap().is_empty());
        assert!(
            reopened
                .add_annotation(
                    &reopened_project,
                    &first_spec,
                    annotation(
                        AnnotationKind::Comment,
                        None,
                        "stale",
                        "whole binary",
                        "local-key-2",
                    ),
                )
                .is_err()
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&database).unwrap().permissions().mode() & 0o077,
                0
            );
        }
    }

    #[test]
    fn addressed_names_require_a_mapped_virtual_address() {
        let directory = tempfile::tempdir().unwrap();
        let binary = directory.path().join("sample.elf");
        fs::write(&binary, b"addressed binary").unwrap();
        let spec = spec(b"addressed binary");
        let mut store = LocalProjectStore::open(&directory.path().join("analyst.sqlite")).unwrap();
        let project = store.open_binary(&binary, &spec).unwrap();
        assert!(
            store
                .add_annotation(
                    &project,
                    &spec,
                    annotation(
                        AnnotationKind::Name,
                        Some(Address(0x402000)),
                        "outside",
                        "entry",
                        "bad-address",
                    ),
                )
                .unwrap_err()
                .contains("outside")
        );
        let named = store
            .add_annotation(
                &project,
                &spec,
                annotation(
                    AnnotationKind::Name,
                    Some(Address(0x401000)),
                    "reviewed_entry",
                    "entry",
                    "valid-address",
                ),
            )
            .unwrap();
        let facts = store.list_annotations(&named).unwrap();
        assert_eq!(facts[0].address, Some(Address(0x401000)));
        assert_eq!(facts[0].kind, AnnotationKind::Name);
    }

    #[test]
    fn workbench_settings_survive_restart_and_version_one_migration() {
        let directory = tempfile::tempdir().unwrap();
        let database = directory.path().join("analyst.sqlite");
        let recent = directory.path().join("recent.elf");
        let expected = WorkbenchSettings {
            navigator_width: 342.0,
            inspector_width: 376.0,
            recent_local_path: Some(recent),
        };
        let mut store = LocalProjectStore::open(&database).unwrap();
        assert_eq!(
            store.load_workbench_settings().unwrap(),
            WorkbenchSettings::default()
        );
        store.save_workbench_settings(&expected).unwrap();
        drop(store);
        let mut reopened = LocalProjectStore::open(&database).unwrap();
        assert_eq!(reopened.load_workbench_settings().unwrap(), expected);
        assert!(
            reopened
                .save_workbench_settings(&WorkbenchSettings {
                    navigator_width: f32::NAN,
                    ..expected.clone()
                })
                .is_err()
        );
        reopened
            .conn
            .execute_batch("DROP TABLE workbench_settings; PRAGMA user_version=1;")
            .unwrap();
        drop(reopened);
        let migrated = LocalProjectStore::open(&database).unwrap();
        assert_eq!(
            migrated.load_workbench_settings().unwrap(),
            WorkbenchSettings::default()
        );
        assert_eq!(
            migrated
                .conn
                .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            3
        );
    }

    #[test]
    fn concurrent_initial_database_opens_serialize_schema_creation() {
        use std::sync::{Arc, Barrier};
        let directory = tempfile::tempdir().unwrap();
        let database = directory.path().join("analyst.sqlite");
        let barrier = Arc::new(Barrier::new(2));
        let threads: Vec<_> = (0..2)
            .map(|_| {
                let database = database.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    LocalProjectStore::open(&database)
                        .unwrap()
                        .load_workbench_settings()
                        .unwrap()
                })
            })
            .collect();
        for thread in threads {
            assert_eq!(thread.join().unwrap(), WorkbenchSettings::default());
        }
    }

    #[test]
    fn local_models_are_revision_checked_idempotent_and_digest_scoped() {
        use std::process::Command;
        let directory = tempfile::tempdir().unwrap();
        let binary = directory.path().join("pair.o");
        let fixture =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/typed_pair.c");
        let output = Command::new("clang")
            .args(["--target=x86_64-unknown-linux-gnu", "-g", "-O2", "-c"])
            .arg(&fixture)
            .arg("-o")
            .arg(&binary)
            .output();
        let Ok(output) = output else {
            return;
        };
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let bytes = fs::read(&binary).unwrap();
        let spec = hydir_loader::import_elf(&bytes).unwrap();
        let mut model = hydir_model::init_model(&bytes).unwrap();
        assert!(hydir_model::import_dwarf(&bytes, &mut model).unwrap() > 0);
        let mut store = LocalProjectStore::open(&directory.path().join("local.sqlite")).unwrap();
        let initial = store.open_binary(&binary, &spec).unwrap();
        assert_eq!(initial.revision, 1);
        assert!(store.load_model(&initial).unwrap().is_none());
        let saved = store.save_model(&initial, &model, "model-1").unwrap();
        assert_eq!(saved.revision, 2);
        assert_eq!(
            store
                .save_model(&initial, &model, "model-1")
                .unwrap()
                .revision,
            2
        );
        assert!(
            store
                .save_model(&initial, &model, "model-2")
                .unwrap_err()
                .contains("Stale")
        );
        let mut loaded = store.load_model(&saved).unwrap().unwrap();
        assert_eq!(loaded.revision, 2);
        if let hydir_model::TypeDefinitionKind::Struct { fields } = &mut loaded.types[0].kind {
            fields[0].name = "renamed_left".to_owned();
        }
        let edited = store.save_model(&saved, &loaded, "model-2").unwrap();
        assert_eq!(edited.revision, 3);
        let latest = store.load_model(&edited).unwrap().unwrap();
        assert_eq!(latest.revision, 3);
        assert!(
            serde_json::to_string(&latest)
                .unwrap()
                .contains("renamed_left")
        );
        assert!(store.load_model(&saved).unwrap_err().contains("Stale"));
        let output = Command::new("clang")
            .args(["--target=x86_64-unknown-linux-gnu", "-g", "-O0", "-c"])
            .arg(&fixture)
            .arg("-o")
            .arg(&binary)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let changed = fs::read(&binary).unwrap();
        let changed_spec = hydir_loader::import_elf(&changed).unwrap();
        let reopened = store.open_binary(&binary, &changed_spec).unwrap();
        assert_eq!(reopened.revision, 4);
        assert!(store.load_model(&reopened).unwrap().is_none());
    }

    #[cfg(unix)]
    #[test]
    fn local_database_refuses_public_files_symlinks_and_newer_schema() {
        use std::os::unix::{fs::PermissionsExt, fs::symlink};

        assert!(
            LocalProjectStore::open(Path::new("relative.sqlite"))
                .err()
                .unwrap()
                .contains("must be absolute")
        );
        let directory = tempfile::tempdir().unwrap();
        let database = directory.path().join("analyst.sqlite");
        fs::write(&database, b"").unwrap();
        fs::set_permissions(&database, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(LocalProjectStore::open(&database).is_err());

        fs::set_permissions(&database, fs::Permissions::from_mode(0o600)).unwrap();
        let store = LocalProjectStore::open(&database).unwrap();
        store.conn.execute_batch("PRAGMA user_version=4;").unwrap();
        drop(store);
        assert!(
            LocalProjectStore::open(&database)
                .err()
                .unwrap()
                .contains("schema is not supported")
        );

        let link = directory.path().join("linked.sqlite");
        symlink(&database, &link).unwrap();
        assert!(
            LocalProjectStore::open(&link)
                .err()
                .unwrap()
                .contains("regular owner-private file")
        );
    }
}
