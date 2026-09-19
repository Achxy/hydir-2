//! Explicit, authenticated client commands for the current remote subset.

use super::{read_binary, write_new_or_identical};
use hydir_api::v1::{
    AnnotationRequest, ArtifactRequest, CreateProjectRequest, DiscoverRequest, FunctionRequest,
    JobEventRequest, JobReply, JobRequest, ProjectReply, ProjectRequest, RebuildRequest,
    SourceRequest, StartLiftJobRequest, TransformRequest, UploadBinaryRequest,
    hydir_client::HydirClient,
};
use hydir_api::v2::{
    PatchRequest as PatchRequestV2, VerifyPatchRequest, hydir_v2_client::HydirV2Client,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{env, error::Error, fs, io::Write, path::Path};
use tonic::{Request, metadata::MetadataValue, transport::Channel};

const HELP: &str = "Remote commands:
  hydirctl remote discover
  hydirctl remote source --output <new-file.tar>
  hydirctl remote create <name> <idempotency-key>
  hydirctl remote project <project-id>
  hydirctl remote upload <project-id> <expected-revision> <elf>
  hydirctl remote inspect <project-id> <revision>
  hydirctl remote analyze <project-id> <revision>
  hydirctl remote analyze-spec <project-id> <revision>
  hydirctl remote annotations <project-id> <revision>
  hydirctl remote annotate <project-id> <revision> <idempotency-key> <name|comment|assumption> <hex-address|-> <scope> <value>
  hydirctl remote cfg <project-id> <revision> <function-symbol>
  hydirctl remote lift <project-id> <revision> <function-symbol> --assume-u64x2 --output <file.ll>
  hydirctl remote decompile <project-id> <revision> <function-symbol> --assume-u64x2 --output <file.c>
  hydirctl remote transform <project-id> <revision> <function-symbol> <idempotency-key> --assume-u64x2 --trusted-fixture --passes <comma-list> --output-dir <new-directory>
  hydirctl remote rebuild <project-id> <revision> <idempotency-key> --trusted-fixture --output-dir <new-directory>
  hydirctl remote patch-preview <project-id> <revision> <patch-v1.json> --trusted-fixture --assume-u64x2 --assume-entry-only --output <bundle.json>
  hydirctl remote patch <project-id> <revision> <patch-v1.json> <idempotency-key> --trusted-fixture --assume-u64x2 --assume-entry-only --output <new.elf>
  hydirctl remote artifact <project-id> <sha256> --output <file>
  hydirctl remote job-start-lift <project-id> <revision> <function-symbol> <idempotency-key> --assume-u64x2
  hydirctl remote job <project-id> <job-id>
  hydirctl remote job-cancel <project-id> <job-id>
  hydirctl remote job-events <project-id> <job-id> <after-sequence>

Set HYDIR_ENDPOINT=http://127.0.0.1:50051 and HYDIR_TOKEN_FILE to a private
credential file. No remote binary upload occurs except the explicit upload command.
";

fn authorized<T>(value: T, credential: &MetadataValue<tonic::metadata::Ascii>) -> Request<T> {
    let mut request = Request::new(value);
    request
        .metadata_mut()
        .insert("authorization", credential.clone());
    request
}

fn revision(value: &str) -> Result<u64, Box<dyn Error>> {
    Ok(value.parse()?)
}

fn project_json(project: ProjectReply) -> serde_json::Value {
    json!({
        "project_id": project.project_id,
        "name": project.name,
        "revision": project.revision,
        "binary_sha256": project.binary_sha256,
    })
}

fn job_json(job: JobReply) -> serde_json::Value {
    json!({
        "project_id": job.project_id,
        "job_id": job.job_id,
        "project_revision": job.project_revision,
        "kind": job.kind,
        "state": job.state,
        "artifact_sha256": job.artifact_sha256,
        "diagnostic": job.diagnostic,
    })
}

fn check_artifact(content: &[u8], digest: &str) -> Result<(), Box<dyn Error>> {
    let actual = format!("{:x}", Sha256::digest(content));
    if actual != digest {
        return Err("received artifact SHA-256 mismatch".into());
    }
    Ok(())
}

fn write_executable_new(path: &str, content: &[u8]) -> Result<(), Box<dyn Error>> {
    let target = Path::new(path);
    if target.exists() {
        return Err("patched ELF output exists; refusing to overwrite it".into());
    }
    let parent = target
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    temporary.write_all(content)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        temporary
            .as_file()
            .set_permissions(fs::Permissions::from_mode(0o700))?;
    }
    temporary.persist_noclobber(target)?;
    Ok(())
}

pub async fn run(args: &[String]) -> Result<(), Box<dyn Error>> {
    let endpoint = env::var("HYDIR_ENDPOINT")
        .map_err(|_| "HYDIR_ENDPOINT must explicitly name the local service")?;
    let address: std::net::SocketAddr = endpoint
        .strip_prefix("http://")
        .ok_or("current remote client only supports explicit http://loopback-host:port")?
        .parse()?;
    if !address.ip().is_loopback() {
        return Err("current remote client refuses non-loopback plaintext connections".into());
    }
    let token_file = env::var("HYDIR_TOKEN_FILE")
        .map_err(|_| "HYDIR_TOKEN_FILE must point to a private credential file")?;
    let token_path = Path::new(&token_file);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if fs::metadata(token_path)?.permissions().mode() & 0o077 != 0 {
            return Err("credential file must not be group/world accessible (chmod 600)".into());
        }
    }
    let token = fs::read_to_string(token_path)?.trim().to_owned();
    if token.len() != 64 || !token.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("credential file does not contain a 64-character hex token".into());
    }
    let credential = format!("Bearer {token}").parse::<MetadataValue<_>>()?;
    let channel = Channel::from_shared(endpoint)?.connect().await?;
    let mut client = HydirClient::new(channel.clone())
        .max_decoding_message_size(hydir_backend::MAX_BINARY_BYTES + 1024);
    let mut client_v2 =
        HydirV2Client::new(channel).max_decoding_message_size(2 * 1024 * 1024 + 1024);
    match args {
        [command] if command == "discover" => {
            let result = client
                .discover(authorized(DiscoverRequest {}, &credential))
                .await?
                .into_inner();
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "api_version": result.api_version,
                    "hydir_version": result.hydir_version,
                    "license": result.license,
                    "source_status": result.source_status,
                    "native_elf_import": result.native_elf_import,
                    "scalar_direct_cfg_lift": result.scalar_direct_cfg_lift,
                    "execution_validation": result.execution_validation,
                    "max_binary_bytes": result.max_binary_bytes,
                    "durable_lift_jobs": result.durable_lift_jobs,
                    "reconnectable_job_events": result.reconnectable_job_events,
                    "job_cancellation": result.job_cancellation,
                    "conservative_global_effect_analysis": result.conservative_global_effect_analysis,
                    "scalar_c_output": result.scalar_c_output,
                    "source_revision": result.source_revision,
                    "source_sha256": result.source_sha256,
                    "named_pass_transform": result.named_pass_transform,
                    "scalar_patch_v1": result.scalar_patch_v1,
                    "whole_rebuild": result.whole_rebuild,
                    "analyzed_program_spec": result.analyzed_program_spec,
                    "revisioned_annotations": result.revisioned_annotations,
                }))?
            );
        }
        [command, output, file] if command == "source" && output == "--output" => {
            let discovery = client
                .discover(authorized(DiscoverRequest {}, &credential))
                .await?
                .into_inner();
            if discovery.source_revision.len() != 40 || discovery.source_sha256.len() != 64 {
                return Err("service has no matching source archive offer".into());
            }
            let result = client
                .get_source(authorized(SourceRequest {}, &credential))
                .await?
                .into_inner();
            if result.revision != discovery.source_revision
                || result.sha256 != discovery.source_sha256
            {
                return Err("source offer changed between discovery and retrieval".into());
            }
            check_artifact(&result.content, &result.sha256)?;
            write_new_or_identical(file, &result.content)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "revision": result.revision,
                    "sha256": result.sha256,
                    "output": file,
                }))?
            );
        }
        [command, name, key] if command == "create" => {
            let project = client
                .create_project(authorized(
                    CreateProjectRequest {
                        name: name.clone(),
                        idempotency_key: key.clone(),
                    },
                    &credential,
                ))
                .await?
                .into_inner();
            println!("{}", serde_json::to_string_pretty(&project_json(project))?);
        }
        [command, id] if command == "project" => {
            let project = client
                .get_project(authorized(
                    ProjectRequest {
                        project_id: id.clone(),
                        expected_revision: 0,
                    },
                    &credential,
                ))
                .await?
                .into_inner();
            println!("{}", serde_json::to_string_pretty(&project_json(project))?);
        }
        [command, id, expected, file] if command == "upload" => {
            let content = read_binary(file)?;
            let digest = format!("{:x}", Sha256::digest(&content));
            let project = client
                .upload_binary(authorized(
                    UploadBinaryRequest {
                        project_id: id.clone(),
                        expected_revision: revision(expected)?,
                        content_sha256: digest,
                        content,
                    },
                    &credential,
                ))
                .await?
                .into_inner();
            println!("{}", serde_json::to_string_pretty(&project_json(project))?);
        }
        [command, id, expected] if command == "inspect" => {
            let result = client
                .inspect(authorized(
                    ProjectRequest {
                        project_id: id.clone(),
                        expected_revision: revision(expected)?,
                    },
                    &credential,
                ))
                .await?
                .into_inner();
            println!("{}", result.json);
        }
        [command, id, expected] if command == "analyze" => {
            let result = client
                .analyze(authorized(
                    ProjectRequest {
                        project_id: id.clone(),
                        expected_revision: revision(expected)?,
                    },
                    &credential,
                ))
                .await?
                .into_inner();
            println!("{}", result.json);
        }
        [command, id, expected] if command == "analyze-spec" => {
            let result = client
                .analyze_spec(authorized(
                    ProjectRequest {
                        project_id: id.clone(),
                        expected_revision: revision(expected)?,
                    },
                    &credential,
                ))
                .await?
                .into_inner();
            println!("{}", result.json);
        }
        [command, id, expected] if command == "annotations" => {
            let result = client
                .list_annotations(authorized(
                    ProjectRequest {
                        project_id: id.clone(),
                        expected_revision: revision(expected)?,
                    },
                    &credential,
                ))
                .await?
                .into_inner();
            println!("{}", result.json);
        }
        [command, id, expected, key, kind, address, scope, value] if command == "annotate" => {
            let result = client
                .add_annotation(authorized(
                    AnnotationRequest {
                        project_id: id.clone(),
                        expected_revision: revision(expected)?,
                        idempotency_key: key.clone(),
                        kind: kind.clone(),
                        address: if address == "-" {
                            String::new()
                        } else {
                            address.clone()
                        },
                        value: value.clone(),
                        scope: scope.clone(),
                    },
                    &credential,
                ))
                .await?
                .into_inner();
            println!("{}", serde_json::to_string_pretty(&project_json(result))?);
        }
        [command, id, expected, symbol] if command == "cfg" => {
            let result = client
                .recover_cfg(authorized(
                    FunctionRequest {
                        project_id: id.clone(),
                        expected_revision: revision(expected)?,
                        function_symbol: symbol.clone(),
                        assume_u64x2: false,
                    },
                    &credential,
                ))
                .await?
                .into_inner();
            println!("{}", result.json);
        }
        [command, id, expected, symbol, assume, output, file]
            if (command == "lift" || command == "decompile")
                && assume == "--assume-u64x2"
                && output == "--output" =>
        {
            let request = authorized(
                FunctionRequest {
                    project_id: id.clone(),
                    expected_revision: revision(expected)?,
                    function_symbol: symbol.clone(),
                    assume_u64x2: true,
                },
                &credential,
            );
            let result = if command == "lift" {
                client.lift(request).await?.into_inner()
            } else {
                client.decompile(request).await?.into_inner()
            };
            check_artifact(&result.content, &result.sha256)?;
            write_new_or_identical(file, &result.content)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "sha256": result.sha256, "media_type": result.media_type,
                    "project_revision": result.project_revision, "output": file,
                }))?
            );
        }
        [command, id, expected, key, trusted, output, directory]
            if command == "rebuild"
                && trusted == "--trusted-fixture"
                && output == "--output-dir" =>
        {
            if Path::new(directory).exists() {
                return Err("rebuild output directory exists; refusing to overwrite".into());
            }
            let expected = revision(expected)?;
            let next = expected.checked_add(1).ok_or("project revision overflow")?;
            let reply = client
                .rebuild(authorized(
                    RebuildRequest {
                        project_id: id.clone(),
                        expected_revision: expected,
                        trusted_fixture: true,
                        idempotency_key: key.clone(),
                    },
                    &credential,
                ))
                .await?
                .into_inner();
            if reply.project_id != *id || reply.revision != next {
                return Err("rebuild returned unexpected project or revision".into());
            }
            let artifacts = [
                ("whole.ll", &reply.ir_sha256, "text/x-llvm-ir"),
                ("rebuilt", &reply.binary_sha256, "application/x-elf"),
                ("report.json", &reply.report_sha256, "application/json"),
            ];
            let mut contents = Vec::with_capacity(3);
            for (_, digest, media_type) in &artifacts {
                let artifact = client
                    .get_artifact(authorized(
                        ArtifactRequest {
                            project_id: id.clone(),
                            sha256: (*digest).clone(),
                        },
                        &credential,
                    ))
                    .await?
                    .into_inner();
                if artifact.project_revision != next || artifact.media_type != *media_type {
                    return Err("rebuild artifact metadata mismatch".into());
                }
                check_artifact(&artifact.content, digest)?;
                contents.push(artifact.content);
            }
            if contents[2] != reply.report_json.as_bytes() {
                return Err("rebuild report bytes differ from reply".into());
            }
            fs::create_dir(directory)?;
            for ((name, _, _), content) in artifacts.iter().zip(contents) {
                let path = Path::new(directory).join(name);
                if *name == "rebuilt" {
                    write_executable_new(
                        path.to_str().ok_or("output path is not UTF-8")?,
                        &content,
                    )?;
                } else {
                    fs::write(path, content)?;
                }
            }
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "project_id": reply.project_id,
                    "revision": reply.revision,
                    "binary_sha256": reply.binary_sha256,
                    "ir_sha256": reply.ir_sha256,
                    "report_sha256": reply.report_sha256,
                    "output_dir": directory,
                }))?
            );
        }
        [
            command,
            id,
            expected,
            patch_path,
            trusted,
            assume,
            entry,
            output,
            file,
        ] if command == "patch-preview"
            && trusted == "--trusted-fixture"
            && assume == "--assume-u64x2"
            && entry == "--assume-entry-only"
            && output == "--output" =>
        {
            if fs::metadata(patch_path)?.len() > hydir_patch::MAX_PATCH_BYTES as u64 {
                return Err("patch document exceeds 4096 bytes".into());
            }
            let patch_json = fs::read(patch_path)?;
            hydir_patch::parse_patch_json(&patch_json)?;
            let request_digest = format!("{:x}", Sha256::digest(&patch_json));
            let artifact = client_v2
                .compile_patch(authorized(
                    PatchRequestV2 {
                        project_id: id.clone(),
                        expected_revision: revision(expected)?,
                        idempotency_key: format!("preview-{}", &request_digest[..32]),
                        patch_json,
                        trusted_fixture: true,
                        assume_u64x2: true,
                        assume_entry_only: true,
                    },
                    &credential,
                ))
                .await?
                .into_inner();
            if artifact.project_revision != revision(expected)?
                || artifact.media_type != "application/vnd.hydir.patch-bundle+json;version=2"
            {
                return Err("PatchBundle preview metadata mismatch".into());
            }
            check_artifact(&artifact.content, &artifact.sha256)?;
            hydir_patch::parse_patch_bundle_json(&artifact.content)?;
            let verification = client_v2
                .verify_patch(authorized(
                    VerifyPatchRequest {
                        project_id: id.clone(),
                        expected_revision: revision(expected)?,
                        patch_bundle_json: artifact.content.clone(),
                    },
                    &credential,
                ))
                .await?
                .into_inner();
            if !verification.structurally_valid {
                return Err("PatchBundle failed structural verification".into());
            }
            write_new_or_identical(file, &artifact.content)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "project_id": id,
                    "project_revision": artifact.project_revision,
                    "patch_bundle_sha256": artifact.sha256,
                    "structurally_valid": verification.structurally_valid,
                    "behavior_verified": verification.behavior_verified,
                    "verification": serde_json::from_str::<serde_json::Value>(&verification.report_json)?,
                    "output": file,
                }))?
            );
        }
        [
            command,
            id,
            expected,
            symbol,
            key,
            assume,
            trusted,
            passes_flag,
            passes,
            output_flag,
            directory,
        ] if command == "transform"
            && assume == "--assume-u64x2"
            && trusted == "--trusted-fixture"
            && passes_flag == "--passes"
            && output_flag == "--output-dir" =>
        {
            hydir_transform::parse_passes(passes)?;
            if Path::new(directory).exists() {
                return Err("transform output directory exists; refusing to overwrite".into());
            }
            let revision = revision(expected)?;
            let next_revision = revision.checked_add(1).ok_or("project revision overflow")?;
            let reply = client
                .transform(authorized(
                    TransformRequest {
                        project_id: id.clone(),
                        expected_revision: revision,
                        function_symbol: symbol.clone(),
                        assume_u64x2: true,
                        trusted_fixture: true,
                        passes: passes.clone(),
                        idempotency_key: key.clone(),
                    },
                    &credential,
                ))
                .await?
                .into_inner();
            if reply.project_id != *id || reply.project_revision != next_revision {
                return Err("transform returned unexpected project or revision".into());
            }
            let digests = [
                reply.raw_sha256.clone(),
                reply.before_sha256.clone(),
                reply.after_sha256.clone(),
                reply.report_sha256.clone(),
            ];
            let files = ["raw.ll", "before.ll", "after.ll", "report.json"];
            let mut contents = Vec::with_capacity(4);
            for digest in &digests {
                let artifact = client
                    .get_artifact(authorized(
                        ArtifactRequest {
                            project_id: id.clone(),
                            sha256: digest.clone(),
                        },
                        &credential,
                    ))
                    .await?
                    .into_inner();
                if artifact.project_revision != reply.project_revision {
                    return Err("transform artifact revision mismatch".into());
                }
                check_artifact(&artifact.content, digest)?;
                contents.push(artifact.content);
            }
            if contents[3] != reply.report_json.as_bytes() {
                return Err("transform report bytes differ from reply".into());
            }
            fs::create_dir(directory)?;
            for (name, content) in files.iter().zip(contents) {
                fs::write(Path::new(directory).join(name), content)?;
            }
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "project_id": reply.project_id,
                    "project_revision": reply.project_revision,
                    "raw_sha256": reply.raw_sha256,
                    "before_sha256": reply.before_sha256,
                    "after_sha256": reply.after_sha256,
                    "report_sha256": reply.report_sha256,
                    "ir_text_changed": reply.ir_text_changed,
                    "output_dir": directory,
                }))?
            );
        }
        [
            command,
            id,
            expected,
            patch_path,
            key,
            trusted,
            assume,
            entry,
            output,
            file,
        ] if command == "patch"
            && trusted == "--trusted-fixture"
            && assume == "--assume-u64x2"
            && entry == "--assume-entry-only"
            && output == "--output" =>
        {
            if Path::new(file).exists() {
                return Err(
                    "patched ELF output exists; refusing to mutate the remote project".into(),
                );
            }
            if fs::metadata(patch_path)?.len() > hydir_patch::MAX_PATCH_BYTES as u64 {
                return Err("patch document exceeds 4096 bytes".into());
            }
            let patch_json = fs::read(patch_path)?;
            hydir_patch::parse_patch_json(&patch_json)?;
            let reply = client_v2
                .apply_patch(authorized(
                    PatchRequestV2 {
                        project_id: id.clone(),
                        expected_revision: revision(expected)?,
                        idempotency_key: key.clone(),
                        patch_json,
                        trusted_fixture: true,
                        assume_u64x2: true,
                        assume_entry_only: true,
                    },
                    &credential,
                ))
                .await?
                .into_inner();
            let artifact = client
                .get_artifact(authorized(
                    ArtifactRequest {
                        project_id: id.clone(),
                        sha256: reply.binary_sha256.clone(),
                    },
                    &credential,
                ))
                .await?
                .into_inner();
            if artifact.media_type != "application/x-elf"
                || artifact.project_revision != reply.revision
                || artifact.sha256 != reply.binary_sha256
            {
                return Err("patched ELF artifact metadata mismatch".into());
            }
            check_artifact(&artifact.content, &artifact.sha256)?;
            write_executable_new(file, &artifact.content)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "project_id": reply.project_id,
                    "revision": reply.revision,
                    "binary_sha256": reply.binary_sha256,
                    "patch_bundle_sha256": reply.patch_bundle_sha256,
                    "output": file,
                }))?
            );
        }
        [command, id, digest, output, file] if command == "artifact" && output == "--output" => {
            let result = client
                .get_artifact(authorized(
                    ArtifactRequest {
                        project_id: id.clone(),
                        sha256: digest.clone(),
                    },
                    &credential,
                ))
                .await?
                .into_inner();
            check_artifact(&result.content, &result.sha256)?;
            write_new_or_identical(file, &result.content)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "sha256": result.sha256, "media_type": result.media_type,
                    "project_revision": result.project_revision, "output": file,
                }))?
            );
        }
        [command, id, expected, symbol, key, assume]
            if command == "job-start-lift" && assume == "--assume-u64x2" =>
        {
            let job = client
                .start_lift_job(authorized(
                    StartLiftJobRequest {
                        project_id: id.clone(),
                        expected_revision: revision(expected)?,
                        function_symbol: symbol.clone(),
                        assume_u64x2: true,
                        idempotency_key: key.clone(),
                    },
                    &credential,
                ))
                .await?
                .into_inner();
            println!("{}", serde_json::to_string_pretty(&job_json(job))?);
        }
        [command, id, job_id] if command == "job" || command == "job-cancel" => {
            let request = authorized(
                JobRequest {
                    project_id: id.clone(),
                    job_id: job_id.clone(),
                },
                &credential,
            );
            let job = if command == "job" {
                client.get_job(request).await?.into_inner()
            } else {
                client.cancel_job(request).await?.into_inner()
            };
            println!("{}", serde_json::to_string_pretty(&job_json(job))?);
        }
        [command, id, job_id, after] if command == "job-events" => {
            let mut events = client
                .stream_job_events(authorized(
                    JobEventRequest {
                        project_id: id.clone(),
                        job_id: job_id.clone(),
                        after_sequence: revision(after)?,
                    },
                    &credential,
                ))
                .await?
                .into_inner();
            while let Some(event) = events.message().await? {
                println!(
                    "{}",
                    serde_json::to_string(&json!({
                        "sequence": event.sequence,
                        "job_id": event.job_id,
                        "state": event.state,
                        "message": event.message,
                        "artifact_sha256": event.artifact_sha256,
                    }))?
                );
            }
        }
        _ => return Err(HELP.into()),
    }
    Ok(())
}
