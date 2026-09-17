//! Explicit, authenticated client commands for the current remote subset.

use super::{read_binary, write_new_or_identical};
use hydir_api::v1::{
    ArtifactRequest, CreateProjectRequest, DiscoverRequest, FunctionRequest, ProjectReply,
    ProjectRequest, UploadBinaryRequest, hydir_client::HydirClient,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{env, error::Error, fs, path::Path};
use tonic::{Request, metadata::MetadataValue, transport::Channel};

const HELP: &str = "Remote commands:
  hydirctl remote discover
  hydirctl remote create <name> <idempotency-key>
  hydirctl remote project <project-id>
  hydirctl remote upload <project-id> <expected-revision> <elf>
  hydirctl remote inspect <project-id> <revision>
  hydirctl remote cfg <project-id> <revision> <function-symbol>
  hydirctl remote lift <project-id> <revision> <function-symbol> --assume-u64x2 --output <file.ll>
  hydirctl remote artifact <project-id> <sha256> --output <file>

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

fn check_artifact(content: &[u8], digest: &str) -> Result<(), Box<dyn Error>> {
    let actual = format!("{:x}", Sha256::digest(content));
    if actual != digest {
        return Err("received artifact SHA-256 mismatch".into());
    }
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
    let mut client =
        HydirClient::new(channel).max_decoding_message_size(hydir_backend::MAX_BINARY_BYTES + 1024);
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
            if command == "lift" && assume == "--assume-u64x2" && output == "--output" =>
        {
            let result = client
                .lift(authorized(
                    FunctionRequest {
                        project_id: id.clone(),
                        expected_revision: revision(expected)?,
                        function_symbol: symbol.clone(),
                        assume_u64x2: true,
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
        _ => return Err(HELP.into()),
    }
    Ok(())
}
