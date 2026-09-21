//! HydIR interchange services with bounded, fail-closed native preflight.
//!
//! Wire compatibility is available now. Semantic responses are emitted only
//! for an empty specification; non-empty regions remain blocked until their
//! physical contracts can be represented without inventing state.

use hydir_api::{
    interchange_service::server::{
        Codegen, SpecChunk as InterchangeSpecChunk,
        hydir_interchange_server::{HydirInterchange, HydirInterchangeServer},
    },
    patch::server::{
        PatchGraph, PatchRequest, PatchResponse, SpecChunk as PatchSpecChunk,
        hydir_patch_service_server::{HydirPatchService, HydirPatchServiceServer},
    },
};
use hydir_interchange::{HYDIR_CHUNK_BYTES, MAX_SPECIFICATION_BYTES, SpecificationDocument};
use tonic::{Request, Response, Status, Streaming};

#[derive(Clone, Copy, Debug, Default)]
pub struct HydirInterchangeEndpoint;

#[derive(Clone, Copy, Debug, Default)]
pub struct HydirPatchEndpoint;

pub fn interchange_service() -> HydirInterchangeServer<HydirInterchangeEndpoint> {
    HydirInterchangeServer::new(HydirInterchangeEndpoint)
        .max_decoding_message_size(HYDIR_CHUNK_BYTES + 1024)
        .max_encoding_message_size(MAX_SPECIFICATION_BYTES + 1024)
}

pub fn patch_service() -> HydirPatchServiceServer<HydirPatchEndpoint> {
    HydirPatchServiceServer::new(HydirPatchEndpoint)
        .max_decoding_message_size(HYDIR_CHUNK_BYTES + 1024)
        .max_encoding_message_size(MAX_SPECIFICATION_BYTES + 1024)
}

fn compatibility_preflight(bytes: &[u8]) -> Result<SpecificationDocument, Status> {
    let document = SpecificationDocument::decode(bytes).map_err(Status::invalid_argument)?;
    document
        .require_stable_target()
        .map_err(Status::failed_precondition)?;
    for function in &document.specification().functions {
        for uid in function.blocks.keys() {
            document
                .block_bytes(*uid)
                .map_err(Status::failed_precondition)?;
        }
    }
    Ok(document)
}

fn append_chunk(bytes: &mut Vec<u8>, chunk: &[u8]) -> Result<(), Status> {
    if chunk.len() > HYDIR_CHUNK_BYTES {
        return Err(Status::resource_exhausted(format!(
            "HydIR chunk exceeds the {HYDIR_CHUNK_BYTES}-byte boundary"
        )));
    }
    let new_length = bytes
        .len()
        .checked_add(chunk.len())
        .ok_or_else(|| Status::resource_exhausted("HydIR specification length overflows"))?;
    if new_length > MAX_SPECIFICATION_BYTES {
        return Err(Status::resource_exhausted(format!(
            "HydIR specification exceeds {MAX_SPECIFICATION_BYTES} bytes"
        )));
    }
    bytes.extend_from_slice(chunk);
    Ok(())
}

async fn collect_interchange(
    mut stream: Streaming<InterchangeSpecChunk>,
) -> Result<Vec<u8>, Status> {
    let mut bytes = Vec::new();
    while let Some(chunk) = stream.message().await? {
        append_chunk(&mut bytes, &chunk.chunk)?;
    }
    Ok(bytes)
}

async fn collect_patch(mut stream: Streaming<PatchSpecChunk>) -> Result<Vec<u8>, Status> {
    let mut bytes = Vec::new();
    while let Some(chunk) = stream.message().await? {
        append_chunk(&mut bytes, &chunk.chunk)?;
    }
    Ok(bytes)
}

#[tonic::async_trait]
impl HydirInterchange for HydirInterchangeEndpoint {
    async fn process_specification(
        &self,
        request: Request<Streaming<InterchangeSpecChunk>>,
    ) -> Result<Response<Codegen>, Status> {
        let bytes = collect_interchange(request.into_inner()).await?;
        let document = compatibility_preflight(&bytes)?;
        if document.inventory().blocks != 0 {
            return Err(Status::failed_precondition(
                "HydIR interchange import succeeded, but native C emission is blocked until every region has proven physical live-state and stack adapters",
            ));
        }
        Ok(Response::new(Codegen {
            json: "{\"patches\":[]}".to_owned(),
        }))
    }
}

#[tonic::async_trait]
impl HydirPatchService for HydirPatchEndpoint {
    async fn generate_patch_graph(
        &self,
        request: Request<Streaming<PatchSpecChunk>>,
    ) -> Result<Response<PatchGraph>, Status> {
        let bytes = collect_patch(request.into_inner()).await?;
        let document = compatibility_preflight(&bytes)?;
        if document.inventory().blocks != 0 {
            return Err(Status::failed_precondition(
                "HydIR interchange import succeeded, but patch graph emission is blocked until typed PatchIR and physical region contracts are complete",
            ));
        }
        Ok(Response::new(PatchGraph::default()))
    }

    async fn apply_patch(
        &self,
        _request: Request<PatchRequest>,
    ) -> Result<Response<PatchResponse>, Status> {
        Err(Status::failed_precondition(
            "no semantically complete HydIR patch graph session is available",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hydir_api::interchange::{Arch, Os, Specification};
    use hydir_api::{
        interchange_service::server::hydir_interchange_client::HydirInterchangeClient,
        patch::server::hydir_patch_service_client::HydirPatchServiceClient,
    };
    use prost::Message;
    use tokio::net::TcpListener;
    use tokio_stream::wrappers::TcpListenerStream;
    use tonic::transport::Server;

    #[test]
    fn accepts_empty_pinned_target_and_rejects_oversized_chunks() {
        let bytes = Specification {
            arch: Arch::Amd64 as i32,
            operating_system: Os::Linux as i32,
            ..Default::default()
        }
        .encode_to_vec();
        let document = compatibility_preflight(&bytes).unwrap();
        assert_eq!(document.inventory().blocks, 0);

        let mut collected = Vec::new();
        assert_eq!(
            append_chunk(&mut collected, &vec![0; HYDIR_CHUNK_BYTES + 1])
                .unwrap_err()
                .code(),
            tonic::Code::ResourceExhausted
        );
    }

    #[test]
    fn reports_non_target_architecture_before_semantic_work() {
        let bytes = Specification {
            arch: Arch::Aarch64 as i32,
            operating_system: Os::Linux as i32,
            ..Default::default()
        }
        .encode_to_vec();
        assert_eq!(
            compatibility_preflight(&bytes).unwrap_err().code(),
            tonic::Code::FailedPrecondition
        );
    }

    #[tokio::test]
    async fn exact_hydir_service_paths_stream_empty_specification() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            Server::builder()
                .add_service(interchange_service())
                .add_service(patch_service())
                .serve_with_incoming_shutdown(TcpListenerStream::new(listener), async {
                    let _ = shutdown_rx.await;
                })
                .await
                .unwrap();
        });
        let endpoint = format!("http://{address}");
        let bytes = Specification {
            arch: Arch::Amd64 as i32,
            operating_system: Os::Linux as i32,
            ..Default::default()
        }
        .encode_to_vec();

        let mut interchange = HydirInterchangeClient::connect(endpoint.clone())
            .await
            .unwrap();
        let codegen = interchange
            .process_specification(tokio_stream::iter([InterchangeSpecChunk {
                chunk: bytes.clone(),
            }]))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(codegen.json, "{\"patches\":[]}");

        let mut patch = HydirPatchServiceClient::connect(endpoint).await.unwrap();
        let graph = patch
            .generate_patch_graph(tokio_stream::iter([PatchSpecChunk { chunk: bytes }]))
            .await
            .unwrap()
            .into_inner();
        assert!(graph.blocks.is_empty());
        let error = patch
            .apply_patch(PatchRequest {
                uid: 1,
                new_code: "(nop)".to_owned(),
            })
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::FailedPrecondition);

        let _ = shutdown_tx.send(());
        server.await.unwrap();
    }
}
