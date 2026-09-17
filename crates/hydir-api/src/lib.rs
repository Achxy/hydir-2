//! Versioned HydIR RPC contract. All local/remote operations must share the
//! backend validation rules; the initial service exposes only a narrow subset.

pub mod v1 {
    tonic::include_proto!("hydir.v1");
}
