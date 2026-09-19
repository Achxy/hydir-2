//! Versioned HydIR RPC contract. All local/remote operations must share the
//! backend validation rules; the initial service exposes only a narrow subset.

pub mod v1 {
    tonic::include_proto!("hydir.v1");
}

pub mod v2 {
    tonic::include_proto!("hydir.v2");
}

/// Exact Anvill protobuf schema pinned by the Irene3 compatibility baseline.
pub mod specification {
    tonic::include_proto!("specification");
}

/// Exact `irene.server.Irene` compatibility service.
pub mod irene {
    pub mod server {
        tonic::include_proto!("irene.server");
    }
}

/// Exact `irene3.server.PatchLangServer` compatibility service.
pub mod irene3 {
    pub mod server {
        tonic::include_proto!("irene3.server");
    }
}
