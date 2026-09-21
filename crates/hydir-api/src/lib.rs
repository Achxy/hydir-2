//! Versioned HydIR RPC contract. All local/remote operations must share the
//! backend validation rules; the initial service exposes only a narrow subset.

pub mod v1 {
    tonic::include_proto!("hydir.v1");
}

pub mod v2 {
    tonic::include_proto!("hydir.v2");
}

pub mod v3 {
    tonic::include_proto!("hydir.v3");
}

/// Canonical HydIR interchange specification.
pub mod interchange {
    tonic::include_proto!("hydir.interchange");
}

/// HydIR native interchange service.
pub mod interchange_service {
    pub mod server {
        tonic::include_proto!("hydir.interchange.server");
    }
}

/// HydIR native patch service.
pub mod patch {
    pub mod server {
        tonic::include_proto!("hydir.patch.server");
    }
}
