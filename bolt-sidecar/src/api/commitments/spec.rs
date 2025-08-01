use alloy::primitives::SignatureError as AlloySignatureError;
use axum::{
    body::Body,
    extract::rejection::JsonRejection,
    http::{Response, StatusCode},
    response::IntoResponse,
    Json,
};
use thiserror::Error;

use crate::{
    primitives::{
        commitment::{ExclusionCommitment, FirstInclusionCommitment, InclusionCommitment},
        jsonrpc::{JsonRpcError, JsonRpcErrorResponse},
        signature::SignatureError,
        ExclusionRequest, FirstInclusionRequest, InclusionRequest,
    },
    state::{consensus::ConsensusError, ValidationError},
};

pub(super) const SIGNATURE_HEADER: &str = "x-bolt-signature";

pub(super) const GET_VERSION_METHOD: &str = "bolt_getVersion";

pub(super) const REQUEST_INCLUSION_METHOD: &str = "bolt_requestInclusion";

pub(super) const REQUEST_EXCLUSION_METHOD: &str = "bolt_requestExclusion";

pub(super) const REQUEST_FIRST_ACCESS_METHOD: &str = "bolt_requestFirstInclusion";

pub(super) const GET_METADATA_METHOD: &str = "bolt_metadata";

pub(super) const MAX_REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(6);

/// Error type for the commitments API.
#[derive(Debug, Error)]
pub enum CommitmentError {
    /// Consensus validation failed.
    #[error("Consensus validation error: {0}")]
    Consensus(#[from] ConsensusError),
    /// Request validation failed.
    #[error("Validation failed: {0}")]
    Validation(#[from] ValidationError),
    /// Duplicate request.
    #[error("Duplicate request")]
    Duplicate,
    /// Internal server error.
    #[error("Internal server error")]
    Internal,
    /// Missing signature.
    #[error("Missing '{SIGNATURE_HEADER}' header")]
    NoSignature,
    /// Invalid signature.
    #[error(transparent)]
    InvalidSignature(#[from] SignatureError),
    /// Malformed authentication header.
    #[error("Malformed authentication header")]
    MalformedHeader,
    /// Signature error.
    #[error(transparent)]
    Signature(#[from] AlloySignatureError),
    /// Unknown method.
    #[error("Unknown method")]
    UnknownMethod,
    /// Invalid JSON.
    #[error(transparent)]
    InvalidJson(#[from] serde_json::Error),
    /// Invalid JSON-RPC request params.
    #[error("Invalid JSON-RPC request params: {0}")]
    InvalidParams(String),
    /// Invalid JSON.
    /// FIXME: (thedevbirb, 2025-13-01) this should be removed because it is dead code,
    /// but it allows Rust to pull the correct axum version and not older ones from
    /// dependencies (commit-boost).
    #[error(transparent)]
    RejectedJson(#[from] JsonRejection),
}

impl From<CommitmentError> for JsonRpcError {
    fn from(err: CommitmentError) -> Self {
        // Reference: https://www.jsonrpc.org/specification#error_object
        // TODO: the custom defined ones should be clearly documented.
        match err {
            CommitmentError::Duplicate => Self::new(-32001, err.to_string()),
            CommitmentError::NoSignature => Self::new(-32002, err.to_string()),
            CommitmentError::InvalidSignature(err) => Self::new(-32003, err.to_string()),
            CommitmentError::Signature(err) => Self::new(-32004, err.to_string()),
            CommitmentError::Consensus(err) => Self::new(-32005, err.to_string()),
            CommitmentError::Validation(err) => Self::new(-32006, err.to_string()),
            CommitmentError::MalformedHeader => Self::new(-32007, err.to_string()),
            CommitmentError::InvalidJson(err) => {
                Self::new(-32600, format!("Invalid request: {err}"))
            }
            CommitmentError::UnknownMethod => Self::new(-32601, err.to_string()),
            CommitmentError::InvalidParams(err) => Self::new(-32602, err.to_string()),
            CommitmentError::Internal => Self::new(-32603, err.to_string()),
            CommitmentError::RejectedJson(err) => Self::new(-32604, err.to_string()),
        }
    }
}

impl From<&CommitmentError> for StatusCode {
    fn from(err: &CommitmentError) -> Self {
        match err {
            CommitmentError::Duplicate
            | CommitmentError::NoSignature
            | CommitmentError::InvalidSignature(_)
            | CommitmentError::Signature(_)
            | CommitmentError::Consensus(_)
            | CommitmentError::Validation(_)
            | CommitmentError::MalformedHeader
            | CommitmentError::UnknownMethod
            | CommitmentError::InvalidParams(_)
            | CommitmentError::RejectedJson(_)
            | CommitmentError::InvalidJson(_) => Self::BAD_REQUEST,
            CommitmentError::Internal => Self::INTERNAL_SERVER_ERROR,
        }
    }
}

impl IntoResponse for CommitmentError {
    fn into_response(self) -> Response<Body> {
        let status_code = StatusCode::from(&self);
        let err = JsonRpcError::from(self);
        let json = Json(JsonRpcErrorResponse::new(err));

        (status_code, json).into_response()
    }
}

/// Implements the commitments-API: <https://chainbound.github.io/bolt-docs/api/rpc>
#[async_trait::async_trait]
pub trait CommitmentsApi {
    /// Implements: <https://chainbound.github.io/bolt-docs/api/rpc#bolt_requestinclusion>
    async fn request_inclusion(
        &self,
        inclusion_request: InclusionRequest,
    ) -> Result<InclusionCommitment, CommitmentError>;

    /// Implements: bolt_requestExclusion
    async fn request_exclusion(
        &self,
        exclusion_request: ExclusionRequest,
    ) -> Result<ExclusionCommitment, CommitmentError>;

    /// Implements: bolt_requestFirstInclusion  
    async fn request_first_access(
        &self,
        first_inclusion_request: FirstInclusionRequest,
    ) -> Result<FirstInclusionCommitment, CommitmentError>;
}
