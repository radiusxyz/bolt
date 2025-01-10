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
        commitment::InclusionCommitment,
        jsonrpc::{JsonError, JsonResponse},
        signature::SignatureError,
        InclusionRequest,
    },
    state::{consensus::ConsensusError, ValidationError},
};

pub(super) const SIGNATURE_HEADER: &str = "x-bolt-signature";

pub(super) const GET_VERSION_METHOD: &str = "bolt_getVersion";

pub(super) const REQUEST_INCLUSION_METHOD: &str = "bolt_requestInclusion";

pub(super) const GET_METADATA_METHOD: &str = "bolt_metadata";

pub(super) const MAX_REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(6);

/// Error type for the commitments API.
#[derive(Debug, Error)]
pub enum CommitmentError {
    /// Request rejected.
    #[error("Request rejected: {0}")]
    Rejected(#[from] RejectionError),
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
    InvalidJson(#[from] JsonRejection),
}

impl From<CommitmentError> for JsonError {
    fn from(err: CommitmentError) -> Self {
        // Reference: https://www.jsonrpc.org/specification#error_object
        // TODO: the custom defined ones should be clearly documented.
        match err {
            CommitmentError::Rejected(err) => err.into(),
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
            CommitmentError::Internal => Self::new(-32603, err.to_string()),
        }
    }
}

impl From<&CommitmentError> for StatusCode {
    fn from(err: &CommitmentError) -> Self {
        match err {
            CommitmentError::Rejected(_)
            | CommitmentError::Duplicate
            | CommitmentError::NoSignature
            | CommitmentError::InvalidSignature(_)
            | CommitmentError::Signature(_)
            | CommitmentError::Consensus(_)
            | CommitmentError::Validation(_)
            | CommitmentError::MalformedHeader
            | CommitmentError::UnknownMethod
            | CommitmentError::InvalidJson(_) => Self::BAD_REQUEST,
            CommitmentError::Internal => Self::INTERNAL_SERVER_ERROR,
        }
    }
}

impl IntoResponse for CommitmentError {
    fn into_response(self) -> Response<Body> {
        let status_code = StatusCode::from(&self);
        let json = Json(JsonResponse::from_error(self.into()));

        (status_code, json).into_response()
    }
}

/// Error indicating the rejection of a commitment request. This should
/// be returned to the user.
#[derive(Debug, Error)]
pub enum RejectionError {
    /// State validation failed for this request.
    #[error("Validation failed: {0}")]
    ValidationFailed(String),
    /// JSON parsing error.
    #[error("JSON parsing error: {0}")]
    Json(#[from] serde_json::Error),
}

impl From<RejectionError> for JsonError {
    fn from(err: RejectionError) -> Self {
        match err {
            RejectionError::ValidationFailed(err) => Self::new(-32600, err),
            RejectionError::Json(err) => Self::new(-32700, err.to_string()),
        }
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
}
