use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use beacon_api_client::VersionedValue;
use ethereum_consensus::{
    builder::SignedValidatorRegistration, deneb::mainnet::SignedBlindedBeaconBlock,
};
use serde::{Deserialize, Serialize, Serializer};

use crate::primitives::{
    BatchedSignedConstraints, GetPayloadResponse, SignedBuilderBid, SignedDelegation,
    SignedRevocation,
};

use super::builder::GetHeaderParams;

/// The path to the builder API status endpoint.
pub const STATUS_PATH: &str = "/eth/v1/builder/status";
/// The path to the builder API register validators endpoint.
pub const REGISTER_VALIDATORS_PATH: &str = "/eth/v1/builder/validators";
/// The path to the builder API get header endpoint.
pub const GET_HEADER_PATH: &str = "/eth/v1/builder/header/:slot/:parent_hash/:pubkey";
/// The path to the builder API get payload endpoint.
pub const GET_PAYLOAD_PATH: &str = "/eth/v1/builder/blinded_blocks";
/// The path to the constraints API submit constraints endpoint.
pub const SUBMIT_CONSTRAINTS_PATH: &str = "/constraints/v1/builder/constraints";
/// The path to the constraints API delegate endpoint.
pub const DELEGATE_PATH: &str = "/constraints/v1/builder/delegate";
/// The path to the constraints API revoke endpoint.
pub const REVOKE_PATH: &str = "/constraints/v1/builder/revoke";

/// A response object for errors.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorResponse {
    #[serde(serialize_with = "serialize_status_code")]
    code: u16,
    message: String,
}

/// Helper to serialize a status code as a string using the provided serializer.
pub fn serialize_status_code<S>(value: &u16, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&value.to_string())
}

#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
#[non_exhaustive]
pub enum BuilderApiError {
    #[error("No validators could be registered: {0:?}")]
    FailedRegisteringValidators(ErrorResponse),
    #[error("Failed getting header: {0:?}")]
    FailedGettingHeader(ErrorResponse),
    #[error("Failed getting payload: {0:?}")]
    FailedGettingPayload(ErrorResponse),
    #[error("Failed submitting constraints: {0:?}")]
    FailedSubmittingConstraints(ErrorResponse),
    #[error("Failed to delegate constraint submission rights: {0:?}")]
    FailedDelegating(ErrorResponse),
    #[error("Failed to revoke constraint submission rights: {0:?}")]
    FailedRevoking(ErrorResponse),
    #[error("No bids found for slot {0}")]
    NoBids(u64),
    #[error("Failed to fetch local payload for slot {0}")]
    FailedToFetchLocalPayload(u64),
    #[error("Axum error: {0:?}")]
    AxumError(#[from] axum::Error),
    #[error("Json error: {0:?}")]
    JsonError(#[from] serde_json::Error),
    #[error("Reqwest error: {0:?}")]
    ReqwestError(#[from] reqwest::Error),
    #[error("API request timed out : {0:?}")]
    Timeout(#[from] tokio::time::error::Elapsed),
    #[error("Invalid fork: {0}")]
    InvalidFork(String),
    #[error("Locally-built payload does not match expected signed header")]
    LocalPayloadIntegrity(#[from] super::builder::LocalPayloadIntegrityError),
    #[error("Generic error: {0}")]
    Generic(String),
}

impl IntoResponse for BuilderApiError {
    fn into_response(self) -> Response {
        match self {
            Self::FailedRegisteringValidators(error) |
            Self::FailedGettingHeader(error) |
            Self::FailedGettingPayload(error) |
            Self::FailedSubmittingConstraints(error) |
            Self::FailedDelegating(error) |
            Self::FailedRevoking(error) => {
                (StatusCode::from_u16(error.code).unwrap(), Json(error)).into_response()
            }
            Self::NoBids(_) => (StatusCode::NO_CONTENT, self.to_string()).into_response(),
            Self::AxumError(err) => (StatusCode::BAD_REQUEST, err.to_string()).into_response(),
            Self::JsonError(err) => (StatusCode::BAD_REQUEST, err.to_string()).into_response(),
            Self::FailedToFetchLocalPayload(_) => {
                (StatusCode::NO_CONTENT, self.to_string()).into_response()
            }
            Self::ReqwestError(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                StatusCode::INTERNAL_SERVER_ERROR.canonical_reason().unwrap(),
            )
                .into_response(),
            Self::Timeout(_) => (
                StatusCode::GATEWAY_TIMEOUT,
                StatusCode::GATEWAY_TIMEOUT.canonical_reason().unwrap(),
            )
                .into_response(),
            Self::InvalidFork(err) => (StatusCode::BAD_REQUEST, Json(err)).into_response(),
            Self::LocalPayloadIntegrity(err) => {
                (StatusCode::BAD_REQUEST, err.to_string()).into_response()
            }
            Self::Generic(err) => (StatusCode::INTERNAL_SERVER_ERROR, Json(err)).into_response(),
        }
    }
}

/// Implements the builder API as defined in <https://ethereum.github.io/builder-specs>.
///
/// The Builder API represents the specification for allowing proposers to request
/// headers and payloads that have been built externally via PBS.
#[async_trait::async_trait]
pub trait BuilderApi {
    /// Implements: <https://ethereum.github.io/builder-specs/#/Builder/status>
    async fn status(&self) -> Result<StatusCode, BuilderApiError>;

    /// Implements: <https://ethereum.github.io/builder-specs/#/Builder/registerValidator>
    async fn register_validators(
        &self,
        registrations: Vec<SignedValidatorRegistration>,
    ) -> Result<(), BuilderApiError>;

    /// Implements: <https://ethereum.github.io/builder-specs/#/Builder/getHeader>
    async fn get_header(
        &self,
        params: GetHeaderParams,
    ) -> Result<SignedBuilderBid, BuilderApiError>;

    /// Implements: <https://ethereum.github.io/builder-specs/#/Builder/submitBlindedBlock>
    async fn get_payload(
        &self,
        signed_block: SignedBlindedBeaconBlock,
    ) -> Result<GetPayloadResponse, BuilderApiError>;
}

/// Implements the constraints API as defined in <https://docs.boltprotocol.xyz/technical-docs/api/builder>.
///
/// The constraints API is an extension of the Builder API that adds a way for proposers to
/// communicate with builders in the PBS pipeline.
#[async_trait::async_trait]
pub trait ConstraintsApi: BuilderApi {
    /// Implements: <https://docs.boltprotocol.xyz/technical-docs/api/builder#constraints>
    async fn submit_constraints(
        &self,
        constraints: &BatchedSignedConstraints,
    ) -> Result<(), BuilderApiError>;

    /// Implements: <https://docs.boltprotocol.xyz/technical-docs/api/builder#get_header_with_proofs>
    async fn get_header_with_proofs(
        &self,
        params: GetHeaderParams,
    ) -> Result<VersionedValue<SignedBuilderBid>, BuilderApiError>;

    /// Implements: <https://docs.boltprotocol.xyz/technical-docs/api/builder#delegate>
    async fn delegate(&self, signed_data: &[SignedDelegation]) -> Result<(), BuilderApiError>;

    /// Implements: <https://docs.boltprotocol.xyz/technical-docs/api/builder#revoke>
    async fn revoke(&self, signed_data: &[SignedRevocation]) -> Result<(), BuilderApiError>;
}
