use std::sync::Arc;

use axum::{
    body::Body,
    extract::State,
    http::{HeaderMap, Request},
    response::Html,
    Json,
};
use axum_extra::extract::WithRejection;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{debug, error, info, instrument};

use crate::{
    api::commitments::{
        server::headers::auth_from_headers,
        spec::{
            CommitmentError, CommitmentsApi, GET_METADATA_METHOD, GET_VERSION_METHOD,
            REQUEST_EXCLUSION_METHOD, REQUEST_FIRST_ACCESS_METHOD, REQUEST_INCLUSION_METHOD,
        },
    },
    common::BOLT_SIDECAR_VERSION,
    config::limits::LimitsOpts,
    primitives::{
        jsonrpc::{JsonRpcRequest, JsonRpcResponse, JsonRpcSuccessResponse},
        signature::SignatureError,
        ExclusionRequest, FirstInclusionRequest, InclusionRequest,
    },
};

use super::CommitmentsApiInner;

/// Response structure for the metadata endpoint that combines
/// limits configuration with version information in a flat structure
#[derive(Debug, Serialize, Deserialize)]
pub struct MetadataResponse {
    /// The operational limits of the sidecar
    #[serde(flatten)]
    pub limits: LimitsOpts,
    /// The version of the Bolt sidecar
    pub version: String,
}

/// Handler function for the root JSON-RPC path.
#[instrument(skip_all, name = "POST /rpc", fields(method = %payload.method))]
pub async fn rpc_entrypoint(
    headers: HeaderMap,
    State(api): State<Arc<CommitmentsApiInner>>,
    WithRejection(Json(payload), _): WithRejection<Json<JsonRpcRequest>, CommitmentError>,
) -> Result<Json<JsonRpcResponse>, CommitmentError> {
    debug!("Received new request");

    match payload.method.as_str() {
        GET_VERSION_METHOD => Ok(Json(
            JsonRpcSuccessResponse {
                id: payload.id,
                result: json!(BOLT_SIDECAR_VERSION.to_string()),
                ..Default::default()
            }
            .into(),
        )),

        GET_METADATA_METHOD => {
            let metadata = MetadataResponse {
                limits: api.limits(),
                version: BOLT_SIDECAR_VERSION.to_string(),
            };

            let response = JsonRpcSuccessResponse {
                id: payload.id,
                result: json!(metadata),
                ..Default::default()
            }
            .into();
            Ok(Json(response))
        }

        REQUEST_INCLUSION_METHOD => {
            // Validate the authentication header and extract the signer and signature
            let (signer, signature) = auth_from_headers(&headers).inspect_err(|e| {
                error!("Failed to extract signature from headers: {:?}", e);
            })?;

            let Some(request_json) = payload.params.first().cloned() else {
                return Err(CommitmentError::InvalidParams("missing param".to_string()));
            };

            // Parse the inclusion request from the parameters
            let mut inclusion_request = serde_json::from_value::<InclusionRequest>(request_json)
                .map_err(CommitmentError::InvalidJson)
                .inspect_err(|err| error!(?err, "Failed to parse inclusion request"))?;

            debug!(?inclusion_request, "New inclusion request");

            // Set the signature here for later processing
            inclusion_request.set_signature(signature.into());

            let digest = inclusion_request.digest();
            let recovered_signer = signature.recover_address_from_prehash(&digest)?;

            if recovered_signer != signer {
                error!(
                    %recovered_signer,
                    %signer,
                    "Recovered signer does not match the provided signer"
                );

                return Err(CommitmentError::InvalidSignature(SignatureError));
            }

            // Set the request signer
            inclusion_request.set_signer(recovered_signer);

            info!(signer = ?recovered_signer, %digest, "New valid inclusion request received");
            let inclusion_commitment = api.request_inclusion(inclusion_request).await?;

            // Create the JSON-RPC response
            let response = JsonRpcSuccessResponse {
                id: payload.id,
                result: json!(inclusion_commitment),
                ..Default::default()
            }
            .into();

            Ok(Json(response))
        }

        REQUEST_EXCLUSION_METHOD => {
            // Validate the authentication header and extract the signer and signature
            let (signer, signature) = auth_from_headers(&headers).inspect_err(|e| {
                error!("Failed to extract signature from headers: {:?}", e);
            })?;

            let Some(request_json) = payload.params.first().cloned() else {
                return Err(CommitmentError::InvalidParams("missing param".to_string()));
            };

            // Parse the exclusion request from the parameters
            let mut exclusion_request = serde_json::from_value::<ExclusionRequest>(request_json)
                .map_err(CommitmentError::InvalidJson)
                .inspect_err(|err| error!(?err, "Failed to parse exclusion request"))?;

            debug!(?exclusion_request, "New exclusion request");

            // Set the signature here for later processing
            exclusion_request.set_signature(signature.into());

            // 🔑 USER SIGNATURE VERIFICATION: Use original digest (without access_list)
            // ✅ SIGNATURE FIX: This matches what user signed in CLI before sidecar modifications
            let digest = exclusion_request.user_signature_digest();
            let recovered_signer = signature.recover_address_from_prehash(&digest)?;

            if recovered_signer != signer {
                error!(
                    %recovered_signer,
                    %signer,
                    "Recovered signer does not match the provided signer"
                );

                return Err(CommitmentError::InvalidSignature(SignatureError));
            }

            // Set the request signer
            exclusion_request.set_signer(recovered_signer);

            info!(signer = ?recovered_signer, %digest, "New valid exclusion request received");
            let exclusion_commitment = api.request_exclusion(exclusion_request).await?;

            // Create the JSON-RPC response
            let response = JsonRpcSuccessResponse {
                id: payload.id,
                result: json!(exclusion_commitment),
                ..Default::default()
            }
            .into();

            Ok(Json(response))
        }

        REQUEST_FIRST_ACCESS_METHOD => {
            // Validate the authentication header and extract the signer and signature
            let (signer, signature) = auth_from_headers(&headers).inspect_err(|e| {
                error!("Failed to extract signature from headers: {:?}", e);
            })?;

            let Some(request_json) = payload.params.first().cloned() else {
                return Err(CommitmentError::InvalidParams("missing param".to_string()));
            };

            // Parse the first access request from the parameters
            let mut first_inclusion_request =
                serde_json::from_value::<FirstInclusionRequest>(request_json)
                    .map_err(CommitmentError::InvalidJson)
                    .inspect_err(|err| error!(?err, "Failed to parse first access request"))?;

            debug!(?first_inclusion_request, "New first access request");

            // Set the signature here for later processing
            first_inclusion_request.set_signature(signature.into());

            let digest = first_inclusion_request.digest();
            let recovered_signer = signature.recover_address_from_prehash(&digest)?;

            if recovered_signer != signer {
                error!(
                    %recovered_signer,
                    %signer,
                    "Recovered signer does not match the provided signer"
                );

                return Err(CommitmentError::InvalidSignature(SignatureError));
            }

            // Set the request signer
            first_inclusion_request.set_signer(recovered_signer);

            info!(signer = ?recovered_signer, %digest, "New valid first access request received");
            let first_access_commitment = api.request_first_access(first_inclusion_request).await?;

            // Create the JSON-RPC response
            let response = JsonRpcSuccessResponse {
                id: payload.id,
                result: json!(first_access_commitment),
                ..Default::default()
            }
            .into();

            Ok(Json(response))
        }

        other => {
            error!("Unknown method: {}", other);
            Err(CommitmentError::UnknownMethod)
        }
    }
}

/// Not found fallback handler for all non-matched routes.
///
/// This handler returns a simple 404 page.
#[instrument(skip_all, name = "not_found")]
pub async fn not_found(req: Request<Body>) -> Html<&'static str> {
    error!(uri = ?req.uri(), "Route not found");
    Html("404 - Not Found")
}

/// Status handler
#[instrument(skip_all, name = "GET /status")]
pub async fn status() -> Html<&'static str> {
    Html("OK")
}
