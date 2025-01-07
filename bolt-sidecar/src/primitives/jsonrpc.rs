use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

/// A JSON-RPC request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    /// The JSON-RPC version string. MUST be "2.0".
    pub jsonrpc: String,
    /// The method string.
    pub method: String,
    /// Optional ID.
    pub id: Option<Value>,
    /// The parameters object.
    pub params: Vec<Value>,
}

/// A JSON-RPC request with a mandatory UUID
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcRequestUuid {
    /// The JSON-RPC version string. MUST be "2.0".
    pub jsonrpc: String,
    /// The method string.
    pub method: String,
    /// Optional ID.
    pub id: Uuid,
    /// The parameters object.
    pub params: Vec<Value>,
}

/// A JSON-RPC response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonResponse {
    /// The JSON-RPC version string. MUST be "2.0".
    pub jsonrpc: String,
    /// Optional ID. Must be serialized as `null` if not present.
    pub id: Option<Value>,
    /// The result object. Must be serialized as `null` if an error is present.
    #[serde(skip_serializing_if = "Value::is_null", default)]
    pub result: Value,
    /// The error object. Must be serialized as `null` if no error is present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonError>,
}

impl Default for JsonResponse {
    fn default() -> Self {
        Self { jsonrpc: "2.0".to_string(), id: None, result: Value::Null, error: None }
    }
}

impl JsonResponse {
    /// Create a new JSON-RPC response with a result
    pub fn from_error(error: JsonError) -> Self {
        Self { error: Some(error), ..Default::default() }
    }
}

/// A JSON-RPC error object
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonError {
    /// The error code
    pub code: i32,
    /// The error message
    pub message: String,
}

impl JsonError {
    /// Create a new JSON-RPC error object
    pub fn new(code: i32, message: String) -> Self {
        Self { code, message }
    }
}
