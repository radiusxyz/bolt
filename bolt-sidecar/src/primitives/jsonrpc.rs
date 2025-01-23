use derive_more::derive::From;
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

/// A response object for JSON-RPC.
#[derive(Debug, Clone, Serialize, Deserialize, From)]
#[serde(untagged)]
pub enum JsonRpcResponse<T = Value> {
    /// A successful response.
    Success(JsonRpcSuccessResponse<T>),
    /// An error response.
    Error(JsonRpcErrorResponse),
}

impl JsonRpcResponse {
    /// Attemps to convert the response into a successful response.
    pub fn into_success(self) -> Option<JsonRpcSuccessResponse> {
        match self {
            Self::Success(success) => Some(success),
            _ => None,
        }
    }

    /// Attemps to convert the response into an error response.
    pub fn into_error(self) -> Option<JsonRpcErrorResponse> {
        match self {
            Self::Error(error) => Some(error),
            _ => None,
        }
    }

    pub fn with_uuid(self, id: Uuid) -> Self {
        match self {
            Self::Success(success) => Self::Success(success.with_uuid(id)),
            Self::Error(error) => Self::Error(error.with_uuid(id)),
        }
    }
}

/// A response object for successful JSON-RPC requests.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct JsonRpcSuccessResponse<T = Value> {
    /// The JSON-RPC version string. MUST be "2.0".
    pub jsonrpc: String,
    /// Optional ID.
    pub id: Option<Value>,
    /// The result object.
    pub result: T,
}

impl<T> JsonRpcSuccessResponse<T> {
    /// Create a new JSON-RPC success response
    pub fn new(result: T) -> Self {
        Self { jsonrpc: "2.0".to_string(), id: None, result }
    }

    /// Set the ID of the response
    pub fn with_id(self, id: Value) -> Self {
        Self { id: Some(id), ..self }
    }

    /// Set the ID of the response from a UUID
    pub fn with_uuid(self, id: Uuid) -> Self {
        Self { id: Some(Value::String(id.to_string())), ..self }
    }
}

/// A JSON-RPC error response.
///
/// Reference: https://www.jsonrpc.org/specification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcErrorResponse {
    /// The JSON-RPC version string. MUST be "2.0".
    pub jsonrpc: String,
    /// Optional ID
    pub id: Option<Value>,
    /// The error object.
    pub error: JsonRpcError,
}

impl JsonRpcErrorResponse {
    /// Create a new JSON-RPC error response
    pub fn new(error: JsonRpcError) -> Self {
        Self { jsonrpc: "2.0".to_string(), id: None, error }
    }

    /// Set the ID of the response.
    pub fn with_id(self, id: Value) -> Self {
        Self { id: Some(id), ..self }
    }

    /// Set the ID of the response from a UUID.
    pub fn with_uuid(self, id: Uuid) -> Self {
        Self { id: Some(Value::String(id.to_string())), ..self }
    }

    /// Returns a clone of the error message.
    pub fn message(&self) -> String {
        self.error.message.clone()
    }

    /// Returns the error code.
    pub fn code(&self) -> i32 {
        self.error.code
    }
}

impl From<JsonRpcError> for JsonRpcErrorResponse {
    fn from(error: JsonRpcError) -> Self {
        Self::new(error)
    }
}

/// A JSON-RPC error object
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcError {
    /// The error code
    pub code: i32,
    /// The error message
    pub message: String,
    /// The optional data of the error
    pub data: Option<Value>,
}

impl JsonRpcError {
    /// Create a new JSON-RPC error object
    pub fn new(code: i32, message: String) -> Self {
        Self { code, message, data: None }
    }

    pub fn with_data(mut self, data: Value) -> Self {
        self.data = Some(data);
        self
    }
}
