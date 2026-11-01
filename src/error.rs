use thiserror::Error;

/// Canonical error type for the `MuIsolation` 3-layer privilege attenuation
/// and sandbox execution engine.
#[derive(Error, Debug)]
pub enum IsolationError {
    #[error("invalid operator host ceiling field '{field}': {reason}")]
    InvalidHostCeiling { field: String, reason: String },

    #[error("invalid desired security profile configuration: {reason}")]
    InvalidProfileConfig { reason: String },

    #[error("unknown security profile '{profile_name}'")]
    UnknownSecurityProfile { profile_name: String },

    #[error(
        "security grant denied against {violated_layer} on field '{offending_field}': requested '{requested_value}', ceiling '{ceiling_value}'"
    )]
    SecurityGrantDenied {
        violated_layer: String,
        offending_field: String,
        requested_value: String,
        ceiling_value: String,
    },

    #[error("unsupported isolation backend '{requested}': {reason}")]
    UnsupportedBackend { requested: String, reason: String },

    #[error("hardware constraint violation on field '{field}': {reason}")]
    HardwareConstraintViolation { field: String, reason: String },

    #[error("YAML serialization/deserialization error: {0}")]
    Yaml(#[from] serde_yaml::Error),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("sandbox execution failed: {0}")]
    SandboxExecutionFailed(String),
}
