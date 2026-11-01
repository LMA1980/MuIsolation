use std::ffi::OsString;

use serde::{Deserialize, Serialize};

use crate::error::IsolationError;
use crate::kernel::landlock_rules::LandlockPathRule;
use crate::kernel::namespaces::NamespaceCloneFlags;
use crate::kernel::seccomp::SeccompFilterPlan;
use crate::kvm::vmm::MicroVmConfig;
use crate::policy::{EffectiveSandboxPolicy, SandboxBackendKind};

/// Lowered, deterministic execution plan produced by an `IsolationBackend` from an
/// `EffectiveSandboxPolicy` and command argument vector.
#[derive(Serialize, Debug, PartialEq, Eq, Clone)]
pub struct SandboxExecutionPlan {
    pub backend: SandboxBackendKind,
    pub argv: Vec<OsString>,
    pub landlock_rules: Vec<LandlockPathRule>,
    pub namespace_flags: Option<NamespaceCloneFlags>,
    pub seccomp_plan: Option<SeccompFilterPlan>,
    pub memlock_bytes: u64,
    pub microvm_config: Option<MicroVmConfig>,
}

/// Handle to a spawned sandboxed child process or microVM instance.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct IsolatedChildHandle {
    pub pid: u32,
    pub backend: SandboxBackendKind,
}

/// Unified trait implemented by both `KernelSandbox` (Landlock, namespaces, cgroupv2, seccomp-BPF)
/// and `HypervisorSandbox` (KVM hardware-virtualized microVM).
pub trait IsolationBackend: Send + Sync {
    /// Return the backend kind (`SandboxBackendKind::Kernel` or `SandboxBackendKind::Hypervisor`).
    fn backend_kind(&self) -> SandboxBackendKind;

    /// Validate that the host architecture, hardware constraints, and policy settings
    /// are compatible with this isolation backend.
    fn validate_host_support(&self, policy: &EffectiveSandboxPolicy) -> Result<(), IsolationError>;

    /// Lower an `EffectiveSandboxPolicy` and command `argv` into a concrete `SandboxExecutionPlan`.
    fn build_execution_plan(
        &self,
        policy: &EffectiveSandboxPolicy,
        argv: &[OsString],
    ) -> Result<SandboxExecutionPlan, IsolationError>;

    /// Execute or instantiate the sandboxed task from a verified `SandboxExecutionPlan`.
    fn spawn_isolated(
        &self,
        plan: &SandboxExecutionPlan,
    ) -> Result<IsolatedChildHandle, IsolationError>;
}
