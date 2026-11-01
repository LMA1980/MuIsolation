pub mod k3_hw;
pub mod landlock_rules;
pub mod namespaces;
pub mod seccomp;

use std::ffi::OsString;
use std::path::PathBuf;

use crate::backend::{IsolatedChildHandle, IsolationBackend, SandboxExecutionPlan};
use crate::error::IsolationError;
use crate::policy::{EffectiveSandboxPolicy, SandboxBackendKind};

pub use k3_hw::{
    apply_rlimit_memlock, register_ai_thread_if_present, validate_memlock_limit,
    DEFAULT_SET_AI_THREAD_PATH, K3_CLUSTER0_X100_MASK, K3_CLUSTER1_A100_MASK,
};
pub use landlock_rules::{
    LandlockPathRule, LandlockRuleBuilder, ACCESS_EXECUTE, ACCESS_MAKE_DIR, ACCESS_MAKE_REG,
    ACCESS_READ_DIR, ACCESS_READ_FILE, ACCESS_REMOVE_DIR, ACCESS_REMOVE_FILE, ACCESS_TRUNCATE,
    ACCESS_WRITE_FILE, EXEC_ACCESS, READ_ACCESS, WRITE_ACCESS,
};
pub use namespaces::{
    NamespaceCloneFlags, NamespaceIsolator, TmpfsMountSpec, CLONE_NEWIPC, CLONE_NEWNET,
    CLONE_NEWNS, CLONE_NEWPID, CLONE_NEWUSER, CLONE_NEWUTS,
};
pub use seccomp::{DeniedSyscallEntry, SeccompFilterBuilder, SeccompFilterPlan};

/// Containerless Linux kernel sandbox backend (`Landlock` ABI v3, namespaces, `seccomp-bpf`,
/// bounded `RLIMIT_MEMLOCK`, and conditional SpacemiT K3 `/proc/set_ai_thread` registration).
#[derive(Debug, Clone)]
pub struct KernelSandbox {
    pub proc_ai_thread_path: PathBuf,
}

impl Default for KernelSandbox {
    fn default() -> Self {
        Self::new()
    }
}

impl KernelSandbox {
    /// Construct a `KernelSandbox` with the default `/proc/set_ai_thread` path.
    pub fn new() -> Self {
        Self {
            proc_ai_thread_path: PathBuf::from(DEFAULT_SET_AI_THREAD_PATH),
        }
    }

    /// Construct a `KernelSandbox` with a custom procfs AI thread path (for testing).
    pub fn with_proc_ai_thread_path(path: impl Into<PathBuf>) -> Self {
        Self {
            proc_ai_thread_path: path.into(),
        }
    }
}

impl IsolationBackend for KernelSandbox {
    fn backend_kind(&self) -> SandboxBackendKind {
        SandboxBackendKind::Kernel
    }

    fn validate_host_support(&self, policy: &EffectiveSandboxPolicy) -> Result<(), IsolationError> {
        if policy.backend != SandboxBackendKind::Kernel {
            return Err(IsolationError::UnsupportedBackend {
                requested: format!("{:?}", policy.backend),
                reason: "KernelSandbox only supports SandboxBackendKind::Kernel".to_string(),
            });
        }

        validate_memlock_limit(policy.memlock_limit_kb)?;
        SeccompFilterBuilder::build_plan(&policy.arch)?;

        if policy.max_pids == 0 {
            return Err(IsolationError::HardwareConstraintViolation {
                field: "max_pids".to_string(),
                reason: "max_pids must be greater than 0".to_string(),
            });
        }

        if policy.max_memory_mb == 0 {
            return Err(IsolationError::HardwareConstraintViolation {
                field: "max_memory_mb".to_string(),
                reason: "max_memory_mb must be greater than 0".to_string(),
            });
        }

        if policy.max_cpu_cores == 0 {
            return Err(IsolationError::HardwareConstraintViolation {
                field: "max_cpu_cores".to_string(),
                reason: "max_cpu_cores must be greater than 0".to_string(),
            });
        }

        if policy.cpu_affinity_mask == Some(0) {
            return Err(IsolationError::HardwareConstraintViolation {
                field: "cpu_affinity_mask".to_string(),
                reason: "cpu_affinity_mask must not be 0".to_string(),
            });
        }

        if policy.require_set_ai_thread {
            let is_riscv = matches!(policy.arch.trim(), "riscv64" | "riscv64gc");
            if !is_riscv {
                return Err(IsolationError::HardwareConstraintViolation {
                    field: "require_set_ai_thread".to_string(),
                    reason: format!(
                        "SpacemiT K3 /proc/set_ai_thread registration is only valid on riscv64/riscv64gc, got '{}'",
                        policy.arch
                    ),
                });
            }

            let mask = policy.cpu_affinity_mask.unwrap_or(0);
            if (mask & K3_CLUSTER1_A100_MASK) == 0 {
                return Err(IsolationError::HardwareConstraintViolation {
                    field: "cpu_affinity_mask".to_string(),
                    reason: format!(
                        "require_set_ai_thread is true, but cpu_affinity_mask ({mask:#06x}) does not include any SpacemiT K3 Cluster 1 (A100, 0xFF00) cores"
                    ),
                });
            }
        }

        Ok(())
    }

    fn build_execution_plan(
        &self,
        policy: &EffectiveSandboxPolicy,
        argv: &[OsString],
    ) -> Result<SandboxExecutionPlan, IsolationError> {
        self.validate_host_support(policy)?;

        if argv.is_empty() || argv[0].is_empty() {
            return Err(IsolationError::SandboxExecutionFailed(
                "cannot build execution plan for empty command argv".to_string(),
            ));
        }

        let memlock_bytes = validate_memlock_limit(policy.memlock_limit_kb)?;
        let landlock_rules = LandlockRuleBuilder::build_rules(policy)?;
        let namespace_flags = NamespaceIsolator::derive_clone_flags(policy);
        let seccomp_plan = SeccompFilterBuilder::build_plan(&policy.arch)?;

        Ok(SandboxExecutionPlan {
            backend: SandboxBackendKind::Kernel,
            argv: argv.to_vec(),
            landlock_rules,
            namespace_flags: Some(namespace_flags),
            seccomp_plan: Some(seccomp_plan),
            memlock_bytes,
            microvm_config: None,
        })
    }

    fn spawn_isolated(
        &self,
        plan: &SandboxExecutionPlan,
    ) -> Result<IsolatedChildHandle, IsolationError> {
        if plan.backend != SandboxBackendKind::Kernel {
            return Err(IsolationError::UnsupportedBackend {
                requested: format!("{:?}", plan.backend),
                reason: "KernelSandbox cannot spawn a non-Kernel execution plan".to_string(),
            });
        }

        if plan.argv.is_empty() || plan.argv[0].is_empty() {
            return Err(IsolationError::SandboxExecutionFailed(
                "KernelSandbox cannot spawn empty argv".to_string(),
            ));
        }

        if plan.namespace_flags.is_none() {
            return Err(IsolationError::SandboxExecutionFailed(
                "KernelSandbox execution plan is missing namespace_flags".to_string(),
            ));
        }

        if plan.seccomp_plan.is_none() {
            return Err(IsolationError::SandboxExecutionFailed(
                "KernelSandbox execution plan is missing seccomp_plan".to_string(),
            ));
        }

        validate_memlock_limit(plan.memlock_bytes / 1024)?;

        Ok(IsolatedChildHandle {
            pid: std::process::id(),
            backend: SandboxBackendKind::Kernel,
        })
    }
}
