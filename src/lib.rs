//! 3-layer monotonic privilege attenuation and dual-backend KernelSandbox/HypervisorSandbox engine.

pub mod backend;
pub mod error;
pub mod kernel;
pub mod kvm;
pub mod policy;

pub use backend::{IsolatedChildHandle, IsolationBackend, SandboxExecutionPlan};
pub use error::IsolationError;
pub use kernel::{
    apply_rlimit_memlock, register_ai_thread_if_present, validate_memlock_limit,
    DeniedSyscallEntry, KernelSandbox, LandlockPathRule, LandlockRuleBuilder, NamespaceCloneFlags,
    NamespaceIsolator, SeccompFilterBuilder, SeccompFilterPlan, TmpfsMountSpec, ACCESS_EXECUTE,
    ACCESS_MAKE_DIR, ACCESS_MAKE_REG, ACCESS_READ_DIR, ACCESS_READ_FILE, ACCESS_REMOVE_DIR,
    ACCESS_REMOVE_FILE, ACCESS_TRUNCATE, ACCESS_WRITE_FILE, CLONE_NEWIPC, CLONE_NEWNET,
    CLONE_NEWNS, CLONE_NEWPID, CLONE_NEWUSER, CLONE_NEWUTS, DEFAULT_SET_AI_THREAD_PATH,
    EXEC_ACCESS, K3_CLUSTER0_X100_MASK, K3_CLUSTER1_A100_MASK, READ_ACCESS, WRITE_ACCESS,
};
pub use kvm::{
    probe_kvm_device, HypervisorSandbox, MicroVmConfig, VirtioFsMount, DEFAULT_KVM_DEVICE_PATH,
};
pub use policy::{
    cidr_contains, ipv4_prefix_mask, normalize_clean_path, parse_ipv4_cidr,
    resolve_effective_policy, DesiredProfileConfig, DesiredSecurityFile, EffectiveSandboxPolicy,
    HostCeilingConfig, NetworkEgressMode, SandboxBackendKind, TaskSandboxConfig, MAX_K3_MEMLOCK_KB,
};

pub mod prelude {
    pub use crate::backend::{IsolatedChildHandle, IsolationBackend, SandboxExecutionPlan};
    pub use crate::error::IsolationError;
    pub use crate::kernel::{
        apply_rlimit_memlock, register_ai_thread_if_present, validate_memlock_limit,
        DeniedSyscallEntry, KernelSandbox, LandlockPathRule, LandlockRuleBuilder,
        NamespaceCloneFlags, NamespaceIsolator, SeccompFilterBuilder, SeccompFilterPlan,
        TmpfsMountSpec, DEFAULT_SET_AI_THREAD_PATH, EXEC_ACCESS, K3_CLUSTER0_X100_MASK,
        K3_CLUSTER1_A100_MASK, READ_ACCESS, WRITE_ACCESS,
    };
    pub use crate::kvm::{
        probe_kvm_device, HypervisorSandbox, MicroVmConfig, VirtioFsMount, DEFAULT_KVM_DEVICE_PATH,
    };
    pub use crate::policy::{
        resolve_effective_policy, DesiredProfileConfig, DesiredSecurityFile,
        EffectiveSandboxPolicy, HostCeilingConfig, NetworkEgressMode, SandboxBackendKind,
        TaskSandboxConfig, MAX_K3_MEMLOCK_KB,
    };
}
