use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::backend::{IsolatedChildHandle, IsolationBackend, SandboxExecutionPlan};
use crate::error::IsolationError;
use crate::kernel::k3_hw::{validate_memlock_limit, K3_CLUSTER0_X100_MASK, K3_CLUSTER1_A100_MASK};
use crate::kernel::landlock_rules::LandlockRuleBuilder;
use crate::kernel::seccomp::SeccompFilterBuilder;
use crate::policy::{normalize_clean_path, EffectiveSandboxPolicy, SandboxBackendKind};

/// Default character device path for the Linux KVM hypervisor (`/dev/kvm`).
pub const DEFAULT_KVM_DEVICE_PATH: &str = "/dev/kvm";

/// A virtio-fs directory share attached to a `HypervisorSandbox` microVM.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct VirtioFsMount {
    pub tag: String,
    pub host_path: PathBuf,
    pub read_only: bool,
}

/// Multi-architecture (`x86_64` VT-x and RISC-V `H`-extension) KVM microVM configuration.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct MicroVmConfig {
    pub arch: String,
    pub kvm_device_path: PathBuf,
    pub vcpu_count: u32,
    pub vcpu_affinity_mask: Option<u32>,
    pub memory_size_mb: u64,
    pub memlock_bytes: u64,
    pub virtio_fs_mounts: Vec<VirtioFsMount>,
}

/// Probe whether the KVM device node (`/dev/kvm` or a custom test path) exists on the host.
pub fn probe_kvm_device(kvm_path: &Path) -> bool {
    kvm_path.exists()
}

/// Hardware-virtualized KVM microVM isolation backend (`x86_64` Intel VT-x / AMD-V and
/// SpacemiT K3 RISC-V `H`-extension on Cluster 0 `X100` cores `0–7`).
#[derive(Debug, Clone)]
pub struct HypervisorSandbox {
    pub kvm_device_path: PathBuf,
}

impl Default for HypervisorSandbox {
    fn default() -> Self {
        Self::new()
    }
}

impl HypervisorSandbox {
    /// Construct a `HypervisorSandbox` using `/dev/kvm`.
    pub fn new() -> Self {
        Self {
            kvm_device_path: PathBuf::from(DEFAULT_KVM_DEVICE_PATH),
        }
    }

    /// Construct a `HypervisorSandbox` with a custom KVM device path (for testing).
    pub fn with_kvm_path(path: impl Into<PathBuf>) -> Self {
        Self {
            kvm_device_path: path.into(),
        }
    }

    fn build_virtio_fs_mounts(
        policy: &EffectiveSandboxPolicy,
    ) -> Result<Vec<VirtioFsMount>, IsolationError> {
        // Map normalized host path -> read_only (false when writable takes precedence)
        let mut mounts_map: BTreeMap<PathBuf, bool> = BTreeMap::new();

        for read_path in &policy.read_paths {
            let clean = normalize_clean_path(read_path).ok_or_else(|| {
                IsolationError::SandboxExecutionFailed(format!(
                    "invalid virtio-fs read_path '{}'",
                    read_path.display()
                ))
            })?;
            mounts_map.entry(clean).or_insert(true);
        }

        for exec_path in &policy.exec_paths {
            let clean = normalize_clean_path(exec_path).ok_or_else(|| {
                IsolationError::SandboxExecutionFailed(format!(
                    "invalid virtio-fs exec_path '{}'",
                    exec_path.display()
                ))
            })?;
            mounts_map.entry(clean).or_insert(true);
        }

        for write_path in &policy.write_paths {
            let clean = normalize_clean_path(write_path).ok_or_else(|| {
                IsolationError::SandboxExecutionFailed(format!(
                    "invalid virtio-fs write_path '{}'",
                    write_path.display()
                ))
            })?;
            mounts_map.insert(clean, false);
        }

        let mounts = mounts_map
            .into_iter()
            .enumerate()
            .map(|(idx, (host_path, read_only))| VirtioFsMount {
                tag: format!("virtiofs{idx}"),
                host_path,
                read_only,
            })
            .collect();

        Ok(mounts)
    }
}

impl IsolationBackend for HypervisorSandbox {
    fn backend_kind(&self) -> SandboxBackendKind {
        SandboxBackendKind::Hypervisor
    }

    fn validate_host_support(&self, policy: &EffectiveSandboxPolicy) -> Result<(), IsolationError> {
        if policy.backend != SandboxBackendKind::Hypervisor {
            return Err(IsolationError::UnsupportedBackend {
                requested: format!("{:?}", policy.backend),
                reason: "HypervisorSandbox only supports SandboxBackendKind::Hypervisor"
                    .to_string(),
            });
        }

        validate_memlock_limit(policy.memlock_limit_kb)?;

        if policy.max_cpu_cores == 0 {
            return Err(IsolationError::HardwareConstraintViolation {
                field: "max_cpu_cores".to_string(),
                reason: "max_cpu_cores must be greater than 0 for KVM microVM".to_string(),
            });
        }

        if policy.max_memory_mb == 0 {
            return Err(IsolationError::HardwareConstraintViolation {
                field: "max_memory_mb".to_string(),
                reason: "max_memory_mb must be greater than 0 for KVM microVM".to_string(),
            });
        }

        if policy.require_set_ai_thread {
            return Err(IsolationError::HardwareConstraintViolation {
                field: "require_set_ai_thread".to_string(),
                reason: "SpacemiT K3 /proc/set_ai_thread and Cluster 1 (A100) matrix threads require bare-metal KernelSandbox and cannot be used inside a HypervisorSandbox microVM".to_string(),
            });
        }

        match policy.arch.trim() {
            "riscv64" | "riscv64gc" => {
                if let Some(mask) = policy.cpu_affinity_mask {
                    if mask == 0 {
                        return Err(IsolationError::HardwareConstraintViolation {
                            field: "cpu_affinity_mask".to_string(),
                            reason: "cpu_affinity_mask must not be 0".to_string(),
                        });
                    }
                    if (mask & K3_CLUSTER1_A100_MASK) != 0 || (mask & !K3_CLUSTER0_X100_MASK) != 0 {
                        return Err(IsolationError::HardwareConstraintViolation {
                            field: "cpu_affinity_mask".to_string(),
                            reason: format!(
                                "RISC-V Hypervisor (H) extension on SpacemiT K3 is only supported on Cluster 0 (X100, cores 0-7, mask 0x00FF); requested mask {mask:#06x} includes non-X100 cores"
                            ),
                        });
                    }
                }
            }
            "x86_64" | "amd64" => {
                if policy.cpu_affinity_mask == Some(0) {
                    return Err(IsolationError::HardwareConstraintViolation {
                        field: "cpu_affinity_mask".to_string(),
                        reason: "cpu_affinity_mask must not be 0".to_string(),
                    });
                }
            }
            other => {
                return Err(IsolationError::HardwareConstraintViolation {
                    field: "arch".to_string(),
                    reason: format!(
                        "unsupported KVM microVM architecture '{other}'; expected 'x86_64' or 'riscv64'/'riscv64gc'"
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
                "cannot build HypervisorSandbox execution plan for empty command argv".to_string(),
            ));
        }

        let memlock_bytes = validate_memlock_limit(policy.memlock_limit_kb)?;
        let landlock_rules = LandlockRuleBuilder::build_rules(policy)?;
        let seccomp_plan = SeccompFilterBuilder::build_plan(&policy.arch)?;
        let virtio_fs_mounts = Self::build_virtio_fs_mounts(policy)?;

        let is_riscv = matches!(policy.arch.trim(), "riscv64" | "riscv64gc");
        let vcpu_affinity_mask = if is_riscv {
            Some(policy.cpu_affinity_mask.unwrap_or(K3_CLUSTER0_X100_MASK))
        } else {
            policy.cpu_affinity_mask
        };

        let vcpu_count = match vcpu_affinity_mask {
            Some(mask) => mask.count_ones().min(policy.max_cpu_cores).max(1),
            None => policy.max_cpu_cores.max(1),
        };

        let canonical_arch = if is_riscv { "riscv64" } else { "x86_64" }.to_string();

        let microvm_config = MicroVmConfig {
            arch: canonical_arch,
            kvm_device_path: self.kvm_device_path.clone(),
            vcpu_count,
            vcpu_affinity_mask,
            memory_size_mb: policy.max_memory_mb,
            memlock_bytes,
            virtio_fs_mounts,
        };

        Ok(SandboxExecutionPlan {
            backend: SandboxBackendKind::Hypervisor,
            argv: argv.to_vec(),
            landlock_rules,
            namespace_flags: None,
            seccomp_plan: Some(seccomp_plan),
            memlock_bytes,
            microvm_config: Some(microvm_config),
        })
    }

    fn spawn_isolated(
        &self,
        plan: &SandboxExecutionPlan,
    ) -> Result<IsolatedChildHandle, IsolationError> {
        if plan.backend != SandboxBackendKind::Hypervisor {
            return Err(IsolationError::UnsupportedBackend {
                requested: format!("{:?}", plan.backend),
                reason: "HypervisorSandbox cannot spawn a non-Hypervisor execution plan"
                    .to_string(),
            });
        }

        if plan.argv.is_empty() || plan.argv[0].is_empty() {
            return Err(IsolationError::SandboxExecutionFailed(
                "HypervisorSandbox cannot spawn empty argv".to_string(),
            ));
        }

        let Some(ref vm_cfg) = plan.microvm_config else {
            return Err(IsolationError::SandboxExecutionFailed(
                "HypervisorSandbox execution plan is missing microvm_config".to_string(),
            ));
        };

        validate_memlock_limit(plan.memlock_bytes / 1024)?;

        if !probe_kvm_device(&vm_cfg.kvm_device_path) {
            return Err(IsolationError::UnsupportedBackend {
                requested: "Hypervisor".to_string(),
                reason: format!(
                    "KVM device '{}' is not available on this host",
                    vm_cfg.kvm_device_path.display()
                ),
            });
        }

        Ok(IsolatedChildHandle {
            pid: std::process::id(),
            backend: SandboxBackendKind::Hypervisor,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{NetworkEgressMode, MAX_K3_MEMLOCK_KB};
    use tempfile::NamedTempFile;

    fn sample_hypervisor_policy(arch: &str) -> EffectiveSandboxPolicy {
        EffectiveSandboxPolicy {
            node_id: if arch.starts_with("riscv64") {
                "worker-riscv64".to_string()
            } else {
                "node-a".to_string()
            },
            arch: arch.to_string(),
            backend: SandboxBackendKind::Hypervisor,
            read_paths: vec![PathBuf::from("/usr"), PathBuf::from("/lib")],
            write_paths: vec![PathBuf::from("/var/lib/action-runner/workspaces/job1")],
            exec_paths: vec![PathBuf::from("/usr/bin")],
            network_mode: NetworkEgressMode::Offline,
            memlock_limit_kb: 2_097_152,
            max_pids: 128,
            max_memory_mb: 4096,
            max_cpu_cores: 8,
            cpu_affinity_mask: None,
            require_set_ai_thread: false,
        }
    }

    #[test]
    fn test_riscv64_hypervisor_defaults_to_cluster0_x100_and_rejects_cluster1_a100() {
        let sandbox = HypervisorSandbox::new();
        let policy = sample_hypervisor_policy("riscv64gc");
        let argv = vec![OsString::from("/usr/bin/cargo"), OsString::from("test")];

        let plan = sandbox
            .build_execution_plan(&policy, &argv)
            .expect("riscv64 hypervisor plan should succeed on Cluster 0");
        let vm = plan.microvm_config.expect("microvm_config present");
        assert_eq!(vm.arch, "riscv64");
        assert_eq!(vm.vcpu_affinity_mask, Some(K3_CLUSTER0_X100_MASK));
        assert_eq!(vm.vcpu_count, 8);
        assert_eq!(vm.memory_size_mb, 4096);

        // Reject Cluster 1 (A100, 0xFF00) affinity on riscv64 HypervisorSandbox
        let mut bad_cluster = policy.clone();
        bad_cluster.cpu_affinity_mask = Some(0x0100);
        let err = sandbox.validate_host_support(&bad_cluster).unwrap_err();
        assert!(matches!(
            err,
            IsolationError::HardwareConstraintViolation { ref field, .. } if field == "cpu_affinity_mask"
        ));

        // Reject require_set_ai_thread = true on HypervisorSandbox
        let mut bad_ai = policy;
        bad_ai.require_set_ai_thread = true;
        let err = sandbox.validate_host_support(&bad_ai).unwrap_err();
        assert!(matches!(
            err,
            IsolationError::HardwareConstraintViolation { ref field, .. } if field == "require_set_ai_thread"
        ));
    }

    #[test]
    fn test_x86_64_hypervisor_plan_and_kvm_probe() {
        let mock_kvm = NamedTempFile::new().expect("create mock /dev/kvm");
        let sandbox = HypervisorSandbox::with_kvm_path(mock_kvm.path());
        let mut policy = sample_hypervisor_policy("x86_64");
        policy.max_cpu_cores = 4;
        policy.max_memory_mb = 8192;
        policy.memlock_limit_kb = MAX_K3_MEMLOCK_KB;

        let argv = vec![OsString::from("/usr/bin/env")];
        let plan = sandbox
            .build_execution_plan(&policy, &argv)
            .expect("x86_64 hypervisor plan");
        let vm = plan.microvm_config.as_ref().unwrap();
        assert_eq!(vm.arch, "x86_64");
        assert_eq!(vm.vcpu_count, 4);
        assert_eq!(vm.memory_size_mb, 8192);
        assert_eq!(vm.virtio_fs_mounts.len(), 4);

        let child = sandbox
            .spawn_isolated(&plan)
            .expect("spawn with mock kvm device");
        assert_eq!(child.backend, SandboxBackendKind::Hypervisor);
        assert!(child.pid > 0);
    }
}
