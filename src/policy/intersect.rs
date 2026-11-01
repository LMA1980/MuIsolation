use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::error::IsolationError;
use crate::policy::ceiling::{
    cidr_contains, normalize_clean_path, parse_ipv4_cidr, HostCeilingConfig, NetworkEgressMode,
    SandboxBackendKind, MAX_K3_MEMLOCK_KB,
};
use crate::policy::profile::DesiredProfileConfig;

/// Layer 3: Per-task / per-stage sandbox configuration overrides (`ActionRunner.yml` / `MuConDe.yml`).
///
/// May only attenuate (tighten) the grants defined in Layer 2 (`DesiredProfileConfig`).
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone, Default)]
pub struct TaskSandboxConfig {
    pub backend: Option<SandboxBackendKind>,
    #[serde(default)]
    pub read_paths: Vec<PathBuf>,
    #[serde(default)]
    pub write_paths: Vec<PathBuf>,
    #[serde(default)]
    pub exec_paths: Vec<PathBuf>,
    #[serde(default)]
    pub network_mode: NetworkEgressMode,
    pub memlock_limit_kb: Option<u64>,
    pub max_pids: Option<u32>,
    pub max_memory_mb: Option<u64>,
    pub cpu_affinity_mask: Option<u32>,
    pub require_set_ai_thread: Option<bool>,
}

/// Verified effective sandbox policy resulting from the monotonic privilege intersection:
/// $\text{Effective} = \text{Ceiling} \cap \text{Profile} \cap \text{Task}$.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct EffectiveSandboxPolicy {
    pub node_id: String,
    pub arch: String,
    pub backend: SandboxBackendKind,
    pub read_paths: Vec<PathBuf>,
    pub write_paths: Vec<PathBuf>,
    pub exec_paths: Vec<PathBuf>,
    pub network_mode: NetworkEgressMode,
    pub memlock_limit_kb: u64,
    pub max_pids: u32,
    pub max_memory_mb: u64,
    pub max_cpu_cores: u32,
    pub cpu_affinity_mask: Option<u32>,
    pub require_set_ai_thread: bool,
}

/// Resolve and verify the 3-layer monotonic privilege intersection:
/// $\text{Ceiling} \cap \text{Profile} \cap \text{Task}$.
///
/// Any attempt by Layer 2 (`profile`) to exceed Layer 1 (`ceiling`), or by Layer 3 (`task`)
/// to exceed Layer 2 (`profile`), fails closed immediately with `IsolationError::SecurityGrantDenied`.
pub fn resolve_effective_policy(
    ceiling: &HostCeilingConfig,
    profile: &DesiredProfileConfig,
    task: &TaskSandboxConfig,
) -> Result<EffectiveSandboxPolicy, IsolationError> {
    ceiling.validate()?;

    // =========================================================================
    // Layer 2 (DesiredProfile) vs Layer 1 (HostCeiling)
    // =========================================================================
    if !ceiling.allowed_backends.contains(&profile.backend) {
        return Err(IsolationError::SecurityGrantDenied {
            violated_layer: "HostCeiling".to_string(),
            offending_field: "backend".to_string(),
            requested_value: format!("{:?}", profile.backend),
            ceiling_value: format!("{:?}", ceiling.allowed_backends),
        });
    }

    let profile_read_paths = validate_path_attenuation(
        "HostCeiling",
        "read_paths",
        &profile.read_paths,
        &ceiling.allowed_read_prefixes,
    )?;
    let profile_write_paths = validate_path_attenuation(
        "HostCeiling",
        "write_paths",
        &profile.write_paths,
        &ceiling.allowed_write_prefixes,
    )?;
    let profile_exec_paths = validate_path_attenuation(
        "HostCeiling",
        "exec_paths",
        &profile.exec_paths,
        &ceiling.allowed_exec_prefixes,
    )?;

    validate_cidr_attenuation(
        "HostCeiling",
        "network_egress_cidrs",
        &profile.network_egress_cidrs,
        &ceiling.allowed_egress_cidrs,
    )?;

    let effective_ceiling_memlock = ceiling.max_memlock_kb.min(MAX_K3_MEMLOCK_KB);
    if profile.memlock_limit_kb == 0
        || profile.memlock_limit_kb == u64::MAX
        || profile.memlock_limit_kb > effective_ceiling_memlock
    {
        return Err(IsolationError::SecurityGrantDenied {
            violated_layer: "HostCeiling".to_string(),
            offending_field: "memlock_limit_kb".to_string(),
            requested_value: profile.memlock_limit_kb.to_string(),
            ceiling_value: effective_ceiling_memlock.to_string(),
        });
    }

    if profile.max_pids == 0 || profile.max_pids > ceiling.max_pids {
        return Err(IsolationError::SecurityGrantDenied {
            violated_layer: "HostCeiling".to_string(),
            offending_field: "max_pids".to_string(),
            requested_value: profile.max_pids.to_string(),
            ceiling_value: ceiling.max_pids.to_string(),
        });
    }

    let profile_memory_mb = match profile.max_memory_mb {
        Some(m) => {
            if m == 0 || m > ceiling.max_memory_mb {
                return Err(IsolationError::SecurityGrantDenied {
                    violated_layer: "HostCeiling".to_string(),
                    offending_field: "max_memory_mb".to_string(),
                    requested_value: m.to_string(),
                    ceiling_value: ceiling.max_memory_mb.to_string(),
                });
            }
            m
        }
        None => ceiling.max_memory_mb,
    };

    if profile.cpu_affinity_mask == Some(0) {
        return Err(IsolationError::SecurityGrantDenied {
            violated_layer: "HostCeiling".to_string(),
            offending_field: "cpu_affinity_mask".to_string(),
            requested_value: "0x0000".to_string(),
            ceiling_value: "non-zero core mask".to_string(),
        });
    }

    if profile.require_set_ai_thread && !ceiling.allow_spacemit_ai_thread {
        return Err(IsolationError::SecurityGrantDenied {
            violated_layer: "HostCeiling".to_string(),
            offending_field: "require_set_ai_thread".to_string(),
            requested_value: "true".to_string(),
            ceiling_value: "false".to_string(),
        });
    }

    // =========================================================================
    // Layer 3 (TaskSandboxConfig) vs Layer 2 (DesiredProfile)
    // =========================================================================
    let effective_backend = match task.backend {
        Some(b) => {
            if b != profile.backend {
                return Err(IsolationError::SecurityGrantDenied {
                    violated_layer: "DesiredProfile".to_string(),
                    offending_field: "backend".to_string(),
                    requested_value: format!("{b:?}"),
                    ceiling_value: format!("{:?}", profile.backend),
                });
            }
            b
        }
        None => profile.backend,
    };

    let effective_read_paths = if task.read_paths.is_empty() {
        profile_read_paths
    } else {
        validate_path_attenuation(
            "DesiredProfile",
            "read_paths",
            &task.read_paths,
            &profile_read_paths,
        )?
    };

    let effective_write_paths = if task.write_paths.is_empty() {
        profile_write_paths
    } else {
        validate_path_attenuation(
            "DesiredProfile",
            "write_paths",
            &task.write_paths,
            &profile_write_paths,
        )?
    };

    let effective_exec_paths = if task.exec_paths.is_empty() {
        profile_exec_paths
    } else {
        validate_path_attenuation(
            "DesiredProfile",
            "exec_paths",
            &task.exec_paths,
            &profile_exec_paths,
        )?
    };

    let effective_network_mode = match &task.network_mode {
        NetworkEgressMode::Offline => NetworkEgressMode::Offline,
        NetworkEgressMode::RestrictedCidrs(requested_cidrs) => {
            if profile.network_egress_cidrs.is_empty() {
                return Err(IsolationError::SecurityGrantDenied {
                    violated_layer: "DesiredProfile".to_string(),
                    offending_field: "network_mode".to_string(),
                    requested_value: format!("RestrictedCidrs({requested_cidrs:?})"),
                    ceiling_value: "Offline ([])".to_string(),
                });
            }
            validate_cidr_attenuation(
                "DesiredProfile",
                "network_mode",
                requested_cidrs,
                &profile.network_egress_cidrs,
            )?;
            NetworkEgressMode::RestrictedCidrs(requested_cidrs.clone())
        }
    };

    let effective_memlock_kb = match task.memlock_limit_kb {
        Some(m) => {
            if m == 0 || m > profile.memlock_limit_kb {
                return Err(IsolationError::SecurityGrantDenied {
                    violated_layer: "DesiredProfile".to_string(),
                    offending_field: "memlock_limit_kb".to_string(),
                    requested_value: m.to_string(),
                    ceiling_value: profile.memlock_limit_kb.to_string(),
                });
            }
            m
        }
        None => profile.memlock_limit_kb,
    };

    let effective_max_pids = match task.max_pids {
        Some(p) => {
            if p == 0 || p > profile.max_pids {
                return Err(IsolationError::SecurityGrantDenied {
                    violated_layer: "DesiredProfile".to_string(),
                    offending_field: "max_pids".to_string(),
                    requested_value: p.to_string(),
                    ceiling_value: profile.max_pids.to_string(),
                });
            }
            p
        }
        None => profile.max_pids,
    };

    let effective_max_memory_mb = match task.max_memory_mb {
        Some(m) => {
            if m == 0 || m > profile_memory_mb {
                return Err(IsolationError::SecurityGrantDenied {
                    violated_layer: "DesiredProfile".to_string(),
                    offending_field: "max_memory_mb".to_string(),
                    requested_value: m.to_string(),
                    ceiling_value: profile_memory_mb.to_string(),
                });
            }
            m
        }
        None => profile_memory_mb,
    };

    let effective_require_set_ai_thread = match task.require_set_ai_thread {
        Some(true) => {
            if !profile.require_set_ai_thread {
                return Err(IsolationError::SecurityGrantDenied {
                    violated_layer: "DesiredProfile".to_string(),
                    offending_field: "require_set_ai_thread".to_string(),
                    requested_value: "true".to_string(),
                    ceiling_value: "false".to_string(),
                });
            }
            true
        }
        Some(false) => false,
        None => profile.require_set_ai_thread,
    };

    let effective_cpu_affinity_mask = match (task.cpu_affinity_mask, profile.cpu_affinity_mask) {
        (Some(mask), Some(pmask)) => {
            if mask == 0 || (mask & !pmask) != 0 {
                return Err(IsolationError::SecurityGrantDenied {
                    violated_layer: "DesiredProfile".to_string(),
                    offending_field: "cpu_affinity_mask".to_string(),
                    requested_value: format!("{mask:#06x}"),
                    ceiling_value: format!("{pmask:#06x}"),
                });
            }
            Some(mask)
        }
        (Some(mask), None) => {
            if mask == 0 {
                return Err(IsolationError::SecurityGrantDenied {
                    violated_layer: "DesiredProfile".to_string(),
                    offending_field: "cpu_affinity_mask".to_string(),
                    requested_value: "0x0000".to_string(),
                    ceiling_value: "non-zero core mask".to_string(),
                });
            }
            Some(mask)
        }
        (None, pmask) => pmask,
    };

    Ok(EffectiveSandboxPolicy {
        node_id: ceiling.node_id.clone(),
        arch: ceiling.arch.clone(),
        backend: effective_backend,
        read_paths: effective_read_paths,
        write_paths: effective_write_paths,
        exec_paths: effective_exec_paths,
        network_mode: effective_network_mode,
        memlock_limit_kb: effective_memlock_kb,
        max_pids: effective_max_pids,
        max_memory_mb: effective_max_memory_mb,
        max_cpu_cores: ceiling.max_cpu_cores,
        cpu_affinity_mask: effective_cpu_affinity_mask,
        require_set_ai_thread: effective_require_set_ai_thread,
    })
}

fn validate_path_attenuation(
    violated_layer: &str,
    offending_field: &str,
    requested_paths: &[PathBuf],
    allowed_prefixes: &[PathBuf],
) -> Result<Vec<PathBuf>, IsolationError> {
    let mut normalized_prefixes = Vec::with_capacity(allowed_prefixes.len());
    for prefix in allowed_prefixes {
        if let Some(clean) = normalize_clean_path(prefix) {
            normalized_prefixes.push(clean);
        }
    }

    let mut normalized_requests = Vec::with_capacity(requested_paths.len());
    for req in requested_paths {
        let Some(clean_req) = normalize_clean_path(req) else {
            return Err(IsolationError::SecurityGrantDenied {
                violated_layer: violated_layer.to_string(),
                offending_field: offending_field.to_string(),
                requested_value: req.display().to_string(),
                ceiling_value: format!("{allowed_prefixes:?}"),
            });
        };

        let is_covered = normalized_prefixes
            .iter()
            .any(|prefix| clean_req.starts_with(prefix));

        if !is_covered {
            return Err(IsolationError::SecurityGrantDenied {
                violated_layer: violated_layer.to_string(),
                offending_field: offending_field.to_string(),
                requested_value: req.display().to_string(),
                ceiling_value: format!("{allowed_prefixes:?}"),
            });
        }

        normalized_requests.push(clean_req);
    }

    Ok(normalized_requests)
}

fn validate_cidr_attenuation(
    violated_layer: &str,
    offending_field: &str,
    requested_cidrs: &[String],
    allowed_cidrs: &[String],
) -> Result<(), IsolationError> {
    for req_cidr in requested_cidrs {
        if parse_ipv4_cidr(req_cidr).is_err() {
            return Err(IsolationError::SecurityGrantDenied {
                violated_layer: violated_layer.to_string(),
                offending_field: offending_field.to_string(),
                requested_value: req_cidr.clone(),
                ceiling_value: format!("{allowed_cidrs:?}"),
            });
        }

        let is_subnet = allowed_cidrs
            .iter()
            .any(|parent| cidr_contains(parent, req_cidr).unwrap_or(false));

        if !is_subnet {
            return Err(IsolationError::SecurityGrantDenied {
                violated_layer: violated_layer.to_string(),
                offending_field: offending_field.to_string(),
                requested_value: req_cidr.clone(),
                ceiling_value: format!("{allowed_cidrs:?}"),
            });
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_ceiling() -> HostCeilingConfig {
        HostCeilingConfig {
            node_id: "worker-riscv64".to_string(),
            arch: "riscv64gc".to_string(),
            allowed_backends: vec![SandboxBackendKind::Kernel, SandboxBackendKind::Hypervisor],
            allowed_read_prefixes: vec![
                PathBuf::from("/usr"),
                PathBuf::from("/lib"),
                PathBuf::from("/var/lib/action-runner"),
            ],
            allowed_write_prefixes: vec![
                PathBuf::from("/var/lib/action-runner/workspaces"),
                PathBuf::from("/tmp"),
            ],
            allowed_exec_prefixes: vec![
                PathBuf::from("/usr/bin"),
                PathBuf::from("/var/lib/action-runner/.cargo/bin"),
            ],
            allowed_egress_cidrs: vec!["192.0.2.0/24".to_string(), "198.51.100.0/24".to_string()],
            max_memlock_kb: MAX_K3_MEMLOCK_KB,
            max_cpu_cores: 16,
            max_memory_mb: 28_672,
            max_pids: 512,
            allow_spacemit_ai_thread: true,
        }
    }

    fn sample_profile() -> DesiredProfileConfig {
        DesiredProfileConfig {
            backend: SandboxBackendKind::Kernel,
            read_paths: vec![
                PathBuf::from("/usr/include"),
                PathBuf::from("/var/lib/action-runner/workspaces/k3"),
            ],
            write_paths: vec![
                PathBuf::from("/var/lib/action-runner/workspaces/k3/target"),
                PathBuf::from("/tmp"),
            ],
            exec_paths: vec![PathBuf::from("/usr/bin")],
            network_egress_cidrs: vec!["192.0.2.128/25".to_string()],
            memlock_limit_kb: 4_194_304,
            max_pids: 128,
            max_memory_mb: Some(16_384),
            cpu_affinity_mask: Some(0xFF00),
            require_set_ai_thread: true,
        }
    }

    #[test]
    fn test_valid_three_layer_monotonic_intersection() {
        let ceiling = sample_ceiling();
        let profile = sample_profile();
        let task = TaskSandboxConfig {
            backend: Some(SandboxBackendKind::Kernel),
            read_paths: vec![PathBuf::from("/var/lib/action-runner/workspaces/k3/src")],
            write_paths: vec![PathBuf::from(
                "/var/lib/action-runner/workspaces/k3/target/debug",
            )],
            exec_paths: vec![],
            network_mode: NetworkEgressMode::RestrictedCidrs(vec!["192.0.2.192/26".to_string()]),
            memlock_limit_kb: Some(1_048_576),
            max_pids: Some(64),
            max_memory_mb: Some(8_192),
            cpu_affinity_mask: Some(0x0F00),
            require_set_ai_thread: Some(true),
        };

        let effective = resolve_effective_policy(&ceiling, &profile, &task)
            .expect("monotonic attenuation should succeed");

        assert_eq!(effective.node_id, "worker-riscv64");
        assert_eq!(effective.arch, "riscv64gc");
        assert_eq!(effective.backend, SandboxBackendKind::Kernel);
        assert_eq!(
            effective.read_paths,
            vec![PathBuf::from("/var/lib/action-runner/workspaces/k3/src")]
        );
        assert_eq!(
            effective.write_paths,
            vec![PathBuf::from(
                "/var/lib/action-runner/workspaces/k3/target/debug"
            )]
        );
        // Empty task exec_paths inherits from profile
        assert_eq!(effective.exec_paths, vec![PathBuf::from("/usr/bin")]);
        assert_eq!(
            effective.network_mode,
            NetworkEgressMode::RestrictedCidrs(vec!["192.0.2.192/26".to_string()])
        );
        assert_eq!(effective.memlock_limit_kb, 1_048_576);
        assert_eq!(effective.max_pids, 64);
        assert_eq!(effective.max_memory_mb, 8_192);
        assert_eq!(effective.max_cpu_cores, 16);
        assert_eq!(effective.cpu_affinity_mask, Some(0x0F00));
        assert!(effective.require_set_ai_thread);
    }

    #[test]
    fn test_layer2_violations_against_host_ceiling() {
        let mut ceiling = sample_ceiling();
        let base_profile = sample_profile();
        let default_task = TaskSandboxConfig::default();

        // 1. Disallowed backend
        ceiling.allowed_backends = vec![SandboxBackendKind::Kernel];
        let mut p_backend = base_profile.clone();
        p_backend.backend = SandboxBackendKind::Hypervisor;
        let err = resolve_effective_policy(&ceiling, &p_backend, &default_task).unwrap_err();
        assert!(matches!(
            err,
            IsolationError::SecurityGrantDenied {
                ref violated_layer,
                ref offending_field,
                ..
            } if violated_layer == "HostCeiling" && offending_field == "backend"
        ));

        // 2. Path outside ceiling prefix or containing '..'
        let ceiling = sample_ceiling();
        let mut p_path = base_profile.clone();
        p_path.read_paths = vec![PathBuf::from("/etc/shadow")];
        let err = resolve_effective_policy(&ceiling, &p_path, &default_task).unwrap_err();
        assert!(matches!(
            err,
            IsolationError::SecurityGrantDenied {
                ref violated_layer,
                ref offending_field,
                ..
            } if violated_layer == "HostCeiling" && offending_field == "read_paths"
        ));

        let mut p_traversal = base_profile.clone();
        p_traversal.write_paths = vec![PathBuf::from("/tmp/../etc/passwd")];
        let err = resolve_effective_policy(&ceiling, &p_traversal, &default_task).unwrap_err();
        assert!(matches!(
            err,
            IsolationError::SecurityGrantDenied {
                ref violated_layer,
                ref offending_field,
                ..
            } if violated_layer == "HostCeiling" && offending_field == "write_paths"
        ));

        // 3. CIDR broader than or outside ceiling CIDR
        let mut p_cidr = base_profile.clone();
        p_cidr.network_egress_cidrs = vec!["192.0.0.0/16".to_string()];
        let err = resolve_effective_policy(&ceiling, &p_cidr, &default_task).unwrap_err();
        assert!(matches!(
            err,
            IsolationError::SecurityGrantDenied {
                ref violated_layer,
                ref offending_field,
                ..
            } if violated_layer == "HostCeiling" && offending_field == "network_egress_cidrs"
        ));

        // 4. Memlock exceeding ceiling
        let mut p_memlock = base_profile.clone();
        p_memlock.memlock_limit_kb = MAX_K3_MEMLOCK_KB + 1024;
        let err = resolve_effective_policy(&ceiling, &p_memlock, &default_task).unwrap_err();
        assert!(matches!(
            err,
            IsolationError::SecurityGrantDenied {
                ref violated_layer,
                ref offending_field,
                ..
            } if violated_layer == "HostCeiling" && offending_field == "memlock_limit_kb"
        ));

        // 5. Max PIDs exceeding ceiling
        let mut p_pids = base_profile.clone();
        p_pids.max_pids = ceiling.max_pids + 1;
        let err = resolve_effective_policy(&ceiling, &p_pids, &default_task).unwrap_err();
        assert!(matches!(
            err,
            IsolationError::SecurityGrantDenied {
                ref violated_layer,
                ref offending_field,
                ..
            } if violated_layer == "HostCeiling" && offending_field == "max_pids"
        ));

        // 6. Max memory exceeding ceiling
        let mut p_mem = base_profile.clone();
        p_mem.max_memory_mb = Some(ceiling.max_memory_mb + 1);
        let err = resolve_effective_policy(&ceiling, &p_mem, &default_task).unwrap_err();
        assert!(matches!(
            err,
            IsolationError::SecurityGrantDenied {
                ref violated_layer,
                ref offending_field,
                ..
            } if violated_layer == "HostCeiling" && offending_field == "max_memory_mb"
        ));

        // 7. SpacemiT AI thread requested on x86_64 node where allow_spacemit_ai_thread = false
        let mut x86_ceiling = sample_ceiling();
        x86_ceiling.node_id = "node-a".to_string();
        x86_ceiling.arch = "x86_64".to_string();
        x86_ceiling.allow_spacemit_ai_thread = false;
        let err = resolve_effective_policy(&x86_ceiling, &base_profile, &default_task).unwrap_err();
        assert!(matches!(
            err,
            IsolationError::SecurityGrantDenied {
                ref violated_layer,
                ref offending_field,
                ..
            } if violated_layer == "HostCeiling" && offending_field == "require_set_ai_thread"
        ));
    }

    #[test]
    fn test_layer3_violations_against_desired_profile() {
        let ceiling = sample_ceiling();
        let profile = sample_profile();

        // 1. Backend mismatch between task and profile
        let t_backend = TaskSandboxConfig {
            backend: Some(SandboxBackendKind::Hypervisor),
            ..Default::default()
        };
        let err = resolve_effective_policy(&ceiling, &profile, &t_backend).unwrap_err();
        assert!(matches!(
            err,
            IsolationError::SecurityGrantDenied {
                ref violated_layer,
                ref offending_field,
                ..
            } if violated_layer == "DesiredProfile" && offending_field == "backend"
        ));

        // 2. Task path outside profile path (even if allowed by host ceiling!)
        let t_path = TaskSandboxConfig {
            read_paths: vec![PathBuf::from("/lib")],
            ..Default::default()
        };
        let err = resolve_effective_policy(&ceiling, &profile, &t_path).unwrap_err();
        assert!(matches!(
            err,
            IsolationError::SecurityGrantDenied {
                ref violated_layer,
                ref offending_field,
                ..
            } if violated_layer == "DesiredProfile" && offending_field == "read_paths"
        ));

        // 3. Task network CIDR outside profile CIDR (even if inside host ceiling 192.0.2.0/24!)
        let t_net = TaskSandboxConfig {
            network_mode: NetworkEgressMode::RestrictedCidrs(vec!["192.0.2.0/25".to_string()]),
            ..Default::default()
        };
        let err = resolve_effective_policy(&ceiling, &profile, &t_net).unwrap_err();
        assert!(matches!(
            err,
            IsolationError::SecurityGrantDenied {
                ref violated_layer,
                ref offending_field,
                ..
            } if violated_layer == "DesiredProfile" && offending_field == "network_mode"
        ));

        // 4. Task requesting RestrictedCidrs when profile is pure-offline (empty egress CIDRs)
        let mut offline_profile = profile.clone();
        offline_profile.network_egress_cidrs.clear();
        let t_net_on_offline = TaskSandboxConfig {
            network_mode: NetworkEgressMode::RestrictedCidrs(vec!["192.0.2.128/25".to_string()]),
            ..Default::default()
        };
        let err =
            resolve_effective_policy(&ceiling, &offline_profile, &t_net_on_offline).unwrap_err();
        assert!(matches!(
            err,
            IsolationError::SecurityGrantDenied {
                ref violated_layer,
                ref offending_field,
                ..
            } if violated_layer == "DesiredProfile" && offending_field == "network_mode"
        ));

        // 5. Task memlock exceeding profile memlock
        let t_memlock = TaskSandboxConfig {
            memlock_limit_kb: Some(profile.memlock_limit_kb + 1),
            ..Default::default()
        };
        let err = resolve_effective_policy(&ceiling, &profile, &t_memlock).unwrap_err();
        assert!(matches!(
            err,
            IsolationError::SecurityGrantDenied {
                ref violated_layer,
                ref offending_field,
                ..
            } if violated_layer == "DesiredProfile" && offending_field == "memlock_limit_kb"
        ));

        // 6. Task max_pids exceeding profile max_pids
        let t_pids = TaskSandboxConfig {
            max_pids: Some(profile.max_pids + 1),
            ..Default::default()
        };
        let err = resolve_effective_policy(&ceiling, &profile, &t_pids).unwrap_err();
        assert!(matches!(
            err,
            IsolationError::SecurityGrantDenied {
                ref violated_layer,
                ref offending_field,
                ..
            } if violated_layer == "DesiredProfile" && offending_field == "max_pids"
        ));

        // 7. Task max_memory_mb exceeding profile max_memory_mb
        let t_mem = TaskSandboxConfig {
            max_memory_mb: Some(16_385),
            ..Default::default()
        };
        let err = resolve_effective_policy(&ceiling, &profile, &t_mem).unwrap_err();
        assert!(matches!(
            err,
            IsolationError::SecurityGrantDenied {
                ref violated_layer,
                ref offending_field,
                ..
            } if violated_layer == "DesiredProfile" && offending_field == "max_memory_mb"
        ));

        // 8. Task require_set_ai_thread = true when profile has require_set_ai_thread = false
        let mut non_ai_profile = profile.clone();
        non_ai_profile.require_set_ai_thread = false;
        let t_ai = TaskSandboxConfig {
            require_set_ai_thread: Some(true),
            ..Default::default()
        };
        let err = resolve_effective_policy(&ceiling, &non_ai_profile, &t_ai).unwrap_err();
        assert!(matches!(
            err,
            IsolationError::SecurityGrantDenied {
                ref violated_layer,
                ref offending_field,
                ..
            } if violated_layer == "DesiredProfile" && offending_field == "require_set_ai_thread"
        ));

        // 9. Task cpu_affinity_mask (0x00FF, cluster 0) not a subset of profile mask (0xFF00, cluster 1)
        let t_mask = TaskSandboxConfig {
            cpu_affinity_mask: Some(0x01FF),
            ..Default::default()
        };
        let err = resolve_effective_policy(&ceiling, &profile, &t_mask).unwrap_err();
        assert!(matches!(
            err,
            IsolationError::SecurityGrantDenied {
                ref violated_layer,
                ref offending_field,
                ..
            } if violated_layer == "DesiredProfile" && offending_field == "cpu_affinity_mask"
        ));
    }
}
