use std::fs;
use std::net::Ipv4Addr;
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::IsolationError;

/// Maximum bounded `RLIMIT_MEMLOCK` ceiling on a 32 GiB SpacemiT K3 host (28 GiB = 29,360,128 KB),
/// preserving ~3.3 GiB strictly for the headless Linux kernel, slab allocator, and SSH daemon.
pub const MAX_K3_MEMLOCK_KB: u64 = 29_360_128;

/// Isolation execution backend kind.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone, Copy, Default)]
pub enum SandboxBackendKind {
    /// Containerless Linux kernel sandbox (Landlock LSM, cgroupv2, namespaces, seccomp-BPF).
    #[default]
    #[serde(alias = "kernel", alias = "KernelSandbox", alias = "kernel_sandbox")]
    Kernel,
    /// Hardware-virtualized KVM microVM sandbox (RISC-V `H` extension or Intel VT-x).
    #[serde(
        alias = "hypervisor",
        alias = "HypervisorSandbox",
        alias = "hypervisor_sandbox"
    )]
    Hypervisor,
}

/// Network egress policy mode for a sandboxed task.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone, Default)]
pub enum NetworkEgressMode {
    /// Complete network isolation (`CLONE_NEWNET` with loopback only, no external egress).
    #[default]
    #[serde(alias = "offline")]
    Offline,
    /// Egress restricted to the specified IPv4 CIDR blocks.
    #[serde(alias = "restricted_cidrs")]
    RestrictedCidrs(Vec<String>),
}

/// Layer 1: Operator Host Ceiling configuration (`/etc/mu-isolation/ceiling.yml`).
///
/// Defines the absolute upper bound of resources, filesystem paths, network egress CIDRs,
/// and hardware features that any repository profile or task on this host may request.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct HostCeilingConfig {
    pub node_id: String,
    pub arch: String,
    #[serde(default)]
    pub allowed_backends: Vec<SandboxBackendKind>,
    #[serde(default)]
    pub allowed_read_prefixes: Vec<PathBuf>,
    #[serde(default)]
    pub allowed_write_prefixes: Vec<PathBuf>,
    #[serde(default)]
    pub allowed_exec_prefixes: Vec<PathBuf>,
    #[serde(default)]
    pub allowed_egress_cidrs: Vec<String>,
    pub max_memlock_kb: u64,
    pub max_cpu_cores: u32,
    pub max_memory_mb: u64,
    pub max_pids: u32,
    #[serde(default)]
    pub allow_spacemit_ai_thread: bool,
}

impl HostCeilingConfig {
    /// Parse and validate a `HostCeilingConfig` from a YAML string.
    pub fn from_yaml_str(yaml: &str) -> Result<Self, IsolationError> {
        let config: Self = serde_yaml::from_str(yaml)?;
        config.validate()?;
        Ok(config)
    }

    /// Read, parse, and validate a `HostCeilingConfig` from a filesystem path.
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self, IsolationError> {
        let content = fs::read_to_string(path.as_ref())?;
        Self::from_yaml_str(&content)
    }

    /// Validate all host ceiling invariants, failing closed on unbounded or empty limits.
    pub fn validate(&self) -> Result<(), IsolationError> {
        if self.node_id.trim().is_empty() {
            return Err(IsolationError::InvalidHostCeiling {
                field: "node_id".to_string(),
                reason: "node_id must not be empty".to_string(),
            });
        }

        if self.arch.trim().is_empty() {
            return Err(IsolationError::InvalidHostCeiling {
                field: "arch".to_string(),
                reason: "arch must not be empty".to_string(),
            });
        }

        if self.allowed_backends.is_empty() {
            return Err(IsolationError::InvalidHostCeiling {
                field: "allowed_backends".to_string(),
                reason: "allowed_backends must contain at least one backend".to_string(),
            });
        }

        if self.max_memlock_kb == 0 {
            return Err(IsolationError::InvalidHostCeiling {
                field: "max_memlock_kb".to_string(),
                reason: "max_memlock_kb must be greater than 0".to_string(),
            });
        }

        if self.max_memlock_kb == u64::MAX || self.max_memlock_kb > MAX_K3_MEMLOCK_KB {
            return Err(IsolationError::InvalidHostCeiling {
                field: "max_memlock_kb".to_string(),
                reason: format!(
                    "max_memlock_kb ({}) exceeds bounded ceiling MAX_K3_MEMLOCK_KB ({} KB / 28 GiB); 'unlimited' memlock is forbidden",
                    self.max_memlock_kb, MAX_K3_MEMLOCK_KB
                ),
            });
        }

        if self.max_cpu_cores == 0 {
            return Err(IsolationError::InvalidHostCeiling {
                field: "max_cpu_cores".to_string(),
                reason: "max_cpu_cores must be greater than 0".to_string(),
            });
        }

        if self.max_memory_mb == 0 {
            return Err(IsolationError::InvalidHostCeiling {
                field: "max_memory_mb".to_string(),
                reason: "max_memory_mb must be greater than 0".to_string(),
            });
        }

        if self.max_pids == 0 {
            return Err(IsolationError::InvalidHostCeiling {
                field: "max_pids".to_string(),
                reason: "max_pids must be greater than 0".to_string(),
            });
        }

        for cidr in &self.allowed_egress_cidrs {
            if let Err(reason) = parse_ipv4_cidr(cidr) {
                return Err(IsolationError::InvalidHostCeiling {
                    field: "allowed_egress_cidrs".to_string(),
                    reason: format!("invalid CIDR '{cidr}': {reason}"),
                });
            }
        }

        for (field, prefixes) in [
            ("allowed_read_prefixes", &self.allowed_read_prefixes),
            ("allowed_write_prefixes", &self.allowed_write_prefixes),
            ("allowed_exec_prefixes", &self.allowed_exec_prefixes),
        ] {
            for prefix in prefixes {
                if normalize_clean_path(prefix).is_none() {
                    return Err(IsolationError::InvalidHostCeiling {
                        field: field.to_string(),
                        reason: format!(
                            "path prefix '{}' must be a normalized absolute path without '..'",
                            prefix.display()
                        ),
                    });
                }
            }
        }

        Ok(())
    }
}

/// Normalize an absolute filesystem path, rejecting empty paths, relative paths, and any `..` traversal components.
pub fn normalize_clean_path(path: &Path) -> Option<PathBuf> {
    if path.as_os_str().is_empty() || !path.is_absolute() {
        return None;
    }

    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(p) => normalized.push(p.as_os_str()),
            Component::RootDir => normalized.push(component.as_os_str()),
            Component::CurDir => {}
            Component::Normal(part) => normalized.push(part),
            Component::ParentDir => return None,
        }
    }

    if normalized.as_os_str().is_empty() {
        None
    } else {
        Some(normalized)
    }
}

/// Parse an IPv4 CIDR string (`a.b.c.d/prefix_len`) into `(ip_u32, prefix_len)`.
pub fn parse_ipv4_cidr(cidr: &str) -> Result<(u32, u8), String> {
    let trimmed = cidr.trim();
    let (ip_part, prefix_part) = trimmed
        .split_once('/')
        .ok_or_else(|| "missing '/prefix_len' delimiter".to_string())?;

    let addr: Ipv4Addr = ip_part
        .parse()
        .map_err(|e| format!("invalid IPv4 address '{ip_part}': {e}"))?;

    let prefix_len: u8 = prefix_part
        .parse()
        .map_err(|e| format!("invalid prefix length '{prefix_part}': {e}"))?;

    if prefix_len > 32 {
        return Err(format!("prefix length {prefix_len} exceeds 32"));
    }

    Ok((u32::from(addr), prefix_len))
}

/// Compute the 32-bit netmask for a given IPv4 prefix length (`0..=32`).
#[inline]
pub fn ipv4_prefix_mask(prefix_len: u8) -> u32 {
    if prefix_len == 0 {
        0
    } else {
        !0u32 << (32 - prefix_len)
    }
}

/// Check whether `child_cidr` is a subnet of (or equal to) `parent_cidr`.
pub fn cidr_contains(parent_cidr: &str, child_cidr: &str) -> Result<bool, String> {
    let (parent_ip, parent_len) = parse_ipv4_cidr(parent_cidr)?;
    let (child_ip, child_len) = parse_ipv4_cidr(child_cidr)?;

    if child_len < parent_len {
        return Ok(false);
    }

    let mask = ipv4_prefix_mask(parent_len);
    Ok((parent_ip & mask) == (child_ip & mask))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    fn sample_valid_ceiling_yaml() -> &'static str {
        r#"
node_id: "worker-riscv64"
arch: "riscv64gc"
allowed_backends:
  - Kernel
  - Hypervisor
allowed_read_prefixes:
  - /usr
  - /lib
  - /etc/ssl
  - /var/lib/action-runner
allowed_write_prefixes:
  - /var/lib/action-runner/workspaces
  - /tmp
allowed_exec_prefixes:
  - /usr/bin
  - /usr/local/bin
  - /var/lib/action-runner/.cargo/bin
allowed_egress_cidrs:
  - "192.0.2.0/24"
  - "198.51.100.0/24"
max_memlock_kb: 29360128
max_cpu_cores: 16
max_memory_mb: 28672
max_pids: 512
allow_spacemit_ai_thread: true
"#
    }

    #[test]
    fn test_parse_valid_host_ceiling_yaml() {
        let cfg = HostCeilingConfig::from_yaml_str(sample_valid_ceiling_yaml())
            .expect("valid ceiling YAML should parse");
        assert_eq!(cfg.node_id, "worker-riscv64");
        assert_eq!(cfg.arch, "riscv64gc");
        assert_eq!(
            cfg.allowed_backends,
            vec![SandboxBackendKind::Kernel, SandboxBackendKind::Hypervisor]
        );
        assert_eq!(cfg.max_memlock_kb, MAX_K3_MEMLOCK_KB);
        assert_eq!(cfg.max_cpu_cores, 16);
        assert_eq!(cfg.max_memory_mb, 28672);
        assert_eq!(cfg.max_pids, 512);
        assert!(cfg.allow_spacemit_ai_thread);
    }

    #[test]
    fn test_load_host_ceiling_from_path() {
        let tmp = NamedTempFile::new().expect("create temp file");
        fs::write(tmp.path(), sample_valid_ceiling_yaml()).expect("write ceiling yaml");
        let cfg = HostCeilingConfig::from_path(tmp.path()).expect("load from path");
        assert_eq!(cfg.node_id, "worker-riscv64");
    }

    #[test]
    fn test_reject_memlock_zero_unlimited_or_above_k3_ceiling() {
        let mut cfg = HostCeilingConfig::from_yaml_str(sample_valid_ceiling_yaml()).unwrap();

        cfg.max_memlock_kb = 0;
        assert!(matches!(
            cfg.validate(),
            Err(IsolationError::InvalidHostCeiling { ref field, .. }) if field == "max_memlock_kb"
        ));

        cfg.max_memlock_kb = MAX_K3_MEMLOCK_KB + 1;
        assert!(matches!(
            cfg.validate(),
            Err(IsolationError::InvalidHostCeiling { ref field, .. }) if field == "max_memlock_kb"
        ));

        cfg.max_memlock_kb = u64::MAX;
        assert!(matches!(
            cfg.validate(),
            Err(IsolationError::InvalidHostCeiling { ref field, .. }) if field == "max_memlock_kb"
        ));
    }

    #[test]
    fn test_reject_empty_fields_and_zero_limits() {
        let base = HostCeilingConfig::from_yaml_str(sample_valid_ceiling_yaml()).unwrap();

        let mut c1 = base.clone();
        c1.node_id = "   ".to_string();
        assert!(matches!(
            c1.validate(),
            Err(IsolationError::InvalidHostCeiling { ref field, .. }) if field == "node_id"
        ));

        let mut c2 = base.clone();
        c2.arch = "".to_string();
        assert!(matches!(
            c2.validate(),
            Err(IsolationError::InvalidHostCeiling { ref field, .. }) if field == "arch"
        ));

        let mut c3 = base.clone();
        c3.allowed_backends.clear();
        assert!(matches!(
            c3.validate(),
            Err(IsolationError::InvalidHostCeiling { ref field, .. }) if field == "allowed_backends"
        ));

        let mut c4 = base.clone();
        c4.max_cpu_cores = 0;
        assert!(matches!(
            c4.validate(),
            Err(IsolationError::InvalidHostCeiling { ref field, .. }) if field == "max_cpu_cores"
        ));

        let mut c5 = base.clone();
        c5.max_memory_mb = 0;
        assert!(matches!(
            c5.validate(),
            Err(IsolationError::InvalidHostCeiling { ref field, .. }) if field == "max_memory_mb"
        ));

        let mut c6 = base.clone();
        c6.max_pids = 0;
        assert!(matches!(
            c6.validate(),
            Err(IsolationError::InvalidHostCeiling { ref field, .. }) if field == "max_pids"
        ));
    }

    #[test]
    fn test_reject_invalid_cidr_and_traversal_prefix_in_ceiling() {
        let base = HostCeilingConfig::from_yaml_str(sample_valid_ceiling_yaml()).unwrap();

        let mut bad_cidr = base.clone();
        bad_cidr.allowed_egress_cidrs = vec!["192.0.2.0/33".to_string()];
        assert!(matches!(
            bad_cidr.validate(),
            Err(IsolationError::InvalidHostCeiling { ref field, .. }) if field == "allowed_egress_cidrs"
        ));

        let mut bad_prefix = base;
        bad_prefix.allowed_read_prefixes = vec![PathBuf::from("/var/lib/../etc/shadow")];
        assert!(matches!(
            bad_prefix.validate(),
            Err(IsolationError::InvalidHostCeiling { ref field, .. }) if field == "allowed_read_prefixes"
        ));
    }
}
