use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::error::IsolationError;
use crate::policy::{EffectiveSandboxPolicy, NetworkEgressMode};

pub const CLONE_NEWNS: u32 = 0x0002_0000;
pub const CLONE_NEWUTS: u32 = 0x0400_0000;
pub const CLONE_NEWIPC: u32 = 0x0800_0000;
pub const CLONE_NEWUSER: u32 = 0x1000_0000;
pub const CLONE_NEWPID: u32 = 0x2000_0000;
pub const CLONE_NEWNET: u32 = 0x4000_0000;

/// Bitmask of Linux namespace clone/unshare flags (`CLONE_NEW*`).
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone, Copy, Default)]
pub struct NamespaceCloneFlags(pub u32);

impl NamespaceCloneFlags {
    /// Return the raw 32-bit namespace clone bitmask.
    #[inline]
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Check whether all bits in `flag` are set in `self`.
    #[inline]
    pub const fn contains(self, flag: u32) -> bool {
        (self.0 & flag) == flag
    }
}

/// Specification for an ephemeral `/tmp` tmpfs mount inside an unshared mount namespace.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct TmpfsMountSpec {
    pub target: PathBuf,
    pub options: Vec<String>,
}

/// Linux namespace isolation planner and executor (`CLONE_NEWNS`, `CLONE_NEWPID`,
/// `CLONE_NEWIPC`, `CLONE_NEWUTS`, `CLONE_NEWUSER`, and conditional `CLONE_NEWNET`).
pub struct NamespaceIsolator;

impl NamespaceIsolator {
    /// Derive the `NamespaceCloneFlags` bitmask for an `EffectiveSandboxPolicy`.
    ///
    /// Always unshares mount (`CLONE_NEWNS`), PID (`CLONE_NEWPID`), IPC (`CLONE_NEWIPC`),
    /// UTS (`CLONE_NEWUTS`), and user (`CLONE_NEWUSER`) namespaces. Additionally unshares
    /// the network namespace (`CLONE_NEWNET`) when `policy.network_mode == NetworkEgressMode::Offline`.
    pub fn derive_clone_flags(policy: &EffectiveSandboxPolicy) -> NamespaceCloneFlags {
        let mut bits = CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWIPC | CLONE_NEWUTS | CLONE_NEWUSER;
        if policy.network_mode == NetworkEgressMode::Offline {
            bits |= CLONE_NEWNET;
        }
        NamespaceCloneFlags(bits)
    }

    /// Return the canonical hardened tmpfs mount specification for `/tmp` (`nodev`, `nosuid`, `noexec`).
    pub fn tmpfs_mount_spec() -> TmpfsMountSpec {
        TmpfsMountSpec {
            target: PathBuf::from("/tmp"),
            options: vec![
                "nodev".to_string(),
                "nosuid".to_string(),
                "noexec".to_string(),
            ],
        }
    }

    /// Execute `unshare(2)` with the specified `NamespaceCloneFlags` on Linux.
    /// On non-Linux hosts, validates that `flags` is non-zero and returns `Ok(())`.
    pub fn apply_unshare(flags: NamespaceCloneFlags) -> Result<(), IsolationError> {
        if flags.bits() == 0 {
            return Err(IsolationError::SandboxExecutionFailed(
                "cannot apply unshare with empty NamespaceCloneFlags (0)".to_string(),
            ));
        }

        #[cfg(target_os = "linux")]
        {
            use nix::sched::{unshare, CloneFlags};

            let mut nix_flags = CloneFlags::empty();
            if flags.contains(CLONE_NEWNS) {
                nix_flags |= CloneFlags::CLONE_NEWNS;
            }
            if flags.contains(CLONE_NEWUTS) {
                nix_flags |= CloneFlags::CLONE_NEWUTS;
            }
            if flags.contains(CLONE_NEWIPC) {
                nix_flags |= CloneFlags::CLONE_NEWIPC;
            }
            if flags.contains(CLONE_NEWUSER) {
                nix_flags |= CloneFlags::CLONE_NEWUSER;
            }
            if flags.contains(CLONE_NEWPID) {
                nix_flags |= CloneFlags::CLONE_NEWPID;
            }
            if flags.contains(CLONE_NEWNET) {
                nix_flags |= CloneFlags::CLONE_NEWNET;
            }

            unshare(nix_flags).map_err(|e| {
                IsolationError::SandboxExecutionFailed(format!(
                    "Linux namespace unshare({:#x}) failed: {e}",
                    flags.bits()
                ))
            })?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::SandboxBackendKind;

    fn sample_policy(network_mode: NetworkEgressMode) -> EffectiveSandboxPolicy {
        EffectiveSandboxPolicy {
            node_id: "worker-riscv64".to_string(),
            arch: "riscv64gc".to_string(),
            backend: SandboxBackendKind::Kernel,
            read_paths: vec![PathBuf::from("/usr")],
            write_paths: vec![PathBuf::from("/tmp")],
            exec_paths: vec![PathBuf::from("/usr/bin")],
            network_mode,
            memlock_limit_kb: 65536,
            max_pids: 64,
            max_memory_mb: 4096,
            max_cpu_cores: 8,
            cpu_affinity_mask: Some(0x00FF),
            require_set_ai_thread: false,
        }
    }

    #[test]
    fn test_derive_clone_flags_offline_includes_clone_newnet() {
        let policy = sample_policy(NetworkEgressMode::Offline);
        let flags = NamespaceIsolator::derive_clone_flags(&policy);

        assert!(flags.contains(CLONE_NEWNS));
        assert!(flags.contains(CLONE_NEWPID));
        assert!(flags.contains(CLONE_NEWIPC));
        assert!(flags.contains(CLONE_NEWUTS));
        assert!(flags.contains(CLONE_NEWUSER));
        assert!(flags.contains(CLONE_NEWNET));
    }

    #[test]
    fn test_derive_clone_flags_restricted_cidrs_omits_clone_newnet() {
        let policy = sample_policy(NetworkEgressMode::RestrictedCidrs(vec![
            "192.0.2.0/24".to_string()
        ]));
        let flags = NamespaceIsolator::derive_clone_flags(&policy);

        assert!(flags.contains(CLONE_NEWNS));
        assert!(flags.contains(CLONE_NEWPID));
        assert!(flags.contains(CLONE_NEWIPC));
        assert!(flags.contains(CLONE_NEWUTS));
        assert!(flags.contains(CLONE_NEWUSER));
        assert!(!flags.contains(CLONE_NEWNET));
    }

    #[test]
    fn test_tmpfs_mount_spec_hardened_options() {
        let spec = NamespaceIsolator::tmpfs_mount_spec();
        assert_eq!(spec.target, PathBuf::from("/tmp"));
        assert_eq!(spec.options, vec!["nodev", "nosuid", "noexec"]);
    }
}
