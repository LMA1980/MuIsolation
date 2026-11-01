use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::error::IsolationError;
use crate::policy::{normalize_clean_path, EffectiveSandboxPolicy};

pub const ACCESS_READ_FILE: u32 = 1 << 0;
pub const ACCESS_READ_DIR: u32 = 1 << 1;
pub const ACCESS_WRITE_FILE: u32 = 1 << 2;
pub const ACCESS_REMOVE_FILE: u32 = 1 << 3;
pub const ACCESS_REMOVE_DIR: u32 = 1 << 4;
pub const ACCESS_MAKE_REG: u32 = 1 << 5;
pub const ACCESS_MAKE_DIR: u32 = 1 << 6;
pub const ACCESS_TRUNCATE: u32 = 1 << 7;
pub const ACCESS_EXECUTE: u32 = 1 << 8;

/// Read-only filesystem access bitmask (`read_file | read_dir`).
pub const READ_ACCESS: u32 = ACCESS_READ_FILE | ACCESS_READ_DIR;

/// Read-write filesystem access bitmask (`read + write + create + remove + truncate`).
pub const WRITE_ACCESS: u32 = ACCESS_READ_FILE
    | ACCESS_READ_DIR
    | ACCESS_WRITE_FILE
    | ACCESS_REMOVE_FILE
    | ACCESS_REMOVE_DIR
    | ACCESS_MAKE_REG
    | ACCESS_MAKE_DIR
    | ACCESS_TRUNCATE;

/// Execute filesystem access bitmask (`read_file | read_dir | execute`).
pub const EXEC_ACCESS: u32 = ACCESS_READ_FILE | ACCESS_READ_DIR | ACCESS_EXECUTE;

/// A deterministic Landlock filesystem path rule with merged access bitflags.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct LandlockPathRule {
    pub path: PathBuf,
    pub access_mask: u32,
}

/// Builder for converting an `EffectiveSandboxPolicy` into deterministic Landlock LSM path rules.
pub struct LandlockRuleBuilder;

impl LandlockRuleBuilder {
    /// Convert `policy.read_paths`, `policy.write_paths`, and `policy.exec_paths` into a
    /// deterministic, sorted, deduplicated list of `LandlockPathRule` entries, merging
    /// bitmasks when a path is granted multiple access modes.
    pub fn build_rules(
        policy: &EffectiveSandboxPolicy,
    ) -> Result<Vec<LandlockPathRule>, IsolationError> {
        let mut merged: BTreeMap<PathBuf, u32> = BTreeMap::new();

        for (paths, mask) in [
            (&policy.read_paths, READ_ACCESS),
            (&policy.write_paths, WRITE_ACCESS),
            (&policy.exec_paths, EXEC_ACCESS),
        ] {
            for raw_path in paths {
                let clean = normalize_clean_path(raw_path).ok_or_else(|| {
                    IsolationError::SandboxExecutionFailed(format!(
                        "invalid Landlock path rule '{}': must be a normalized absolute path without '..'",
                        raw_path.display()
                    ))
                })?;
                *merged.entry(clean).or_insert(0) |= mask;
            }
        }

        let rules = merged
            .into_iter()
            .map(|(path, access_mask)| LandlockPathRule { path, access_mask })
            .collect();

        Ok(rules)
    }

    /// Apply the Landlock ruleset (`ABI::V3`) to restrict the calling process on Linux.
    /// On non-Linux hosts, validates all rule invariants and returns `Ok(())`.
    pub fn apply_rules(rules: &[LandlockPathRule]) -> Result<(), IsolationError> {
        for rule in rules {
            if rule.access_mask == 0 {
                return Err(IsolationError::SandboxExecutionFailed(format!(
                    "Landlock rule for '{}' has an empty access_mask (0)",
                    rule.path.display()
                )));
            }
            if normalize_clean_path(&rule.path).is_none() {
                return Err(IsolationError::SandboxExecutionFailed(format!(
                    "Landlock rule path '{}' is not a normalized absolute path",
                    rule.path.display()
                )));
            }
        }

        #[cfg(target_os = "linux")]
        {
            use landlock::{
                Access, AccessFs, BitFlags, PathBeneath, PathFd, Ruleset, RulesetAttr,
                RulesetCreatedAttr, ABI,
            };

            let abi = ABI::V3;
            let mut ruleset = Ruleset::default()
                .handle_access(AccessFs::from_all(abi))
                .map_err(|e| {
                    IsolationError::SandboxExecutionFailed(format!(
                        "failed to initialize Landlock ABI::V3 ruleset: {e}"
                    ))
                })?
                .create()
                .map_err(|e| {
                    IsolationError::SandboxExecutionFailed(format!(
                        "failed to create Landlock ruleset: {e}"
                    ))
                })?;

            for rule in rules {
                let mut access = BitFlags::<AccessFs>::empty();
                if (rule.access_mask & ACCESS_READ_FILE) != 0 {
                    access |= AccessFs::ReadFile;
                }
                if (rule.access_mask & ACCESS_READ_DIR) != 0 {
                    access |= AccessFs::ReadDir;
                }
                if (rule.access_mask & ACCESS_WRITE_FILE) != 0 {
                    access |= AccessFs::WriteFile;
                }
                if (rule.access_mask & ACCESS_REMOVE_FILE) != 0 {
                    access |= AccessFs::RemoveFile;
                }
                if (rule.access_mask & ACCESS_REMOVE_DIR) != 0 {
                    access |= AccessFs::RemoveDir;
                }
                if (rule.access_mask & ACCESS_MAKE_REG) != 0 {
                    access |= AccessFs::MakeReg;
                }
                if (rule.access_mask & ACCESS_MAKE_DIR) != 0 {
                    access |= AccessFs::MakeDir;
                }
                if (rule.access_mask & ACCESS_TRUNCATE) != 0 {
                    access |= AccessFs::Truncate;
                }
                if (rule.access_mask & ACCESS_EXECUTE) != 0 {
                    access |= AccessFs::Execute;
                }

                let path_fd = PathFd::new(&rule.path).map_err(|e| {
                    IsolationError::SandboxExecutionFailed(format!(
                        "failed to open Landlock PathFd for '{}': {e}",
                        rule.path.display()
                    ))
                })?;
                ruleset = ruleset
                    .add_rule(PathBeneath::new(path_fd, access))
                    .map_err(|e| {
                        IsolationError::SandboxExecutionFailed(format!(
                            "failed to add Landlock PathBeneath rule for '{}': {e}",
                            rule.path.display()
                        ))
                    })?;
            }

            ruleset.restrict_self().map_err(|e| {
                IsolationError::SandboxExecutionFailed(format!(
                    "Landlock restrict_self() failed: {e}"
                ))
            })?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{NetworkEgressMode, SandboxBackendKind};

    fn sample_effective_policy() -> EffectiveSandboxPolicy {
        EffectiveSandboxPolicy {
            node_id: "worker-riscv64".to_string(),
            arch: "riscv64gc".to_string(),
            backend: SandboxBackendKind::Kernel,
            read_paths: vec![
                PathBuf::from("/usr"),
                PathBuf::from("/var/lib/action-runner/workspaces/repo"),
            ],
            write_paths: vec![
                PathBuf::from("/tmp"),
                PathBuf::from("/var/lib/action-runner/workspaces/repo"),
            ],
            exec_paths: vec![PathBuf::from("/usr"), PathBuf::from("/usr/bin")],
            network_mode: NetworkEgressMode::Offline,
            memlock_limit_kb: 65536,
            max_pids: 64,
            max_memory_mb: 4096,
            max_cpu_cores: 8,
            cpu_affinity_mask: Some(0x00FF),
            require_set_ai_thread: false,
        }
    }

    #[test]
    fn test_landlock_rule_builder_merges_and_sorts_deterministically() {
        let policy = sample_effective_policy();
        let rules = LandlockRuleBuilder::build_rules(&policy).expect("build Landlock rules");

        assert_eq!(rules.len(), 4);
        assert_eq!(rules[0].path, PathBuf::from("/tmp"));
        assert_eq!(rules[0].access_mask, WRITE_ACCESS);

        // /usr appears in both read_paths and exec_paths
        assert_eq!(rules[1].path, PathBuf::from("/usr"));
        assert_eq!(rules[1].access_mask, READ_ACCESS | EXEC_ACCESS);

        assert_eq!(rules[2].path, PathBuf::from("/usr/bin"));
        assert_eq!(rules[2].access_mask, EXEC_ACCESS);

        // /var/lib/action-runner/workspaces/repo appears in both read_paths and write_paths
        assert_eq!(
            rules[3].path,
            PathBuf::from("/var/lib/action-runner/workspaces/repo")
        );
        assert_eq!(rules[3].access_mask, READ_ACCESS | WRITE_ACCESS);
    }

    #[test]
    fn test_landlock_rule_builder_rejects_relative_or_traversal_path() {
        let mut policy = sample_effective_policy();
        policy.read_paths.push(PathBuf::from("/usr/../etc/shadow"));
        let err = LandlockRuleBuilder::build_rules(&policy).unwrap_err();
        assert!(matches!(err, IsolationError::SandboxExecutionFailed(_)));
    }
}
