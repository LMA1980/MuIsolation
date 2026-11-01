use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::IsolationError;
use crate::policy::ceiling::{parse_ipv4_cidr, SandboxBackendKind};

/// Layer 2: Repository-level desired security profile file (`.actionrunner/security.yml`).
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct DesiredSecurityFile {
    pub default_profile: String,
    pub profiles: BTreeMap<String, DesiredProfileConfig>,
}

/// Layer 2: A named desired security profile within `.actionrunner/security.yml`.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct DesiredProfileConfig {
    #[serde(default)]
    pub backend: SandboxBackendKind,
    #[serde(default)]
    pub read_paths: Vec<PathBuf>,
    #[serde(default)]
    pub write_paths: Vec<PathBuf>,
    #[serde(default)]
    pub exec_paths: Vec<PathBuf>,
    #[serde(default)]
    pub network_egress_cidrs: Vec<String>,
    pub memlock_limit_kb: u64,
    pub max_pids: u32,
    #[serde(default)]
    pub max_memory_mb: Option<u64>,
    #[serde(default)]
    pub cpu_affinity_mask: Option<u32>,
    #[serde(default)]
    pub require_set_ai_thread: bool,
}

impl DesiredSecurityFile {
    /// Parse and validate a `DesiredSecurityFile` from a YAML string.
    pub fn from_yaml_str(yaml: &str) -> Result<Self, IsolationError> {
        let file: Self = serde_yaml::from_str(yaml)?;
        file.validate()?;
        Ok(file)
    }

    /// Read, parse, and validate a `DesiredSecurityFile` from a filesystem path.
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self, IsolationError> {
        let content = fs::read_to_string(path.as_ref())?;
        Self::from_yaml_str(&content)
    }

    /// Validate structural invariants of the desired security profile configuration.
    pub fn validate(&self) -> Result<(), IsolationError> {
        if self.default_profile.trim().is_empty() {
            return Err(IsolationError::InvalidProfileConfig {
                reason: "default_profile must not be empty".to_string(),
            });
        }

        if self.profiles.is_empty() {
            return Err(IsolationError::InvalidProfileConfig {
                reason: "profiles map must contain at least one profile".to_string(),
            });
        }

        if !self.profiles.contains_key(&self.default_profile) {
            return Err(IsolationError::InvalidProfileConfig {
                reason: format!(
                    "default_profile '{}' is not defined in profiles",
                    self.default_profile
                ),
            });
        }

        for (name, profile) in &self.profiles {
            if name.trim().is_empty() {
                return Err(IsolationError::InvalidProfileConfig {
                    reason: "profile name must not be empty".to_string(),
                });
            }

            if profile.memlock_limit_kb == 0 || profile.memlock_limit_kb == u64::MAX {
                return Err(IsolationError::InvalidProfileConfig {
                    reason: format!(
                        "profile '{name}' has invalid memlock_limit_kb ({}); must be bounded and > 0",
                        profile.memlock_limit_kb
                    ),
                });
            }

            if profile.max_pids == 0 {
                return Err(IsolationError::InvalidProfileConfig {
                    reason: format!("profile '{name}' must have max_pids > 0"),
                });
            }

            if profile.max_memory_mb == Some(0) {
                return Err(IsolationError::InvalidProfileConfig {
                    reason: format!("profile '{name}' cannot specify max_memory_mb = 0"),
                });
            }

            if profile.cpu_affinity_mask == Some(0) {
                return Err(IsolationError::InvalidProfileConfig {
                    reason: format!("profile '{name}' cannot specify cpu_affinity_mask = 0"),
                });
            }

            for cidr in &profile.network_egress_cidrs {
                if let Err(err) = parse_ipv4_cidr(cidr) {
                    return Err(IsolationError::InvalidProfileConfig {
                        reason: format!(
                            "profile '{name}' contains invalid network_egress_cidr '{cidr}': {err}"
                        ),
                    });
                }
            }
        }

        Ok(())
    }

    /// Look up a profile by optional name, falling back to `default_profile` when `name` is `None`.
    pub fn get_profile(
        &self,
        name: Option<&str>,
    ) -> Result<(&str, &DesiredProfileConfig), IsolationError> {
        let target = name.unwrap_or(&self.default_profile);
        self.profiles
            .get_key_value(target)
            .map(|(k, v)| (k.as_str(), v))
            .ok_or_else(|| IsolationError::UnknownSecurityProfile {
                profile_name: target.to_string(),
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    fn sample_security_yaml() -> &'static str {
        r#"
default_profile: "pure-offline"
profiles:
  pure-offline:
    backend: Kernel
    read_paths:
      - /usr
      - /lib
      - /var/lib/action-runner/workspaces/repo
    write_paths:
      - /var/lib/action-runner/workspaces/repo/target
      - /tmp
    exec_paths:
      - /usr/bin
      - /var/lib/action-runner/.cargo/bin
    network_egress_cidrs: []
    memlock_limit_kb: 65536
    max_pids: 128
    max_memory_mb: 8192
    cpu_affinity_mask: 0x00FF
    require_set_ai_thread: false
  k3-matrix-bench:
    backend: Kernel
    read_paths:
      - /usr
      - /var/lib/action-runner/workspaces/repo
    write_paths:
      - /tmp
    exec_paths:
      - /usr/bin
    network_egress_cidrs:
      - "192.0.2.128/25"
    memlock_limit_kb: 4194304
    max_pids: 64
    max_memory_mb: 16384
    cpu_affinity_mask: 0xFF00
    require_set_ai_thread: true
"#
    }

    #[test]
    fn test_parse_desired_security_file_and_lookup_profiles() {
        let sec = DesiredSecurityFile::from_yaml_str(sample_security_yaml())
            .expect("valid security.yml should parse");
        assert_eq!(sec.default_profile, "pure-offline");
        assert_eq!(sec.profiles.len(), 2);

        let (default_name, default_prof) = sec.get_profile(None).expect("resolve default profile");
        assert_eq!(default_name, "pure-offline");
        assert_eq!(default_prof.backend, SandboxBackendKind::Kernel);
        assert_eq!(default_prof.memlock_limit_kb, 65536);
        assert_eq!(default_prof.cpu_affinity_mask, Some(0x00FF));
        assert!(!default_prof.require_set_ai_thread);

        let (bench_name, bench_prof) = sec
            .get_profile(Some("k3-matrix-bench"))
            .expect("resolve k3-matrix-bench profile");
        assert_eq!(bench_name, "k3-matrix-bench");
        assert_eq!(bench_prof.cpu_affinity_mask, Some(0xFF00));
        assert!(bench_prof.require_set_ai_thread);

        let err = sec.get_profile(Some("non-existent")).unwrap_err();
        assert!(matches!(
            err,
            IsolationError::UnknownSecurityProfile { ref profile_name } if profile_name == "non-existent"
        ));
    }

    #[test]
    fn test_load_desired_security_file_from_path() {
        let tmp = NamedTempFile::new().expect("temp file");
        fs::write(tmp.path(), sample_security_yaml()).expect("write yaml");
        let sec = DesiredSecurityFile::from_path(tmp.path()).expect("load from path");
        assert_eq!(sec.default_profile, "pure-offline");
    }

    #[test]
    fn test_reject_missing_default_profile_or_invalid_limits() {
        let bad_default = r#"
default_profile: "missing"
profiles:
  pure-offline:
    memlock_limit_kb: 65536
    max_pids: 64
"#;
        assert!(matches!(
            DesiredSecurityFile::from_yaml_str(bad_default),
            Err(IsolationError::InvalidProfileConfig { .. })
        ));

        let zero_memlock = r#"
default_profile: "pure-offline"
profiles:
  pure-offline:
    memlock_limit_kb: 0
    max_pids: 64
"#;
        assert!(matches!(
            DesiredSecurityFile::from_yaml_str(zero_memlock),
            Err(IsolationError::InvalidProfileConfig { .. })
        ));

        let bad_cidr = r#"
default_profile: "pure-offline"
profiles:
  pure-offline:
    memlock_limit_kb: 1024
    max_pids: 64
    network_egress_cidrs:
      - "not-a-cidr"
"#;
        assert!(matches!(
            DesiredSecurityFile::from_yaml_str(bad_cidr),
            Err(IsolationError::InvalidProfileConfig { .. })
        ));
    }
}
