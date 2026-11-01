use std::fs;
use std::path::Path;

use crate::error::IsolationError;
use crate::policy::MAX_K3_MEMLOCK_KB;

/// Canonical SpacemiT K3 Cluster 0 (`X100`, cores `0–7`) CPU affinity mask.
/// Out-of-Order general-purpose cores (`2.15 GHz`), `VLEN = 256` (`vlenb = 32`),
/// supporting the RISC-V Hypervisor (`H`) extension (`/dev/kvm`).
pub const K3_CLUSTER0_X100_MASK: u32 = 0x00FF;

/// Canonical SpacemiT K3 Cluster 1 (`A100`, cores `8–15`) CPU affinity mask.
/// In-Order AI/Matrix cores (`1.80 GHz`), `VLEN = 1024` (`vlenb = 128`),
/// supporting `XSMTVDotII` (`smt.vpack.vv` and `smt.vmadot`).
pub const K3_CLUSTER1_A100_MASK: u32 = 0xFF00;

/// Default procfs registration node on the SpacemiT-patched (`spacemit-hmp`) Linux kernel.
pub const DEFAULT_SET_AI_THREAD_PATH: &str = "/proc/set_ai_thread";

/// Validate that `memlock_limit_kb` is strictly positive, bounded, and does not exceed
/// `MAX_K3_MEMLOCK_KB` (`29,360,128` KB / 28 GiB), returning the validated limit in bytes.
///
/// Setting `RLIMIT_MEMLOCK` to `0`, `u64::MAX` (`unlimited`), or `> 28 GiB` is rejected
/// with `IsolationError::HardwareConstraintViolation` to prevent kernel slab/SSH lockups.
pub fn validate_memlock_limit(memlock_limit_kb: u64) -> Result<u64, IsolationError> {
    if memlock_limit_kb == 0 {
        return Err(IsolationError::HardwareConstraintViolation {
            field: "memlock_limit_kb".to_string(),
            reason: "memlock_limit_kb must be greater than 0".to_string(),
        });
    }

    if memlock_limit_kb == u64::MAX || memlock_limit_kb > MAX_K3_MEMLOCK_KB {
        return Err(IsolationError::HardwareConstraintViolation {
            field: "memlock_limit_kb".to_string(),
            reason: format!(
                "memlock_limit_kb ({memlock_limit_kb}) exceeds bounded ceiling MAX_K3_MEMLOCK_KB ({MAX_K3_MEMLOCK_KB} KB / 28 GiB); 'unlimited' memlock is forbidden"
            ),
        });
    }

    memlock_limit_kb
        .checked_mul(1024)
        .ok_or_else(|| IsolationError::HardwareConstraintViolation {
            field: "memlock_limit_kb".to_string(),
            reason: "memlock_limit_kb overflowed when converting KB to bytes".to_string(),
        })
}

/// Validate and enforce `RLIMIT_MEMLOCK` on the calling process on Linux, returning the
/// applied byte limit. On non-Linux hosts, validates the limit and returns the byte count.
pub fn apply_rlimit_memlock(memlock_limit_kb: u64) -> Result<u64, IsolationError> {
    let memlock_bytes = validate_memlock_limit(memlock_limit_kb)?;

    #[cfg(target_os = "linux")]
    {
        let rlim = libc::rlimit {
            rlim_cur: memlock_bytes as libc::rlim_t,
            rlim_max: memlock_bytes as libc::rlim_t,
        };
        // SAFETY: `setrlimit` is called with a valid pointer to a stack-allocated `libc::rlimit`.
        let rc = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
        if rc != 0 {
            let err = std::io::Error::last_os_error();
            return Err(IsolationError::SandboxExecutionFailed(format!(
                "setrlimit(RLIMIT_MEMLOCK, {memlock_bytes} bytes) failed: {err}"
            )));
        }
    }

    Ok(memlock_bytes)
}

/// Conditionally register a worker thread ID (`tid`) with `/proc/set_ai_thread` before
/// pinning to SpacemiT K3 Cluster 1 (`A100`, cores `8–15`, mask `0xFF00`).
///
/// - Returns `Ok(false)` when `require_set_ai_thread` is `false` or when `cpu_affinity_mask`
///   does not intersect `K3_CLUSTER1_A100_MASK` (`0xFF00`).
/// - When `require_set_ai_thread` is `true` and `cpu_affinity_mask` intersects `0xFF00`:
///   - If `proc_path` exists on the running kernel (`spacemit-hmp`), writes `"{tid}\n"` to
///     `proc_path` and returns `Ok(true)`.
///   - If `proc_path` does **not** exist (vanilla Linux kernel or non-K3 host), cleanly
///     skips the write and returns `Ok(false)`.
pub fn register_ai_thread_if_present(
    proc_path: &Path,
    tid: u32,
    cpu_affinity_mask: Option<u32>,
    require_set_ai_thread: bool,
) -> Result<bool, IsolationError> {
    if !require_set_ai_thread {
        return Ok(false);
    }

    let mask = cpu_affinity_mask.unwrap_or(0);
    if (mask & K3_CLUSTER1_A100_MASK) == 0 {
        return Ok(false);
    }

    if tid == 0 {
        return Err(IsolationError::HardwareConstraintViolation {
            field: "tid".to_string(),
            reason: "thread ID (tid) must be non-zero when registering /proc/set_ai_thread"
                .to_string(),
        });
    }

    if !proc_path.exists() {
        return Ok(false);
    }

    fs::write(proc_path, format!("{tid}\n"))?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_validate_memlock_limit_enforces_bounded_ceiling() {
        assert_eq!(validate_memlock_limit(64).unwrap(), 65_536);
        assert_eq!(
            validate_memlock_limit(MAX_K3_MEMLOCK_KB).unwrap(),
            MAX_K3_MEMLOCK_KB * 1024
        );

        assert!(matches!(
            validate_memlock_limit(0),
            Err(IsolationError::HardwareConstraintViolation { ref field, .. }) if field == "memlock_limit_kb"
        ));
        assert!(matches!(
            validate_memlock_limit(MAX_K3_MEMLOCK_KB + 1),
            Err(IsolationError::HardwareConstraintViolation { ref field, .. }) if field == "memlock_limit_kb"
        ));
        assert!(matches!(
            validate_memlock_limit(u64::MAX),
            Err(IsolationError::HardwareConstraintViolation { ref field, .. }) if field == "memlock_limit_kb"
        ));
    }

    #[test]
    fn test_register_ai_thread_if_present_writes_when_node_exists_and_skips_when_absent() {
        let tmp = NamedTempFile::new().expect("create temp procfs mock");

        // 1. Node exists + A100 affinity (0xFF00) + require_set_ai_thread = true -> writes TID
        let registered =
            register_ai_thread_if_present(tmp.path(), 4242, Some(K3_CLUSTER1_A100_MASK), true)
                .expect("should register TID");
        assert!(registered);
        let written = fs::read_to_string(tmp.path()).expect("read procfs mock");
        assert_eq!(written, "4242\n");

        // 2. Node does NOT exist (vanilla Linux kernel) -> clean no-op Ok(false)
        let missing_path = tmp.path().with_file_name("nonexistent_set_ai_thread");
        let registered_missing =
            register_ai_thread_if_present(&missing_path, 4242, Some(K3_CLUSTER1_A100_MASK), true)
                .expect("missing procfs node should be treated as conditional no-op");
        assert!(!registered_missing);

        // 3. Cluster 0 (X100, 0x00FF) only -> does not write even if require_set_ai_thread = true
        let registered_c0 =
            register_ai_thread_if_present(tmp.path(), 4242, Some(K3_CLUSTER0_X100_MASK), true)
                .expect("cluster 0 should not register AI thread");
        assert!(!registered_c0);
    }
}
