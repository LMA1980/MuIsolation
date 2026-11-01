use serde::Serialize;

use crate::error::IsolationError;

/// A dangerous Linux kernel-surface syscall blocked by `seccomp-bpf` with `-EPERM`.
#[derive(Serialize, Debug, PartialEq, Eq, Clone, Copy)]
pub struct DeniedSyscallEntry {
    pub name: &'static str,
    pub x86_64_nr: i64,
    pub riscv64_nr: i64,
    pub errno: i32,
}

impl DeniedSyscallEntry {
    /// Return the architecture-specific syscall number for `x86_64` or `riscv64`/`riscv64gc`.
    pub fn nr_for_arch(&self, arch: &str) -> Option<i64> {
        match normalize_seccomp_arch(arch)? {
            "x86_64" => Some(self.x86_64_nr),
            "riscv64" => Some(self.riscv64_nr),
            _ => None,
        }
    }
}

/// Complete `seccomp-bpf` and `PR_SET_NO_NEW_PRIVS` enforcement plan for a sandboxed task.
#[derive(Serialize, Debug, PartialEq, Eq, Clone)]
pub struct SeccompFilterPlan {
    pub enforce_no_new_privs: bool,
    pub target_arch: String,
    pub denied_syscalls: Vec<DeniedSyscallEntry>,
}

const DENIED_KERNEL_SURFACE_SYSCALLS: [DeniedSyscallEntry; 16] = [
    DeniedSyscallEntry {
        name: "kexec_load",
        x86_64_nr: 246,
        riscv64_nr: 104,
        errno: libc::EPERM,
    },
    DeniedSyscallEntry {
        name: "kexec_file_load",
        x86_64_nr: 320,
        riscv64_nr: 294,
        errno: libc::EPERM,
    },
    DeniedSyscallEntry {
        name: "reboot",
        x86_64_nr: 169,
        riscv64_nr: 142,
        errno: libc::EPERM,
    },
    DeniedSyscallEntry {
        name: "swapon",
        x86_64_nr: 167,
        riscv64_nr: 224,
        errno: libc::EPERM,
    },
    DeniedSyscallEntry {
        name: "swapoff",
        x86_64_nr: 168,
        riscv64_nr: 225,
        errno: libc::EPERM,
    },
    DeniedSyscallEntry {
        name: "init_module",
        x86_64_nr: 175,
        riscv64_nr: 105,
        errno: libc::EPERM,
    },
    DeniedSyscallEntry {
        name: "finit_module",
        x86_64_nr: 313,
        riscv64_nr: 273,
        errno: libc::EPERM,
    },
    DeniedSyscallEntry {
        name: "delete_module",
        x86_64_nr: 176,
        riscv64_nr: 106,
        errno: libc::EPERM,
    },
    DeniedSyscallEntry {
        name: "acct",
        x86_64_nr: 163,
        riscv64_nr: 89,
        errno: libc::EPERM,
    },
    DeniedSyscallEntry {
        name: "bpf",
        x86_64_nr: 321,
        riscv64_nr: 280,
        errno: libc::EPERM,
    },
    DeniedSyscallEntry {
        name: "perf_event_open",
        x86_64_nr: 298,
        riscv64_nr: 241,
        errno: libc::EPERM,
    },
    DeniedSyscallEntry {
        name: "ptrace",
        x86_64_nr: 101,
        riscv64_nr: 117,
        errno: libc::EPERM,
    },
    DeniedSyscallEntry {
        name: "userfaultfd",
        x86_64_nr: 323,
        riscv64_nr: 282,
        errno: libc::EPERM,
    },
    DeniedSyscallEntry {
        name: "mount",
        x86_64_nr: 165,
        riscv64_nr: 40,
        errno: libc::EPERM,
    },
    DeniedSyscallEntry {
        name: "umount2",
        x86_64_nr: 166,
        riscv64_nr: 39,
        errno: libc::EPERM,
    },
    DeniedSyscallEntry {
        name: "pivot_root",
        x86_64_nr: 155,
        riscv64_nr: 41,
        errno: libc::EPERM,
    },
];

fn normalize_seccomp_arch(arch: &str) -> Option<&'static str> {
    match arch.trim() {
        "x86_64" | "amd64" => Some("x86_64"),
        "riscv64" | "riscv64gc" => Some("riscv64"),
        _ => None,
    }
}

/// Builder and enforcer for `PR_SET_NO_NEW_PRIVS` and `seccomp-bpf` system call filtering.
pub struct SeccompFilterBuilder;

impl SeccompFilterBuilder {
    /// Build the canonical 16-syscall kernel-surface denylist plan for `x86_64` or `riscv64`.
    pub fn build_plan(arch: &str) -> Result<SeccompFilterPlan, IsolationError> {
        let Some(canonical_arch) = normalize_seccomp_arch(arch) else {
            return Err(IsolationError::HardwareConstraintViolation {
                field: "arch".to_string(),
                reason: format!(
                    "unsupported architecture '{arch}' for seccomp-bpf filter; expected 'x86_64' or 'riscv64'/'riscv64gc'"
                ),
            });
        };

        Ok(SeccompFilterPlan {
            enforce_no_new_privs: true,
            target_arch: canonical_arch.to_string(),
            denied_syscalls: DENIED_KERNEL_SURFACE_SYSCALLS.to_vec(),
        })
    }

    /// Enforce `prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)` on the calling thread on Linux.
    /// On non-Linux hosts, returns `Ok(())`.
    pub fn enforce_no_new_privs() -> Result<(), IsolationError> {
        #[cfg(target_os = "linux")]
        {
            // SAFETY: `prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)` is memory-safe and takes only integer arguments.
            let rc = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
            if rc != 0 {
                let err = std::io::Error::last_os_error();
                return Err(IsolationError::SandboxExecutionFailed(format!(
                    "prctl(PR_SET_NO_NEW_PRIVS, 1) failed: {err}"
                )));
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_seccomp_build_plan_for_x86_64_and_riscv64() {
        let x86_plan = SeccompFilterBuilder::build_plan("x86_64").expect("x86_64 seccomp plan");
        assert!(x86_plan.enforce_no_new_privs);
        assert_eq!(x86_plan.target_arch, "x86_64");
        assert_eq!(x86_plan.denied_syscalls.len(), 16);

        let rv_plan =
            SeccompFilterBuilder::build_plan("riscv64gc").expect("riscv64gc seccomp plan");
        assert!(rv_plan.enforce_no_new_privs);
        assert_eq!(rv_plan.target_arch, "riscv64");
        assert_eq!(rv_plan.denied_syscalls.len(), 16);

        for entry in &rv_plan.denied_syscalls {
            assert_eq!(entry.errno, libc::EPERM);
            assert!(entry.nr_for_arch("x86_64").unwrap() > 0);
            assert!(entry.nr_for_arch("riscv64").unwrap() > 0);
        }
    }

    #[test]
    fn test_seccomp_rejects_unknown_arch() {
        let err = SeccompFilterBuilder::build_plan("mips64").unwrap_err();
        assert!(matches!(
            err,
            IsolationError::HardwareConstraintViolation { ref field, .. } if field == "arch"
        ));
    }
}
