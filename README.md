# MuIsolation

<p align="center">
  <a href="https://hook.lma1980.duckdns.org/jobs">
    <img src="https://hook.lma1980.duckdns.org/cards/LMA1980/MuIsolation/card.svg" alt="MuIsolation Factory Scorecard" width="520"/>
  </a>
</p>

<p align="center">
  <a href="https://hook.lma1980.duckdns.org/jobs"><img src="https://hook.lma1980.duckdns.org/badges/LMA1980/MuIsolation/status.svg" alt="CI Status"/></a>
  <a href="https://hook.lma1980.duckdns.org/jobs"><img src="https://hook.lma1980.duckdns.org/badges/LMA1980/MuIsolation/score.svg" alt="Quality Score"/></a>
  <a href="https://hook.lma1980.duckdns.org/jobs"><img src="https://hook.lma1980.duckdns.org/badges/LMA1980/MuIsolation/coverage.svg" alt="Coverage"/></a>
  <a href="https://hook.lma1980.duckdns.org/jobs"><img src="https://hook.lma1980.duckdns.org/badges/LMA1980/MuIsolation/benchmark.svg" alt="Benchmark"/></a>
</p>

---

3-layer monotonic privilege attenuation and dual-backend sandboxing for high-performance CI/CD execution across heterogeneous hosts (SpacemiT K3 RISC-V and Intel x86_64).

---

## 3-Layer Monotonic Privilege Attenuation

Privileges are monotonically attenuated from the physical host down to individual task execution. Any request for elevated privileges beyond the enclosing layer fails closed immediately with `SecurityGrantDenied`.

```text
+--------------------------------------------------------------------------+
| Layer 1: Operator Host Ceiling (/etc/mu-isolation/ceiling.yml)          |
| Host-wide maximum memory, core allocations, network CIDRs, devices      |
+--------------------------------------------------------------------------+
                                    │  Monotonic Attenuation (∩)
                                    ▼
+--------------------------------------------------------------------------+
| Layer 2: Desired Profiles (.actionrunner/security.yml)                  |
| Repository-level boundaries: pure-offline, network-restricted, full     |
+--------------------------------------------------------------------------+
                                    │  Monotonic Attenuation (∩)
                                    ▼
+--------------------------------------------------------------------------+
| Layer 3: Task/Stage Constraints (ActionRunner.yml / MuConDe.yml)         |
| Granular per-step execution constraints and read/write mounts            |
+--------------------------------------------------------------------------+
```

### Invariant: Monotonic Privilege Rule
$$\text{Effective Grants} = \text{Ceiling} \cap \text{Profile} \cap \text{Task}$$
If $\text{Task} \not\subseteq \text{Profile}$ or $\text{Profile} \not\subseteq \text{Ceiling}$, the engine refuses execution and emits `SecurityGrantDenied`.

---

## Dual-Backend Isolation Architecture

`MuIsolation` abstracts execution through the `IsolationBackend` trait with two specialized backends:

```rust
pub trait IsolationBackend: Send + Sync {
    fn name(&self) -> &'static str;
    fn prepare(&self, ctx: &IsolationContext) -> Result<PreparedSandbox, IsolationError>;
    fn execute(&self, sandbox: PreparedSandbox, cmd: &SandboxedCommand) -> Result<ExecutionResult, IsolationError>;
    fn teardown(&self, sandbox: PreparedSandbox) -> Result<(), IsolationError>;
}
```

### 1. `KernelSandbox` (Containerless Linux Security)
- **Landlock LSM**: Unprivileged file system access restriction rules.
- **systemd cgroupv2 Delegation**: Enforces CPU quotas, memory ceilings, and I/O limits under `.actionrunner.slice`.
- **Linux Namespaces**: Unshares `CLONE_NEWNS`, `CLONE_NEWPID`, `CLONE_NEWNET`, `CLONE_NEWIPC`, `CLONE_NEWUTS`, and `CLONE_NEWUSER`.
- **`PR_SET_NO_NEW_PRIVS`**: Disallows obtaining new privileges via setuid/setgid binaries.
- **Seccomp-BPF**: Filters dangerous syscalls (`kexec`, `reboot`, raw sockets, ptrace).
- **SpacemiT K3 `/proc/set_ai_thread`**: Conditional thread registration prior to core affinity pinning on SpacemiT-patched kernels.
- **Bounded `RLIMIT_MEMLOCK` Ceiling**: Strictly enforces bounded memlock limits (e.g. 28 GiB ceiling on 32 GiB host), reserving minimum 3.3 GiB strictly for kernel/OS stability. Never sets `unlimited`.

### 2. `HypervisorSandbox` (KVM MicroVM)
- **Sub-50ms Cold Boots**: Lightweight microVM runtime providing hardware-enforced virtual machine boundaries.
- **Cross-Architecture Virtualization**:
  - RISC-V Hypervisor (`H`) extension on SpacemiT K3 (`pey-wail-deu`).
  - Intel VT-x hardware acceleration on Alder Lake (`entrance`) and Xeon (`rubicon`).
- **Complete Guest Kernel Isolation**: Used for untrusted public PR validation and hostile execution payloads.

---

## Target Node Capabilities

| Node | Architecture | Cores / RAM | Primary Isolation Backend | Hardware Acceleration |
|---|---|---|---|---|
| `entrance` | Intel N100 (x86_64) | 4C / 32GB DDR5 | `KernelSandbox` / `HypervisorSandbox` | Intel VT-x |
| `rubicon` | Intel Xeon E3 (x86_64)| 4C/8T / 32GB DDR3 | `KernelSandbox` / `HypervisorSandbox` | Intel VT-x |
| `pey-wail-deu` | SpacemiT K3 (riscv64) | 16C (8×X100 + 8×A100) / 32GB LPDDR5 | `KernelSandbox` / `HypervisorSandbox` | Landlock / RVV / RISC-V KVM `H` |

---

## License

Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0-only). See LICENSE for details.
