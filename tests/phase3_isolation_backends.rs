use std::ffi::OsString;
use std::fs;
use std::path::PathBuf;

use mu_isolation::{
    apply_rlimit_memlock, probe_kvm_device, register_ai_thread_if_present,
    resolve_effective_policy, validate_memlock_limit, DesiredSecurityFile, HostCeilingConfig,
    HypervisorSandbox, IsolationBackend, IsolationError, KernelSandbox, LandlockRuleBuilder,
    NamespaceIsolator, NetworkEgressMode, SandboxBackendKind, SeccompFilterBuilder,
    TaskSandboxConfig, CLONE_NEWIPC, CLONE_NEWNET, CLONE_NEWNS, CLONE_NEWPID, CLONE_NEWUSER,
    CLONE_NEWUTS, EXEC_ACCESS, K3_CLUSTER0_X100_MASK, K3_CLUSTER1_A100_MASK, MAX_K3_MEMLOCK_KB,
    READ_ACCESS, WRITE_ACCESS,
};
use tempfile::NamedTempFile;

fn riscv64_ceiling_yaml() -> &'static str {
    r#"
node_id: "worker-riscv64"
arch: "riscv64gc"
allowed_backends:
  - Kernel
  - Hypervisor
allowed_read_prefixes:
  - /usr
  - /lib
  - /var/lib/action-runner
allowed_write_prefixes:
  - /var/lib/action-runner/workspaces
  - /tmp
allowed_exec_prefixes:
  - /usr/bin
  - /var/lib/action-runner/.cargo/bin
allowed_egress_cidrs:
  - "192.0.2.0/24"
max_memlock_kb: 29360128
max_cpu_cores: 16
max_memory_mb: 28672
max_pids: 512
allow_spacemit_ai_thread: true
"#
}

fn security_profiles_yaml() -> &'static str {
    r#"
default_profile: "pure-offline"
profiles:
  pure-offline:
    backend: Kernel
    read_paths:
      - /usr
      - /var/lib/action-runner/workspaces/repo
    write_paths:
      - /var/lib/action-runner/workspaces/repo
      - /tmp
    exec_paths:
      - /usr/bin
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
  kvm-isolated-ci:
    backend: Hypervisor
    read_paths:
      - /usr
      - /lib
    write_paths:
      - /var/lib/action-runner/workspaces/repo
      - /tmp
    exec_paths:
      - /usr/bin
    network_egress_cidrs: []
    memlock_limit_kb: 2097152
    max_pids: 128
    max_memory_mb: 4096
    cpu_affinity_mask: 0x003F
    require_set_ai_thread: false
"#
}

#[test]
fn test_end_to_end_kernel_sandbox_landlock_namespaces_seccomp_and_k3_hw() {
    let ceiling = HostCeilingConfig::from_yaml_str(riscv64_ceiling_yaml()).unwrap();
    let sec_file = DesiredSecurityFile::from_yaml_str(security_profiles_yaml()).unwrap();
    let (_, bench_profile) = sec_file.get_profile(Some("k3-matrix-bench")).unwrap();

    // Task override: narrow egress to 192.0.2.192/26 and affinity to 4 A100 cores (0x0F00)
    let task = TaskSandboxConfig {
        network_mode: NetworkEgressMode::RestrictedCidrs(vec!["192.0.2.192/26".to_string()]),
        cpu_affinity_mask: Some(0x0F00),
        ..Default::default()
    };

    let policy = resolve_effective_policy(&ceiling, bench_profile, &task).unwrap();

    // 1. Landlock rules (#9)
    let rules = LandlockRuleBuilder::build_rules(&policy).unwrap();
    assert_eq!(rules.len(), 4);
    assert_eq!(rules[0].path, PathBuf::from("/tmp"));
    assert_eq!(rules[0].access_mask, WRITE_ACCESS);
    assert_eq!(rules[1].path, PathBuf::from("/usr"));
    assert_eq!(rules[1].access_mask, READ_ACCESS);
    assert_eq!(rules[2].path, PathBuf::from("/usr/bin"));
    assert_eq!(rules[2].access_mask, EXEC_ACCESS);
    assert_eq!(
        rules[3].path,
        PathBuf::from("/var/lib/action-runner/workspaces/repo")
    );
    assert_eq!(rules[3].access_mask, READ_ACCESS);

    // 2. Namespace unshare flags (#10): RestrictedCidrs -> omits CLONE_NEWNET; Offline -> includes CLONE_NEWNET
    let ns_restricted = NamespaceIsolator::derive_clone_flags(&policy);
    assert!(ns_restricted
        .contains(CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWIPC | CLONE_NEWUTS | CLONE_NEWUSER));
    assert!(!ns_restricted.contains(CLONE_NEWNET));

    let (_, offline_profile) = sec_file.get_profile(None).unwrap();
    let offline_policy =
        resolve_effective_policy(&ceiling, offline_profile, &TaskSandboxConfig::default()).unwrap();
    let ns_offline = NamespaceIsolator::derive_clone_flags(&offline_policy);
    assert!(ns_offline.contains(CLONE_NEWNET));

    // 3. Seccomp-BPF 16-syscall kernel-surface denylist (#12)
    let seccomp = SeccompFilterBuilder::build_plan(&policy.arch).unwrap();
    assert!(seccomp.enforce_no_new_privs);
    assert_eq!(seccomp.target_arch, "riscv64");
    assert_eq!(seccomp.denied_syscalls.len(), 16);

    // 4. Conditional /proc/set_ai_thread & bounded RLIMIT_MEMLOCK (#13)
    let mock_proc = NamedTempFile::new().unwrap();
    let wrote_ai = register_ai_thread_if_present(
        mock_proc.path(),
        9001,
        policy.cpu_affinity_mask,
        policy.require_set_ai_thread,
    )
    .unwrap();
    assert!(wrote_ai);
    assert_eq!(fs::read_to_string(mock_proc.path()).unwrap(), "9001\n");

    let missing_proc = mock_proc
        .path()
        .with_file_name("missing_set_ai_thread_node");
    let skipped_vanilla = register_ai_thread_if_present(
        &missing_proc,
        9001,
        policy.cpu_affinity_mask,
        policy.require_set_ai_thread,
    )
    .unwrap();
    assert!(!skipped_vanilla);

    assert!(validate_memlock_limit(MAX_K3_MEMLOCK_KB + 1).is_err());
    assert_eq!(apply_rlimit_memlock(64).unwrap(), 65_536);

    // 5. KernelSandbox IsolationBackend trait execution (#16)
    let kernel_sb = KernelSandbox::with_proc_ai_thread_path(mock_proc.path());
    assert_eq!(kernel_sb.backend_kind(), SandboxBackendKind::Kernel);
    let argv = vec![OsString::from("/usr/bin/cargo"), OsString::from("bench")];
    let plan = kernel_sb.build_execution_plan(&policy, &argv).unwrap();
    assert_eq!(plan.backend, SandboxBackendKind::Kernel);
    assert!(plan.microvm_config.is_none());
    let child = kernel_sb.spawn_isolated(&plan).unwrap();
    assert_eq!(child.backend, SandboxBackendKind::Kernel);
}

#[test]
fn test_end_to_end_hypervisor_sandbox_riscv64_h_extension_and_x86_64_vtx() {
    let ceiling = HostCeilingConfig::from_yaml_str(riscv64_ceiling_yaml()).unwrap();
    let sec_file = DesiredSecurityFile::from_yaml_str(security_profiles_yaml()).unwrap();
    let (_, kvm_profile) = sec_file.get_profile(Some("kvm-isolated-ci")).unwrap();

    let policy =
        resolve_effective_policy(&ceiling, kvm_profile, &TaskSandboxConfig::default()).unwrap();

    let mock_kvm = NamedTempFile::new().unwrap();
    assert!(probe_kvm_device(mock_kvm.path()));

    let hypervisor = HypervisorSandbox::with_kvm_path(mock_kvm.path());
    assert_eq!(hypervisor.backend_kind(), SandboxBackendKind::Hypervisor);

    let argv = vec![OsString::from("/usr/bin/cargo"), OsString::from("test")];
    let plan = hypervisor.build_execution_plan(&policy, &argv).unwrap();
    let vm = plan.microvm_config.as_ref().unwrap();
    assert_eq!(vm.arch, "riscv64");
    // 0x003F has 6 cores within Cluster 0 (X100, 0x00FF)
    assert_eq!(vm.vcpu_affinity_mask, Some(0x003F));
    assert_eq!(vm.vcpu_count, 6);
    assert_eq!(vm.memory_size_mb, 4096);
    assert_eq!((vm.vcpu_affinity_mask.unwrap() & K3_CLUSTER1_A100_MASK), 0);
    assert_eq!(
        (vm.vcpu_affinity_mask.unwrap() & K3_CLUSTER0_X100_MASK),
        0x003F
    );

    let handle = hypervisor.spawn_isolated(&plan).unwrap();
    assert_eq!(handle.backend, SandboxBackendKind::Hypervisor);

    // Verify missing /dev/kvm returns UnsupportedBackend on spawn
    let missing_kvm_sb =
        HypervisorSandbox::with_kvm_path(mock_kvm.path().with_file_name("missing_dev_kvm"));
    let bad_plan = missing_kvm_sb.build_execution_plan(&policy, &argv).unwrap();
    assert!(matches!(
        missing_kvm_sb.spawn_isolated(&bad_plan),
        Err(IsolationError::UnsupportedBackend { .. })
    ));
}
