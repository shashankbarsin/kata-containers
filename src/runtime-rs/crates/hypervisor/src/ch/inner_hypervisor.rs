// Copyright (c) 2019-2022 Alibaba Cloud
// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

use super::inner::CloudHypervisorInner;
use crate::ch::utils::get_api_socket_path;
use crate::ch::utils::get_rootless_symlink_sandbox_path;
use crate::ch::utils::get_vsock_path;
use crate::device::DeviceType;
use crate::kernel_param::KernelParams;
use crate::selinux;
use crate::utils::create_dir_all_with_inherit_owner;
use crate::utils::open_named_tuntap;
use crate::utils::remove_dir_all_if_exists;
use crate::utils::set_groups;
use crate::utils::vm_cleanup;
use crate::utils::{bytes_to_megs, get_jailer_root, get_sandbox_path, megs_to_bytes};
use crate::MemoryConfig;
use crate::VM_ROOTFS_DRIVER_BLK;
use crate::{VcpuThreadIds, VmmState};
use anyhow::{anyhow, Context, Result};
use ch_config::ch_api::cloud_hypervisor_vm_netdev_add_with_fds;
use ch_config::{
    ch_api::{
        cloud_hypervisor_vm_create, cloud_hypervisor_vm_info, cloud_hypervisor_vm_pause,
        cloud_hypervisor_vm_resize, cloud_hypervisor_vm_resume, cloud_hypervisor_vm_snapshot,
        cloud_hypervisor_vm_start, cloud_hypervisor_vmm_ping, cloud_hypervisor_vmm_shutdown,
    },
    VmResize,
};
use ch_config::{guest_protection_is_tdx, NamedHypervisorConfig, VmConfig};
use core::future::poll_fn;
use futures::future::join_all;
use kata_sys_util::netns::NetnsGuard;
use kata_sys_util::protection::{available_guest_protection, GuestProtection};
use kata_types::capabilities::{Capabilities, CapabilityBits};
use kata_types::config::default::DEFAULT_CH_ROOTFS_TYPE;
use kata_types::config::hypervisor::RootlessUser;
use kata_types::rootless::is_rootless;
use lazy_static::lazy_static;
use nix::sched::{setns, CloneFlags};
use nix::unistd::setgid;
use nix::unistd::setuid;
use nix::unistd::Gid;
use nix::unistd::Uid;
use serde_json::Value;
use std::collections::HashMap;
use std::convert::TryFrom;
use std::fs;
use std::os::unix::io::AsRawFd;use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::Stdio;
use std::sync::{Arc, RwLock};
use tokio::io::BufReader;
use tokio::process::{Child, Command};
use tokio::sync::watch::Receiver;
use tokio::task;
use tokio::task::JoinHandle;
use tokio::time::Duration;
use tokio::{io::AsyncBufReadExt, sync::mpsc};

const CH_NAME: &str = "clh";

/// Number of milliseconds to wait before retrying a CH operation.
const CH_POLL_TIME_MS: u64 = 50;

// The name of the CH JSON key for the build-time features list.
const CH_FEATURES_KEY: &str = "features";

// The name of the CH build-time feature for Intel TDX.
const CH_FEATURE_TDX: &str = "tdx";

#[derive(Debug, PartialEq)]
enum CloudHypervisorLogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

#[derive(thiserror::Error, Debug, PartialEq)]
pub enum GuestProtectionError {
    #[error("guest protection requested but no guest protection available")]
    NoProtectionAvailable,

    // LIMITATION: Current CH TDX limitation.
    //
    // When built to support TDX, if Cloud Hypervisor determines the host
    // system supports TDX, it can only create TD's (as opposed to VMs).
    // Hence, on a TDX capable system, confidential_guest *MUST* be set to
    // "true".
    #[error("TDX guest protection available and must be used with Cloud Hypervisor (set 'confidential_guest=true')")]
    TDXProtectionMustBeUsedWithCH,

    // TDX is the only tested CH protection currently.
    #[error("Expected TDX protection, found {0}")]
    ExpectedTDXProtection(GuestProtection),
}

impl CloudHypervisorInner {
    async fn start_hypervisor(&mut self, timeout_secs: i32) -> Result<()> {
        self.cloud_hypervisor_launch(timeout_secs)
            .await
            .context("launch failed")?;

        self.cloud_hypervisor_setup_comms()
            .await
            .context("comms setup failed")?;

        self.cloud_hypervisor_check_running()
            .await
            .context("hypervisor running check failed")?;

        if guest_protection_is_tdx(self.guest_protection_to_use.clone()) {
            if let Some(features) = &self.ch_features {
                if !features.contains(&CH_FEATURE_TDX.to_string()) {
                    return Err(anyhow!("Cloud Hypervisor is not built with TDX support"));
                }
            }
        }

        Ok(())
    }

    async fn get_kernel_params(&self) -> Result<String> {
        let cfg = &self.config;

        let enable_debug = cfg.debug_info.enable_debug;

        let confidential_guest = cfg.security_info.confidential_guest;

        // Note that the configuration option hypervisor.block_device_driver is not used.
        // NVDIMM is not supported for Cloud Hypervisor.
        let rootfs_driver = VM_ROOTFS_DRIVER_BLK;

        let rootfs_type = match cfg.boot_info.rootfs_type.is_empty() {
            true => DEFAULT_CH_ROOTFS_TYPE,
            false => &cfg.boot_info.rootfs_type,
        };

        // Start by adding the default set of kernel parameters.
        let mut params = KernelParams::new(enable_debug);

        #[cfg(target_arch = "x86_64")]
        let console_param_debug = KernelParams::from_string("console=ttyS0,115200n8");

        #[cfg(target_arch = "aarch64")]
        let console_param_debug = KernelParams::from_string("console=ttyAMA0,115200n8");

        let mut rootfs_params = KernelParams::new_rootfs_kernel_params(
            &cfg.boot_info.kernel_verity_params,
            rootfs_driver,
            rootfs_type,
            true,
        )?;

        let mut console_params = if enable_debug {
            if confidential_guest {
                KernelParams::from_string("console=hvc0")
            } else {
                console_param_debug
            }
        } else {
            KernelParams::from_string("quiet")
        };

        params.append(&mut console_params);

        params.append(&mut rootfs_params);

        // Now add some additional options required for CH
        let extra_options = [
            "no_timer_check",             // Do not Check broken timer IRQ resources
            "noreplace-smp",              // Do not replace SMP instructions
            "systemd.log_target=console", // Send logging output to the console
        ];

        let mut extra_params = KernelParams::from_string(&extra_options.join(" "));
        params.append(&mut extra_params);

        // Finally, add the user-specified options at the end
        // (so they will take priority).
        params.append(&mut KernelParams::from_string(&cfg.boot_info.kernel_params));

        let kernel_params = params.to_string()?;

        Ok(kernel_params)
    }

    async fn boot_vm(&mut self) -> Result<()> {
        let (shared_fs_devices, network_devices, host_devices, protection_device) =
            self.get_shared_devices().await?;

        let sandbox_path = get_sandbox_path(&self.id);

        create_dir_all_with_inherit_owner(sandbox_path.clone(), 0o750)
            .context("failed to create sandbox path")?;

        let vsock_socket_path = get_vsock_path(&self.id)?;

        debug!(
            sl!(),
            "generic Hypervisor configuration: {:?}",
            self.config.clone()
        );

        let kernel_params = self.get_kernel_params().await?;

        let named_cfg = NamedHypervisorConfig {
            kernel_params,
            sandbox_path,
            vsock_socket_path,
            cfg: self.config.clone(),
            guest_protection_to_use: self.guest_protection_to_use.clone(),
            shared_fs_devices,
            host_devices,
            protection_device,
            ..Default::default()
        };

        let cfg = VmConfig::try_from(named_cfg)?;

        let serialised = serde_json::to_string(&cfg)?;

        debug!(
            sl!(),
            "CH specific VmConfig configuration (JSON): {:?}", serialised
        );

        let response = cloud_hypervisor_vm_create(&self.api_socket, cfg).await?;

        if let Some(detail) = response {
            debug!(sl!(), "vm boot response: {:?}", detail);
        }

        if let Some(network_devices) = network_devices {
            for net in network_devices {
                let vm_fds = net.fds.clone().unwrap_or_default();
                let response =
                    cloud_hypervisor_vm_netdev_add_with_fds(&self.api_socket, net, vm_fds.clone())
                        .await
                        .context("failed to add vm netdev with fds")?;

                if let Some(detail) = response {
                    debug!(sl!(), "vm netdev add response: {:?}", detail);
                }

                for fd in vm_fds {
                    // Explicitly close the fd now that it has been sent to CLH.
                    nix::unistd::close(fd).context("failed to close netdev fd")?;
                }
            }
        }

        let response = cloud_hypervisor_vm_start(&self.api_socket).await?;

        if let Some(detail) = response {
            debug!(sl!(), "vm start response: {:?}", detail);
        }

        Ok(())
    }

    async fn cloud_hypervisor_setup_comms(&mut self) -> Result<()> {
        let api_socket_path = get_api_socket_path(&self.id)?;

        // The hypervisor has just been spawned, but may not yet have created
        // the API socket, so repeatedly try to connect for up to
        // timeout_secs.
        let join_handle: JoinHandle<Result<UnixStream>> =
            task::spawn_blocking(move || -> Result<UnixStream> {
                let api_socket: UnixStream;

                loop {
                    let result = UnixStream::connect(api_socket_path.clone());

                    if let Ok(result) = result {
                        api_socket = result;
                        break;
                    }

                    std::thread::sleep(Duration::from_millis(CH_POLL_TIME_MS));
                }

                Ok(api_socket)
            });

        let timeout_msg = format!(
            "API socket connect timed out after {} seconds",
            self.timeout_secs
        );

        let result =
            tokio::time::timeout(Duration::from_secs(self.timeout_secs as u64), join_handle)
                .await
                .context(timeout_msg)?;

        let result = result?;

        let api_socket = result?;

        *self.api_socket.lock().await = Some(api_socket);

        Ok(())
    }

    async fn cloud_hypervisor_check_running(&mut self) -> Result<()> {
        let timeout_secs = self.timeout_secs;

        let timeout_msg = format!("API socket connect timed out after {timeout_secs} seconds");

        let join_handle = self.cloud_hypervisor_ping_until_ready(CH_POLL_TIME_MS);

        tokio::time::timeout(Duration::new(timeout_secs as u64, 0), join_handle)
            .await
            .context(timeout_msg)?
    }

    async fn cloud_hypervisor_ensure_not_launched(&self) -> Result<()> {
        if let Some(child) = &self.process {
            return Err(anyhow!(
                "{} already running with PID {}",
                CH_NAME,
                child.id().unwrap_or(0)
            ));
        }

        Ok(())
    }

    async fn cloud_hypervisor_launch(&mut self, _timeout_secs: i32) -> Result<()> {
        self.cloud_hypervisor_ensure_not_launched().await?;

        let cfg = &self.config;

        let debug = cfg.debug_info.enable_debug;

        let disable_seccomp = cfg.security_info.disable_seccomp;

        let api_socket_path = get_api_socket_path(&self.id)?;

        let _ = std::fs::remove_file(api_socket_path.clone());

        let binary_path = cfg.path.to_string();

        let path = Path::new(&binary_path).canonicalize()?;

        let mut cmd = Command::new(path);

        cmd.current_dir("/");

        cmd.stdin(Stdio::null());
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        cmd.env("RUST_BACKTRACE", "full");

        cmd.args(["--api-socket", &api_socket_path]);

        if let Some(extra_args) = &self.extra_args {
            cmd.args(extra_args);
        }

        if debug {
            // Note that with TDX enabled, this results in a lot of additional
            // CH output, particularly if the user adds "earlyprintk" to the
            // guest kernel command line (by modifying "kernel_params=").
            cmd.arg("-v");
        }

        if disable_seccomp {
            cmd.args(["--seccomp", "false"]);
        }

        // AKS Pod Snapshot POC (Phase C4 / C4.1): if prepare_for_restore()
        // armed a snapshot source, append `--restore source_url=file://<dir>`.
        // If set_restore_net_fds() armed per-device tap fds for this launch,
        // also emit `,net_fds=[<id>@<fd>,...]` and arrange for each fd to
        // land at child slots 3..n via a pre_exec dup2 closure. CLH inherits
        // child fd 3 first, then 4, etc -- matching the order of the Vec.
        // start_vm() also skips boot_vm() when restore_src is set because
        // CLH does CreateVM+BootVM internally as part of --restore (see
        // clh.go::launchClh comment block).
        //
        // We take ownership of restore_net_fds out of self here so each
        // launch consumes them exactly once. The owning File handles stay
        // alive in the local `net_fds` binding until after cmd.spawn(); they
        // are then dropped at end of this method, closing the parent's
        // copies. (The child already has its own copies post-fork.)
        let net_fds: Vec<(String, std::fs::File)> = std::mem::take(&mut self.restore_net_fds);
        let net_fd_raws: Vec<std::os::unix::io::RawFd> =
            net_fds.iter().map(|(_, f)| f.as_raw_fd()).collect();
        if let Some(src) = &self.restore_src {
            let mut restore_val = format!("source_url=file://{src}");
            if !net_fds.is_empty() {
                let entries: Vec<String> = net_fds
                    .iter()
                    .enumerate()
                    .map(|(i, (id, _))| format!("{}@{}", id, 3 + i))
                    .collect();
                restore_val.push_str(",net_fds=[");
                restore_val.push_str(&entries.join(","));
                restore_val.push(']');
            }
            info!(sl!(), "cloud_hypervisor_launch: restore mode";
                  "sandbox" => &self.id,
                  "restore_arg" => &restore_val);
            cmd.args(["--restore", &restore_val]);
        } else if !net_fds.is_empty() {
            // Defensive: if a caller armed net fds without a snapshot src
            // we have nowhere to plumb them. Surface that as an error rather
            // than silently leaking the fds into a fresh boot.
            return Err(anyhow!(
                "set_restore_net_fds armed {} net fd(s) but no restore_src is set",
                net_fds.len()
            ));
        }

        // Stage the dup2() side of net-fd inheritance. We collect raw fds
        // (Copy, so cheap to move into the closure) and dup2 them onto child
        // fds starting at 3. dup2 clears CLOEXEC on the target as a side
        // effect; if the source fd already happens to live at the target
        // slot we still need to clear CLOEXEC explicitly. The closure runs
        // post-fork pre-exec in the child, so failures must surface through
        // io::Error.
        if !net_fd_raws.is_empty() {
            let raws = net_fd_raws.clone();
            let dbg_path: std::ffi::CString =
                std::ffi::CString::new("/tmp/kata-rs-dup2.log").expect("valid cstr");
            // Safety: pre_exec runs after fork in the child; libc calls here
            // touch only the child's fd table.
            unsafe {
                let _ = cmd.pre_exec(move || {
                    // Open a debug file in the child to verify the closure runs.
                    // We can't use slog/info! here because logging bridges may
                    // not be fork-safe; raw libc::open + write is sufficient.
                    let dbg_fd = libc::open(
                        dbg_path.as_ptr(),
                        libc::O_WRONLY | libc::O_APPEND | libc::O_CREAT,
                        0o644,
                    );
                    let log = |msg: &str| {
                        if dbg_fd >= 0 {
                            let _ = libc::write(dbg_fd, msg.as_ptr() as *const _, msg.len());
                        }
                    };
                    log("pre_exec dup2: start\n");

                    for (idx, &fd) in raws.iter().enumerate() {
                        let target: std::os::unix::io::RawFd = 3 + idx as i32;
                        let line = format!("pre_exec dup2: idx={idx} fd={fd} target={target}\n");
                        log(&line);
                        if fd != target {
                            if libc::dup2(fd, target) < 0 {
                                let e = std::io::Error::last_os_error();
                                log(&format!("pre_exec dup2: FAIL dup2: {e}\n"));
                                if dbg_fd >= 0 {
                                    libc::close(dbg_fd);
                                }
                                return Err(e);
                            }
                        }
                        let flags = libc::fcntl(target, libc::F_GETFD);
                        if flags < 0 {
                            let e = std::io::Error::last_os_error();
                            log(&format!("pre_exec dup2: FAIL F_GETFD: {e}\n"));
                            if dbg_fd >= 0 {
                                libc::close(dbg_fd);
                            }
                            return Err(e);
                        }
                        if libc::fcntl(target, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                            let e = std::io::Error::last_os_error();
                            log(&format!("pre_exec dup2: FAIL F_SETFD: {e}\n"));
                            if dbg_fd >= 0 {
                                libc::close(dbg_fd);
                            }
                            return Err(e);
                        }
                        // Verify the target fd is what we expect.
                        let mut st: libc::stat = std::mem::zeroed();
                        if libc::fstat(target, &mut st) == 0 {
                            log(&format!(
                                "pre_exec dup2: OK target={target} mode=0o{:o} ino={}\n",
                                st.st_mode, st.st_ino
                            ));
                        }
                    }
                    log("pre_exec dup2: done\n");
                    if dbg_fd >= 0 {
                        libc::close(dbg_fd);
                    }
                    Ok(())
                });
            }
        }

        let netns = self.netns.clone();
        if let Some(netns_ref) = &self.netns {
            info!(sl!(), "set netns for vmm : {:?}", netns_ref);
        }

        let user: Option<RootlessUser> = if is_rootless() {
            Some(
                self.config
                    .security_info
                    .rootless_user
                    .clone()
                    .ok_or_else(|| {
                        anyhow!("rootless user must be specified for rootless cloud-hypervisor")
                    })?,
            )
        } else {
            None
        };

        unsafe {
            let selinux_label = self.config.security_info.selinux_label.clone();
            let _pre = cmd.pre_exec(move || {
                if let Some(netns_path) = &netns {
                    let netns_fd = std::fs::File::open(netns_path);
                    let _ = setns(netns_fd?.as_raw_fd(), CloneFlags::CLONE_NEWNET)
                        .context("set netns failed");
                }
                if let Some(label) = selinux_label.as_ref() {
                    if let Err(e) = selinux::set_exec_label(label) {
                        error!(sl!(), "Failed to set SELinux label in child process: {}", e);
                        // Don't return error here to avoid breaking the process startup
                        // Log the error and continue
                    } else {
                        info!(
                            sl!(),
                            "Successfully set SELinux label in child process: {}", &label
                        );
                    }
                }
                if let Some(user) = &user {
                    let groups = user.groups.clone();
                    let gid = Gid::from_raw(user.gid);
                    let uid = Uid::from_raw(user.uid);

                    let _ = set_groups(&groups);
                    let _ = setgid(gid).context("setgid failed");
                    let _ = setuid(uid).context("setuid failed");
                }

                Ok(())
            });
        }

        debug!(sl!(), "launching {} as: {:?}", CH_NAME, cmd);

        // Sandbox snapshot/restore: log net fd plumbing for restore mode so
        // we can diagnose mismatches between what the shim opens and what
        // CLH receives at child fd 3+.
        if !net_fd_raws.is_empty() {
            info!(sl!(), "spawn: net fd plumbing raws={:?} count={}", net_fd_raws, net_fd_raws.len());
            for (i, &fd) in net_fd_raws.iter().enumerate() {
                let kind = match nix::sys::stat::fstat(fd) {
                    Ok(s) => format!("mode=0o{:o} ino={}", s.st_mode, s.st_ino),
                    Err(e) => format!("fstat-err={e}"),
                };
                info!(sl!(), "spawn: parent fd idx={} fd={} {}", i, fd, kind);
            }
        }

        let child = cmd.spawn().context(format!("{CH_NAME} spawn failed"))?;

        // AKS Pod Snapshot POC (Phase C4.1): the child has now forked and is
        // headed for exec(); the parent's copies of the tap fds are no
        // longer needed (the child has its own copies under fds 3+). Drop
        // the Vec here to close them promptly rather than at end-of-scope.
        drop(net_fds);

        // Save process PID
        self.pid = child.id();

        let shutdown = self
            .shutdown_rx
            .as_ref()
            .ok_or("no receiver channel")
            .map_err(|e| anyhow!(e))?
            .clone();

        let exit_notify: mpsc::Sender<i32> = self
            .exit_notify
            .take()
            .ok_or_else(|| anyhow!("no exit notify"))?;

        let ch_outputlogger_task =
            tokio::spawn(cloud_hypervisor_log_output(child, shutdown, exit_notify));

        let tasks = vec![ch_outputlogger_task];

        self.tasks = Some(tasks);

        Ok(())
    }

    async fn cloud_hypervisor_shutdown(&mut self) -> Result<()> {
        let response = cloud_hypervisor_vmm_shutdown(&self.api_socket)
            .await
            .context("shutdown failed")?;

        if let Some(detail) = response {
            debug!(sl!(), "shutdown response: {:?}", detail);
        }

        // Trigger a controlled shutdown
        self.shutdown_tx
            .as_mut()
            .ok_or("no shutdown channel")
            .map_err(|e| anyhow!(e))?
            .send(true)
            .map_err(|e| anyhow!(e).context("failed to request shutdown"))?;

        let tasks = self
            .tasks
            .take()
            .ok_or("no tasks")
            .map_err(|e| anyhow!(e))?;

        let results = join_all(tasks).await;

        let mut wait_errors: Vec<tokio::task::JoinError> = vec![];

        for result in results {
            if let Err(e) = result {
                eprintln!("wait task error: {e:#?}");

                wait_errors.push(e);
            }
        }

        if wait_errors.is_empty() {
            Ok(())
        } else {
            Err(anyhow!("wait all tasks failed: {:#?}", wait_errors))
        }
    }

    #[allow(dead_code)]
    async fn cloud_hypervisor_wait(&mut self) -> Result<()> {
        let mut child = self
            .process
            .take()
            .ok_or(format!("{CH_NAME} not running"))
            .map_err(|e| anyhow!(e))?;

        let _pid = child
            .id()
            .ok_or(format!("{CH_NAME} missing PID"))
            .map_err(|e| anyhow!(e))?;

        // Note that this kills _and_ waits for the process!
        child.kill().await?;

        Ok(())
    }

    // Check the specified ping API response to see if it contains CH's
    // build-time features list. If so, save them.
    async fn handle_ch_build_features(&mut self, ping_response: &str) -> Result<()> {
        let v: Value = serde_json::from_str(ping_response)?;

        let got = &v[CH_FEATURES_KEY];

        if got.is_null() {
            return Ok(());
        }

        let features_list = got
            .as_array()
            .ok_or("expected CH to return array of features")
            .map_err(|e| anyhow!(e))?;

        let features: Vec<String> = features_list
            .iter()
            .map(Value::to_string)
            .map(|s| s.trim_start_matches('"').trim_end_matches('"').to_string())
            .collect();

        self.ch_features = Some(features);

        Ok(())
    }

    async fn cloud_hypervisor_ping_until_ready(&mut self, _poll_time_ms: u64) -> Result<()> {
        loop {
            let response = cloud_hypervisor_vmm_ping(&self.api_socket)
                .await
                .context("ping failed");

            if let Ok(response) = response {
                if let Some(detail) = response {
                    // Check for a list of built-in features, returned by this
                    // API call in newer versions of CH.
                    debug!(sl!(), "ping response: {:?}", detail);

                    self.handle_ch_build_features(&detail).await?;
                }
                break;
            }

            tokio::time::sleep(Duration::from_millis(CH_POLL_TIME_MS)).await;
        }

        Ok(())
    }

    pub(crate) async fn prepare_vm(
        &mut self,
        id: &str,
        netns: Option<String>,
        selinux_label: Option<String>,
    ) -> Result<()> {
        self.id = id.to_string();
        self.state = VmmState::NotReady;

        self.setup_environment().await?;

        self.handle_guest_protection().await?;

        self.netns = netns;

        if !self.hypervisor_config().disable_selinux {
            if let Some(label) = selinux_label.as_ref() {
                self.config.security_info.selinux_label = Some(label.to_string());
                selinux::set_exec_label(label).context("failed to set SELinux process label")?;
            }
        }

        Ok(())
    }

    // Check if guest protection is available and also check if the user
    // actually wants to use it.
    //
    // Note: This method must be called as early as possible since after this
    // call, if confidential_guest is set, a confidential
    // guest will be created.
    async fn handle_guest_protection(&mut self) -> Result<()> {
        let cfg = &self.config;

        let confidential_guest = cfg.security_info.confidential_guest;

        if confidential_guest {
            info!(sl!(), "confidential guest requested");
        }

        let protection =
            task::spawn_blocking(|| -> Result<GuestProtection> { get_guest_protection() })
                .await??;

        self.guest_protection_to_use = protection.clone();

        info!(sl!(), "guest protection {:?}", protection.to_string());

        if confidential_guest {
            if protection == GuestProtection::NoProtection {
                // User wants protection, but none available.
                return Err(anyhow!(GuestProtectionError::NoProtectionAvailable));
            } else if let GuestProtection::Tdx = protection {
                info!(sl!(), "guest protection available and requested"; "guest-protection" => protection.to_string());
            } else {
                return Err(anyhow!(GuestProtectionError::ExpectedTDXProtection(
                    protection
                )));
            }
        } else if protection == GuestProtection::NoProtection {
            debug!(sl!(), "no guest protection available");
        } else if let GuestProtection::Tdx = protection {
            // CH requires TDX protection to be used.
            return Err(anyhow!(GuestProtectionError::TDXProtectionMustBeUsedWithCH));
        } else {
            info!(sl!(), "guest protection available but not requested"; "guest-protection" => protection.to_string());
        }

        Ok(())
    }

    async fn setup_environment(&mut self) -> Result<()> {
        // run_dir and vm_path are the same (shared)
        self.run_dir = get_sandbox_path(&self.id);
        self.vm_path = self.run_dir.to_string();

        create_dir_all_with_inherit_owner(&self.run_dir, 0o750)
            .with_context(|| anyhow!("failed to create sandbox directory {}", self.run_dir))?;

        if !self.jailer_root.is_empty() {
            create_dir_all_with_inherit_owner(self.jailer_root.as_str(), 0o750)
                .map_err(|e| anyhow!("Failed to create dir {} err : {:?}", self.jailer_root, e))?;
        }

        Ok(())
    }

    pub(crate) async fn start_vm(&mut self, timeout_secs: i32) -> Result<()> {
        self.timeout_secs = timeout_secs;

        // Sandbox snapshot/restore: in restore mode, the new sandbox's net
        // devices have been queued on pending_devices via add_device() but
        // boot_vm (which would normally drain them) is skipped because CLH
        // does CreateVM+BootVM internally during --restore. Drain them now,
        // open the host tap fds, and stash them so cloud_hypervisor_launch
        // can pass them to the child via `--restore net_fds=[<id>@<fd>,...]`.
        if self.restore_src.is_some() {
            self.finalize_restore_pending_devices().await?;
        }

        self.start_hypervisor(self.timeout_secs).await?;

        self.state = VmmState::VmmServerReady;

        // AKS Pod Snapshot POC (Phase C4): in restore mode CLH does
        // CreateVM+BootVM internally as part of --restore, so skip the
        // explicit boot_vm() that issues HTTP vm.create + vm.boot.
        if self.restore_src.is_some() {
            info!(sl!(), "start_vm: skipping boot_vm (restore mode)";
                  "sandbox" => &self.id);
            // CLH leaves vCPUs paused after --restore. Issue an explicit
            // /vm.resume so the kata-agent vsock listener wakes up and
            // subsequent agent grpcs (or short-circuits) can proceed.
            // Without this, the shim hangs in subsequent Task/State calls
            // because no in-guest process makes progress.
            info!(sl!(), "start_vm: post-restore resume";
                  "sandbox" => &self.id);
            cloud_hypervisor_vm_resume(&self.api_socket)
                .await
                .context("post-restore resume_vm")?;
        } else {
            self.boot_vm().await?;
        }

        self.state = VmmState::VmRunning;

        Ok(())
    }

    /// Sandbox snapshot/restore: drain pending net devices into the
    /// `restore_net_fds` slot so cloud_hypervisor_launch can pass them to
    /// the child via `--restore net_fds=[<id>@<fd>,...]`. Called from
    /// start_vm() before start_hypervisor() when restore_src is armed.
    ///
    /// In the normal boot path get_shared_devices() is what drains
    /// pending_devices into the boot-time VmConfig + post-boot
    /// /vm.netdev.add HTTP calls; that path is skipped in restore mode
    /// because CLH does CreateVM+BootVM internally during --restore. So we
    /// take ownership of the queued net devices here, open their host tap
    /// fds in the destination netns, and pair the resulting File handles
    /// with the snapshot's declared net device IDs (in declaration order).
    ///
    /// Non-net pending devices (ShareFs, Vfio, Protection) are part of the
    /// snapshot's CH state and must not be re-added; they are dropped here
    /// with a log line.
    async fn finalize_restore_pending_devices(&mut self) -> Result<()> {
        let restore_src = self
            .restore_src
            .as_ref()
            .ok_or_else(|| anyhow!("finalize_restore_pending_devices: not in restore mode"))?
            .clone();

        let config_path = std::path::Path::new(&restore_src).join("config.json");
        let snap_nets =
            crate::ch::snapshot_rewrite::read_snapshot_net_ids(&config_path)
                .context("reading snapshot net ids for restore")?;

        // Drain pending devices. Net devices contribute tap fds; everything
        // else is already captured in the snapshot and must not be re-added.
        let pending = std::mem::take(&mut self.pending_devices);

        // Filter and count net devices first, so we can pair each device
        // with the snapshot's required num_fds (which dictates how many
        // tap queues we need to open). Using the current TOML's
        // network_queues here would mismatch when the snapshot was taken
        // with a different num_queues.
        let mut net_devs: Vec<crate::NetworkDevice> = Vec::new();
        for dev in pending {
            match dev {
                DeviceType::Network(net_device) => net_devs.push(net_device),
                other => {
                    info!(sl!(),
                        "finalize_restore_pending_devices: dropping non-net pending device (already in snapshot)";
                        "sandbox" => &self.id,
                        "device" => format!("{:?}", other));
                }
            }
        }
        let net_count = net_devs.len();
        if snap_nets.len() != net_count {
            return Err(anyhow!(
                "snapshot has {} net device(s) but new sandbox queued {}",
                snap_nets.len(),
                net_count
            ));
        }

        // Open all host taps inside the destination netns so they live in
        // the network namespace the restored guest expects. NetnsGuard is
        // RAII and restores the caller's netns when dropped at function
        // end (the File handles outlive the guard, which is fine -- a tap
        // fd's network namespace is fixed at open time).
        let netns = self.netns.clone().unwrap_or_default();
        let mut all_files: Vec<std::fs::File> = Vec::new();
        {
            let _netns_guard =
                NetnsGuard::new(&netns).context("enter netns for restore tap open")?;
            for (idx, net_device) in net_devs.iter().enumerate() {
                // CLH expects num_queues fds for this device; snap_nets[idx]
                // carries that count from the snapshot config (taken from
                // its `num_queues` field, falling back to `fds.len()`).
                let queues_needed = snap_nets[idx].num_fds.max(1) as u32;
                info!(sl!(),
                    "finalize_restore_pending_devices: opening tap";
                    "sandbox" => &self.id,
                    "host_dev_name" => &net_device.config.host_dev_name,
                    "queues" => queues_needed,
                    "snap_net_id" => &snap_nets[idx].id);
                let mut files = open_named_tuntap(
                    &net_device.config.host_dev_name,
                    queues_needed,
                )
                .context("open named tuntap for restore")?;
                all_files.append(&mut files);
            }
        }
        let total_expected: usize = snap_nets.iter().map(|n| n.num_fds).sum();
        if total_expected != all_files.len() {
            return Err(anyhow!(
                "snapshot expects {} fd(s) total but new sandbox opened {}",
                total_expected,
                all_files.len()
            ));
        }

        // Pair flat file list with snapshot net IDs in declaration order.
        // For each device, snap_nets[i].num_fds files contribute pairs
        // (snap_nets[i].id, file). Ordering relies on the new sandbox's
        // add_device(Network) calls happening in the same OCI/CNI-derived
        // order as the original sandbox -- the same assumption the Go
        // runtime relies on (clh.go::buildRestoreArgs).
        let mut paired: Vec<(String, std::fs::File)> = Vec::with_capacity(all_files.len());
        let mut file_iter = all_files.into_iter();
        for n in &snap_nets {
            for _ in 0..n.num_fds {
                let f = file_iter
                    .next()
                    .ok_or_else(|| anyhow!("ran out of restore tap fds while pairing"))?;
                paired.push((n.id.clone(), f));
            }
        }

        info!(sl!(), "finalize_restore_pending_devices: armed";
            "sandbox" => &self.id,
            "net_devices" => net_count,
            "fds" => paired.len());

        self.restore_net_fds = paired;
        Ok(())
    }

    pub(crate) async fn stop_vm(&mut self) -> Result<()> {
        // If the container workload exits, this method gets called. However,
        // the container manager always makes a ShutdownContainer request,
        // which results in this method being called potentially a second
        // time. Without this check, we'll return an error representing EPIPE
        // since the CH API socket is at that point invalid.
        if self.state != VmmState::VmRunning {
            return Ok(());
        }

        self.state = VmmState::NotReady;

        self.cloud_hypervisor_shutdown().await?;

        Ok(())
    }

    #[allow(dead_code)]
    pub(crate) async fn wait_vm(&self) -> Result<i32> {
        Ok(0)
    }

    pub(crate) async fn pause_vm(&mut self) -> Result<()> {
        // Sandbox snapshot/restore: reset api socket before each call so a
        // prior keep-alive response's leftover bytes can't bleed into the
        // next request's HTTP parser. See `save_vm` / `reset_api_connection`
        // for the full rationale.
        if let Err(e) = self.reset_api_connection().await {
            warn!(sl!(), "pause_vm: reset_api_connection failed: {e:#}"; "sandbox" => &self.id);
        }
        info!(sl!(), "pause_vm: PUT /vm.pause";
              "sandbox" => &self.id);
        cloud_hypervisor_vm_pause(&self.api_socket)
            .await
            .context("cloud_hypervisor_vm_pause")?;
        Ok(())
    }

    pub(crate) async fn resume_vm(&mut self) -> Result<()> {
        if let Err(e) = self.reset_api_connection().await {
            warn!(sl!(), "resume_vm: reset_api_connection failed: {e:#}"; "sandbox" => &self.id);
        }
        info!(sl!(), "resume_vm: PUT /vm.resume";
              "sandbox" => &self.id);
        cloud_hypervisor_vm_resume(&self.api_socket)
            .await
            .context("cloud_hypervisor_vm_resume")?;
        Ok(())
    }

    pub(crate) async fn save_vm(&mut self, dest_dir: &str) -> Result<()> {
        // AKS Pod Snapshot POC (Phase C2/C3.1): port of the Go runtime's SaveVM().
        // The caller is responsible for having paused the VM first; this method
        // only invokes /vm.snapshot with the requested destination directory.
        // The directory layout matches what `cloud-hypervisor --restore
        // source_url=file://...` expects on the restore side.
        if dest_dir.is_empty() {
            return Err(anyhow!("save_vm: dest_dir is required"));
        }
        let dest_dir = std::path::Path::new(dest_dir);
        std::fs::create_dir_all(dest_dir).with_context(|| {
            format!(
                "save_vm: create snapshot destination {}",
                dest_dir.display()
            )
        })?;
        let url = format!("file://{}", dest_dir.display());

        // Sandbox snapshot/restore: the CLH `api_client` we link against
        // shares one persistent UnixStream across calls (see
        // `ch_api::api_command`'s `try_clone()`). With CLH's keep-alive
        // server, any leftover bytes on the wire from a preceding response
        // bleed into the next request's parser ("HTTP output is missing
        // protocol statement"). Reset the socket BEFORE the long
        // /vm.snapshot call so it starts on a clean stream, AND again
        // after, so resume_vm gets a fresh connection too.
        if let Err(e) = self.reset_api_connection().await {
            warn!(sl!(), "save_vm: pre-snapshot reset_api_connection failed: {e:#}";
                  "sandbox" => &self.id);
        }

        info!(sl!(), "save_vm: PUT /vm.snapshot";
              "sandbox" => &self.id,
              "destination_url" => &url);
        let snap_call_result = cloud_hypervisor_vm_snapshot(&self.api_socket, &url).await;
        match &snap_call_result {
            Ok(resp) => info!(sl!(), "save_vm: /vm.snapshot returned"; "sandbox" => &self.id, "response" => format!("{resp:?}")),
            Err(e) => warn!(sl!(), "save_vm: /vm.snapshot ERR: {e:#}"; "sandbox" => &self.id),
        }

        if let Err(e) = self.reset_api_connection().await {
            warn!(sl!(), "save_vm: post-snapshot reset_api_connection failed: {e:#}";
                  "sandbox" => &self.id);
        } else {
            info!(sl!(), "save_vm: api socket reset"; "sandbox" => &self.id);
        }

        snap_call_result.with_context(|| format!("cloud_hypervisor_vm_snapshot to {url}"))?;
        Ok(())
    }

    /// Sandbox snapshot/restore: re-connect to the cloud-hypervisor API
    /// socket, dropping the persistent UnixStream we keep on `self.api_socket`
    /// and replacing it with a fresh connection to the same path.
    ///
    /// Why this exists: every CH HTTP wrapper in `ch_api.rs` does
    /// `try_clone()` on the persistent socket, so all calls share the same
    /// underlying TCP-equivalent (Unix) connection. That works for short
    /// PUTs (vm.create, vm.boot, vm.add-net, vm.pause, vm.resume) but
    /// `/vm.snapshot` for a 384 MiB guest takes seconds to write to disk,
    /// and observation on the v48 cloud-hypervisor in our POC shows the
    /// server closes the keep-alive connection after that response. Subsequent
    /// calls (the post-snapshot resume_vm in particular) then fail with a
    /// closed-socket error. The Go runtime sidesteps this by opening a fresh
    /// connection per call; until we restructure ch_api.rs the same way, this
    /// targeted reset is what `Sandbox.snapshot` calls between save_vm and
    /// resume_vm to keep the VM live.
    pub(crate) async fn reset_api_connection(&mut self) -> Result<()> {
        let api_socket_path = get_api_socket_path(&self.id)?;
        let new_sock = task::spawn_blocking(move || -> Result<UnixStream> {
            UnixStream::connect(&api_socket_path).with_context(|| {
                format!("reconnect to CH api socket {api_socket_path:?}")
            })
        })
        .await??;
        *self.api_socket.lock().await = Some(new_sock);
        Ok(())
    }

    // AKS Pod Snapshot POC (Phase C4): arm the next start_vm() to launch
    // cloud-hypervisor in restore mode, sourcing the VM state from
    // <snapshot_src>. The actual --restore argv construction lives in
    // cloud_hypervisor_launch(); start_vm() also short-circuits boot_vm()
    // when this is set because CLH does CreateVM+BootVM internally as part
    // of --restore (see clh.go::launchClh comment block).
    //
    // Phase C4.2: before stashing the path we patch the snapshot in place
    // for the new sandbox id (config.json) and apply the vhost-user-fs
    // activate-on-restore workaround (state.json). Both are idempotent.
    pub(crate) async fn prepare_for_restore(&mut self, snapshot_src: &str) -> Result<()> {
        if snapshot_src.is_empty() {
            return Err(anyhow!("prepare_for_restore: snapshot_src is required"));
        }
        if !std::path::Path::new(snapshot_src).is_dir() {
            return Err(anyhow!(
                "prepare_for_restore: snapshot_src {} is not a directory",
                snapshot_src
            ));
        }
        for fname in ["state.json", "config.json"] {
            let p = std::path::Path::new(snapshot_src).join(fname);
            if !p.exists() {
                return Err(anyhow!(
                    "prepare_for_restore: snapshot missing required file {}",
                    p.display()
                ));
            }
        }

        let config_path = std::path::Path::new(snapshot_src).join("config.json");
        let state_path = std::path::Path::new(snapshot_src).join("state.json");
        crate::ch::snapshot_rewrite::rewrite_snapshot_config_for_new_sandbox(
            &config_path,
            &self.id,
        )
        .context("rewriting snapshot config for new sandbox")?;
        crate::ch::snapshot_rewrite::rewrite_snapshot_state_for_new_sandbox(&state_path)
            .context("rewriting snapshot state for new sandbox")?;

        info!(sl!(), "prepare_for_restore: arming restore launch";
              "sandbox" => &self.id,
              "snapshot_src" => snapshot_src);
        self.restore_src = Some(snapshot_src.to_string());
        Ok(())
    }

    // AKS Pod Snapshot POC (Phase C4.1): stash per-net-device tap fds the
    // next launch should hand to cloud-hypervisor as inheritable child fds.
    // The caller is responsible for matching its sandbox's prepared taps
    // (one File per net device id) to the IDs declared in the snapshot's
    // config.json, and for opening those taps inside the destination netns.
    // The Vec is drained at launch time; passing an empty Vec disarms.
    pub(crate) async fn set_restore_net_fds(
        &mut self,
        net_fds: Vec<(String, std::fs::File)>,
    ) -> Result<()> {
        info!(sl!(), "set_restore_net_fds: arming";
              "sandbox" => &self.id,
              "net_fd_count" => net_fds.len());
        self.restore_net_fds = net_fds;
        Ok(())
    }

    pub(crate) async fn get_agent_socket(&self) -> Result<String> {
        const HYBRID_VSOCK_SCHEME: &str = "hvsock";

        let vsock_path = get_vsock_path(&self.id)?;

        let uri = format!("{HYBRID_VSOCK_SCHEME}://{vsock_path}");

        Ok(uri)
    }

    pub(crate) async fn disconnect(&mut self) {
        self.state = VmmState::NotReady;
    }

    pub(crate) async fn get_thread_ids(&self) -> Result<VcpuThreadIds> {
        let thread_id = self.get_vmm_master_tid().await?;
        let proc_path = format!("/proc/{thread_id}");

        let vcpus = get_ch_vcpu_tids(&proc_path)?;
        let vcpu_thread_ids = VcpuThreadIds { vcpus };

        Ok(vcpu_thread_ids)
    }

    pub(crate) async fn cleanup(&self) -> Result<()> {
        info!(sl!(), "CloudHypervisor::cleanup()");
        if is_rootless() {
            remove_dir_all_if_exists(get_rootless_symlink_sandbox_path(self.id.as_str()).as_str())?;
        }
        vm_cleanup(&self.config, self.vm_path.as_str())
    }

    pub(crate) async fn resize_vcpu(
        &self,
        old_vcpus: u32,
        mut new_vcpus: u32,
    ) -> Result<(u32, u32)> {
        info!(
            sl!(),
            "cloud hypervisor resize_vcpu(): {} -> {}", old_vcpus, new_vcpus
        );

        if new_vcpus == 0 {
            return Err(anyhow!("resize to 0 vcpus requested"));
        }

        if new_vcpus > self.config.cpu_info.default_maxvcpus {
            warn!(
                sl!(),
                "Cannot allocate more vcpus than the max allowed number of vcpus. The maximum allowed amount of vcpus will be used instead.");
            new_vcpus = self.config.cpu_info.default_maxvcpus;
        }

        if new_vcpus == old_vcpus {
            return Ok((old_vcpus, new_vcpus));
        }

        let vmresize = VmResize {
            desired_vcpus: Some(new_vcpus as u8),
            ..Default::default()
        };

        cloud_hypervisor_vm_resize(&self.api_socket, vmresize)
            .await
            .context("resize vcpus")?;

        Ok((old_vcpus, new_vcpus))
    }

    pub(crate) async fn get_pids(&self) -> Result<Vec<u32>> {
        let pid = self.get_vmm_master_tid().await?;

        Ok(vec![pid])
    }

    pub(crate) async fn get_vmm_master_tid(&self) -> Result<u32> {
        if let Some(pid) = self.pid {
            Ok(pid)
        } else {
            Err(anyhow!("could not get vmm master tid"))
        }
    }

    pub(crate) async fn get_ns_path(&self) -> Result<String> {
        if let Some(pid) = self.pid {
            let ns_path = format!("/proc/{pid}/ns");
            Ok(ns_path)
        } else {
            Err(anyhow!("could not get ns path"))
        }
    }

    pub(crate) async fn check(&self) -> Result<()> {
        Ok(())
    }

    pub(crate) async fn get_jailer_root(&self) -> Result<String> {
        let root_path = get_jailer_root(&self.id);

        create_dir_all_with_inherit_owner(&root_path, 0o750)?;

        Ok(root_path)
    }

    pub(crate) async fn capabilities(&self) -> Result<Capabilities> {
        let mut caps = Capabilities::default();

        let flags = if guest_protection_is_tdx(self.guest_protection_to_use.clone()) {
            // TDX does not permit the use of virtio-fs.
            CapabilityBits::BlockDeviceSupport
                | CapabilityBits::BlockDeviceHotplugSupport
                | CapabilityBits::HybridVsockSupport
        } else {
            CapabilityBits::BlockDeviceSupport
                | CapabilityBits::BlockDeviceHotplugSupport
                | CapabilityBits::FsSharingSupport
                | CapabilityBits::HybridVsockSupport
        };

        caps.set(flags);

        Ok(caps)
    }

    pub(crate) async fn get_hypervisor_metrics(&self) -> Result<String> {
        Err(anyhow!("CH hypervisor metrics not implemented - see https://github.com/kata-containers/kata-containers/issues/8800"))
    }

    pub(crate) fn set_capabilities(&mut self, flag: CapabilityBits) {
        let mut caps = Capabilities::default();

        caps.set(flag)
    }

    pub(crate) fn set_guest_memory_block_size(&mut self, size: u32) {
        self.guest_memory_block_size_mb = bytes_to_megs(size as u64);
    }

    pub(crate) fn guest_memory_block_size_mb(&self) -> u32 {
        self.guest_memory_block_size_mb
    }

    pub(crate) async fn resize_memory(&self, new_mem_mb: u32) -> Result<(u32, MemoryConfig)> {
        let vminfo = cloud_hypervisor_vm_info(&self.api_socket)
            .await
            .context("get vminfo")?;

        let current_mem_size = vminfo.config.memory.size;
        let new_total_mem = megs_to_bytes(new_mem_mb);

        info!(
            sl!(),
            "cloud-hypervisor::resize_memory(): asked to resize memory to {} MB, current memory is {} MB", new_mem_mb, bytes_to_megs(current_mem_size)
        );

        // Early Check to verify if boot memory is the same as requested
        if current_mem_size == new_total_mem {
            info!(sl!(), "VM alreay has requested memory");
            return Ok((new_mem_mb, MemoryConfig::default()));
        }

        if current_mem_size > new_total_mem {
            info!(sl!(), "Remove memory is not supported, nothing to do");
            return Ok((new_mem_mb, MemoryConfig::default()));
        }

        let guest_mem_block_size = megs_to_bytes(self.guest_memory_block_size_mb);

        let mut new_hotplugged_mem = new_total_mem - current_mem_size;

        info!(
            sl!(),
            "new hotplugged mem before alignment: {} B ({} MB), guest_mem_block_size: {} MB",
            new_hotplugged_mem,
            bytes_to_megs(new_hotplugged_mem),
            bytes_to_megs(guest_mem_block_size)
        );

        let is_unaligned = !new_hotplugged_mem.is_multiple_of(guest_mem_block_size);
        if is_unaligned {
            new_hotplugged_mem = ch_config::convert::checked_next_multiple_of(
                new_hotplugged_mem,
                guest_mem_block_size,
            )
            .ok_or(anyhow!(format!(
                "alignment of {} B to the block size of {} B failed",
                new_hotplugged_mem, guest_mem_block_size
            )))?
        }

        let new_total_mem_aligned = new_hotplugged_mem + current_mem_size;

        let max_total_mem = megs_to_bytes(self.config.memory_info.default_maxmemory);
        if new_total_mem_aligned > max_total_mem {
            return Err(anyhow!(
                "requested memory ({} MB) is greater than maximum allowed ({} MB)",
                bytes_to_megs(new_total_mem_aligned),
                self.config.memory_info.default_maxmemory
            ));
        }

        info!(
            sl!(),
            "hotplugged mem from {} MB to {} MB)",
            bytes_to_megs(current_mem_size),
            bytes_to_megs(new_total_mem_aligned)
        );

        let vmresize = VmResize {
            desired_ram: Some(new_total_mem_aligned),
            ..Default::default()
        };

        cloud_hypervisor_vm_resize(&self.api_socket, vmresize)
            .await
            .context("resize memory")?;

        Ok((new_mem_mb, MemoryConfig::default()))
    }
}

// Log all output from the CH process until a shutdown signal is received.
// When that happens, stop logging and wait for the child process to finish
// before returning.
async fn cloud_hypervisor_log_output(
    mut child: Child,
    mut shutdown: Receiver<bool>,
    exit_notify: mpsc::Sender<i32>,
) -> Result<()> {
    let stdout = child
        .stdout
        .as_mut()
        .ok_or("failed to get child stdout")
        .map_err(|e| anyhow!(e))?;

    let stdout_reader = BufReader::new(stdout);
    let mut stdout_lines = stdout_reader.lines();

    let stderr = child
        .stderr
        .as_mut()
        .ok_or("failed to get child stderr")
        .map_err(|e| anyhow!(e))?;

    let stderr_reader = BufReader::new(stderr);
    let mut stderr_lines = stderr_reader.lines();

    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                info!(sl!(), "got shutdown request");
                break;
            },
            stderr_line = poll_fn(|cx| Pin::new(&mut stderr_lines).poll_next_line(cx)) => {
                match stderr_line {
                    Ok(Some(line)) => {
                        // Sandbox snapshot/restore: CLH `Fatal error:` lines from
                        // a failed --restore don't carry the WARN:/ERRO: prefix
                        // parse_ch_log_level expects; force-classify them so the
                        // root cause shows up in journald rather than getting
                        // bucketed as info and lost in noise.
                        let lvl = if line.contains("Fatal error") || line.contains("ERROR:") {
                            CloudHypervisorLogLevel::Error
                        } else {
                            parse_ch_log_level(&line)
                        };
                        match lvl {
                            CloudHypervisorLogLevel::Trace => trace!(sl!(), "{:?}", line; "stream" => "stderr"),
                            CloudHypervisorLogLevel::Debug => debug!(sl!(), "{:?}", line; "stream" => "stderr"),
                            CloudHypervisorLogLevel::Warn => warn!(sl!(), "{:?}", line; "stream" => "stderr"),
                            CloudHypervisorLogLevel::Error => error!(sl!(), "CH stderr: {}", line),
                            _ => info!(sl!(), "{:?}", line; "stream" => "stderr"),
                        }
                    }
                    // EOF: CH stderr closed (CH probably exited). Stop logging
                    // and break the loop so the cleanup at the bottom of the
                    // function fires (kill + exit_notify).
                    Ok(None) => {
                        warn!(sl!(), "CH stderr EOF; child likely exited");
                        break;
                    }
                    Err(e) => {
                        warn!(sl!(), "CH stderr read error: {e}");
                        break;
                    }
                }
            },
            stdout_line = poll_fn(|cx| Pin::new(&mut stdout_lines).poll_next_line(cx)) => {
                match stdout_line {
                    Ok(Some(line)) => {
                        let lvl = if line.contains("Fatal error") || line.contains("ERROR:") {
                            CloudHypervisorLogLevel::Error
                        } else {
                            parse_ch_log_level(&line)
                        };
                        match lvl {
                            CloudHypervisorLogLevel::Trace => trace!(sl!(), "{:?}", line; "stream" => "stdout"),
                            CloudHypervisorLogLevel::Debug => debug!(sl!(), "{:?}", line; "stream" => "stdout"),
                            CloudHypervisorLogLevel::Warn => warn!(sl!(), "{:?}", line; "stream" => "stdout"),
                            CloudHypervisorLogLevel::Error => error!(sl!(), "CH stdout: {}", line),
                            _ => info!(sl!(), "{:?}", line; "stream" => "stdout"),
                        }
                    }
                    Ok(None) => continue,
                    Err(_) => continue,
                }
            },
        };
    }

    // Note that this kills _and_ waits for the process!
    let _ = child.kill().await;
    if let Ok(status) = child.wait().await {
        let code = status.code().unwrap_or(0);
        warn!(sl!(), "CH process exited with code {code}");
        let _ = exit_notify.try_send(code);
    }

    Ok(())
}

// Search in the log line looking for the log level.
//
// For performance, the line is scanned exactly once and all log levels
// are search for.
fn parse_ch_log_level(line: &str) -> CloudHypervisorLogLevel {
    for (i, c) in line.char_indices() {
        if c == 'I' && line[i..].starts_with("INFO:") {
            return CloudHypervisorLogLevel::Info;
        } else if c == 'D' && line[i..].starts_with("DEBG:") {
            return CloudHypervisorLogLevel::Debug;
        } else if c == 'W' && line[i..].starts_with("WARN:") {
            return CloudHypervisorLogLevel::Warn;
        } else if c == 'E' && line[i..].starts_with("ERRO:") {
            return CloudHypervisorLogLevel::Error;
        } else if c == 'T' && line[i..].starts_with("TRCE:") {
            return CloudHypervisorLogLevel::Trace;
        }
    }

    // Default - logging code cannot fail.
    CloudHypervisorLogLevel::Info
}

lazy_static! {
    // Store the fake guest protection value used by
    // get_fake_guest_protection() and set_fake_guest_protection().
    //
    // Note that if this variable is set to None, get_fake_guest_protection()
    // will fall back to checking the actual guest protection by calling
    // get_guest_protection().
    static ref FAKE_GUEST_PROTECTION: Arc<RwLock<Option<GuestProtection>>> =
        Arc::new(RwLock::new(Some(GuestProtection::NoProtection)));
}

// Return the _fake_ GuestProtection value set by set_guest_protection().
fn get_fake_guest_protection() -> Result<GuestProtection> {
    let existing_ref = FAKE_GUEST_PROTECTION.clone();

    let existing = existing_ref.read().unwrap();

    let real_protection = available_guest_protection()?;

    let protection = if let Some(ref protection) = *existing {
        protection
    } else {
        // XXX: If no fake value is set, fall back to the real function.
        &real_protection
    };

    Ok(protection.clone())
}

// Return available hardware protection, or GuestProtection::NoProtection
// if none available.
//
// XXX: Note that this function wraps the low-level function to determine
// guest protection. It does this to allow us to force a particular guest
// protection type in the unit tests.
fn get_guest_protection() -> Result<GuestProtection> {
    let guest_protection = if cfg!(test) {
        get_fake_guest_protection()
    } else {
        available_guest_protection().map_err(|e| anyhow!(e.to_string()))
    }?;

    Ok(guest_protection)
}

// Return a VCPU/TID map from a specified /proc/{pid} path.
fn get_ch_vcpu_tids(proc_path: &str) -> Result<HashMap<u32, u32>> {
    const VCPU_STR: &str = "vcpu";

    let src = std::fs::canonicalize(proc_path)
        .map_err(|e| anyhow!("Invalid proc path: {proc_path}: {e}"))?;

    let tid_path = src.join("task");

    let mut vcpus = HashMap::new();

    for entry in fs::read_dir(&tid_path)? {
        let entry = entry?;

        let tid_str = match entry.file_name().into_string() {
            Ok(id) => id,
            Err(_) => continue,
        };

        let tid = tid_str
            .parse::<u32>()
            .map_err(|e| anyhow!(e).context("invalid tid."))?;

        let comm_path = tid_path.join(tid_str.clone()).join("comm");

        if !comm_path.exists() {
            return Err(anyhow!("comm path was not found."));
        }

        let p_name = fs::read_to_string(comm_path)?;

        // The CH names it's threads with a vcpu${number} to identify them, where
        // the thread name is located at /proc/${ch_pid}/task/${thread_id}/comm.
        if !p_name.starts_with(VCPU_STR) {
            continue;
        }

        let vcpu_id = p_name
            .trim_start_matches(VCPU_STR)
            .trim()
            .parse::<u32>()
            .map_err(|e| anyhow!(e).context("Invalid vcpu id."))?;

        vcpus.insert(vcpu_id, tid);
    }

    if vcpus.is_empty() {
        return Err(anyhow!("The contents of proc path are not available."));
    }

    Ok(vcpus)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kata_sys_util::protection::SevSnpDetails;

    #[cfg(target_arch = "x86_64")]
    use kata_sys_util::protection::TDX_KVM_PARAMETER_PATH;

    use kata_types::config::hypervisor::{Hypervisor as HypervisorConfig, SecurityInfo};
    use serial_test::serial;
    use test_utils::{assert_result, skip_if_not_root};

    use std::fs::File;
    use tempfile::Builder;

    fn set_fake_guest_protection(protection: Option<GuestProtection>) {
        let existing_ref = FAKE_GUEST_PROTECTION.clone();

        let mut existing = existing_ref.write().unwrap();

        // Modify the lazy static global config structure
        *existing = protection;
    }

    #[serial]
    #[actix_rt::test]
    async fn test_get_guest_protection() {
        // available_guest_protection() requires super user privs.
        skip_if_not_root!();

        let sev_snp_details = SevSnpDetails {
            cbitpos: 42,
            phys_addr_reduction: 42,
        };

        #[derive(Debug)]
        struct TestData {
            value: Option<GuestProtection>,
            result: Result<GuestProtection>,
        }

        let tests = &[
            TestData {
                value: Some(GuestProtection::NoProtection),
                result: Ok(GuestProtection::NoProtection),
            },
            TestData {
                value: Some(GuestProtection::Pef),
                result: Ok(GuestProtection::Pef),
            },
            TestData {
                value: Some(GuestProtection::Se),
                result: Ok(GuestProtection::Se),
            },
            TestData {
                value: Some(GuestProtection::Sev(sev_snp_details.clone())),
                result: Ok(GuestProtection::Sev(sev_snp_details.clone())),
            },
            TestData {
                value: Some(GuestProtection::Snp(sev_snp_details.clone())),
                result: Ok(GuestProtection::Snp(sev_snp_details.clone())),
            },
            TestData {
                value: Some(GuestProtection::Tdx),
                result: Ok(GuestProtection::Tdx),
            },
        ];

        for (i, d) in tests.iter().enumerate() {
            let msg = format!("test[{i}]: {d:?}");

            set_fake_guest_protection(d.value.clone());

            let result =
                task::spawn_blocking(|| -> Result<GuestProtection> { get_guest_protection() })
                    .await
                    .unwrap();

            let msg = format!("{msg}: actual result: {result:?}");

            if std::env::var("DEBUG").is_ok() {
                eprintln!("DEBUG: {msg}");
            }

            assert_result!(d.result, result, msg);
        }

        // Reset
        set_fake_guest_protection(None);
    }

    #[cfg(target_arch = "x86_64")]
    #[serial]
    #[actix_rt::test]
    async fn test_get_guest_protection_tdx() {
        // available_guest_protection() requires super user privs.
        skip_if_not_root!();

        // Use the hosts protection, not a fake one.
        set_fake_guest_protection(None);

        let have_tdx = fs::read(TDX_KVM_PARAMETER_PATH)
            .is_ok_and(|content| !content.is_empty() && content[0] == b'Y');

        let protection =
            task::spawn_blocking(|| -> Result<GuestProtection> { get_guest_protection() })
                .await
                .unwrap()
                .unwrap();

        if std::env::var("DEBUG").is_ok() {
            let msg = format!("have_tdx: {have_tdx:?}, protection: {protection:?}");

            eprintln!("DEBUG: {msg}");
        }

        if have_tdx {
            assert_eq!(protection, GuestProtection::Tdx);
        } else {
            assert_eq!(protection, GuestProtection::NoProtection);
        }
    }

    #[serial]
    #[actix_rt::test]
    async fn test_handle_guest_protection() {
        // available_guest_protection() requires super user privs.
        skip_if_not_root!();

        #[derive(Debug)]
        struct TestData {
            confidential_guest: bool,
            available_protection: Option<GuestProtection>,

            result: Result<()>,

            // The expected result (internal state)
            guest_protection_to_use: GuestProtection,
        }

        let tests = &[
            TestData {
                confidential_guest: false,
                available_protection: Some(GuestProtection::NoProtection),
                result: Ok(()),
                guest_protection_to_use: GuestProtection::NoProtection,
            },
            TestData {
                confidential_guest: true,
                available_protection: Some(GuestProtection::NoProtection),
                result: Err(anyhow!(GuestProtectionError::NoProtectionAvailable)),
                guest_protection_to_use: GuestProtection::NoProtection,
            },
            TestData {
                confidential_guest: false,
                available_protection: Some(GuestProtection::Tdx),
                result: Err(anyhow!(GuestProtectionError::TDXProtectionMustBeUsedWithCH)),
                guest_protection_to_use: GuestProtection::Tdx,
            },
            TestData {
                confidential_guest: true,
                available_protection: Some(GuestProtection::Tdx),
                result: Ok(()),
                guest_protection_to_use: GuestProtection::Tdx,
            },
            TestData {
                confidential_guest: false,
                available_protection: Some(GuestProtection::Pef),
                result: Ok(()),
                guest_protection_to_use: GuestProtection::NoProtection,
            },
            TestData {
                confidential_guest: true,
                available_protection: Some(GuestProtection::Pef),
                result: Err(anyhow!(GuestProtectionError::ExpectedTDXProtection(
                    GuestProtection::Pef
                ))),
                guest_protection_to_use: GuestProtection::Pef,
            },
        ];

        for (i, d) in tests.iter().enumerate() {
            let msg = format!("test[{i}]: {d:?}");

            set_fake_guest_protection(d.available_protection.clone());

            let mut ch = CloudHypervisorInner::default();

            let cfg = HypervisorConfig {
                security_info: SecurityInfo {
                    confidential_guest: d.confidential_guest,

                    ..Default::default()
                },

                ..Default::default()
            };

            ch.set_hypervisor_config(cfg);

            let result = ch.handle_guest_protection().await;

            let msg = format!("{msg}: actual result: {result:?}");

            if std::env::var("DEBUG").is_ok() {
                eprintln!("DEBUG: {msg}");
            }

            if d.result.is_ok() && result.is_ok() {
                continue;
            }

            assert_result!(d.result, result, msg);

            assert_eq!(
                ch.guest_protection_to_use, d.guest_protection_to_use,
                "{msg}"
            );
        }

        // Reset
        set_fake_guest_protection(None);
    }

    #[actix_rt::test]
    async fn test_get_kernel_params() {
        #[derive(Debug)]
        struct TestData<'a> {
            cfg: Option<HypervisorConfig>,
            confidential_guest: bool,
            debug: bool,
            fails: bool,
            contains: Vec<&'a str>,
        }

        let tests = &[
            TestData {
                cfg: None,
                confidential_guest: false,
                debug: false,
                fails: true, // No hypervisor config
                contains: vec![],
            },
            TestData {
                cfg: Some(HypervisorConfig::default()),
                confidential_guest: false,
                debug: false,
                fails: false,
                contains: vec![],
            },
        ];

        for (i, d) in tests.iter().enumerate() {
            let msg = format!("test[{i}]: {d:?}");

            let mut ch = CloudHypervisorInner::default();

            if let Some(ref mut cfg) = d.cfg.clone() {
                if d.debug {
                    cfg.debug_info.enable_debug = true;
                }

                if d.confidential_guest {
                    cfg.security_info.confidential_guest = true;
                }

                ch.set_hypervisor_config(cfg.clone());

                let result = ch.get_kernel_params().await;

                let msg = format!("{msg}: actual result: {result:?}");

                if std::env::var("DEBUG").is_ok() {
                    eprintln!("DEBUG: {msg}");
                }

                if d.fails {
                    assert!(result.is_err(), "{}", msg);
                    continue;
                }

                let result = result.unwrap();

                for token in d.contains.clone() {
                    assert!(result.contains(token), "{}", msg);
                }
            }
        }
    }

    #[actix_rt::test]
    async fn test_parse_ch_log_level() {
        #[derive(Debug)]
        struct TestData<'a> {
            line: &'a str,
            level: CloudHypervisorLogLevel,
        }

        let tests = &[
            // Test default level with various values
            TestData {
                line: "",
                level: CloudHypervisorLogLevel::Info,
            },
            TestData {
                line: "foo",
                level: CloudHypervisorLogLevel::Info,
            },
            TestData {
                line: "info:",
                level: CloudHypervisorLogLevel::Info,
            },
            // Levels are case sensitive
            TestData {
                line: "foo trce: bar",
                level: CloudHypervisorLogLevel::Info,
            },
            TestData {
                line: "foo debg: bar",
                level: CloudHypervisorLogLevel::Info,
            },
            TestData {
                line: "foo info: bar",
                level: CloudHypervisorLogLevel::Info,
            },
            TestData {
                line: "foo warn: bar",
                level: CloudHypervisorLogLevel::Info,
            },
            TestData {
                line: "foo erro: bar",
                level: CloudHypervisorLogLevel::Info,
            },
            TestData {
                line: "foo INFO: bar",
                level: CloudHypervisorLogLevel::Info,
            },
            TestData {
                line: "foo DEBUG: bar",
                level: CloudHypervisorLogLevel::Info,
            },
            TestData {
                line: "foo DEBG: bar",
                level: CloudHypervisorLogLevel::Debug,
            },
            TestData {
                line: "foo WARN:bar",
                level: CloudHypervisorLogLevel::Warn,
            },
            TestData {
                line: "foo ERROR: bar",
                level: CloudHypervisorLogLevel::Info,
            },
            TestData {
                line: "foo ERRO: bar",
                level: CloudHypervisorLogLevel::Error,
            },
            TestData {
                line: "foo TRACE: bar",
                level: CloudHypervisorLogLevel::Info,
            },
            TestData {
                line: "foo TRCE: bar",
                level: CloudHypervisorLogLevel::Trace,
            },
            // First match wins
            TestData {
                line: "TRCE:ERRO:WARN:DEBG:INFO:",
                level: CloudHypervisorLogLevel::Trace,
            },
            TestData {
                line: "ERRO:WARN:DEBG:INFO:TRCE",
                level: CloudHypervisorLogLevel::Error,
            },
            TestData {
                line: "WARN:DEBG:INFO:TRCE:ERRO:",
                level: CloudHypervisorLogLevel::Warn,
            },
            TestData {
                line: "DEBG:INFO:TRCE:ERRO:WARN:",
                level: CloudHypervisorLogLevel::Debug,
            },
            TestData {
                line: "INFO:TRCE:ERRO:WARN:DEBG:",
                level: CloudHypervisorLogLevel::Info,
            },
        ];

        for (i, d) in tests.iter().enumerate() {
            let msg = format!("test[{i}]: {d:?}");

            let level = parse_ch_log_level(d.line);

            let msg = format!("{msg}: actual level: {level:?}");

            if std::env::var("DEBUG").is_ok() {
                eprintln!("DEBUG: {msg}");
            }

            assert_eq!(d.level, level, "{msg}");
        }
    }

    #[actix_rt::test]
    async fn test_get_thread_ids() {
        let path_dir = "/tmp/proc";
        let file_name = "1";

        let tmp_dir = Builder::new().prefix("proc").tempdir().unwrap();
        let file_path = tmp_dir.path().join(file_name);
        let _tmp_file = File::create(file_path.as_os_str()).unwrap();
        let file_path_name = file_path.as_path().to_str().map(|s| s.to_string());
        let file_path_name_str = file_path_name.as_ref().unwrap().to_string();

        #[derive(Debug)]
        struct TestData<'a> {
            proc_path: &'a str,
            result: Result<HashMap<u32, u32>>,
        }

        let tests = &[
            TestData {
                // Test on a non-existent directory.
                proc_path: path_dir,
                result: Err(anyhow!(
                    "Invalid proc path: {path_dir}: No such file or directory (os error 2)"
                )),
            },
            TestData {
                // Test on an existing path, however it is not valid because it does not point to a pid.
                proc_path: &file_path_name_str,
                result: Err(anyhow!("Not a directory (os error 20)")),
            },
            TestData {
                // Test on an existing proc/${pid} but that does not correspond to a CH pid.
                proc_path: "/proc/1",
                result: Err(anyhow!("The contents of proc path are not available.")),
            },
        ];

        for (i, d) in tests.iter().enumerate() {
            let msg = format!("test: [{i}]: {d:?}");

            if std::env::var("DEBUG").is_ok() {
                println!("DEBUG: {msg}");
            }

            let result = get_ch_vcpu_tids(d.proc_path);
            let msg = format!("{msg}, result: {result:?}");

            let expected_error = format!("{}", d.result.as_ref().unwrap_err());
            let actual_error = format!("{}", result.unwrap_err());

            assert!(actual_error == expected_error, "{}", msg);
        }
    }

    #[actix_rt::test]
    async fn test_get_ch_vcpu_tids_mapping() {
        let tmp_dir = Builder::new().prefix("fake-proc-pid").tempdir().unwrap();
        let task_dir = tmp_dir.path().join("task");
        fs::create_dir_all(&task_dir).unwrap();

        #[derive(Debug)]
        struct ThreadInfo<'a> {
            tid: &'a str,
            comm: &'a str,
        }

        let threads = &[
            // Non-vcpu thread, should be skipped.
            ThreadInfo {
                tid: "1000",
                comm: "main_thread\n",
            },
            ThreadInfo {
                tid: "2001",
                comm: "vcpu0\n",
            },
            ThreadInfo {
                tid: "2002",
                comm: "vcpu1\n",
            },
            ThreadInfo {
                tid: "2003",
                comm: "vcpu2\n",
            },
        ];

        for t in threads {
            let tid_dir = task_dir.join(t.tid);
            fs::create_dir_all(&tid_dir).unwrap();
            fs::write(tid_dir.join("comm"), t.comm).unwrap();
        }

        let proc_path = tmp_dir.path().to_str().unwrap();
        let result = get_ch_vcpu_tids(proc_path);

        let msg = format!("result: {result:?}");

        if std::env::var("DEBUG").is_ok() {
            println!("DEBUG: {msg}");
        }

        let vcpus = result.unwrap();

        // The mapping must be vcpu_id -> tid.
        assert_eq!(vcpus.len(), 3, "non-vcpu threads should be excluded");
        assert_eq!(vcpus[&0], 2001, "vcpu 0 should map to tid 2001");
        assert_eq!(vcpus[&1], 2002, "vcpu 1 should map to tid 2002");
        assert_eq!(vcpus[&2], 2003, "vcpu 2 should map to tid 2003");

        assert!(
            !vcpus.contains_key(&1000),
            "non-vcpu thread should not be in the map"
        );
    }
}
