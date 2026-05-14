//go:build linux

// Copyright (c) 2019 Ericsson Eurolab Deutschland GmbH
//
// SPDX-License-Identifier: Apache-2.0
//

package virtcontainers

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/containerd/console"
	chclient "github.com/kata-containers/kata-containers/src/runtime/virtcontainers/pkg/cloud-hypervisor/client"
	selinux "github.com/opencontainers/selinux/go-selinux"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/kata-containers/kata-containers/src/runtime/pkg/device/config"
	hv "github.com/kata-containers/kata-containers/src/runtime/pkg/hypervisors"
	"github.com/kata-containers/kata-containers/src/runtime/pkg/katautils/katatrace"
	pkgUtils "github.com/kata-containers/kata-containers/src/runtime/pkg/utils"
	"github.com/kata-containers/kata-containers/src/runtime/virtcontainers/pkg/rootless"
	"github.com/kata-containers/kata-containers/src/runtime/virtcontainers/types"
	"github.com/kata-containers/kata-containers/src/runtime/virtcontainers/utils"
	"github.com/kata-containers/kata-containers/src/runtime/virtcontainers/utils/retry"
)

// clhTracingTags defines tags for the trace span
var clhTracingTags = map[string]string{
	"source":    "runtime",
	"package":   "virtcontainers",
	"subsystem": "hypervisor",
	"type":      "clh",
}

//
// Constants and type definitions related to cloud hypervisor
//

type clhState uint8

const (
	clhNotReady clhState = iota
	clhReady
)

const (
	clhStateCreated = "Created"
	clhStateRunning = "Running"
)

const (
	// Values are mandatory by http API
	// Values based on:
	clhTimeout                     = 10
	clhAPITimeout                  = 1
	clhAPITimeoutConfidentialGuest = 20
	// Minimum timout for calling CreateVM followed by BootVM. Executing these two APIs
	// might take longer than the value returned by getClhAPITimeout().
	clhCreateAndBootVMMinimumTimeout = 10
	// Timeout for hot-plug - hotplug devices can take more time, than usual API calls
	// Use longer time timeout for it.
	clhHotPlugAPITimeout                   = 5
	clhStopSandboxTimeout                  = 3
	clhStopSandboxTimeoutConfidentialGuest = 10
	clhSocket                              = "clh.sock"
	clhAPISocket                           = "clh-api.sock"
	virtioFsSocket                         = "virtiofsd.sock"
	defaultClhPath                         = "/usr/local/bin/cloud-hypervisor"
)

// Interface that hides the implementation of openAPI client
// If the client changes  its methods, this interface should do it as well,
// The main purpose is to hide the client in an interface to allow mock testing.
// This is an interface that has to match with OpenAPI CLH client
type clhClient interface {
	// Check for the REST API availability
	VmmPingGet(ctx context.Context) (chclient.VmmPingResponse, *http.Response, error)
	// Shut the VMM down
	ShutdownVMM(ctx context.Context) (*http.Response, error)
	// Create the VM
	CreateVM(ctx context.Context, vmConfig chclient.VmConfig) (*http.Response, error)
	// Dump the VM information
	// No lint: golint suggest to rename to VMInfoGet.
	VmInfoGet(ctx context.Context) (chclient.VmInfo, *http.Response, error) //nolint:golint
	// Boot the VM
	BootVM(ctx context.Context) (*http.Response, error)
	// Add/remove CPUs to/from the VM
	VmResizePut(ctx context.Context, vmResize chclient.VmResize) (*http.Response, error)
	// Add VFIO PCI device to the VM
	VmAddDevicePut(ctx context.Context, deviceConfig chclient.DeviceConfig) (chclient.PciDeviceInfo, *http.Response, error)
	// Add a new disk device to the VM
	VmAddDiskPut(ctx context.Context, diskConfig chclient.DiskConfig) (chclient.PciDeviceInfo, *http.Response, error)
	// Remove a device from the VM
	VmRemoveDevicePut(ctx context.Context, vmRemoveDevice chclient.VmRemoveDevice) (*http.Response, error)
	// Pause a previously booted VM (PUT /vm.pause)
	PauseVM(ctx context.Context) (*http.Response, error)
	// Resume a previously paused VM (PUT /vm.resume)
	ResumeVM(ctx context.Context) (*http.Response, error)
	// Take a snapshot of the VM and write it to the destination URL (PUT /vm.snapshot)
	VmSnapshotPut(ctx context.Context, vmSnapshotConfig chclient.VmSnapshotConfig) (*http.Response, error)
	// Restore the VM from a previously taken snapshot at the source URL (PUT /vm.restore)
	VmRestorePut(ctx context.Context, restoreConfig chclient.RestoreConfig) (*http.Response, error)
}

type clhClientApi struct {
	ApiInternal *chclient.DefaultApiService
}

func (c *clhClientApi) VmmPingGet(ctx context.Context) (chclient.VmmPingResponse, *http.Response, error) {
	return c.ApiInternal.VmmPingGet(ctx).Execute()
}

func (c *clhClientApi) ShutdownVMM(ctx context.Context) (*http.Response, error) {
	return c.ApiInternal.ShutdownVMM(ctx).Execute()
}

func (c *clhClientApi) CreateVM(ctx context.Context, vmConfig chclient.VmConfig) (*http.Response, error) {
	return c.ApiInternal.CreateVM(ctx).VmConfig(vmConfig).Execute()
}

//nolint:golint
func (c *clhClientApi) VmInfoGet(ctx context.Context) (chclient.VmInfo, *http.Response, error) {
	return c.ApiInternal.VmInfoGet(ctx).Execute()
}

func (c *clhClientApi) BootVM(ctx context.Context) (*http.Response, error) {
	return c.ApiInternal.BootVM(ctx).Execute()
}

func (c *clhClientApi) VmResizePut(ctx context.Context, vmResize chclient.VmResize) (*http.Response, error) {
	return c.ApiInternal.VmResizePut(ctx).VmResize(vmResize).Execute()
}

func (c *clhClientApi) VmAddDevicePut(ctx context.Context, deviceConfig chclient.DeviceConfig) (chclient.PciDeviceInfo, *http.Response, error) {
	return c.ApiInternal.VmAddDevicePut(ctx).DeviceConfig(deviceConfig).Execute()
}

func (c *clhClientApi) VmAddDiskPut(ctx context.Context, diskConfig chclient.DiskConfig) (chclient.PciDeviceInfo, *http.Response, error) {
	return c.ApiInternal.VmAddDiskPut(ctx).DiskConfig(diskConfig).Execute()
}

func (c *clhClientApi) VmRemoveDevicePut(ctx context.Context, vmRemoveDevice chclient.VmRemoveDevice) (*http.Response, error) {
	return c.ApiInternal.VmRemoveDevicePut(ctx).VmRemoveDevice(vmRemoveDevice).Execute()
}

func (c *clhClientApi) PauseVM(ctx context.Context) (*http.Response, error) {
	return c.ApiInternal.PauseVM(ctx).Execute()
}

func (c *clhClientApi) ResumeVM(ctx context.Context) (*http.Response, error) {
	return c.ApiInternal.ResumeVM(ctx).Execute()
}

func (c *clhClientApi) VmSnapshotPut(ctx context.Context, vmSnapshotConfig chclient.VmSnapshotConfig) (*http.Response, error) {
	return c.ApiInternal.VmSnapshotPut(ctx).VmSnapshotConfig(vmSnapshotConfig).Execute()
}

func (c *clhClientApi) VmRestorePut(ctx context.Context, restoreConfig chclient.RestoreConfig) (*http.Response, error) {
	return c.ApiInternal.VmRestorePut(ctx).RestoreConfig(restoreConfig).Execute()
}

// This is done in order to be able to override such a function as part of
// our unit tests, as when testing bootVM we're on a mocked scenario already.
var vmAddNetPutRequest = func(clh *cloudHypervisor) ([]chclient.PciDeviceInfo, error) {
	var netDevicesPciInfo []chclient.PciDeviceInfo
	if clh.netDevices == nil {
		clh.Logger().Info("No network device has been configured by the upper layer")
		return nil, nil
	}

	addr, err := net.ResolveUnixAddr("unix", clh.state.apiSocket)
	if err != nil {
		return nil, err
	}

	conn, err := net.DialUnix("unix", nil, addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	for _, netDevice := range *clh.netDevices {
		clh.Logger().Infof("Adding the net device to the Cloud Hypervisor VM configuration: %+v", netDevice)

		netDeviceAsJson, err := json.Marshal(netDevice)
		if err != nil {
			return nil, err
		}
		netDeviceAsIoReader := bytes.NewBuffer(netDeviceAsJson)

		req, err := http.NewRequest(http.MethodPut, "http://localhost/api/v1/vm.add-net", netDeviceAsIoReader)
		if err != nil {
			return nil, err
		}

		req.Header.Set("Accept", "application/json")
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Content-Length", strconv.Itoa(int(netDeviceAsIoReader.Len())))

		payload, err := httputil.DumpRequest(req, true)
		if err != nil {
			return nil, err
		}

		files := clh.netDevicesFiles[*netDevice.Mac]
		var fds []int
		for _, f := range files {
			fds = append(fds, int(f.Fd()))
		}
		oob := syscall.UnixRights(fds...)
		payloadn, oobn, err := conn.WriteMsgUnix([]byte(payload), oob, nil)
		if err != nil {
			return nil, err
		}
		if payloadn != len(payload) || oobn != len(oob) {
			return nil, fmt.Errorf("Failed to send all the request to Cloud Hypervisor. %d bytes expect to send as payload, %d bytes expect to send as oob date,  but only %d sent as payload, and %d sent as oob", len(payload), len(oob), payloadn, oobn)
		}

		reader := bufio.NewReader(conn)
		resp, err := http.ReadResponse(reader, req)
		if err != nil {
			return nil, err
		}

		respBody, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}

		resp.Body.Close()
		resp.Body = io.NopCloser(bytes.NewBuffer(respBody))
		if resp.StatusCode != 200 && resp.StatusCode != 204 {
			clh.Logger().Errorf("vmAddNetPut failed with error '%d'. Response: %+v", resp.StatusCode, resp)
			return nil, fmt.Errorf("Failed to add the network device '%+v' to Cloud Hypervisor: %v", netDevice, resp.StatusCode)
		}

		// Parse the pci info received in response
		var pciInfo chclient.PciDeviceInfo
		decoder := json.NewDecoder(resp.Body)
		err = decoder.Decode(&pciInfo)
		if err != nil && err.Error() != "EOF" {
			return nil, err
		}
		// PciInfo is received in response after the
		// vm is booted.
		if err == nil {
			netDevicesPciInfo = append(netDevicesPciInfo, pciInfo)
		}
	}

	return netDevicesPciInfo, nil
}

// Cloud hypervisor state
type CloudHypervisorState struct {
	apiSocket         string
	PID               int
	VirtiofsDaemonPid int
	state             clhState
}

func (s *CloudHypervisorState) reset() {
	s.PID = 0
	s.VirtiofsDaemonPid = 0
	s.state = clhNotReady
}

type cloudHypervisor struct {
	console         console.Console
	virtiofsDaemon  VirtiofsDaemon
	APIClient       clhClient
	ctx             context.Context
	id              string
	netDevices      *[]chclient.NetConfig
	devicesIds      map[string]string
	netDevicesFiles map[string][]*os.File
	vmconfig        chclient.VmConfig
	state           CloudHypervisorState
	config          HypervisorConfig
	stopped         int32
	mu              sync.Mutex

	// restoreTmpDir is set when buildRestoreArgs decompresses a
	// zstd-compressed snapshot into a sibling tmp directory. CLH reads
	// from this dir for /vm.restore. Cleaned up on stopSandbox so
	// repeated restore-from-the-same-snapshot flows do not leak disk.
	restoreTmpDir string
}

var clhKernelParams = []Param{
	{"panic", "1"},         // upon kernel panic wait 1 second before reboot
	{"no_timer_check", ""}, // do not Check broken timer IRQ resources
	{"noreplace-smp", ""},  // do not replace SMP instructions
}

var clhDebugKernelParams = []Param{
	{"console", "ttyS0,115200n8"}, // enable serial console
}

var clhArmDebugKernelParams = []Param{
	{"console", "ttyAMA0,115200n8"}, // enable serial console
}

var clhDebugConfidentialGuestKernelParams = []Param{
	{"console", "hvc0"}, // enable HVC console
}

var clhDebugKernelParamsCommon = []Param{
	{"systemd.log_target", "console"}, // send loggng to the console
}

//###########################################################
//
// hypervisor interface implementation for cloud-hypervisor
//
//###########################################################

func (clh *cloudHypervisor) getClhAPITimeout() time.Duration {
	// Increase the APITimeout when dealing with a Confidential Guest.
	// The value has been chosen based on tests using `ctr`, and hopefully
	// this change can be dropped in further steps of the development.
	if clh.config.ConfidentialGuest {
		return clhAPITimeoutConfidentialGuest
	}

	return clhAPITimeout
}

func (clh *cloudHypervisor) getClhStopSandboxTimeout() time.Duration {
	// Increase the StopSandboxTimeout when dealing with a Confidential Guest.
	// The value has been chosen based on tests using `ctr`, and hopefully
	// this change can be dropped in further steps of the development.
	if clh.config.ConfidentialGuest {
		return clhStopSandboxTimeoutConfidentialGuest
	}

	return clhStopSandboxTimeout
}

func (clh *cloudHypervisor) setConfig(config *HypervisorConfig) error {
	clh.config = *config

	// We don't support NVDIMM with Cloud Hypervisor.
	clh.config.DisableImageNvdimm = true

	return nil
}

func (clh *cloudHypervisor) createVirtiofsDaemon(sharedPath string) (VirtiofsDaemon, error) {
	virtiofsdSocketPath, err := clh.virtioFsSocketPath(clh.id)
	if err != nil {
		return nil, err
	}

	if clh.config.SharedFS == config.VirtioFSNydus {
		apiSockPath, err := clh.nydusdAPISocketPath(clh.id)
		if err != nil {
			clh.Logger().WithError(err).Error("Invalid api socket path for nydusd")
			return nil, err
		}
		nd := &nydusd{
			path:        clh.config.VirtioFSDaemon,
			sockPath:    virtiofsdSocketPath,
			apiSockPath: apiSockPath,
			sourcePath:  sharedPath,
			debug:       clh.config.Debug,
			extraArgs:   clh.config.VirtioFSExtraArgs,
			startFn:     startInShimNS,
		}
		nd.setupShareDirFn = nd.setupPassthroughFS
		return nd, nil
	}

	// default: use virtiofsd
	return &virtiofsd{
		path:       clh.config.VirtioFSDaemon,
		sourcePath: sharedPath,
		socketPath: virtiofsdSocketPath,
		extraArgs:  clh.config.VirtioFSExtraArgs,
		cache:      clh.config.VirtioFSCache,
	}, nil
}

func (clh *cloudHypervisor) setupVirtiofsDaemon(ctx context.Context) error {
	if clh.config.SharedFS == config.NoSharedFS {
		return nil
	}

	if clh.config.SharedFS == config.Virtio9P {
		return errors.New("cloud-hypervisor only supports virtio based file sharing")
	}

	// virtioFS or virtioFsNydus
	clh.Logger().WithField("function", "setupVirtiofsDaemon").Info("Starting virtiofsDaemon")

	if clh.virtiofsDaemon == nil {
		return errors.New("Missing virtiofsDaemon configuration")
	}

	pid, err := clh.virtiofsDaemon.Start(ctx, func() {
		// AKS Pod Snapshot POC: in restore mode CLH spends ~30s paging in a
		// multi-GB memory file before its API server starts answering. If
		// virtiofsd disconnects during this window (which it does — its
		// vhost-user handshake doesn't tolerate the stall), the original
		// callback would call clh.StopVM, flip clh.stopped=1, and the very
		// next isClhRunning iteration in waitVMM would return
		// (false, nil) — surfacing as the misleading
		// "CLH is not running" error while CLH is in fact mid-restore and
		// healthy. Suppress the auto-stop in restore mode; if virtiofsd
		// genuinely needs to be respawned post-restore that's a follow-up.
		clh.Logger().Warn("AKS Pod Snapshot DEBUG: virtiofsd onQuit callback fired")
		if clh.config.RestoreFromSnapshot {
			clh.Logger().Warn("AKS Pod Snapshot: virtiofsd quit in restore mode — suppressing StopVM so CLH can finish memory page-in")
			return
		}
		clh.StopVM(ctx, false)
	})
	if err != nil {
		return err
	}
	clh.state.VirtiofsDaemonPid = pid

	return nil
}

func (clh *cloudHypervisor) stopVirtiofsDaemon(ctx context.Context) (err error) {
	if clh.state.VirtiofsDaemonPid == 0 {
		clh.Logger().Warn("The virtiofsd had stopped")
		return nil
	}

	err = clh.virtiofsDaemon.Stop(ctx)
	if err != nil {
		return err
	}

	clh.state.VirtiofsDaemonPid = 0

	return nil
}

func (clh *cloudHypervisor) loadVirtiofsDaemon(sharedPath string) (VirtiofsDaemon, error) {
	virtiofsdSocketPath, err := clh.virtioFsSocketPath(clh.id)
	if err != nil {
		return nil, err
	}

	return &virtiofsd{
		PID:        clh.state.VirtiofsDaemonPid,
		sourcePath: sharedPath,
		socketPath: virtiofsdSocketPath,
	}, nil
}

func (clh *cloudHypervisor) nydusdAPISocketPath(id string) (string, error) {
	return utils.BuildSocketPath(clh.config.VMStorePath, id, nydusdAPISock)
}

func (clh *cloudHypervisor) enableProtection() error {
	protection, err := availableGuestProtection()
	if err != nil {
		return err
	}

	switch protection {
	case tdxProtection:
		firmwarePath, err := clh.config.FirmwareAssetPath()
		if err != nil {
			return err
		}

		if firmwarePath == "" {
			return errors.New("Firmware path is not specified")
		}

		clh.vmconfig.Payload.SetFirmware(firmwarePath)

		if clh.vmconfig.Platform == nil {
			clh.vmconfig.Platform = chclient.NewPlatformConfig()
		}
		clh.vmconfig.Platform.SetTdx(true)

		return nil

	case sevProtection:
		return errors.New("SEV protection is not supported by Cloud Hypervisor")
	case snpProtection:
		return errors.New("SEV-SNP protection is not supported by Cloud Hypervisor")

	default:
		return errors.New("This system doesn't support Confidential Computing (Guest Protection)")
	}
}

func getNonUserDefinedKernelParams(rootfstype string, disableNvdimm bool, dax bool, debug bool, confidential bool, iommu bool, kernelVerityParams string) ([]Param, error) {
	params, err := GetKernelRootParams(rootfstype, disableNvdimm, dax, kernelVerityParams)
	if err != nil {
		return []Param{}, err
	}
	params = append(params, clhKernelParams...)

	if iommu {
		params = append(params, Param{"iommu", "pt"})
	}

	if !debug {
		// start the guest kernel with 'quiet' in non-debug mode
		params = append(params, Param{"quiet", ""})
		return params, nil
	}

	// In case of debug ...

	// Followed by extra debug parameters if debug enabled in configuration file
	if confidential {
		params = append(params, clhDebugConfidentialGuestKernelParams...)
	} else if runtime.GOARCH == "arm64" {
		params = append(params, clhArmDebugKernelParams...)
	} else {
		params = append(params, clhDebugKernelParams...)
	}
	params = append(params, clhDebugKernelParamsCommon...)
	return params, nil
}

// For cloudHypervisor this call only sets the internal structure up.
// The VM will be created and started through StartVM().
func (clh *cloudHypervisor) CreateVM(ctx context.Context, id string, network Network, hypervisorConfig *HypervisorConfig) error {
	clh.ctx = ctx

	span, newCtx := katatrace.Trace(clh.ctx, clh.Logger(), "CreateVM", clhTracingTags, map[string]string{"sandbox_id": clh.id})
	clh.ctx = newCtx
	defer span.End()

	if err := clh.setConfig(hypervisorConfig); err != nil {
		return err
	}

	clh.id = id
	clh.state.state = clhNotReady
	clh.devicesIds = make(map[string]string)
	clh.netDevicesFiles = make(map[string][]*os.File)

	clh.Logger().WithField("function", "CreateVM").Info("creating Sandbox")

	if clh.state.PID > 0 {
		clh.Logger().WithField("function", "CreateVM").Info("Sandbox already exist, loading from state")

		virtiofsDaemon, err := clh.loadVirtiofsDaemon(hypervisorConfig.SharedFS)
		if err != nil {
			return err
		}
		clh.virtiofsDaemon = virtiofsDaemon

		return nil
	}

	// No need to return an error from there since there might be nothing
	// to fetch if this is the first time the hypervisor is created.
	clh.Logger().WithField("function", "CreateVM").Info("Sandbox not found creating")

	// Create the VM config via the constructor to ensure default values are properly assigned
	clh.vmconfig = *chclient.NewVmConfig(*chclient.NewPayloadConfig())

	// Make sure the kernel path is valid
	kernelPath, err := clh.config.KernelAssetPath()
	if err != nil {
		return err
	}
	clh.vmconfig.Payload.SetKernel(kernelPath)

	clh.vmconfig.Platform = chclient.NewPlatformConfig()
	platform := clh.vmconfig.Platform
	platform.SetNumPciSegments(2)
	if clh.config.IOMMU {
		platform.SetIommuSegments([]int32{0})
	}

	if clh.config.ConfidentialGuest {
		if err := clh.enableProtection(); err != nil {
			return err
		}
	}

	// Create the VM memory config via the constructor to ensure default values are properly assigned
	clh.vmconfig.Memory = chclient.NewMemoryConfig(int64((utils.MemUnit(clh.config.MemorySize) * utils.MiB).ToBytes()))
	// Memory config shared is to be enabled when using vhost_user backends, ex. virtio-fs
	// or when using HugePages.
	// If such features are disabled, turn off shared memory config.
	if clh.config.SharedFS == config.NoSharedFS && !clh.config.HugePages {
		clh.vmconfig.Memory.Shared = func(b bool) *bool { return &b }(false)
	} else {
		clh.vmconfig.Memory.Shared = func(b bool) *bool { return &b }(true)
	}
	// Enable hugepages if needed
	clh.vmconfig.Memory.Hugepages = func(b bool) *bool { return &b }(clh.config.HugePages)
	// Opt the guest RAM mapping into KSM (madvise(MADV_MERGEABLE)) when the
	// kata config asks for it. The host kernel must have KSM enabled
	// independently for actual page sharing to happen.
	if clh.config.EnableMergeable {
		clh.vmconfig.Memory.SetMergeable(true)
	}
	if !clh.config.ConfidentialGuest {
		hotplugSize := clh.config.DefaultMaxMemorySize
		// OpenAPI only supports int64 values
		clh.vmconfig.Memory.HotplugSize = func(i int64) *int64 { return &i }(int64((utils.MemUnit(hotplugSize) * utils.MiB).ToBytes()))

		if clh.config.ReclaimGuestFreedMemory {
			// Create VM with a balloon config so we can enable free page reporting (size of the balloon can be set to zero)
			clh.vmconfig.Balloon = chclient.NewBalloonConfig(0)
			// Set the free page reporting flag for ballooning to be true
			clh.vmconfig.Balloon.SetFreePageReporting(true)
		}
	}

	// Set initial amount of cpu's for the virtual machine
	clh.vmconfig.Cpus = chclient.NewCpusConfig(int32(clh.config.NumVCPUs()), int32(clh.config.DefaultMaxVCPUs))

	if pathExists("/dev/mshv") {
		// The nested property is true by default, but is not supported yet on MSHV.
		clh.vmconfig.Cpus.SetNested(false)
	}

	disableNvdimm := true
	enableDax := false

	params, err := getNonUserDefinedKernelParams(hypervisorConfig.RootfsType, disableNvdimm, enableDax, clh.config.Debug, clh.config.ConfidentialGuest, clh.config.IOMMU, hypervisorConfig.KernelVerityParams)
	if err != nil {
		return err
	}
	// Followed by extra kernel parameters defined in the configuration file
	params = append(params, clh.config.KernelParams...)

	clh.vmconfig.Payload.SetCmdline(kernelParamsToString(params))

	// set random device generator to hypervisor
	clh.vmconfig.Rng = chclient.NewRngConfig(clh.config.EntropySource)
	clh.vmconfig.Rng.SetIommu(clh.config.IOMMU)

	// set the initial root/boot disk of hypervisor
	assetPath, assetType, err := clh.config.ImageOrInitrdAssetPath()
	if err != nil {
		return err
	}

	if assetType == types.ImageAsset {
		disk := chclient.NewDiskConfig()
		disk.Path = &assetPath
		disk.SetReadonly(true)
		disk.SetImageType("Raw")

		diskRateLimiterConfig := clh.getDiskRateLimiterConfig()
		if diskRateLimiterConfig != nil {
			disk.SetRateLimiterConfig(*diskRateLimiterConfig)
		}

		if clh.vmconfig.Disks != nil {
			*clh.vmconfig.Disks = append(*clh.vmconfig.Disks, *disk)
		} else {
			clh.vmconfig.Disks = &[]chclient.DiskConfig{*disk}
		}
	} else {
		// assetType == types.InitrdAsset
		clh.vmconfig.Payload.SetInitramfs(assetPath)
	}

	if clh.config.ConfidentialGuest {
		// Use HVC as the guest console only in debug mode, only
		// for Confidential Guests
		if clh.config.Debug {
			clh.vmconfig.Console = chclient.NewConsoleConfig(cctTTY)
		} else {
			clh.vmconfig.Console = chclient.NewConsoleConfig(cctOFF)
		}

		clh.vmconfig.Serial = chclient.NewConsoleConfig(cctOFF)
	} else {
		// Use serial port as the guest console only in debug mode,
		// so that we can gather early OS booting log
		if clh.config.Debug {
			clh.vmconfig.Serial = chclient.NewConsoleConfig(cctTTY)
		} else {
			clh.vmconfig.Serial = chclient.NewConsoleConfig(cctOFF)
		}

		clh.vmconfig.Console = chclient.NewConsoleConfig(cctOFF)
	}
	clh.vmconfig.Console.SetIommu(clh.config.IOMMU)

	cpu_topology := chclient.NewCpuTopology()
	cpu_topology.ThreadsPerCore = func(i int32) *int32 { return &i }(1)
	cpu_topology.CoresPerDie = func(i int32) *int32 { return &i }(int32(clh.config.DefaultMaxVCPUs))
	cpu_topology.DiesPerPackage = func(i int32) *int32 { return &i }(1)
	cpu_topology.Packages = func(i int32) *int32 { return &i }(1)
	clh.vmconfig.Cpus.Topology = cpu_topology

	// Overwrite the default value of HTTP API socket path for cloud hypervisor
	apiSocketPath, err := clh.apiSocketPath(id)
	if err != nil {
		clh.Logger().WithError(err).Info("Invalid api socket path for cloud-hypervisor")
		return err
	}
	clh.state.apiSocket = apiSocketPath

	cfg := chclient.NewConfiguration()
	cfg.HTTPClient = &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, path string) (net.Conn, error) {
				addr, err := net.ResolveUnixAddr("unix", clh.state.apiSocket)
				if err != nil {
					return nil, err
				}

				return net.DialUnix("unix", nil, addr)
			},
		},
	}

	clh.APIClient = &clhClientApi{
		ApiInternal: chclient.NewAPIClient(cfg).DefaultApi,
	}

	clh.virtiofsDaemon, err = clh.createVirtiofsDaemon(filepath.Join(GetSharePath(clh.id)))
	if err != nil {
		return err
	}

	if err := setupInitdata(clh, hypervisorConfig); err != nil {
		return err
	}

	return nil
}

// setupInitdata prepares and attaches the initdata disk if present.
func setupInitdata(clh *cloudHypervisor, hypervisorConfig *HypervisorConfig) error {
	if len(hypervisorConfig.Initdata) == 0 {
		return nil
	}

	if err := prepareInitdataMount(clh.Logger(), clh.id, hypervisorConfig); err != nil {
		return err
	}

	clh.addInitdataDisk(hypervisorConfig.InitdataImage)

	return nil
}

// StartVM will start the VMM and boot the virtual machine for the given sandbox.
func (clh *cloudHypervisor) StartVM(ctx context.Context, timeout int) error {
	span, ctx := katatrace.Trace(ctx, clh.Logger(), "StartVM", clhTracingTags, map[string]string{"sandbox_id": clh.id})
	defer span.End()

	clh.Logger().WithField("function", "StartVM").Info("starting Sandbox")

	vmPath := filepath.Join(clh.config.VMStorePath, clh.id)
	err := utils.MkdirAllWithInheritedOwner(vmPath, DirMode)
	if err != nil {
		return err
	}

	// This needs to be done as late as possible, just before launching
	// virtiofsd are executed by kata-runtime after this call, run with
	// the SELinux label. If these processes require privileged, we do
	// notwant to run them under confinement.
	if !clh.config.DisableSeLinux {

		if err := selinux.SetExecLabel(clh.config.SELinuxProcessLabel); err != nil {
			return err
		}
		defer selinux.SetExecLabel("")
	}

	err = clh.setupVirtiofsDaemon(ctx)
	if err != nil {
		return err
	}
	defer func() {
		if err == nil {
			return
		}

		if clh.config.SharedFS == config.VirtioFS || clh.config.SharedFS == config.VirtioFSNydus {
			if shutdownErr := clh.stopVirtiofsDaemon(ctx); shutdownErr != nil {
				clh.Logger().WithError(shutdownErr).Warn("error shutting down VirtiofsDaemon")
			}
		}
	}()

	err = clh.launchClh()
	if err != nil {
		return fmt.Errorf("failed to launch cloud-hypervisor: %q", err)
	}

	bootTimeout := clh.getClhAPITimeout()
	if bootTimeout < clhCreateAndBootVMMinimumTimeout {
		bootTimeout = clhCreateAndBootVMMinimumTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, bootTimeout*time.Second)
	defer cancel()

	// When restoring a sandbox from a previously taken snapshot, skip the
	// normal CreateVM+BootVM dance and ask Cloud Hypervisor to load state from
	// the snapshot directory. The freshly launched VMM will resume execution
	// from the captured point.
	if clh.config.RestoreFromSnapshot {
		if err := clh.restoreVM(ctx); err != nil {
			return err
		}
	} else {
		if err := clh.bootVM(ctx); err != nil {
			return err
		}
	}

	clh.state.state = clhReady
	return nil
}

// GetVMConsole builds the path of the console where we can read logs coming
// from the sandbox.
func (clh *cloudHypervisor) GetVMConsole(ctx context.Context, id string) (string, string, error) {
	clh.Logger().WithField("function", "GetVMConsole").WithField("id", id).Info("Get Sandbox Console")
	master, slave, err := console.NewPty()
	if err != nil {
		clh.Logger().WithError(err).Error("Error create pseudo tty")
		return consoleProtoPty, "", err
	}
	clh.console = master

	return consoleProtoPty, slave, nil
}

func (clh *cloudHypervisor) Disconnect(ctx context.Context) {
	clh.Logger().WithField("function", "Disconnect").Info("Disconnecting Sandbox Console")
}

func (clh *cloudHypervisor) GetThreadIDs(ctx context.Context) (VcpuThreadIDs, error) {

	clh.Logger().WithField("function", "GetThreadIDs").Info("get thread ID's")

	var vcpuInfo VcpuThreadIDs

	vcpuInfo.vcpus = make(map[int]int)

	getVcpus := func(pid int) (map[int]int, error) {
		vcpus := make(map[int]int)

		dir := fmt.Sprintf("/proc/%d/task", pid)
		files, err := os.ReadDir(dir)
		if err != nil {
			return vcpus, err
		}

		pattern, err := regexp.Compile(`^vcpu\d+$`)
		if err != nil {
			return vcpus, err
		}
		for _, file := range files {
			comm, err := os.ReadFile(fmt.Sprintf("%s/%s/comm", dir, file.Name()))
			if err != nil {
				return vcpus, err
			}
			pName := strings.TrimSpace(string(comm))
			if !pattern.MatchString(pName) {
				continue
			}

			cpuID := strings.TrimPrefix(pName, "vcpu")
			threadID := file.Name()

			k, err := strconv.Atoi(cpuID)
			if err != nil {
				return vcpus, err
			}
			v, err := strconv.Atoi(threadID)
			if err != nil {
				return vcpus, err
			}
			vcpus[k] = v
		}
		return vcpus, nil
	}

	if clh.state.PID == 0 {
		return vcpuInfo, nil
	}

	vcpus, err := getVcpus(clh.state.PID)
	if err != nil {
		return vcpuInfo, err
	}
	vcpuInfo.vcpus = vcpus

	return vcpuInfo, nil
}

func clhDriveIndexToID(i int) string {
	return "clh_drive_" + strconv.Itoa(i)
}

// Various cloud-hypervisor APIs report a PCI address in "BB:DD.F"
// form within the PciDeviceInfo struct.  This is a broken API,
// because there's no way clh can reliably know the guest side bdf for
// a device, since the bus number depends on how the guest firmware
// and/or kernel enumerates it.  They get away with it only because
// they don't use bridges, and so the bus is always 0.  Under that
// assumption convert a clh PciDeviceInfo into a PCI path
func clhPciInfoToPath(pciInfo chclient.PciDeviceInfo) (types.PciPath, error) {
	tokens := strings.Split(pciInfo.Bdf, ":")
	if len(tokens) != 3 || tokens[0] != "0000" || tokens[1] != "00" {
		return types.PciPath{}, fmt.Errorf("Unexpected PCI address %q from clh hotplug", pciInfo.Bdf)
	}

	tokens = strings.Split(tokens[2], ".")
	if len(tokens) != 2 || tokens[1] != "0" || len(tokens[0]) != 2 {
		return types.PciPath{}, fmt.Errorf("Unexpected PCI address %q from clh hotplug", pciInfo.Bdf)
	}

	return types.PciPathFromString(tokens[0])
}

// addInitdataDisk attaches initdataImage to the CLH VM as a read-only virtio-blk disk.
// It builds a DiskConfig (Readonly=true, VhostUser=false), sets one queue per vCPU
// with queue size 1024, applies Direct-I/O/IOMMU/rate-limiter from clh.config, and
// appends the disk to the pending VM config (no hotplug).
func (clh *cloudHypervisor) addInitdataDisk(initdataImage string) {
	disk := chclient.NewDiskConfig()
	disk.Path = &initdataImage

	ro := true
	disk.Readonly = &ro

	// Use virtio-blk
	vu := false
	disk.VhostUser = &vu

	// Reasonable queues; mirror your hotplug path
	queues := int32(clh.config.NumVCPUs())
	qsz := int32(1024)
	disk.NumQueues = &queues
	disk.QueueSize = &qsz

	// Honor runtime settings
	if clh.config.BlockDeviceCacheSet {
		disk.Direct = &clh.config.BlockDeviceCacheDirect
	}
	disk.SetIommu(clh.config.IOMMU)
	disk.SetImageType("Raw")

	if rl := clh.getDiskRateLimiterConfig(); rl != nil {
		disk.SetRateLimiterConfig(*rl)
	}

	if clh.vmconfig.Disks != nil {
		*clh.vmconfig.Disks = append(*clh.vmconfig.Disks, *disk)
	} else {
		clh.vmconfig.Disks = &[]chclient.DiskConfig{*disk}
	}
}

func (clh *cloudHypervisor) hotplugAddBlockDevice(drive *config.BlockDrive) error {
	if drive.Swap {
		return fmt.Errorf("cloudHypervisor doesn't support swap")
	}

	if clh.config.BlockDeviceDriver != config.VirtioBlock {
		return fmt.Errorf("incorrect hypervisor configuration on 'block_device_driver':"+
			" using '%v' but only support '%v'", clh.config.BlockDeviceDriver, config.VirtioBlock)
	}

	var err error

	cl := clh.client()
	ctx, cancel := context.WithTimeout(context.Background(), clhHotPlugAPITimeout*time.Second)
	defer cancel()

	driveID := clhDriveIndexToID(drive.Index)

	if drive.Pmem {
		return fmt.Errorf("pmem device hotplug not supported")
	}

	// Create the clh disk config via the constructor to ensure default values are properly assigned
	clhDisk := *chclient.NewDiskConfig()
	clhDisk.Path = &drive.File
	clhDisk.Readonly = &drive.ReadOnly
	clhDisk.SetImageType("Raw")
	clhDisk.VhostUser = func(b bool) *bool { return &b }(false)
	if clh.config.BlockDeviceCacheSet {
		clhDisk.Direct = &clh.config.BlockDeviceCacheDirect
	}

	queues := int32(clh.config.NumVCPUs())
	queueSize := int32(1024)
	clhDisk.NumQueues = &queues
	clhDisk.QueueSize = &queueSize
	clhDisk.SetIommu(clh.config.IOMMU)

	diskRateLimiterConfig := clh.getDiskRateLimiterConfig()
	if diskRateLimiterConfig != nil {
		clhDisk.SetRateLimiterConfig(*diskRateLimiterConfig)
	}

	pciInfo, _, err := cl.VmAddDiskPut(ctx, clhDisk)

	if err != nil {
		return fmt.Errorf("failed to hotplug block device %+v %s", drive, openAPIClientError(err))
	}

	clh.devicesIds[driveID] = pciInfo.GetId()
	drive.PCIPath, err = clhPciInfoToPath(pciInfo)

	return err
}

// coldPlugVFIODevice appends a VFIO device to the VM configuration so that it
// is present when the VM is created (before boot). Cloud Hypervisor's CreateVM
// API accepts a list of devices that are attached at VM creation time, which
// effectively provides cold-plug semantics — the guest sees the device on its
// PCI bus from the very first enumeration.
func (clh *cloudHypervisor) coldPlugVFIODevice(device *config.VFIODev) error {
	switch device.Type {
	case config.VFIOPCIDeviceNormalType, config.VFIOPCIDeviceMediatedType:
		// Supported PCI VFIO device types for Cloud Hypervisor.
	default:
		return fmt.Errorf("VFIO device %+v has unsupported type %v; only PCI VFIO devices are supported in Cloud Hypervisor", device, device.Type)
	}
	if strings.TrimSpace(device.SysfsDev) == "" {
		return fmt.Errorf("VFIO device %q has empty or invalid SysfsDev path", device.ID)
	}

	clh.Logger().WithFields(log.Fields{
		"device": device.ID,
		"sysfs":  device.SysfsDev,
		"bdf":    device.BDF,
	}).Info("Cold-plugging VFIO device into VM config")

	clhDevice := *chclient.NewDeviceConfig(device.SysfsDev)
	clhDevice.SetIommu(clh.config.IOMMU)
	clhDevice.SetId(device.ID)

	if clh.vmconfig.Devices != nil {
		*clh.vmconfig.Devices = append(*clh.vmconfig.Devices, clhDevice)
	} else {
		clh.vmconfig.Devices = &[]chclient.DeviceConfig{clhDevice}
	}

	// Track the device ID so that it can be referenced later (e.g. for removal).
	clh.devicesIds[device.ID] = device.ID

	return nil
}

func (clh *cloudHypervisor) hotPlugVFIODevice(device *config.VFIODev) error {
	cl := clh.client()
	ctx, cancel := context.WithTimeout(context.Background(), clhHotPlugAPITimeout*time.Second)
	defer cancel()

	// Create the clh device config via the constructor to ensure default values are properly assigned
	clhDevice := *chclient.NewDeviceConfig(device.SysfsDev)
	clhDevice.SetIommu(clh.config.IOMMU)
	pciInfo, _, err := cl.VmAddDevicePut(ctx, clhDevice)
	if err != nil {
		return fmt.Errorf("Failed to hotplug device %+v %s", device, openAPIClientError(err))
	}
	clh.devicesIds[device.ID] = pciInfo.GetId()

	// clh doesn't use bridges, so the PCI path is simply the slot
	// number of the device.  This will break if clh starts using
	// bridges (including PCI-E root ports), but so will the clh
	// API, since there's no way it can reliably predict a guest
	// Bdf when bridges are present.
	tokens := strings.Split(pciInfo.Bdf, ":")
	if len(tokens) != 3 || tokens[0] != "0000" || tokens[1] != "00" {
		return fmt.Errorf("Unexpected PCI address %q from clh hotplug", pciInfo.Bdf)
	}

	tokens = strings.Split(tokens[2], ".")
	if len(tokens) != 2 || tokens[1] != "0" || len(tokens[0]) != 2 {
		return fmt.Errorf("Unexpected PCI address %q from clh hotplug", pciInfo.Bdf)
	}

	if device.Type == config.VFIOAPDeviceMediatedType {
		return fmt.Errorf("VFIO device %+v is not PCI, only PCI is supported in Cloud Hypervisor", device)
	}

	device.GuestPciPath, err = types.PciPathFromString(tokens[0])

	return err
}

func (clh *cloudHypervisor) hotplugAddNetDevice(e Endpoint) error {
	err := clh.addNet(e)
	if err != nil {
		return err
	}

	pciInfo, err := clh.vmAddNetPut()

	if err != nil || len(pciInfo) == 0 {
		return err
	}

	// Set the pci Path for the network endpoint
	for i, netdev := range *clh.netDevices {
		if e.HardwareAddr() == *netdev.Mac {
			if i >= len(pciInfo) {
				continue
			}
			pciPath, err := clhPciInfoToPath(pciInfo[i])
			if err != nil {
				return err
			}
			e.SetPciPath(pciPath)
			break
		}
	}

	return nil
}

func (clh *cloudHypervisor) HotplugAddDevice(ctx context.Context, devInfo interface{}, devType DeviceType) (interface{}, error) {
	span, _ := katatrace.Trace(ctx, clh.Logger(), "HotplugAddDevice", clhTracingTags, map[string]string{"sandbox_id": clh.id})
	defer span.End()

	switch devType {
	case BlockDev:
		drive := devInfo.(*config.BlockDrive)
		return nil, clh.hotplugAddBlockDevice(drive)
	case VfioDev:
		device := devInfo.(*config.VFIODev)
		return nil, clh.hotPlugVFIODevice(device)
	case NetDev:
		device := devInfo.(Endpoint)
		return nil, clh.hotplugAddNetDevice(device)
	default:
		return nil, fmt.Errorf("cannot hotplug device: unsupported device type '%v'", devType)
	}

}

func (clh *cloudHypervisor) HotplugRemoveDevice(ctx context.Context, devInfo interface{}, devType DeviceType) (interface{}, error) {
	span, _ := katatrace.Trace(ctx, clh.Logger(), "HotplugRemoveDevice", clhTracingTags, map[string]string{"sandbox_id": clh.id})
	defer span.End()

	var deviceID string

	switch devType {
	case BlockDev:
		deviceID = clhDriveIndexToID(devInfo.(*config.BlockDrive).Index)
	case VfioDev:
		deviceID = devInfo.(*config.VFIODev).ID
	default:
		clh.Logger().WithFields(log.Fields{"devInfo": devInfo,
			"deviceType": devType}).Error("HotplugRemoveDevice: unsupported device")
		return nil, fmt.Errorf("Could not hot remove device: unsupported device: %v, type: %v",
			devInfo, devType)
	}

	cl := clh.client()
	ctx, cancel := context.WithTimeout(context.Background(), clhHotPlugAPITimeout*time.Second)
	defer cancel()

	originalDeviceID := clh.devicesIds[deviceID]
	remove := *chclient.NewVmRemoveDevice()
	remove.Id = &originalDeviceID
	_, err := cl.VmRemoveDevicePut(ctx, remove)
	if err != nil {
		err = fmt.Errorf("failed to hotplug remove (unplug) device %+v: %s", devInfo, openAPIClientError(err))
	}

	delete(clh.devicesIds, deviceID)
	return nil, err
}

func (clh *cloudHypervisor) HypervisorConfig() HypervisorConfig {
	return clh.config
}

func (clh *cloudHypervisor) ResizeMemory(ctx context.Context, reqMemMB uint32, memoryBlockSizeMB uint32, probe bool) (uint32, MemoryDevice, error) {

	// TODO: Add support for virtio-mem

	if probe {
		return 0, MemoryDevice{}, errors.New("probe memory is not supported for cloud-hypervisor")
	}

	if reqMemMB == 0 {
		// This is a corner case if requested to resize to 0 means something went really wrong.
		return 0, MemoryDevice{}, errors.New("Can not resize memory to 0")
	}

	info, err := clh.vmInfo()
	if err != nil {
		return 0, MemoryDevice{}, err
	}

	// HotplugSize can be nil in cases where Hotplug is not supported, as Cloud Hypervisor API
	// does *not* allow us to set 0 as the HotplugSize.
	maxHotplugSize := 0 * utils.Byte
	if info.Config.Memory.HotplugSize != nil {
		maxHotplugSize = utils.MemUnit(*info.Config.Memory.HotplugSize) * utils.Byte
	}

	if reqMemMB > uint32(maxHotplugSize.ToMiB()) {
		reqMemMB = uint32(maxHotplugSize.ToMiB())
	}

	currentMem := utils.MemUnit(info.Config.Memory.Size) * utils.Byte
	newMem := utils.MemUnit(reqMemMB) * utils.MiB

	// Early Check to verify if boot memory is the same as requested
	if currentMem == newMem {
		clh.Logger().WithField("memory", reqMemMB).Debugf("VM already has requested memory")
		return uint32(currentMem.ToMiB()), MemoryDevice{}, nil
	}

	if currentMem > newMem {
		clh.Logger().Warn("Remove memory is not supported, nothing to do")
		return uint32(currentMem.ToMiB()), MemoryDevice{}, nil
	}

	blockSize := utils.MemUnit(memoryBlockSizeMB) * utils.MiB
	hotplugSize := (newMem - currentMem).AlignMem(blockSize)

	// Update memory request to increase memory aligned block
	alignedRequest := currentMem + hotplugSize
	if newMem != alignedRequest {
		clh.Logger().WithFields(log.Fields{"request": newMem, "aligned-request": alignedRequest}).Debug("aligning VM memory request")
		newMem = alignedRequest
	}

	// Post-alignment checks
	if currentMem == newMem {
		clh.Logger().WithFields(log.Fields{"current-memory": currentMem, "new-memory": newMem}).Debug("VM already has requested memory(after alignment)")
		return uint32(currentMem.ToMiB()), MemoryDevice{}, nil
	}
	// Check for aligned memory exceeding max hotplug size
	if newMem > (utils.MemUnit(uint32(maxHotplugSize.ToMiB())) * utils.MiB) {
		newMem = utils.MemUnit(uint32(maxHotplugSize.ToMiB())) * utils.MiB
	}

	cl := clh.client()
	ctx, cancelResize := context.WithTimeout(ctx, clh.getClhAPITimeout()*time.Second)
	defer cancelResize()

	resize := *chclient.NewVmResize()
	// OpenApi does not support uint64, convert to int64
	resize.DesiredRam = func(i int64) *int64 { return &i }(int64(newMem.ToBytes()))
	clh.Logger().WithFields(log.Fields{"current-memory": currentMem, "new-memory": newMem}).Debug("updating VM memory")
	if _, err = cl.VmResizePut(ctx, resize); err != nil {
		clh.Logger().WithError(err).WithFields(log.Fields{"current-memory": currentMem, "new-memory": newMem}).Warnf("failed to update memory %s", openAPIClientError(err))
		err = fmt.Errorf("Failed to resize memory from %d to %d: %s", currentMem, newMem, openAPIClientError(err))
		return uint32(currentMem.ToMiB()), MemoryDevice{}, openAPIClientError(err)
	}

	return uint32(newMem.ToMiB()), MemoryDevice{SizeMB: int(hotplugSize.ToMiB())}, nil
}

func (clh *cloudHypervisor) ResizeVCPUs(ctx context.Context, reqVCPUs uint32) (currentVCPUs uint32, newVCPUs uint32, err error) {
	cl := clh.client()

	// Retrieve the number of current vCPUs via HTTP API
	info, err := clh.vmInfo()
	if err != nil {
		clh.Logger().WithField("function", "ResizeVCPUs").WithError(err).Info("[clh] vmInfo failed")
		return 0, 0, openAPIClientError(err)
	}

	currentVCPUs = uint32(info.Config.Cpus.BootVcpus)
	newVCPUs = currentVCPUs

	// Sanity Check
	if reqVCPUs == 0 {
		clh.Logger().WithField("function", "ResizeVCPUs").Debugf("Cannot resize vCPU to 0")
		return currentVCPUs, newVCPUs, fmt.Errorf("Cannot resize vCPU to 0")
	}
	if reqVCPUs > uint32(info.Config.Cpus.MaxVcpus) {
		clh.Logger().WithFields(log.Fields{
			"function":    "ResizeVCPUs",
			"reqVCPUs":    reqVCPUs,
			"clhMaxVCPUs": info.Config.Cpus.MaxVcpus,
		}).Warn("exceeding the 'clhMaxVCPUs' (resizing to 'clhMaxVCPUs')")

		reqVCPUs = uint32(info.Config.Cpus.MaxVcpus)
	}

	// Resize (hot-plug) vCPUs via HTTP API
	ctx, cancel := context.WithTimeout(ctx, clh.getClhAPITimeout()*time.Second)
	defer cancel()
	resize := *chclient.NewVmResize()
	resize.DesiredVcpus = func(i int32) *int32 { return &i }(int32(reqVCPUs))

	// Since the cloud hypervisor's resize vCPU is an asynchronous operation,
	// it's possible that the previous resize operation hasn't completed when
	// the request is sent, causing the current call to return an error. Therefore,
	// several retries can be performed to avoid this error.
	ret := retry.Do(func() error {

		if _, err = cl.VmResizePut(ctx, resize); err != nil {
			errMsg := err.Error()
			// see https://github.com/cloud-hypervisor/cloud-hypervisor/commit/d0225fe68fd14146bacc3be26f0b7e548ce9c239
			if !strings.Contains(errMsg, "Too Many Requests") {
				return retry.Unrecoverable(err)
			}
			return errors.Wrap(err, "[clh] VmResizePut failed")
		} else {
			return nil
		}
	},
		retry.Attempts(20),
		retry.LastErrorOnly(true),
		retry.Delay(20*time.Millisecond))

	newVCPUs = reqVCPUs

	return currentVCPUs, newVCPUs, ret
}

func (clh *cloudHypervisor) Cleanup(ctx context.Context) error {
	clh.Logger().WithField("function", "Cleanup").Info("Cleanup")
	return nil
}

func (clh *cloudHypervisor) PauseVM(ctx context.Context) error {
	clh.Logger().WithField("function", "PauseVM").Info("Pause Sandbox")

	cl := clh.client()

	ctx, cancel := context.WithTimeout(ctx, clh.getClhAPITimeout()*time.Second)
	defer cancel()

	if _, err := cl.PauseVM(ctx); err != nil {
		clh.Logger().WithError(err).Error("Failed to pause VM")
		return openAPIClientError(err)
	}
	return nil
}

// SaveVM persists the running VM's memory + device state to clh.config.SnapshotPath.
// The destination is communicated to Cloud Hypervisor via /vm.snapshot using the
// `file://` URL scheme. SaveVM expects PauseVM to have been called by the caller
// (mirrors qemu's SaveVM contract used by the templating factory).
//
// When SnapshotPath is empty (the templating-factory path that still relies on
// MemoryPath/DevicesStatePath), we fall back to the directory derived from
// MemoryPath so the existing factory flow keeps working untouched.
func (clh *cloudHypervisor) SaveVM() error {
	clh.Logger().WithField("function", "SaveVM").Info("Save Sandbox")

	cl := clh.client()

	dest, err := clh.snapshotDestinationDir()
	if err != nil {
		return err
	}

	// Cloud Hypervisor writes a directory of files (config.json, state.json,
	// memory-ranges-*) to the destination. Make sure it exists with sensible
	// perms — otherwise CLH errors out with a non-obvious filesystem error.
	if err := os.MkdirAll(dest, 0o700); err != nil {
		return fmt.Errorf("creating snapshot destination %q: %w", dest, err)
	}

	// Snapshotting may take many seconds for non-trivial VMs (CLH writes the
	// guest's full RAM to disk synchronously). Use a generous timeout —
	// getClhAPITimeout() returns 1s by default which is fine for most API
	// calls but far too tight for /vm.snapshot.
	const snapshotTimeoutSeconds = 120
	ctx, cancel := context.WithTimeout(context.Background(), snapshotTimeoutSeconds*time.Second)
	defer cancel()

	cfg := *chclient.NewVmSnapshotConfig()
	cfg.SetDestinationUrl("file://" + dest)

	if _, err := cl.VmSnapshotPut(ctx, cfg); err != nil {
		clh.Logger().WithError(err).Errorf("Failed to snapshot VM to %s", dest)
		return openAPIClientError(err)
	}
	return nil
}

func (clh *cloudHypervisor) ResumeVM(ctx context.Context) error {
	clh.Logger().WithField("function", "ResumeVM").Info("Resume Sandbox")

	cl := clh.client()

	ctx, cancel := context.WithTimeout(ctx, clh.getClhAPITimeout()*time.Second)
	defer cancel()

	if _, err := cl.ResumeVM(ctx); err != nil {
		clh.Logger().WithError(err).Error("Failed to resume VM")
		return openAPIClientError(err)
	}
	return nil
}

// SnapshotVM is the sandbox-level snapshot primitive. It writes the full VM
// state to destDir and is invoked by Sandbox.Snapshot (called in turn by the
// containerd-shim Checkpoint RPC). The caller is responsible for pausing and
// resuming the VM around this call.
//
// SnapshotVM mutates clh.config.SnapshotPath so that SaveVM (which the rest of
// the runtime calls) writes to the per-pod destination, then restores it on
// exit so subsequent templating-style flows are not affected.
//
// When clh.config.SnapshotCompression is set ("zstd"), the bulk
// memory-ranges-* blobs are compressed in place after CLH finishes writing.
// JSON files are left untouched. Compression is best-effort: a failure logs
// a warning and leaves the raw snapshot intact rather than failing the
// snapshot RPC.
func (clh *cloudHypervisor) SnapshotVM(ctx context.Context, destDir string) error {
	if destDir == "" {
		return fmt.Errorf("SnapshotVM: destDir is required")
	}

	prev := clh.config.SnapshotPath
	clh.config.SnapshotPath = destDir
	defer func() { clh.config.SnapshotPath = prev }()

	if err := clh.SaveVM(); err != nil {
		return err
	}

	if snapshotCompressionEnabled(clh.config.SnapshotCompression) {
		count, in, out, err := compressSnapshotMemory(destDir, clh.config.SnapshotCompressionLevel)
		if err != nil {
			// Compression failure is not fatal — the raw snapshot is
			// still usable. Surface the error in the log so operators
			// know to investigate, but keep the snapshot.
			clh.Logger().WithError(err).WithField("snapshot_dir", destDir).
				Warn("snapshot bulk-memory compression failed; snapshot retained uncompressed")
			return nil
		}
		if count > 0 {
			ratio := float64(in) / float64(out)
			clh.Logger().WithFields(map[string]interface{}{
				"snapshot_dir":  destDir,
				"files":         count,
				"bytes_raw":     in,
				"bytes_zstd":    out,
				"zstd_level":    clh.config.SnapshotCompressionLevel,
				"ratio":         fmt.Sprintf("%.2fx", ratio),
				"saved_bytes":   in - out,
			}).Info("Compressed snapshot bulk memory with zstd")
		}
	}
	return nil
}

// snapshotDestinationDir returns the on-disk directory used as both the
// destination of /vm.snapshot and the source of /vm.restore. Precedence:
//  1. clh.config.SnapshotPath if set (sandbox-level snapshot/restore flow)
//  2. directory of clh.config.MemoryPath (legacy templating-factory flow)
func (clh *cloudHypervisor) snapshotDestinationDir() (string, error) {
	if clh.config.SnapshotPath != "" {
		return clh.config.SnapshotPath, nil
	}
	if clh.config.MemoryPath != "" {
		return filepath.Dir(clh.config.MemoryPath), nil
	}
	return "", fmt.Errorf("neither SnapshotPath nor MemoryPath is set; cannot derive snapshot destination")
}

// restoreVM is the post-launchClh phase of restore. With Path A
// (launchClh handles `--restore` + `--net id=,fd=` directly), CLH performs
// CreateVM+BootVM internally during its own startup using the snapshot at
// clh.config.SnapshotPath, so this function only validates that the
// resulting VM is responsive. The heavy lifting moved to launchClh /
// buildRestoreArgs.
//
// Earlier POC iterations went via /vm.restore over OOB SCM_RIGHTS, but CLH
// silently rejects the inbound fds with "Ignoring FDs sent via the HTTP
// request body". The CLI-flag path is the only one that actually works
// against CLH v48.
func (clh *cloudHypervisor) restoreVM(ctx context.Context) error {
	clh.Logger().WithField("function", "restoreVM").Info("Verifying VM is responsive after --restore")

	cl := clh.client()
	pingCtx, cancel := context.WithTimeout(ctx, clh.getClhAPITimeout()*time.Second)
	defer cancel()
	if _, _, err := cl.VmmPingGet(pingCtx); err != nil {
		return fmt.Errorf("post-restore VmmPing: %w", err)
	}
	return nil
}

// buildRestoreArgs constructs the additional CLH command-line arguments and
// the inheritable file descriptors needed for `--restore`. Returns the args
// to append to launchClh's args slice, plus the *os.File handles to add to
// cmd.ExtraFiles (in the order they should be inherited; the first file
// becomes child fd 3, the next fd 4, etc).
//
// Steps:
//  1. Validate the snapshot dir + state.json + config.json.
//  2. If the snapshot was written compressed (memory-ranges-*.zst), stream
//     it into a sibling tmpdir of decompressed blobs and copies of the JSON
//     metadata; CLH /vm.restore will be pointed at the tmpdir. The tmpdir
//     is tracked on clh.restoreTmpDir for cleanup at stopSandbox time.
//  3. Rewrite the snapshot config so absolute paths to per-sandbox sockets
//     point at the new sandbox-id (CLH's restore code path opens these).
//  4. Read the snapshot's net device IDs in declaration order.
//  5. Match them up with this sandbox's already-prepared tap fds.
//  6. Emit `--restore source_url=file://...` plus one `--net id=,fd=` per
//     device, with fd numbers starting at 3.
func (clh *cloudHypervisor) buildRestoreArgs() ([]string, []*os.File, error) {
	canonicalSrc, err := clh.snapshotDestinationDir()
	if err != nil {
		return nil, nil, err
	}

	// Determine the on-disk directory CLH will actually read from. If the
	// snapshot is compressed we materialise a tmpdir of raw blobs +
	// JSON copies; otherwise CLH reads the canonical dir directly.
	src := canonicalSrc
	if compressed, cerr := snapshotIsCompressed(canonicalSrc); cerr != nil {
		return nil, nil, fmt.Errorf("probing snapshot compression: %w", cerr)
	} else if compressed {
		tmpDir, derr := decompressSnapshotForRestore(canonicalSrc)
		if derr != nil {
			return nil, nil, fmt.Errorf("decompressing snapshot for restore: %w", derr)
		}
		clh.Logger().WithFields(map[string]interface{}{
			"snapshot_src": canonicalSrc,
			"restore_src":  tmpDir,
		}).Info("Decompressed zstd snapshot into tmpdir for /vm.restore")
		clh.restoreTmpDir = tmpDir
		src = tmpDir
	}

	for _, fname := range []string{"state.json", "config.json"} {
		fp := filepath.Join(src, fname)
		if _, err := os.Stat(fp); err != nil {
			return nil, nil, fmt.Errorf("snapshot file %s not accessible: %w", fp, err)
		}
	}

	// Patch absolute /run/vc/vm/<old-id>/ paths inside the snapshot config
	// to point at this new sandbox's runtime dir. CLH binds vsock + connects
	// virtiofsd at these paths during /vm.restore.
	if err := clh.rewriteSnapshotConfigForNewSandbox(filepath.Join(src, "config.json")); err != nil {
		return nil, nil, fmt.Errorf("rewriting snapshot config: %w", err)
	}

	// POC workaround: patch state.json so CLH skips activate() on the
	// vhost-user-fs PCI device. Without this CLH hangs forever waiting
	// on a re-handshake with the freshly-spawned virtiofsd, which has
	// no prior FUSE session state. See clh_snapshot_restore_workaround.go
	// for the full diagnosis; this hook gets removed when Phase C6
	// (virtiofsd migration in the Rust runtime) lands.
	if err := rewriteSnapshotStateForNewSandbox(filepath.Join(src, "state.json")); err != nil {
		return nil, nil, fmt.Errorf("rewriting snapshot state: %w", err)
	}

	snapNets, err := readSnapshotNetIDs(filepath.Join(src, "config.json"))
	if err != nil {
		return nil, nil, fmt.Errorf("reading snapshot net ids: %w", err)
	}

	// Build the single `--restore` arg. The fd-bearing net devices go
	// inside it as `net_fds=[<id>@<fd>,...]`. Per CLH v48 `--help`:
	//
	//   --restore <restore>
	//     "source_url=<source_url>,prefault=on|off,
	//      net_fds=<list_of_net_ids_with_their_associated_fds>"
	//
	// IMPORTANT: do NOT also pass `--kernel` or `--net` separately on
	// restore. We tried that earlier and CLH silently took the
	// fresh-boot path (VmCreate + VmBoot in the log) instead of
	// restoring — net_fds inside `--restore` is the only path CLH's
	// restore code understands.
	restoreVal := "source_url=file://" + src
	if len(snapNets) == 0 {
		// Snapshot has no net devices — nothing else to plumb.
		return []string{"--restore", restoreVal}, nil, nil
	}

	hostFiles := flattenNetDeviceFiles(clh.netDevicesFiles)
	if len(hostFiles) == 0 {
		return nil, nil, fmt.Errorf("snapshot has %d net device(s) but the new sandbox provided no tap fds; "+
			"network namespace must be set up before launchClh in restore mode", len(snapNets))
	}

	var extraFiles []*os.File
	// CLH inherits ExtraFiles[0] as child fd 3, ExtraFiles[1] as fd 4, ...
	const firstChildFd = 3
	fileIdx := 0
	netFdEntries := make([]string, 0, len(snapNets))
	for _, n := range snapNets {
		if fileIdx+n.NumFds > len(hostFiles) {
			return nil, nil, fmt.Errorf("snapshot expects %d fd(s) for net device %q but only %d remain in host pool",
				n.NumFds, n.Id, len(hostFiles)-fileIdx)
		}
		// For each net device, emit one `<id>@<fd>` entry. For multi-fd
		// (multi-queue) net devices, kata-clh's default is 1 fd per
		// device; if a snapshot was taken with num_queues>1 a future
		// extension will need `<id>@<fd1>:<fd2>` syntax (CLH supports
		// it). For the POC we only emit one fd per device.
		for i := 0; i < n.NumFds; i++ {
			extraFiles = append(extraFiles, hostFiles[fileIdx+i])
			netFdEntries = append(netFdEntries,
				fmt.Sprintf("%s@%d", n.Id, firstChildFd+len(extraFiles)-1))
		}
		fileIdx += n.NumFds
	}
	restoreVal += ",net_fds=[" + strings.Join(netFdEntries, ",") + "]"

	return []string{"--restore", restoreVal}, extraFiles, nil
}

// snapshotNetID is the (id, num_fds) tuple extracted from a CLH snapshot's
// config.json `net` array, in declaration order.
type snapshotNetID struct {
	Id     string
	NumFds int
}

// readSnapshotNetIDs parses the `net` section of a CLH snapshot config.json
// and returns the device ID + fd-count for each, in declaration order. CLH's
// /vm.restore needs these so it can re-attach the new sandbox's tap fds.
func readSnapshotNetIDs(configPath string) ([]snapshotNetID, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, err
	}
	var doc struct {
		Net []struct {
			Id  string `json:"id"`
			Fds []int  `json:"fds"`
		} `json:"net"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse %s: %w", configPath, err)
	}
	out := make([]snapshotNetID, 0, len(doc.Net))
	for _, n := range doc.Net {
		// `fds: [-1]` in the snapshot means 1 expected fd; CLH writes the
		// length of the original fds slice but blanks the values.
		out = append(out, snapshotNetID{Id: n.Id, NumFds: len(n.Fds)})
	}
	return out, nil
}

// flattenNetDeviceFiles walks the net-device file map in deterministic MAC
// order so two restores against the same sandbox produce the same fd ordering.
func flattenNetDeviceFiles(m map[string][]*os.File) []*os.File {
	macs := make([]string, 0, len(m))
	for mac := range m {
		macs = append(macs, mac)
	}
	sort.Strings(macs)
	var out []*os.File
	for _, mac := range macs {
		out = append(out, m[mac]...)
	}
	return out
}

// rewriteSnapshotConfigForNewSandbox patches the snapshot's config.json in
// place, swapping the original sandbox's runtime directory for the new
// sandbox's. CLH bakes absolute paths for sockets it needs to bind (vsock /
// clh.sock) and connect (virtiofsd.sock) into the snapshot config. Without
// this rewrite CLH on /vm.restore tries to bind/connect at the old path
// (which doesn't exist for the new sandbox) and either crashes or hangs.
//
// The substitution is purely textual on a "/run/vc/vm/<old-id>/" prefix; this
// covers every per-sandbox-dir socket CLH writes. The state.json holds opaque
// CRIU memory data and does not need rewriting.
func (clh *cloudHypervisor) rewriteSnapshotConfigForNewSandbox(configPath string) error {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return err
	}

	// Find the original sandbox's runtime dir from the FIRST per-sandbox path
	// we recognise. Both the vsock and virtiofs sockets sit directly under
	// /run/vc/vm/<sandbox-id>/.
	const vmDirPrefix = "/run/vc/vm/"
	idx := bytes.Index(data, []byte(vmDirPrefix))
	if idx < 0 {
		// Snapshot has no per-sandbox sockets — nothing to do.
		return nil
	}
	rest := data[idx+len(vmDirPrefix):]
	end := bytes.IndexAny(rest, "/\"")
	if end <= 0 {
		return fmt.Errorf("malformed sandbox-id in snapshot config at %s", configPath)
	}
	oldID := string(rest[:end])
	if oldID == clh.id {
		// Snapshot was already taken on this sandbox — nothing to do.
		return nil
	}

	clh.Logger().WithField("old_sandbox_id", oldID).WithField("new_sandbox_id", clh.id).
		Info("Rewriting snapshot config to replace old sandbox-id with new")

	patched := bytes.ReplaceAll(data,
		[]byte(vmDirPrefix+oldID+"/"),
		[]byte(vmDirPrefix+clh.id+"/"))

	// Write back atomically (write to temp + rename) so a partial write can't
	// corrupt the snapshot.
	tmp := configPath + ".tmp"
	if err := os.WriteFile(tmp, patched, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, configPath)
}

// StopVM will stop the Sandbox's VM.
func (clh *cloudHypervisor) StopVM(ctx context.Context, waitOnly bool) (err error) {
	clh.mu.Lock()
	defer func() {
		if err == nil {
			atomic.StoreInt32(&clh.stopped, 1)
		}
		clh.mu.Unlock()
	}()
	span, _ := katatrace.Trace(ctx, clh.Logger(), "StopVM", clhTracingTags, map[string]string{"sandbox_id": clh.id})
	defer span.End()
	clh.Logger().WithField("function", "StopVM").Info("Stop Sandbox")
	if atomic.LoadInt32(&clh.stopped) != 0 {
		clh.Logger().Info("Already stopped")
		return nil
	}

	return clh.terminate(ctx, waitOnly)
}

func (clh *cloudHypervisor) fromGrpc(ctx context.Context, hypervisorConfig *HypervisorConfig, j []byte) error {
	return errors.New("cloudHypervisor is not supported by VM cache")
}

func (clh *cloudHypervisor) toGrpc(ctx context.Context) ([]byte, error) {
	return nil, errors.New("cloudHypervisor is not supported by VM cache")
}

func (clh *cloudHypervisor) Save() (s hv.HypervisorState) {
	s.Pid = clh.state.PID
	s.Type = string(ClhHypervisor)
	s.VirtiofsDaemonPid = clh.state.VirtiofsDaemonPid
	s.APISocket = clh.state.apiSocket
	return
}

func (clh *cloudHypervisor) Load(s hv.HypervisorState) {
	clh.state.PID = s.Pid
	clh.state.VirtiofsDaemonPid = s.VirtiofsDaemonPid
	clh.state.apiSocket = s.APISocket
}

// Check is the implementation of Check from the Hypervisor interface.
// Check if the VMM API is working.

func (clh *cloudHypervisor) Check() error {
	// Use a long timeout to check if the VMM is running:
	// Check is used by the monitor thread(a background thread). If the
	// monitor thread calls Check() during the Container boot, it will take
	// longer than usual specially if there is a hot-plug request in progress.
	running, err := clh.isClhRunning(10)
	if !running {
		return fmt.Errorf("clh is not running: %s", err)
	}
	return err
}

func (clh *cloudHypervisor) GetPids() []int {
	return []int{clh.state.PID}
}

func (clh *cloudHypervisor) GetVirtioFsPid() *int {
	return &clh.state.VirtiofsDaemonPid
}

func (clh *cloudHypervisor) AddDevice(ctx context.Context, devInfo interface{}, devType DeviceType) error {
	span, _ := katatrace.Trace(ctx, clh.Logger(), "AddDevice", clhTracingTags, map[string]string{"sandbox_id": clh.id})
	defer span.End()

	var err error

	switch v := devInfo.(type) {
	case Endpoint:
		if err := clh.addNet(v); err != nil {
			return err
		}
	case types.HybridVSock:
		clh.addVSock(defaultGuestVSockCID, v.UdsPath)
	case types.Volume:
		err = clh.addVolume(v)
	case config.VFIODev:
		err = clh.coldPlugVFIODevice(&v)
	default:
		clh.Logger().WithField("function", "AddDevice").Warnf("Add device of type %v is not supported.", v)
		return fmt.Errorf("Not implemented support for %s", v)
	}

	return err
}

//###########################################################################
//
// Local helper methods related to the hypervisor interface implementation
//
//###########################################################################

func (clh *cloudHypervisor) Logger() *log.Entry {
	return hvLogger.WithField("subsystem", "cloudHypervisor")
}

// Adds all capabilities supported by cloudHypervisor implementation of hypervisor interface
func (clh *cloudHypervisor) Capabilities(ctx context.Context) types.Capabilities {
	span, _ := katatrace.Trace(ctx, clh.Logger(), "Capabilities", clhTracingTags, map[string]string{"sandbox_id": clh.id})
	defer span.End()

	clh.Logger().WithField("function", "Capabilities").Info("get Capabilities")
	var caps types.Capabilities
	if clh.config.SharedFS != config.NoSharedFS {
		caps.SetFsSharingSupport()
	}
	caps.SetBlockDeviceHotplugSupport()
	caps.SetNetworkDeviceHotplugSupported()
	return caps
}

func (clh *cloudHypervisor) terminate(ctx context.Context, waitOnly bool) (err error) {
	span, _ := katatrace.Trace(ctx, clh.Logger(), "terminate", clhTracingTags, map[string]string{"sandbox_id": clh.id})
	defer span.End()

	pid := clh.state.PID
	pidRunning := pid != 0

	defer func() {
		clh.Logger().Debug("Cleanup VM")
		if err1 := clh.cleanupVM(true); err1 != nil {
			clh.Logger().WithError(err1).Error("failed to cleanupVM")
		}
	}()

	clh.Logger().Debug("Stopping Cloud Hypervisor")

	if pidRunning && !waitOnly {
		clhRunning, _ := clh.isClhRunning(uint(clh.getClhStopSandboxTimeout()))
		if clhRunning {
			ctx, cancel := context.WithTimeout(context.Background(), clh.getClhStopSandboxTimeout()*time.Second)
			defer cancel()
			if _, err = clh.client().ShutdownVMM(ctx); err != nil {
				return err
			}
		}
	}

	if err = utils.WaitLocalProcess(pid, uint(clh.getClhStopSandboxTimeout()), syscall.Signal(0), clh.Logger()); err != nil {
		return err
	}

	if clh.config.SharedFS == config.VirtioFS || clh.config.SharedFS == config.VirtioFSNydus {
		clh.Logger().Debug("stop virtiofsDaemon")

		if err = clh.stopVirtiofsDaemon(ctx); err != nil {
			clh.Logger().WithError(err).Error("failed to stop virtiofsDaemon")
		}
	}

	return
}

func (clh *cloudHypervisor) reset() {
	clh.state.reset()
}

func (clh *cloudHypervisor) GenerateSocket(id string) (interface{}, error) {
	udsPath, err := clh.vsockSocketPath(id)
	if err != nil {
		clh.Logger().Info("Can't generate socket path for cloud-hypervisor")
		return types.HybridVSock{}, err
	}

	return types.HybridVSock{
		UdsPath: udsPath,
		Port:    uint32(vSockPort),
	}, nil
}

func (clh *cloudHypervisor) virtioFsSocketPath(id string) (string, error) {
	return utils.BuildSocketPath(clh.config.VMStorePath, id, virtioFsSocket)
}

func (clh *cloudHypervisor) vsockSocketPath(id string) (string, error) {
	return utils.BuildSocketPath(clh.config.VMStorePath, id, clhSocket)
}

func (clh *cloudHypervisor) apiSocketPath(id string) (string, error) {
	return utils.BuildSocketPath(clh.config.VMStorePath, id, clhAPISocket)
}

func (clh *cloudHypervisor) waitVMM(timeout uint) error {
	clhRunning, err := clh.isClhRunning(timeout)
	if err != nil {
		return err
	}

	if !clhRunning {
		return fmt.Errorf("CLH is not running")
	}

	return nil
}

func (clh *cloudHypervisor) clhPath() (string, error) {
	p, err := clh.config.HypervisorAssetPath()
	if err != nil {
		return "", err
	}

	if p == "" {
		p = defaultClhPath
	}

	if _, err = os.Stat(p); os.IsNotExist(err) {
		return "", fmt.Errorf("Cloud-Hypervisor path (%s) does not exist", p)
	}

	return p, err
}

func (clh *cloudHypervisor) launchClh() error {

	clh.state.PID = -1

	clhPath, err := clh.clhPath()
	if err != nil {
		return err
	}

	args := []string{cscAPIsocket, clh.state.apiSocket}
	if clh.config.Debug && clh.config.HypervisorLoglevel > 0 {
		// Cloud hypervisor log levels
		// 'v' occurrences increase the level
		//0 =>  Warn
		//1 =>  Info
		//2 =>  Debug
		//3+ => Trace
		// Use Info, the CI runs with debug enabled
		// a high level of logging increases the boot time
		// and in a nested environment this could increase
		// the chances to fail because agent is not
		// ready on time.
		//
		// Note that for debugging CLH boot failures, the Info level
		// should be sufficient: Debug level generates so many
		// messages it floods the output stream to the extent that it
		// is almost impossible to view the guest kernel and userland
		// output. For further details, see the discussion on:
		//
		//   https://github.com/kata-containers/kata-containers/pull/2751
		verbosityString := fmt.Sprintf("-%s", strings.Repeat("v", int(clh.config.HypervisorLoglevel)))
		args = append(args, verbosityString)
	}

	// Enable the `seccomp` feature from Cloud Hypervisor by default
	// Disable it only when requested by users for debugging purposes
	if clh.config.DisableSeccomp {
		args = append(args, "--seccomp", "false")
	}

	// AKS Pod Snapshot POC — Path A: when restoring a sandbox-level snapshot,
	// extend the CLH CLI with `--restore source_url=...` and one
	// `--net id=<id>,fd=<n>` per net device the snapshot expects. CLH does
	// CreateVM+BootVM internally as part of `--restore` (no follow-up HTTP
	// call needed), but it requires net device fds to be inherited at
	// process start time — POSTing them via OOB on /vm.restore is silently
	// rejected (CLH logs "Ignoring FDs sent via the HTTP request body").
	//
	// extraFiles holds the *os.File handles for the new sandbox's tap fds
	// in the order CLH should inherit them; ExtraFiles[0] -> child fd 3,
	// ExtraFiles[1] -> child fd 4, etc.
	var extraFiles []*os.File
	if clh.config.RestoreFromSnapshot {
		clh.Logger().Warn("AKS Pod Snapshot: launchClh is in restore mode")
		restoreArgs, restoreFiles, err := clh.buildRestoreArgs()
		if err != nil {
			clh.Logger().WithError(err).Warn("AKS Pod Snapshot: buildRestoreArgs failed")
			return fmt.Errorf("building restore args: %w", err)
		}
		args = append(args, restoreArgs...)
		extraFiles = restoreFiles
		clh.Logger().Warnf("AKS Pod Snapshot: restore args=%q extra_fds=%d", strings.Join(restoreArgs, " "), len(extraFiles))
	} else {
		clh.Logger().Warn("AKS Pod Snapshot: launchClh in NORMAL (non-restore) mode")
	}

	clh.Logger().WithField("path", clhPath).Info()
	clh.Logger().WithField("args", strings.Join(args, " ")).Info()
	clh.Logger().Warnf("AKS Pod Snapshot DEBUG: full args = [%s] %s", clhPath, strings.Join(args, " "))

	cmdHypervisor := exec.Command(clhPath, args...)
	if len(extraFiles) > 0 {
		cmdHypervisor.ExtraFiles = extraFiles
	}
	if clh.config.Debug {
		cmdHypervisor.Env = os.Environ()
		cmdHypervisor.Env = append(cmdHypervisor.Env, "RUST_BACKTRACE=full")
		if clh.console != nil {
			cmdHypervisor.Stderr = clh.console
			cmdHypervisor.Stdout = clh.console
		}
	}
	cmdHypervisor.Stderr = cmdHypervisor.Stdout

	// AKS Pod Snapshot POC: always capture CLH stdout+stderr to a per-VM log
	// file so restore failures (which historically only surface as
	// "unexpected EOF" on the API socket) leave a forensic trail. The log
	// file lives in the same dir as the API socket.
	if clh.state.apiSocket != "" {
		if logFile, ferr := os.Create(filepath.Join(filepath.Dir(clh.state.apiSocket), "clh.log")); ferr == nil {
			cmdHypervisor.Stdout = logFile
			cmdHypervisor.Stderr = logFile
		}
	}

	attr := syscall.SysProcAttr{}
	attr.Credential = &syscall.Credential{
		Uid:    clh.config.Uid,
		Gid:    clh.config.Gid,
		Groups: clh.config.Groups,
	}
	cmdHypervisor.SysProcAttr = &attr

	err = utils.StartCmd(cmdHypervisor)
	if err != nil {
		return err
	}

	clh.state.PID = cmdHypervisor.Process.Pid

	// AKS Pod Snapshot POC: in restore mode CLH is busy slurping the
	// snapshot's memory-ranges file from disk before its API server starts
	// answering vmm.ping. Use a much longer wait than clhTimeout (10s).
	waitTimeout := uint(clhTimeout)
	if clh.config.RestoreFromSnapshot {
		waitTimeout = 600
	}
	if err := clh.waitVMM(waitTimeout); err != nil {
		clh.Logger().WithError(err).Warn("cloud-hypervisor init failed")
		return err
	}

	return nil
}

//###########################################################################
//
// Cloud-hypervisor CLI builder
//
//###########################################################################

const (
	cctOFF string = "Off"
	cctTTY string = "Tty"
)

const (
	cscAPIsocket string = "--api-socket"
)

//****************************************
// The kernel command line
//****************************************

func kernelParamsToString(params []Param) string {

	var paramBuilder strings.Builder
	for _, p := range params {
		paramBuilder.WriteString(p.Key)
		if len(p.Value) > 0 {
			paramBuilder.WriteString("=")
			paramBuilder.WriteString(p.Value)
		}
		paramBuilder.WriteString(" ")
	}
	return strings.TrimSpace(paramBuilder.String())
}

// ****************************************
// API calls
// ****************************************
func (clh *cloudHypervisor) isClhRunning(timeout uint) (bool, error) {

	pid := clh.state.PID

	if atomic.LoadInt32(&clh.stopped) != 0 {
		clh.Logger().Warnf("AKS Pod Snapshot DEBUG: isClhRunning: clh.stopped flag set on entry, returning (false, nil) (pid=%d)", pid)
		return false, nil
	}

	timeStart := time.Now()
	cl := clh.client()
	iter := 0
	lastLog := timeStart
	for {
		iter++
		waitedPid, err := syscall.Wait4(pid, nil, syscall.WNOHANG, nil)
		if waitedPid == pid && err == nil {
			clh.Logger().Warnf("AKS Pod Snapshot DEBUG: isClhRunning: Wait4 reaped pid=%d after %.2fs (iter=%d) — CLH process exited", pid, time.Since(timeStart).Seconds(), iter)
			return false, nil
		}

		if atomic.LoadInt32(&clh.stopped) != 0 {
			clh.Logger().Warnf("AKS Pod Snapshot DEBUG: isClhRunning: clh.stopped flag flipped mid-loop after %.2fs (iter=%d) — likely virtiofsd onQuit fired", time.Since(timeStart).Seconds(), iter)
			return false, nil
		}

		err = syscall.Kill(pid, syscall.Signal(0))
		if err != nil {
			clh.Logger().WithError(err).Warnf("AKS Pod Snapshot DEBUG: isClhRunning: kill(0) on pid=%d failed after %.2fs (iter=%d) — process gone", pid, time.Since(timeStart).Seconds(), iter)
			return false, nil
		}
		ctx, cancel := context.WithTimeout(context.Background(), clh.getClhAPITimeout()*time.Second)
		_, _, err = cl.VmmPingGet(ctx)
		cancel()
		if err == nil {
			clh.Logger().Warnf("AKS Pod Snapshot DEBUG: isClhRunning: VmmPingGet succeeded after %.2fs (iter=%d)", time.Since(timeStart).Seconds(), iter)
			return true, nil
		}

		// Heartbeat log every 5s to confirm the loop is still polling and
		// not silently exiting via some unexpected path.
		if time.Since(lastLog).Seconds() >= 5 {
			clh.Logger().Warnf("AKS Pod Snapshot DEBUG: isClhRunning: still polling pid=%d at %.2fs (iter=%d) timeout=%ds last_err=%v", pid, time.Since(timeStart).Seconds(), iter, timeout, err)
			lastLog = time.Now()
		}

		if time.Since(timeStart).Seconds() > float64(timeout) {
			clh.Logger().Warnf("AKS Pod Snapshot DEBUG: isClhRunning: hit outer timeout=%ds after %d iterations", timeout, iter)
			return false, fmt.Errorf("Failed to connect to API (timeout %ds): %s", timeout, openAPIClientError(err))
		}

		time.Sleep(time.Duration(10) * time.Millisecond)
	}

}

func (clh *cloudHypervisor) client() clhClient {
	return clh.APIClient
}

func openAPIClientError(err error) error {

	if err == nil {
		return nil
	}

	reason := ""
	if apierr, ok := err.(chclient.GenericOpenAPIError); ok {
		reason = string(apierr.Body())
	}

	return fmt.Errorf("error: %v reason: %s", err, reason)
}

func (clh *cloudHypervisor) vmAddNetPut() ([]chclient.PciDeviceInfo, error) {
	return vmAddNetPutRequest(clh)
}

func (clh *cloudHypervisor) bootVM(ctx context.Context) error {

	cl := clh.client()

	if clh.config.Debug {
		bodyBuf, err := json.Marshal(clh.vmconfig)
		if err != nil {
			return err
		}
		clh.Logger().WithField("body", string(bodyBuf)).Debug("VM config")
	}
	_, err := cl.CreateVM(ctx, clh.vmconfig)
	if err != nil {
		return openAPIClientError(err)
	}

	info, err := clh.vmInfo()
	if err != nil {
		return err
	}

	clh.Logger().Debugf("VM state after create: %#v", info)

	if info.State != clhStateCreated {
		return fmt.Errorf("VM state is not 'Created' after 'CreateVM'")
	}

	_, err = clh.vmAddNetPut()
	if err != nil {
		return err
	}

	clh.Logger().Debug("Booting VM")
	_, err = cl.BootVM(ctx)
	if err != nil {
		return openAPIClientError(err)
	}

	info, err = clh.vmInfo()
	if err != nil {
		return err
	}

	clh.Logger().Debugf("VM state after boot: %#v", info)

	if info.State != clhStateRunning {
		return fmt.Errorf("VM state is not 'Running' after 'BootVM'")
	}

	return nil
}

func (clh *cloudHypervisor) addVSock(cid int64, path string) {
	clh.Logger().WithFields(log.Fields{
		"path": path,
		"cid":  cid,
	}).Info("Adding HybridVSock")

	clh.vmconfig.Vsock = chclient.NewVsockConfig(cid, path)
	clh.vmconfig.Vsock.SetIommu(clh.config.IOMMU)
}

func (clh *cloudHypervisor) getRateLimiterConfig(bwSize, bwOneTimeBurst, opsSize, opsOneTimeBurst int64) *chclient.RateLimiterConfig {
	if bwSize == 0 && opsSize == 0 {
		return nil
	}

	rateLimiterConfig := chclient.NewRateLimiterConfig()

	if bwSize != 0 {
		bwTokenBucket := chclient.NewTokenBucket(bwSize, int64(utils.DefaultRateLimiterRefillTimeMilliSecs))

		if bwOneTimeBurst != 0 {
			bwTokenBucket.SetOneTimeBurst(bwOneTimeBurst)
		}

		rateLimiterConfig.SetBandwidth(*bwTokenBucket)
	}

	if opsSize != 0 {
		opsTokenBucket := chclient.NewTokenBucket(opsSize, int64(utils.DefaultRateLimiterRefillTimeMilliSecs))

		if opsOneTimeBurst != 0 {
			opsTokenBucket.SetOneTimeBurst(opsOneTimeBurst)
		}

		rateLimiterConfig.SetOps(*opsTokenBucket)
	}

	return rateLimiterConfig
}

func (clh *cloudHypervisor) getNetRateLimiterConfig() *chclient.RateLimiterConfig {
	return clh.getRateLimiterConfig(
		int64(utils.RevertBytes(uint64(clh.config.NetRateLimiterBwMaxRate/8))),
		int64(utils.RevertBytes(uint64(clh.config.NetRateLimiterBwOneTimeBurst/8))),
		clh.config.NetRateLimiterOpsMaxRate,
		clh.config.NetRateLimiterOpsOneTimeBurst)
}

func (clh *cloudHypervisor) getDiskRateLimiterConfig() *chclient.RateLimiterConfig {
	return clh.getRateLimiterConfig(
		int64(utils.RevertBytes(uint64(clh.config.DiskRateLimiterBwMaxRate/8))),
		int64(utils.RevertBytes(uint64(clh.config.DiskRateLimiterBwOneTimeBurst/8))),
		clh.config.DiskRateLimiterOpsMaxRate,
		clh.config.DiskRateLimiterOpsOneTimeBurst)
}

func (clh *cloudHypervisor) addNet(e Endpoint) error {
	clh.Logger().WithField("endpoint", e).Debugf("Adding Endpoint of type %v", e.Type())

	mac := e.HardwareAddr()
	netPair := e.NetworkPair()
	if netPair == nil {
		return errors.New("net Pair to be added is nil, needed to get TAP file descriptors")
	}

	if len(netPair.VMFds) == 0 {
		return errors.New("The file descriptors for the network pair are not present")
	}
	clh.netDevicesFiles[mac] = netPair.VMFds

	netRateLimiterConfig := clh.getNetRateLimiterConfig()

	net := chclient.NewNetConfig()
	net.Mac = &mac
	if netRateLimiterConfig != nil {
		net.SetRateLimiterConfig(*netRateLimiterConfig)
	}
	net.SetIommu(clh.config.IOMMU)

	if clh.netDevices != nil {
		*clh.netDevices = append(*clh.netDevices, *net)
	} else {
		clh.netDevices = &[]chclient.NetConfig{*net}
	}

	clh.Logger().Infof("Storing the Cloud Hypervisor network configuration: %+v", net)

	return nil
}

// Add shared Volume using virtiofs
func (clh *cloudHypervisor) addVolume(volume types.Volume) error {
	if clh.config.SharedFS != config.VirtioFS && clh.config.SharedFS != config.VirtioFSNydus {
		return fmt.Errorf("shared fs method not supported %s", clh.config.SharedFS)
	}

	vfsdSockPath, err := clh.virtioFsSocketPath(clh.id)
	if err != nil {
		return err
	}

	// numQueues and queueSize are required, let's use the
	// default values defined by cloud-hypervisor
	numQueues := int32(1)
	queueSize := int32(1024)
	if clh.config.VirtioFSQueueSize != 0 {
		queueSize = int32(clh.config.VirtioFSQueueSize)
	}

	fs := chclient.NewFsConfig(volume.MountTag, vfsdSockPath, numQueues, queueSize)
	fs.SetPciSegment(1)
	clh.vmconfig.Fs = &[]chclient.FsConfig{*fs}

	clh.Logger().Debug("Adding share volume to hypervisor: ", volume.MountTag)
	return nil
}

// cleanupVM will remove generated files and directories related with the virtual machine
func (clh *cloudHypervisor) cleanupVM(force bool) error {

	if clh.id == "" {
		return errors.New("Hypervisor ID is empty")
	}

	clh.Logger().Debug("removing vm sockets")

	// Remove the per-restore decompress tmpdir, if any. This was created
	// in buildRestoreArgs to materialise zstd-compressed snapshot blobs
	// for CLH; the canonical (compressed) snapshot dir lives elsewhere
	// and is not touched here.
	if clh.restoreTmpDir != "" {
		if err := os.RemoveAll(clh.restoreTmpDir); err != nil {
			clh.Logger().WithError(err).WithField("path", clh.restoreTmpDir).
				Warn("removing restore decompress tmpdir failed")
		}
		clh.restoreTmpDir = ""
	}

	path, err := clh.vsockSocketPath(clh.id)
	if err == nil {
		if err := os.Remove(path); err != nil {
			clh.Logger().WithError(err).WithField("path", path).Warn("removing vm socket failed")
		}
	}

	// Cleanup vm path
	dir := filepath.Join(clh.config.VMStorePath, clh.id)

	// If it's a symlink, remove both dir and the target.
	link, err := filepath.EvalSymlinks(dir)
	if err != nil {
		clh.Logger().WithError(err).WithField("dir", dir).Warn("failed to resolve vm path")
	}

	clh.Logger().WithFields(log.Fields{
		"link": link,
		"dir":  dir,
	}).Infof("Cleanup vm path")

	if err := os.RemoveAll(dir); err != nil {
		if !force {
			return err
		}
		clh.Logger().WithError(err).Warnf("failed to remove vm path %s", dir)
	}
	if link != dir && link != "" {
		if err := os.RemoveAll(link); err != nil {
			if !force {
				return err
			}
			clh.Logger().WithError(err).WithField("link", link).Warn("failed to remove resolved vm path")
		}
	}

	if clh.config.VMid != "" {
		dir = filepath.Join(clh.config.VMStorePath, clh.config.VMid)
		if err := os.RemoveAll(dir); err != nil {
			if !force {
				return err
			}
			clh.Logger().WithError(err).WithField("path", dir).Warnf("failed to remove vm path")
		}
	}
	if rootless.IsRootless() {
		if _, err := user.Lookup(clh.config.User); err != nil {
			clh.Logger().WithError(err).WithFields(
				log.Fields{
					"user": clh.config.User,
					"uid":  clh.config.Uid,
				}).Warn("failed to find the user, it might have been removed")
			return nil
		}

		if err := pkgUtils.RemoveVmmUser(clh.config.User); err != nil {
			clh.Logger().WithError(err).WithFields(
				log.Fields{
					"user": clh.config.User,
					"uid":  clh.config.Uid,
				}).Warn("failed to delete the user")
			return nil
		}
		clh.Logger().WithFields(
			log.Fields{
				"user": clh.config.User,
				"uid":  clh.config.Uid,
			}).Debug("successfully removed the non root user")
	}

	// If we have initdata, we should drop initdata image path
	hypervisorConfig := clh.HypervisorConfig()
	if len(hypervisorConfig.Initdata) > 0 {
		initdataWorkdir := filepath.Join(string(filepath.Separator), "/run/kata-containers/shared/initdata", clh.id)
		if err := os.RemoveAll(initdataWorkdir); err != nil {
			clh.Logger().WithError(err).Warnf("failed to remove initdata work dir %s", initdataWorkdir)
		}
	}

	clh.reset()

	return nil
}

func (clh *cloudHypervisor) GetTotalMemoryMB(ctx context.Context) uint32 {
	vminfo, err := clh.vmInfo()
	if err != nil {
		clh.Logger().WithError(err).Error("failed to get vminfo")
		return 0
	}

	return uint32(vminfo.GetMemoryActualSize() >> utils.MibToBytesShift)
}

// vmInfo ask to hypervisor for current VM status
func (clh *cloudHypervisor) vmInfo() (chclient.VmInfo, error) {
	cl := clh.client()
	ctx, cancelInfo := context.WithTimeout(context.Background(), clh.getClhAPITimeout()*time.Second)
	defer cancelInfo()

	info, _, err := cl.VmInfoGet(ctx)
	if err != nil {
		clh.Logger().WithError(openAPIClientError(err)).Warn("VmInfoGet failed")
	}
	return info, openAPIClientError(err)
}

func (clh *cloudHypervisor) IsRateLimiterBuiltin() bool {
	return true
}

func pathExists(path string) bool {
	if _, err := os.Stat(path); err != nil {
		return false
	}
	return true
}
