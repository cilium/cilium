// +build linux

/*
Copyright 2015 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package cm

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path"
	"strconv"
	"sync"
	"time"

	"github.com/golang/glog"
	"github.com/opencontainers/runc/libcontainer/cgroups"
	"github.com/opencontainers/runc/libcontainer/cgroups/fs"
	"github.com/opencontainers/runc/libcontainer/configs"

	"k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	utilfeature "k8s.io/apiserver/pkg/util/feature"
	"k8s.io/client-go/tools/record"
	kubefeatures "k8s.io/kubernetes/pkg/features"
	internalapi "k8s.io/kubernetes/pkg/kubelet/apis/cri"
	"k8s.io/kubernetes/pkg/kubelet/cadvisor"
	"k8s.io/kubernetes/pkg/kubelet/cm/cpumanager"
	cmutil "k8s.io/kubernetes/pkg/kubelet/cm/util"
	kubecontainer "k8s.io/kubernetes/pkg/kubelet/container"
	"k8s.io/kubernetes/pkg/kubelet/qos"
	"k8s.io/kubernetes/pkg/kubelet/status"
	utilfile "k8s.io/kubernetes/pkg/util/file"
	"k8s.io/kubernetes/pkg/util/mount"
	"k8s.io/kubernetes/pkg/util/oom"
	"k8s.io/kubernetes/pkg/util/procfs"
	utilsysctl "k8s.io/kubernetes/pkg/util/sysctl"
	utilversion "k8s.io/kubernetes/pkg/util/version"
)

const (
	// The percent of the machine memory capacity. The value is used to calculate
	// docker memory resource container's hardlimit to workaround docker memory
	// leakage issue. Please see kubernetes/issues/9881 for more detail.
	DockerMemoryLimitThresholdPercent = 70
	// The minimum memory limit allocated to docker container: 150Mi
	MinDockerMemoryLimit = 150 * 1024 * 1024

	dockerProcessName     = "docker"
	dockerPidFile         = "/var/run/docker.pid"
	containerdProcessName = "docker-containerd"
	containerdPidFile     = "/run/docker/libcontainerd/docker-containerd.pid"
)

var (
	// The docker version in which containerd was introduced.
	containerdAPIVersion = utilversion.MustParseGeneric("1.23")
)

// A non-user container tracked by the Kubelet.
type systemContainer struct {
	// Absolute name of the container.
	name string

	// CPU limit in millicores.
	cpuMillicores int64

	// Function that ensures the state of the container.
	// m is the cgroup manager for the specified container.
	ensureStateFunc func(m *fs.Manager) error

	// Manager for the cgroups of the external container.
	manager *fs.Manager
}

func newSystemCgroups(containerName string) *systemContainer {
	return &systemContainer{
		name:    containerName,
		manager: createManager(containerName),
	}
}

type containerManagerImpl struct {
	sync.RWMutex
	cadvisorInterface cadvisor.Interface
	mountUtil         mount.Interface
	NodeConfig
	status Status
	// External containers being managed.
	systemContainers []*systemContainer
	qosContainers    QOSContainersInfo
	// Tasks that are run periodically
	periodicTasks []func()
	// holds all the mounted cgroup subsystems
	subsystems *CgroupSubsystems
	nodeInfo   *v1.Node
	// Interface for cgroup management
	cgroupManager CgroupManager
	// Capacity of this node.
	capacity v1.ResourceList
	// Absolute cgroupfs path to a cgroup that Kubelet needs to place all pods under.
	// This path include a top level container for enforcing Node Allocatable.
	cgroupRoot string
	// Event recorder interface.
	recorder record.EventRecorder
	// Interface for QoS cgroup management
	qosContainerManager QOSContainerManager
	// Interface for exporting and allocating devices reported by device plugins.
	devicePluginHandler DevicePluginHandler
	// Interface for CPU affinity management.
	cpuManager cpumanager.Manager
}

type features struct {
	cpuHardcapping bool
}

var _ ContainerManager = &containerManagerImpl{}

// checks if the required cgroups subsystems are mounted.
// As of now, only 'cpu' and 'memory' are required.
// cpu quota is a soft requirement.
func validateSystemRequirements(mountUtil mount.Interface) (features, error) {
	const (
		cgroupMountType = "cgroup"
		localErr        = "system validation failed"
	)
	var (
		cpuMountPoint string
		f             features
	)
	mountPoints, err := mountUtil.List()
	if err != nil {
		return f, fmt.Errorf("%s - %v", localErr, err)
	}

	expectedCgroups := sets.NewString("cpu", "cpuacct", "cpuset", "memory")
	for _, mountPoint := range mountPoints {
		if mountPoint.Type == cgroupMountType {
			for _, opt := range mountPoint.Opts {
				if expectedCgroups.Has(opt) {
					expectedCgroups.Delete(opt)
				}
				if opt == "cpu" {
					cpuMountPoint = mountPoint.Path
				}
			}
		}
	}

	if expectedCgroups.Len() > 0 {
		return f, fmt.Errorf("%s - Following Cgroup subsystem not mounted: %v", localErr, expectedCgroups.List())
	}

	// Check if cpu quota is available.
	// CPU cgroup is required and so it expected to be mounted at this point.
	periodExists, err := utilfile.FileExists(path.Join(cpuMountPoint, "cpu.cfs_period_us"))
	if err != nil {
		glog.Errorf("failed to detect if CPU cgroup cpu.cfs_period_us is available - %v", err)
	}
	quotaExists, err := utilfile.FileExists(path.Join(cpuMountPoint, "cpu.cfs_quota_us"))
	if err != nil {
		glog.Errorf("failed to detect if CPU cgroup cpu.cfs_quota_us is available - %v", err)
	}
	if quotaExists && periodExists {
		f.cpuHardcapping = true
	}
	return f, nil
}

// TODO(vmarmol): Add limits to the system containers.
// Takes the absolute name of the specified containers.
// Empty container name disables use of the specified container.
func NewContainerManager(mountUtil mount.Interface, cadvisorInterface cadvisor.Interface, nodeConfig NodeConfig, failSwapOn bool, devicePluginEnabled bool, recorder record.EventRecorder) (ContainerManager, error) {
	subsystems, err := GetCgroupSubsystems()
	if err != nil {
		return nil, fmt.Errorf("failed to get mounted cgroup subsystems: %v", err)
	}

	// Check whether swap is enabled. The Kubelet does not support running with swap enabled.
	cmd := exec.Command("cat", "/proc/swaps")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	var buf []string
	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() { // Splits on newlines by default
		buf = append(buf, scanner.Text())
	}
	if err := cmd.Wait(); err != nil { // Clean up
		return nil, err
	}

	// Running with swap enabled should be considered an error, but in order to maintain legacy
	// behavior we have to require an opt-in to this error for a period of time.
	// If there is more than one line (table headers) in /proc/swaps, swap is enabled and we should
	// error out unless --fail-swap-on is set to false.
	if len(buf) > 1 {
		if failSwapOn {
			return nil, fmt.Errorf("Running with swap on is not supported, please disable swap! or set --fail-swap-on flag to false. /proc/swaps contained: %v", buf)
		}
	}
	var capacity = v1.ResourceList{}
	// It is safe to invoke `MachineInfo` on cAdvisor before logically initializing cAdvisor here because
	// machine info is computed and cached once as part of cAdvisor object creation.
	// But `RootFsInfo` and `ImagesFsInfo` are not available at this moment so they will be called later during manager starts
	machineInfo, err := cadvisorInterface.MachineInfo()
	if err != nil {
		return nil, err
	}
	capacity = cadvisor.CapacityFromMachineInfo(machineInfo)

	cgroupRoot := nodeConfig.CgroupRoot
	cgroupManager := NewCgroupManager(subsystems, nodeConfig.CgroupDriver)
	// Check if Cgroup-root actually exists on the node
	if nodeConfig.CgroupsPerQOS {
		// this does default to / when enabled, but this tests against regressions.
		if nodeConfig.CgroupRoot == "" {
			return nil, fmt.Errorf("invalid configuration: cgroups-per-qos was specified and cgroup-root was not specified. To enable the QoS cgroup hierarchy you need to specify a valid cgroup-root")
		}

		// we need to check that the cgroup root actually exists for each subsystem
		// of note, we always use the cgroupfs driver when performing this check since
		// the input is provided in that format.
		// this is important because we do not want any name conversion to occur.
		if !cgroupManager.Exists(CgroupName(cgroupRoot)) {
			return nil, fmt.Errorf("invalid configuration: cgroup-root %q doesn't exist: %v", cgroupRoot, err)
		}
		glog.Infof("container manager verified user specified cgroup-root exists: %v", cgroupRoot)
		// Include the the top level cgroup for enforcing node allocatable into cgroup-root.
		// This way, all sub modules can avoid having to understand the concept of node allocatable.
		cgroupRoot = path.Join(cgroupRoot, defaultNodeAllocatableCgroupName)
	}
	glog.Infof("Creating Container Manager object based on Node Config: %+v", nodeConfig)

	qosContainerManager, err := NewQOSContainerManager(subsystems, cgroupRoot, nodeConfig)
	if err != nil {
		return nil, err
	}

	cm := &containerManagerImpl{
		cadvisorInterface:   cadvisorInterface,
		mountUtil:           mountUtil,
		NodeConfig:          nodeConfig,
		subsystems:          subsystems,
		cgroupManager:       cgroupManager,
		capacity:            capacity,
		cgroupRoot:          cgroupRoot,
		recorder:            recorder,
		qosContainerManager: qosContainerManager,
	}

	updateDeviceCapacityFunc := func(updates v1.ResourceList) {
		cm.Lock()
		defer cm.Unlock()
		for k, v := range updates {
			if v.Value() <= 0 {
				delete(cm.capacity, k)
			} else {
				cm.capacity[k] = v
			}
		}
	}

	glog.Infof("Creating device plugin handler: %t", devicePluginEnabled)
	if devicePluginEnabled {
		cm.devicePluginHandler, err = NewDevicePluginHandlerImpl(updateDeviceCapacityFunc)
	} else {
		cm.devicePluginHandler, err = NewDevicePluginHandlerStub()
	}
	if err != nil {
		return nil, err
	}

	// Initialize CPU manager
	if utilfeature.DefaultFeatureGate.Enabled(kubefeatures.CPUManager) {
		cm.cpuManager, err = cpumanager.NewManager(
			nodeConfig.ExperimentalCPUManagerPolicy,
			nodeConfig.ExperimentalCPUManagerReconcilePeriod,
			machineInfo,
			cm.GetNodeAllocatableReservation(),
		)
		if err != nil {
			glog.Errorf("failed to initialize cpu manager: %v", err)
			return nil, err
		}
	}

	return cm, nil
}

// NewPodContainerManager is a factory method returns a PodContainerManager object
// If qosCgroups are enabled then it returns the general pod container manager
// otherwise it returns a no-op manager which essentially does nothing
func (cm *containerManagerImpl) NewPodContainerManager() PodContainerManager {
	if cm.NodeConfig.CgroupsPerQOS {
		return &podContainerManagerImpl{
			qosContainersInfo: cm.GetQOSContainersInfo(),
			subsystems:        cm.subsystems,
			cgroupManager:     cm.cgroupManager,
		}
	}
	return &podContainerManagerNoop{
		cgroupRoot: CgroupName(cm.cgroupRoot),
	}
}

func (cm *containerManagerImpl) InternalContainerLifecycle() InternalContainerLifecycle {
	return &internalContainerLifecycleImpl{cm.cpuManager}
}

// Create a cgroup container manager.
func createManager(containerName string) *fs.Manager {
	allowAllDevices := true
	return &fs.Manager{
		Cgroups: &configs.Cgroup{
			Parent: "/",
			Name:   containerName,
			Resources: &configs.Resources{
				AllowAllDevices: &allowAllDevices,
			},
		},
	}
}

type KernelTunableBehavior string

const (
	KernelTunableWarn   KernelTunableBehavior = "warn"
	KernelTunableError  KernelTunableBehavior = "error"
	KernelTunableModify KernelTunableBehavior = "modify"
)

// setupKernelTunables validates kernel tunable flags are set as expected
// depending upon the specified option, it will either warn, error, or modify the kernel tunable flags
func setupKernelTunables(option KernelTunableBehavior) error {
	desiredState := map[string]int{
		utilsysctl.VmOvercommitMemory: utilsysctl.VmOvercommitMemoryAlways,
		utilsysctl.VmPanicOnOOM:       utilsysctl.VmPanicOnOOMInvokeOOMKiller,
		utilsysctl.KernelPanic:        utilsysctl.KernelPanicRebootTimeout,
		utilsysctl.KernelPanicOnOops:  utilsysctl.KernelPanicOnOopsAlways,
		utilsysctl.RootMaxKeys:        utilsysctl.RootMaxKeysSetting,
		utilsysctl.RootMaxBytes:       utilsysctl.RootMaxBytesSetting,
	}

	sysctl := utilsysctl.New()

	errList := []error{}
	for flag, expectedValue := range desiredState {
		val, err := sysctl.GetSysctl(flag)
		if err != nil {
			errList = append(errList, err)
			continue
		}
		if val == expectedValue {
			continue
		}

		switch option {
		case KernelTunableError:
			errList = append(errList, fmt.Errorf("Invalid kernel flag: %v, expected value: %v, actual value: %v", flag, expectedValue, val))
		case KernelTunableWarn:
			glog.V(2).Infof("Invalid kernel flag: %v, expected value: %v, actual value: %v", flag, expectedValue, val)
		case KernelTunableModify:
			glog.V(2).Infof("Updating kernel flag: %v, expected value: %v, actual value: %v", flag, expectedValue, val)
			err = sysctl.SetSysctl(flag, expectedValue)
			if err != nil {
				errList = append(errList, err)
			}
		}
	}
	return utilerrors.NewAggregate(errList)
}

func (cm *containerManagerImpl) setupNode(activePods ActivePodsFunc) error {
	f, err := validateSystemRequirements(cm.mountUtil)
	if err != nil {
		return err
	}
	if !f.cpuHardcapping {
		cm.status.SoftRequirements = fmt.Errorf("CPU hardcapping unsupported")
	}
	b := KernelTunableModify
	if cm.GetNodeConfig().ProtectKernelDefaults {
		b = KernelTunableError
	}
	if err := setupKernelTunables(b); err != nil {
		return err
	}

	// Setup top level qos containers only if CgroupsPerQOS flag is specified as true
	if cm.NodeConfig.CgroupsPerQOS {
		if err := cm.createNodeAllocatableCgroups(); err != nil {
			return err
		}
		err = cm.qosContainerManager.Start(cm.getNodeAllocatableAbsolute, activePods)
		if err != nil {
			return fmt.Errorf("failed to initialize top level QOS containers: %v", err)
		}
	}

	// Enforce Node Allocatable (if required)
	if err := cm.enforceNodeAllocatableCgroups(); err != nil {
		return err
	}

	systemContainers := []*systemContainer{}
	if cm.ContainerRuntime == "docker" {
		// With the docker-CRI integration, dockershim will manage the cgroups
		// and oom score for the docker processes.
		// In the future, NodeSpec should mandate the cgroup that the
		// runtime processes need to be in. For now, we still check the
		// cgroup for docker periodically, so that kubelet can recognize
		// the cgroup for docker and serve stats for the runtime.
		// TODO(#27097): Fix this after NodeSpec is clearly defined.
		cm.periodicTasks = append(cm.periodicTasks, func() {
			glog.V(4).Infof("[ContainerManager]: Adding periodic tasks for docker CRI integration")
			cont, err := getContainerNameForProcess(dockerProcessName, dockerPidFile)
			if err != nil {
				glog.Error(err)
				return
			}
			glog.V(2).Infof("[ContainerManager]: Discovered runtime cgroups name: %s", cont)
			cm.Lock()
			defer cm.Unlock()
			cm.RuntimeCgroupsName = cont
		})
	}

	if cm.SystemCgroupsName != "" {
		if cm.SystemCgroupsName == "/" {
			return fmt.Errorf("system container cannot be root (\"/\")")
		}
		cont := newSystemCgroups(cm.SystemCgroupsName)
		cont.ensureStateFunc = func(manager *fs.Manager) error {
			return ensureSystemCgroups("/", manager)
		}
		systemContainers = append(systemContainers, cont)
	}

	if cm.KubeletCgroupsName != "" {
		cont := newSystemCgroups(cm.KubeletCgroupsName)
		allowAllDevices := true
		manager := fs.Manager{
			Cgroups: &configs.Cgroup{
				Parent: "/",
				Name:   cm.KubeletCgroupsName,
				Resources: &configs.Resources{
					AllowAllDevices: &allowAllDevices,
				},
			},
		}
		cont.ensureStateFunc = func(_ *fs.Manager) error {
			return ensureProcessInContainerWithOOMScore(os.Getpid(), qos.KubeletOOMScoreAdj, &manager)
		}
		systemContainers = append(systemContainers, cont)
	} else {
		cm.periodicTasks = append(cm.periodicTasks, func() {
			if err := ensureProcessInContainerWithOOMScore(os.Getpid(), qos.KubeletOOMScoreAdj, nil); err != nil {
				glog.Error(err)
				return
			}
			cont, err := getContainer(os.Getpid())
			if err != nil {
				glog.Errorf("failed to find cgroups of kubelet - %v", err)
				return
			}
			cm.Lock()
			defer cm.Unlock()

			cm.KubeletCgroupsName = cont
		})
	}

	cm.systemContainers = systemContainers
	return nil
}

func getContainerNameForProcess(name, pidFile string) (string, error) {
	pids, err := getPidsForProcess(name, pidFile)
	if err != nil {
		return "", fmt.Errorf("failed to detect process id for %q - %v", name, err)
	}
	if len(pids) == 0 {
		return "", nil
	}
	cont, err := getContainer(pids[0])
	if err != nil {
		return "", err
	}
	return cont, nil
}

func (cm *containerManagerImpl) GetNodeConfig() NodeConfig {
	cm.RLock()
	defer cm.RUnlock()
	return cm.NodeConfig
}

func (cm *containerManagerImpl) GetMountedSubsystems() *CgroupSubsystems {
	return cm.subsystems
}

func (cm *containerManagerImpl) GetQOSContainersInfo() QOSContainersInfo {
	return cm.qosContainerManager.GetQOSContainersInfo()
}

func (cm *containerManagerImpl) UpdateQOSCgroups() error {
	return cm.qosContainerManager.UpdateCgroups()
}

func (cm *containerManagerImpl) Status() Status {
	cm.RLock()
	defer cm.RUnlock()
	return cm.status
}

func (cm *containerManagerImpl) Start(node *v1.Node,
	activePods ActivePodsFunc,
	podStatusProvider status.PodStatusProvider,
	runtimeService internalapi.RuntimeService) error {

	// Initialize CPU manager
	if utilfeature.DefaultFeatureGate.Enabled(kubefeatures.CPUManager) {
		cm.cpuManager.Start(cpumanager.ActivePodsFunc(activePods), podStatusProvider, runtimeService)
	}

	// cache the node Info including resource capacity and
	// allocatable of the node
	cm.nodeInfo = node

	// Ensure that node allocatable configuration is valid.
	if err := cm.validateNodeAllocatable(); err != nil {
		return err
	}

	// Setup the node
	if err := cm.setupNode(activePods); err != nil {
		return err
	}

	// Don't run a background thread if there are no ensureStateFuncs.
	hasEnsureStateFuncs := false
	for _, cont := range cm.systemContainers {
		if cont.ensureStateFunc != nil {
			hasEnsureStateFuncs = true
			break
		}
	}
	if hasEnsureStateFuncs {
		// Run ensure state functions every minute.
		go wait.Until(func() {
			for _, cont := range cm.systemContainers {
				if cont.ensureStateFunc != nil {
					if err := cont.ensureStateFunc(cont.manager); err != nil {
						glog.Warningf("[ContainerManager] Failed to ensure state of %q: %v", cont.name, err)
					}
				}
			}
		}, time.Minute, wait.NeverStop)

	}

	if len(cm.periodicTasks) > 0 {
		go wait.Until(func() {
			for _, task := range cm.periodicTasks {
				if task != nil {
					task()
				}
			}
		}, 5*time.Minute, wait.NeverStop)
	}

	// Local storage filesystem information from `RootFsInfo` and `ImagesFsInfo` is available at a later time
	// depending on the time when cadvisor manager updates container stats. Therefore use a go routine to keep
	// retrieving the information until it is available.
	stopChan := make(chan struct{})
	go wait.Until(func() {
		if err := cm.setFsCapacity(); err != nil {
			glog.Errorf("[ContainerManager]: %v", err)
			return
		}
		close(stopChan)
	}, time.Second, stopChan)

	// Starts device plugin manager.
	if err := cm.devicePluginHandler.Start(); err != nil {
		return err
	}
	return nil
}

func (cm *containerManagerImpl) setFsCapacity() error {
	rootfs, err := cm.cadvisorInterface.RootFsInfo()
	if err != nil {
		return fmt.Errorf("Fail to get rootfs information %v", err)
	}

	cm.Lock()
	for rName, rCap := range cadvisor.EphemeralStorageCapacityFromFsInfo(rootfs) {
		cm.capacity[rName] = rCap
	}
	cm.Unlock()
	return nil
}

// TODO: move the GetResources logic to PodContainerManager.
func (cm *containerManagerImpl) GetResources(pod *v1.Pod, container *v1.Container, activePods []*v1.Pod) (*kubecontainer.RunContainerOptions, error) {
	opts := &kubecontainer.RunContainerOptions{}
	// Gets devices, mounts, and envs from device plugin handler.
	glog.V(3).Infof("Calling devicePluginHandler AllocateDevices")
	// Maps to detect duplicate settings.
	devsMap := make(map[string]string)
	mountsMap := make(map[string]string)
	envsMap := make(map[string]string)
	allocResps, err := cm.devicePluginHandler.Allocate(pod, container, activePods)
	if err != nil {
		return opts, err
	}
	// Loops through AllocationResponses of all required extended resources.
	for _, resp := range allocResps {
		// Loops through runtime spec of all devices of the given resource.
		for _, devRuntime := range resp.Spec {
			// Updates RunContainerOptions.Devices.
			for _, dev := range devRuntime.Devices {
				if d, ok := devsMap[dev.ContainerPath]; ok {
					glog.V(3).Infof("skip existing device %s %s", dev.ContainerPath, dev.HostPath)
					if d != dev.HostPath {
						glog.Errorf("Container device %s has conflicting mapping host devices: %s and %s",
							dev.ContainerPath, d, dev.HostPath)
					}
					continue
				}
				devsMap[dev.ContainerPath] = dev.HostPath
				opts.Devices = append(opts.Devices, kubecontainer.DeviceInfo{
					PathOnHost:      dev.HostPath,
					PathInContainer: dev.ContainerPath,
					Permissions:     dev.Permissions,
				})
			}
			// Updates RunContainerOptions.Mounts.
			for _, mount := range devRuntime.Mounts {
				if m, ok := mountsMap[mount.ContainerPath]; ok {
					glog.V(3).Infof("skip existing mount %s %s", mount.ContainerPath, mount.HostPath)
					if m != mount.HostPath {
						glog.Errorf("Container mount %s has conflicting mapping host mounts: %s and %s",
							mount.ContainerPath, m, mount.HostPath)
					}
					continue
				}
				mountsMap[mount.ContainerPath] = mount.HostPath
				opts.Mounts = append(opts.Mounts, kubecontainer.Mount{
					Name:           mount.ContainerPath,
					ContainerPath:  mount.ContainerPath,
					HostPath:       mount.HostPath,
					ReadOnly:       mount.ReadOnly,
					SELinuxRelabel: false,
				})
			}
			// Updates RunContainerOptions.Envs.
			for k, v := range devRuntime.Envs {
				if e, ok := envsMap[k]; ok {
					glog.V(3).Infof("skip existing envs %s %s", k, v)
					if e != v {
						glog.Errorf("Environment variable %s has conflicting setting: %s and %s", k, e, v)
					}
					continue
				}
				envsMap[k] = v
				opts.Envs = append(opts.Envs, kubecontainer.EnvVar{Name: k, Value: v})
			}
		}
	}
	return opts, nil
}

func (cm *containerManagerImpl) SystemCgroupsLimit() v1.ResourceList {
	cpuLimit := int64(0)

	// Sum up resources of all external containers.
	for _, cont := range cm.systemContainers {
		cpuLimit += cont.cpuMillicores
	}

	return v1.ResourceList{
		v1.ResourceCPU: *resource.NewMilliQuantity(
			cpuLimit,
			resource.DecimalSI),
	}
}

func isProcessRunningInHost(pid int) (bool, error) {
	// Get init pid namespace.
	initPidNs, err := os.Readlink("/proc/1/ns/pid")
	if err != nil {
		return false, fmt.Errorf("failed to find pid namespace of init process")
	}
	glog.V(10).Infof("init pid ns is %q", initPidNs)
	processPidNs, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/pid", pid))
	if err != nil {
		return false, fmt.Errorf("failed to find pid namespace of process %q", pid)
	}
	glog.V(10).Infof("Pid %d pid ns is %q", pid, processPidNs)
	return initPidNs == processPidNs, nil
}

func getPidFromPidFile(pidFile string) (int, error) {
	file, err := os.Open(pidFile)
	if err != nil {
		return 0, fmt.Errorf("error opening pid file %s: %v", pidFile, err)
	}
	defer file.Close()

	data, err := ioutil.ReadAll(file)
	if err != nil {
		return 0, fmt.Errorf("error reading pid file %s: %v", pidFile, err)
	}

	pid, err := strconv.Atoi(string(data))
	if err != nil {
		return 0, fmt.Errorf("error parsing %s as a number: %v", string(data), err)
	}

	return pid, nil
}

func getPidsForProcess(name, pidFile string) ([]int, error) {
	if len(pidFile) == 0 {
		return procfs.PidOf(name)
	}

	pid, err := getPidFromPidFile(pidFile)
	if err == nil {
		return []int{pid}, nil
	}

	// Try to lookup pid by process name
	pids, err2 := procfs.PidOf(name)
	if err2 == nil {
		return pids, nil
	}

	// Return error from getPidFromPidFile since that should have worked
	// and is the real source of the problem.
	glog.V(4).Infof("unable to get pid from %s: %v", pidFile, err)
	return []int{}, err
}

// Ensures that the Docker daemon is in the desired container.
// Temporarily export the function to be used by dockershim.
// TODO(yujuhong): Move this function to dockershim once kubelet migrates to
// dockershim as the default.
func EnsureDockerInContainer(dockerAPIVersion *utilversion.Version, oomScoreAdj int, manager *fs.Manager) error {
	type process struct{ name, file string }
	dockerProcs := []process{{dockerProcessName, dockerPidFile}}
	if dockerAPIVersion.AtLeast(containerdAPIVersion) {
		dockerProcs = append(dockerProcs, process{containerdProcessName, containerdPidFile})
	}
	var errs []error
	for _, proc := range dockerProcs {
		pids, err := getPidsForProcess(proc.name, proc.file)
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to get pids for %q: %v", proc.name, err))
			continue
		}

		// Move if the pid is not already in the desired container.
		for _, pid := range pids {
			if err := ensureProcessInContainerWithOOMScore(pid, oomScoreAdj, manager); err != nil {
				errs = append(errs, fmt.Errorf("errors moving %q pid: %v", proc.name, err))
			}
		}
	}
	return utilerrors.NewAggregate(errs)
}

func ensureProcessInContainerWithOOMScore(pid int, oomScoreAdj int, manager *fs.Manager) error {
	if runningInHost, err := isProcessRunningInHost(pid); err != nil {
		// Err on the side of caution. Avoid moving the docker daemon unless we are able to identify its context.
		return err
	} else if !runningInHost {
		// Process is running inside a container. Don't touch that.
		glog.V(2).Infof("pid %d is not running in the host namespaces", pid)
		return nil
	}

	var errs []error
	if manager != nil {
		cont, err := getContainer(pid)
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to find container of PID %d: %v", pid, err))
		}

		if cont != manager.Cgroups.Name {
			err = manager.Apply(pid)
			if err != nil {
				errs = append(errs, fmt.Errorf("failed to move PID %d (in %q) to %q: %v", pid, cont, manager.Cgroups.Name, err))
			}
		}
	}

	// Also apply oom-score-adj to processes
	oomAdjuster := oom.NewOOMAdjuster()
	glog.V(5).Infof("attempting to apply oom_score_adj of %d to pid %d", oomScoreAdj, pid)
	if err := oomAdjuster.ApplyOOMScoreAdj(pid, oomScoreAdj); err != nil {
		glog.V(3).Infof("Failed to apply oom_score_adj %d for pid %d: %v", oomScoreAdj, pid, err)
		errs = append(errs, fmt.Errorf("failed to apply oom score %d to PID %d: %v", oomScoreAdj, pid, err))
	}
	return utilerrors.NewAggregate(errs)
}

// getContainer returns the cgroup associated with the specified pid.
// It enforces a unified hierarchy for memory and cpu cgroups.
// On systemd environments, it uses the name=systemd cgroup for the specified pid.
func getContainer(pid int) (string, error) {
	cgs, err := cgroups.ParseCgroupFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return "", err
	}

	cpu, found := cgs["cpu"]
	if !found {
		return "", cgroups.NewNotFoundError("cpu")
	}
	memory, found := cgs["memory"]
	if !found {
		return "", cgroups.NewNotFoundError("memory")
	}

	// since we use this container for accounting, we need to ensure its a unified hierarchy.
	if cpu != memory {
		return "", fmt.Errorf("cpu and memory cgroup hierarchy not unified.  cpu: %s, memory: %s", cpu, memory)
	}

	// on systemd, every pid is in a unified cgroup hierarchy (name=systemd as seen in systemd-cgls)
	// cpu and memory accounting is off by default, users may choose to enable it per unit or globally.
	// users could enable CPU and memory accounting globally via /etc/systemd/system.conf (DefaultCPUAccounting=true DefaultMemoryAccounting=true).
	// users could also enable CPU and memory accounting per unit via CPUAccounting=true and MemoryAccounting=true
	// we only warn if accounting is not enabled for CPU or memory so as to not break local development flows where kubelet is launched in a terminal.
	// for example, the cgroup for the user session will be something like /user.slice/user-X.slice/session-X.scope, but the cpu and memory
	// cgroup will be the closest ancestor where accounting is performed (most likely /) on systems that launch docker containers.
	// as a result, on those systems, you will not get cpu or memory accounting statistics for kubelet.
	// in addition, you would not get memory or cpu accounting for the runtime unless accounting was enabled on its unit (or globally).
	if systemd, found := cgs["name=systemd"]; found {
		if systemd != cpu {
			glog.Warningf("CPUAccounting not enabled for pid: %d", pid)
		}
		if systemd != memory {
			glog.Warningf("MemoryAccounting not enabled for pid: %d", pid)
		}
		return systemd, nil
	}

	return cpu, nil
}

// Ensures the system container is created and all non-kernel threads and process 1
// without a container are moved to it.
//
// The reason of leaving kernel threads at root cgroup is that we don't want to tie the
// execution of these threads with to-be defined /system quota and create priority inversions.
//
func ensureSystemCgroups(rootCgroupPath string, manager *fs.Manager) error {
	// Move non-kernel PIDs to the system container.
	attemptsRemaining := 10
	var errs []error
	for attemptsRemaining >= 0 {
		// Only keep errors on latest attempt.
		errs = []error{}
		attemptsRemaining--

		allPids, err := cmutil.GetPids(rootCgroupPath)
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to list PIDs for root: %v", err))
			continue
		}

		// Remove kernel pids and other protected PIDs (pid 1, PIDs already in system & kubelet containers)
		pids := make([]int, 0, len(allPids))
		for _, pid := range allPids {
			if pid == 1 || isKernelPid(pid) {
				continue
			}

			pids = append(pids, pid)
		}
		glog.Infof("Found %d PIDs in root, %d of them are not to be moved", len(allPids), len(allPids)-len(pids))

		// Check if we have moved all the non-kernel PIDs.
		if len(pids) == 0 {
			break
		}

		glog.Infof("Moving non-kernel processes: %v", pids)
		for _, pid := range pids {
			err := manager.Apply(pid)
			if err != nil {
				errs = append(errs, fmt.Errorf("failed to move PID %d into the system container %q: %v", pid, manager.Cgroups.Name, err))
			}
		}

	}
	if attemptsRemaining < 0 {
		errs = append(errs, fmt.Errorf("ran out of attempts to create system containers %q", manager.Cgroups.Name))
	}

	return utilerrors.NewAggregate(errs)
}

// Determines whether the specified PID is a kernel PID.
func isKernelPid(pid int) bool {
	// Kernel threads have no associated executable.
	_, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	return err != nil
}

// Helper for getting the docker API version.
func getDockerAPIVersion(cadvisor cadvisor.Interface) *utilversion.Version {
	versions, err := cadvisor.VersionInfo()
	if err != nil {
		glog.Errorf("Error requesting cAdvisor VersionInfo: %v", err)
		return utilversion.MustParseSemantic("0.0")
	}
	dockerAPIVersion, err := utilversion.ParseGeneric(versions.DockerAPIVersion)
	if err != nil {
		glog.Errorf("Error parsing docker version %q: %v", versions.DockerVersion, err)
		return utilversion.MustParseSemantic("0.0")
	}
	return dockerAPIVersion
}

func (cm *containerManagerImpl) GetCapacity() v1.ResourceList {
	cm.RLock()
	defer cm.RUnlock()
	return cm.capacity
}
