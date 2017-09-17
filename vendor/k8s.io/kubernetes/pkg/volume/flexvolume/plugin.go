/*
Copyright 2017 The Kubernetes Authors.

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

package flexvolume

import (
	"fmt"
	"path"
	"strings"
	"sync"

	"github.com/golang/glog"

	api "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/kubernetes/pkg/util/mount"
	utilstrings "k8s.io/kubernetes/pkg/util/strings"
	"k8s.io/kubernetes/pkg/volume"
	"k8s.io/utils/exec"
)

const flexVolumePluginName = "kubernetes.io/flexvolume"

// FlexVolumePlugin object.
type flexVolumePlugin struct {
	driverName string
	execPath   string
	host       volume.VolumeHost
	runner     exec.Interface

	sync.Mutex
	unsupportedCommands []string
	capabilities        DriverCapabilities
}

type flexVolumeAttachablePlugin struct {
	*flexVolumePlugin
}

var _ volume.AttachableVolumePlugin = &flexVolumeAttachablePlugin{}
var _ volume.PersistentVolumePlugin = &flexVolumePlugin{}

type PluginFactory interface {
	NewFlexVolumePlugin(pluginDir, driverName string) (volume.VolumePlugin, error)
}

type pluginFactory struct{}

func (pluginFactory) NewFlexVolumePlugin(pluginDir, name string) (volume.VolumePlugin, error) {
	execPath := path.Join(pluginDir, name)

	driverName := utilstrings.UnescapePluginName(name)

	flexPlugin := &flexVolumePlugin{
		driverName:          driverName,
		execPath:            execPath,
		runner:              exec.New(),
		unsupportedCommands: []string{},
	}

	// Initialize the plugin and probe the capabilities
	call := flexPlugin.NewDriverCall(initCmd)
	ds, err := call.Run()
	if err != nil {
		return nil, err
	}
	flexPlugin.capabilities = *ds.Capabilities

	if flexPlugin.capabilities.Attach {
		// Plugin supports attach/detach, so return flexVolumeAttachablePlugin
		return &flexVolumeAttachablePlugin{flexVolumePlugin: flexPlugin}, nil
	} else {
		return flexPlugin, nil
	}
}

// Init is part of the volume.VolumePlugin interface.
func (plugin *flexVolumePlugin) Init(host volume.VolumeHost) error {
	plugin.host = host
	// Hardwired 'success' as any errors from calling init() will be caught by NewFlexVolumePlugin()
	return nil
}

func (plugin *flexVolumePlugin) getExecutable() string {
	parts := strings.Split(plugin.driverName, "/")
	execName := parts[len(parts)-1]
	return path.Join(plugin.execPath, execName)
}

// Name is part of the volume.VolumePlugin interface.
func (plugin *flexVolumePlugin) GetPluginName() string {
	return "flexvolume-" + plugin.driverName
}

// GetVolumeName is part of the volume.VolumePlugin interface.
func (plugin *flexVolumePlugin) GetVolumeName(spec *volume.Spec) (string, error) {
	call := plugin.NewDriverCall(getVolumeNameCmd)
	call.AppendSpec(spec, plugin.host, nil)

	_, err := call.Run()
	if isCmdNotSupportedErr(err) {
		return (*pluginDefaults)(plugin).GetVolumeName(spec)
	} else if err != nil {
		return "", err
	}

	name, err := (*pluginDefaults)(plugin).GetVolumeName(spec)
	if err != nil {
		return "", err
	}

	glog.Warning(logPrefix(plugin), "GetVolumeName is not supported yet. Defaulting to PV or volume name: ", name)

	return name, nil
}

// CanSupport is part of the volume.VolumePlugin interface.
func (plugin *flexVolumePlugin) CanSupport(spec *volume.Spec) bool {
	source, _ := getVolumeSource(spec)
	return (source != nil) && (source.Driver == plugin.driverName)
}

// RequiresRemount is part of the volume.VolumePlugin interface.
func (plugin *flexVolumePlugin) RequiresRemount() bool {
	return false
}

// GetAccessModes gets the allowed access modes for this plugin.
func (plugin *flexVolumePlugin) GetAccessModes() []api.PersistentVolumeAccessMode {
	return []api.PersistentVolumeAccessMode{
		api.ReadWriteOnce,
		api.ReadOnlyMany,
	}
}

// NewMounter is part of the volume.VolumePlugin interface.
func (plugin *flexVolumePlugin) NewMounter(spec *volume.Spec, pod *api.Pod, _ volume.VolumeOptions) (volume.Mounter, error) {
	return plugin.newMounterInternal(spec, pod, plugin.host.GetMounter(plugin.GetPluginName()), plugin.runner)
}

// newMounterInternal is the internal mounter routine to build the volume.
func (plugin *flexVolumePlugin) newMounterInternal(spec *volume.Spec, pod *api.Pod, mounter mount.Interface, runner exec.Interface) (volume.Mounter, error) {
	source, readOnly := getVolumeSource(spec)
	return &flexVolumeMounter{
		flexVolume: &flexVolume{
			driverName:            source.Driver,
			execPath:              plugin.getExecutable(),
			mounter:               mounter,
			plugin:                plugin,
			podName:               pod.Name,
			podUID:                pod.UID,
			podNamespace:          pod.Namespace,
			podServiceAccountName: pod.Spec.ServiceAccountName,
			volName:               spec.Name(),
		},
		runner:   runner,
		spec:     spec,
		readOnly: readOnly,
	}, nil
}

// NewUnmounter is part of the volume.VolumePlugin interface.
func (plugin *flexVolumePlugin) NewUnmounter(volName string, podUID types.UID) (volume.Unmounter, error) {
	return plugin.newUnmounterInternal(volName, podUID, plugin.host.GetMounter(plugin.GetPluginName()), plugin.runner)
}

// newUnmounterInternal is the internal unmounter routine to clean the volume.
func (plugin *flexVolumePlugin) newUnmounterInternal(volName string, podUID types.UID, mounter mount.Interface, runner exec.Interface) (volume.Unmounter, error) {
	return &flexVolumeUnmounter{
		flexVolume: &flexVolume{
			driverName: plugin.driverName,
			execPath:   plugin.getExecutable(),
			mounter:    mounter,
			plugin:     plugin,
			podUID:     podUID,
			volName:    volName,
		},
		runner: runner,
	}, nil
}

// NewAttacher is part of the volume.AttachableVolumePlugin interface.
func (plugin *flexVolumeAttachablePlugin) NewAttacher() (volume.Attacher, error) {
	return &flexVolumeAttacher{plugin}, nil
}

// NewDetacher is part of the volume.AttachableVolumePlugin interface.
func (plugin *flexVolumeAttachablePlugin) NewDetacher() (volume.Detacher, error) {
	return &flexVolumeDetacher{plugin}, nil
}

// ConstructVolumeSpec is part of the volume.AttachableVolumePlugin interface.
func (plugin *flexVolumePlugin) ConstructVolumeSpec(volumeName, mountPath string) (*volume.Spec, error) {
	flexVolume := &api.Volume{
		Name: volumeName,
		VolumeSource: api.VolumeSource{
			FlexVolume: &api.FlexVolumeSource{
				Driver: plugin.driverName,
			},
		},
	}
	return volume.NewSpecFromVolume(flexVolume), nil
}

func (plugin *flexVolumePlugin) SupportsMountOption() bool {
	return false
}

// Mark the given commands as unsupported.
func (plugin *flexVolumePlugin) unsupported(commands ...string) {
	plugin.Lock()
	defer plugin.Unlock()
	plugin.unsupportedCommands = append(plugin.unsupportedCommands, commands...)
}

func (plugin *flexVolumePlugin) SupportsBulkVolumeVerification() bool {
	return false
}

// Returns true iff the given command is known to be unsupported.
func (plugin *flexVolumePlugin) isUnsupported(command string) bool {
	plugin.Lock()
	defer plugin.Unlock()
	for _, unsupportedCommand := range plugin.unsupportedCommands {
		if command == unsupportedCommand {
			return true
		}
	}
	return false
}

func (plugin *flexVolumePlugin) GetDeviceMountRefs(deviceMountPath string) ([]string, error) {
	mounter := plugin.host.GetMounter(plugin.GetPluginName())
	return mount.GetMountRefs(mounter, deviceMountPath)
}

func (plugin *flexVolumePlugin) getDeviceMountPath(spec *volume.Spec) (string, error) {
	volumeName, err := plugin.GetVolumeName(spec)
	if err != nil {
		return "", fmt.Errorf("GetVolumeName failed from getDeviceMountPath: %s", err)
	}

	mountsDir := path.Join(plugin.host.GetPluginDir(flexVolumePluginName), plugin.driverName, "mounts")
	return path.Join(mountsDir, volumeName), nil
}
