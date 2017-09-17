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

package scaleio

import (
	"fmt"
	"os"
	"path"
	"strconv"
	"strings"

	"github.com/golang/glog"
	api "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/uuid"
	"k8s.io/kubernetes/pkg/util/mount"
	kstrings "k8s.io/kubernetes/pkg/util/strings"
	"k8s.io/kubernetes/pkg/volume"
	"k8s.io/kubernetes/pkg/volume/util"
	"k8s.io/kubernetes/pkg/volume/util/volumehelper"
)

type sioVolume struct {
	sioMgr      *sioMgr
	plugin      *sioPlugin
	pod         *api.Pod
	podUID      types.UID
	spec        *volume.Spec
	source      *api.ScaleIOVolumeSource
	namespace   string
	volSpecName string
	volName     string
	readOnly    bool
	fsType      string
	options     volume.VolumeOptions
	configData  map[string]string

	volume.MetricsNil
}

// *******************
// volume.Volume Impl
var _ volume.Volume = &sioVolume{}

// GetPath returns the path where the volume will be mounted.
// The volumeName is prefixed with the pod's namespace a <pod.Namespace>-<volumeName>
func (v *sioVolume) GetPath() string {
	return v.plugin.host.GetPodVolumeDir(
		v.podUID,
		kstrings.EscapeQualifiedNameForDisk(sioPluginName),
		v.volSpecName)
}

// *************
// Mounter Impl
// *************
var _ volume.Mounter = &sioVolume{}

// CanMount checks to verify that the volume can be mounted prior to Setup.
// A nil error indicates that the volume is ready for mounitnig.
func (v *sioVolume) CanMount() error {
	return nil
}

func (v *sioVolume) SetUp(fsGroup *int64) error {
	return v.SetUpAt(v.GetPath(), fsGroup)
}

// SetUp bind mounts the disk global mount to the volume path.
func (v *sioVolume) SetUpAt(dir string, fsGroup *int64) error {
	v.plugin.volumeMtx.LockKey(v.volSpecName)
	defer v.plugin.volumeMtx.UnlockKey(v.volSpecName)

	glog.V(4).Info(log("setting up volume for PV.spec %s", v.volSpecName))
	if err := v.setSioMgr(); err != nil {
		glog.Error(log("setup failed to create scalio manager: %v", err))
		return err
	}

	mounter := v.plugin.host.GetMounter(v.plugin.GetPluginName())
	notDevMnt, err := mounter.IsLikelyNotMountPoint(dir)
	if err != nil && !os.IsNotExist(err) {
		glog.Error(log("IsLikelyNotMountPoint test failed for dir %v", dir))
		return err
	}
	if !notDevMnt {
		glog.V(4).Info(log("skipping setup, dir %s already a mount point", v.volName))
		return nil
	}

	// should multiple-mapping be enabled
	enableMultiMaps := false
	isROM := false
	if v.spec.PersistentVolume != nil {
		ams := v.spec.PersistentVolume.Spec.AccessModes
		for _, am := range ams {
			if am == api.ReadOnlyMany {
				enableMultiMaps = true
				isROM = true
			}
		}
	}
	glog.V(4).Info(log("multiple mapping enabled = %v", enableMultiMaps))

	volName := v.volName
	devicePath, err := v.sioMgr.AttachVolume(volName, enableMultiMaps)
	if err != nil {
		glog.Error(log("setup of volume %v:  %v", v.volSpecName, err))
		return err
	}
	options := []string{}
	switch {
	default:
		options = append(options, "rw")
	case isROM && !v.source.ReadOnly:
		options = append(options, "rw")
	case isROM:
		options = append(options, "ro")
	case v.source.ReadOnly:
		options = append(options, "ro")
	}

	glog.V(4).Info(log("mounting device  %s -> %s", devicePath, dir))
	if err := os.MkdirAll(dir, 0750); err != nil {
		glog.Error(log("failed to create dir %#v:  %v", dir, err))
		return err
	}
	glog.V(4).Info(log("setup created mount point directory %s", dir))

	diskMounter := volumehelper.NewSafeFormatAndMountFromHost(v.plugin.GetPluginName(), v.plugin.host)
	err = diskMounter.FormatAndMount(devicePath, dir, v.fsType, options)

	if err != nil {
		glog.Error(log("mount operation failed during setup: %v", err))
		if err := os.Remove(dir); err != nil && !os.IsNotExist(err) {
			glog.Error(log("failed to remove dir %s during a failed mount at setup: %v", dir, err))
			return err
		}
		return err
	}

	if !v.readOnly && fsGroup != nil {
		glog.V(4).Info(log("applying  value FSGroup ownership"))
		volume.SetVolumeOwnership(v, fsGroup)
	}

	glog.V(4).Info(log("successfully setup PV %s: volume %s mapped as %s mounted at %s", v.volSpecName, v.volName, devicePath, dir))
	return nil
}

func (v *sioVolume) GetAttributes() volume.Attributes {
	return volume.Attributes{
		ReadOnly:        v.readOnly,
		Managed:         !v.readOnly,
		SupportsSELinux: true,
	}
}

// **********************
// volume.Unmounter Impl
// *********************
var _ volume.Unmounter = &sioVolume{}

// TearDownAt unmounts the bind mount
func (v *sioVolume) TearDown() error {
	return v.TearDownAt(v.GetPath())
}

// TearDown unmounts  and remove the volume
func (v *sioVolume) TearDownAt(dir string) error {
	v.plugin.volumeMtx.LockKey(v.volSpecName)
	defer v.plugin.volumeMtx.UnlockKey(v.volSpecName)

	mounter := v.plugin.host.GetMounter(v.plugin.GetPluginName())
	dev, _, err := mount.GetDeviceNameFromMount(mounter, dir)
	if err != nil {
		glog.Errorf(log("failed to get reference count for volume: %s", dir))
		return err
	}

	glog.V(4).Info(log("attempting to unmount %s", dir))
	if err := util.UnmountPath(dir, mounter); err != nil {
		glog.Error(log("teardown failed while unmounting dir %s: %v ", dir, err))
		return err
	}
	glog.V(4).Info(log("dir %s unmounted successfully", dir))

	// detach/unmap
	deviceBusy, err := mounter.DeviceOpened(dev)
	if err != nil {
		glog.Error(log("teardown unable to get status for device %s: %v", dev, err))
		return err
	}

	// Detach volume from node:
	// use "last attempt wins" strategy to detach volume from node
	// only allow volume to detach when it is not busy (not being used by other pods)
	if !deviceBusy {
		glog.V(4).Info(log("teardown is attempting to detach/unmap volume for PV %s", v.volSpecName))
		if err := v.resetSioMgr(); err != nil {
			glog.Error(log("teardown failed, unable to reset scalio mgr: %v", err))
		}
		volName := v.volName
		if err := v.sioMgr.DetachVolume(volName); err != nil {
			glog.Warning(log("warning: detaching failed for volume %s:  %v", volName, err))
			return nil
		}
		glog.V(4).Infof(log("teardown of volume %v detached successfully", volName))
	}
	return nil
}

// ********************
// volume.Deleter Impl
// ********************
var _ volume.Deleter = &sioVolume{}

func (v *sioVolume) Delete() error {
	glog.V(4).Info(log("deleting pvc %s", v.volSpecName))

	if err := v.setSioMgrFromSpec(); err != nil {
		glog.Error(log("delete failed while setting sio manager: %v", err))
		return err
	}

	err := v.sioMgr.DeleteVolume(v.volName)
	if err != nil {
		glog.Error(log("failed to delete volume %s: %v", v.volName, err))
		return err
	}

	glog.V(4).Info(log("successfully deleted PV %s with volume %s", v.volSpecName, v.volName))
	return nil
}

// ************************
// volume.Provisioner Impl
// ************************
var _ volume.Provisioner = &sioVolume{}

func (v *sioVolume) Provision() (*api.PersistentVolume, error) {
	glog.V(4).Info(log("attempting to dynamically provision pvc %v", v.options.PVC.Name))

	if !volume.AccessModesContainedInAll(v.plugin.GetAccessModes(), v.options.PVC.Spec.AccessModes) {
		return nil, fmt.Errorf("invalid AccessModes %v: only AccessModes %v are supported", v.options.PVC.Spec.AccessModes, v.plugin.GetAccessModes())
	}

	// setup volume attrributes
	genName := v.generateName("k8svol", 11)
	var oneGig int64 = 1024 * 1024 * 1024
	var eightGig int64 = 8 * oneGig

	capacity := v.options.PVC.Spec.Resources.Requests[api.ResourceName(api.ResourceStorage)]
	volSizeBytes := capacity.Value()
	volSizeGB := int64(volume.RoundUpSize(volSizeBytes, oneGig))

	if volSizeBytes == 0 {
		return nil, fmt.Errorf("invalid volume size of 0 specified")
	}

	if volSizeBytes < eightGig {
		volSizeGB = int64(volume.RoundUpSize(eightGig, oneGig))
		glog.V(4).Info(log("capacity less than 8Gi found, adjusted to %dGi", volSizeGB))

	}

	// create sio manager
	if err := v.setSioMgrFromConfig(); err != nil {
		glog.Error(log("provision failed while setting up sio mgr: %v", err))
		return nil, err
	}

	// create volume
	volName := genName
	vol, err := v.sioMgr.CreateVolume(volName, volSizeGB)
	if err != nil {
		glog.Error(log("provision failed while creating volume: %v", err))
		return nil, err
	}

	// prepare data for pv
	v.configData[confKey.volumeName] = volName
	sslEnabled, err := strconv.ParseBool(v.configData[confKey.sslEnabled])
	if err != nil {
		glog.Warning(log("failed to parse parameter sslEnabled, setting to false"))
		sslEnabled = false
	}
	readOnly, err := strconv.ParseBool(v.configData[confKey.readOnly])
	if err != nil {
		glog.Warning(log("failed to parse parameter readOnly, setting it to false"))
		readOnly = false
	}

	// describe created pv
	pvName := genName
	pv := &api.PersistentVolume{
		ObjectMeta: meta.ObjectMeta{
			Name:      pvName,
			Namespace: v.options.PVC.Namespace,
			Labels:    map[string]string{},
			Annotations: map[string]string{
				volumehelper.VolumeDynamicallyCreatedByKey: "scaleio-dynamic-provisioner",
			},
		},
		Spec: api.PersistentVolumeSpec{
			PersistentVolumeReclaimPolicy: v.options.PersistentVolumeReclaimPolicy,
			AccessModes:                   v.options.PVC.Spec.AccessModes,
			Capacity: api.ResourceList{
				api.ResourceName(api.ResourceStorage): resource.MustParse(
					fmt.Sprintf("%dGi", volSizeGB),
				),
			},
			PersistentVolumeSource: api.PersistentVolumeSource{
				ScaleIO: &api.ScaleIOVolumeSource{
					Gateway:          v.configData[confKey.gateway],
					SSLEnabled:       sslEnabled,
					SecretRef:        &api.LocalObjectReference{Name: v.configData[confKey.secretRef]},
					System:           v.configData[confKey.system],
					ProtectionDomain: v.configData[confKey.protectionDomain],
					StoragePool:      v.configData[confKey.storagePool],
					StorageMode:      v.configData[confKey.storageMode],
					VolumeName:       volName,
					FSType:           v.configData[confKey.fsType],
					ReadOnly:         readOnly,
				},
			},
		},
	}
	if len(v.options.PVC.Spec.AccessModes) == 0 {
		pv.Spec.AccessModes = v.plugin.GetAccessModes()
	}

	glog.V(4).Info(log("provisioner created pv %v and volume %s successfully", pvName, vol.Name))
	return pv, nil
}

// setSioMgr creates scaleio mgr from cached config data if found
// otherwise, setups new config data and create mgr
func (v *sioVolume) setSioMgr() error {
	glog.V(4).Info(log("setting up sio mgr for spec  %s", v.volSpecName))
	podDir := v.plugin.host.GetPodPluginDir(v.podUID, sioPluginName)
	configName := path.Join(podDir, sioConfigFileName)
	if v.sioMgr == nil {
		configData, err := loadConfig(configName) // try to load config if exist
		if err != nil {
			if !os.IsNotExist(err) {
				glog.Error(log("failed to load config %s : %v", configName, err))
				return err
			}
			glog.V(4).Info(log("previous config file not found, creating new one"))
			// prepare config data
			configData = make(map[string]string)
			mapVolumeSource(configData, v.source)
			if err := validateConfigs(configData); err != nil {
				glog.Error(log("config setup failed: %s", err))
				return err
			}
			configData[confKey.namespace] = v.namespace
			configData[confKey.volSpecName] = v.volSpecName

			// persist config
			if err := saveConfig(configName, configData); err != nil {
				glog.Error(log("failed to save config data: %v", err))
				return err
			}
		}
		// merge in secret
		if err := attachSecret(v.plugin, v.namespace, configData); err != nil {
			glog.Error(log("failed to load secret: %v", err))
			return err
		}

		mgr, err := newSioMgr(configData, v.plugin.host.GetExec(v.plugin.GetPluginName()))
		if err != nil {
			glog.Error(log("failed to reset sio manager: %v", err))
			return err
		}

		v.sioMgr = mgr
	}
	return nil
}

// resetSioMgr creates scaleio manager from existing (cached) config data
func (v *sioVolume) resetSioMgr() error {
	podDir := v.plugin.host.GetPodPluginDir(v.podUID, sioPluginName)
	configName := path.Join(podDir, sioConfigFileName)
	if v.sioMgr == nil {
		// load config data from disk
		configData, err := loadConfig(configName)
		if err != nil {
			glog.Error(log("failed to load config data: %v", err))
			return err
		}
		v.namespace = configData[confKey.namespace]
		v.volName = configData[confKey.volumeName]
		v.volSpecName = configData[confKey.volSpecName]

		// attach secret
		if err := attachSecret(v.plugin, v.namespace, configData); err != nil {
			glog.Error(log("failed to load secret: %v", err))
			return err
		}

		mgr, err := newSioMgr(configData, v.plugin.host.GetExec(v.plugin.GetPluginName()))
		if err != nil {
			glog.Error(log("failed to reset scaleio mgr: %v", err))
			return err
		}
		v.sioMgr = mgr
	}
	return nil
}

// setSioFromConfig sets up scaleio mgr from an available config data map
// designed to be called from dynamic provisioner
func (v *sioVolume) setSioMgrFromConfig() error {
	glog.V(4).Info(log("setting scaleio mgr from available config"))
	if v.sioMgr == nil {
		configData := v.configData
		applyConfigDefaults(configData)
		if err := validateConfigs(configData); err != nil {
			glog.Error(log("config data setup failed: %s", err))
			return err
		}
		configData[confKey.namespace] = v.namespace
		configData[confKey.volSpecName] = v.volSpecName

		// copy config and attach secret
		data := map[string]string{}
		for k, v := range configData {
			data[k] = v
		}
		if err := attachSecret(v.plugin, v.namespace, data); err != nil {
			glog.Error(log("failed to load secret: %v", err))
			return err
		}

		mgr, err := newSioMgr(data, v.plugin.host.GetExec(v.plugin.GetPluginName()))
		if err != nil {
			glog.Error(log("failed while setting scaleio mgr from config: %v", err))
			return err
		}
		v.sioMgr = mgr
	}
	return nil
}

func (v *sioVolume) setSioMgrFromSpec() error {
	glog.V(4).Info(log("setting sio manager from spec"))
	if v.sioMgr == nil {
		// get config data form spec volume source
		configData := map[string]string{}
		mapVolumeSource(configData, v.source)
		if err := validateConfigs(configData); err != nil {
			glog.Error(log("config setup failed: %s", err))
			return err
		}
		configData[confKey.namespace] = v.namespace
		configData[confKey.volSpecName] = v.volSpecName

		// attach secret object to config data
		if err := attachSecret(v.plugin, v.namespace, configData); err != nil {
			glog.Error(log("failed to load secret: %v", err))
			return err
		}

		mgr, err := newSioMgr(configData, v.plugin.host.GetExec(v.plugin.GetPluginName()))
		if err != nil {
			glog.Error(log("failed to reset sio manager: %v", err))
			return err
		}
		v.sioMgr = mgr
	}
	return nil
}

func (v *sioVolume) generateName(prefix string, size int) string {
	return fmt.Sprintf("%s-%s", prefix, strings.Replace(string(uuid.NewUUID()), "-", "", -1)[0:size])
}
