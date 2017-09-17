/*
Copyright 2014 The Kubernetes Authors.

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

package gce_pd

import (
	"fmt"
	"os"
	"path"
	"strconv"

	"github.com/golang/glog"
	"k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/kubernetes/pkg/util/mount"
	kstrings "k8s.io/kubernetes/pkg/util/strings"
	"k8s.io/kubernetes/pkg/volume"
	"k8s.io/kubernetes/pkg/volume/util"
	"k8s.io/kubernetes/pkg/volume/util/volumehelper"
)

// This is the primary entrypoint for volume plugins.
func ProbeVolumePlugins() []volume.VolumePlugin {
	return []volume.VolumePlugin{&gcePersistentDiskPlugin{nil}}
}

type gcePersistentDiskPlugin struct {
	host volume.VolumeHost
}

var _ volume.VolumePlugin = &gcePersistentDiskPlugin{}
var _ volume.PersistentVolumePlugin = &gcePersistentDiskPlugin{}
var _ volume.DeletableVolumePlugin = &gcePersistentDiskPlugin{}
var _ volume.ProvisionableVolumePlugin = &gcePersistentDiskPlugin{}

const (
	gcePersistentDiskPluginName = "kubernetes.io/gce-pd"
)

func getPath(uid types.UID, volName string, host volume.VolumeHost) string {
	return host.GetPodVolumeDir(uid, kstrings.EscapeQualifiedNameForDisk(gcePersistentDiskPluginName), volName)
}

func (plugin *gcePersistentDiskPlugin) Init(host volume.VolumeHost) error {
	plugin.host = host
	return nil
}

func (plugin *gcePersistentDiskPlugin) GetPluginName() string {
	return gcePersistentDiskPluginName
}

func (plugin *gcePersistentDiskPlugin) GetVolumeName(spec *volume.Spec) (string, error) {
	volumeSource, _, err := getVolumeSource(spec)
	if err != nil {
		return "", err
	}

	return volumeSource.PDName, nil
}

func (plugin *gcePersistentDiskPlugin) CanSupport(spec *volume.Spec) bool {
	return (spec.PersistentVolume != nil && spec.PersistentVolume.Spec.GCEPersistentDisk != nil) ||
		(spec.Volume != nil && spec.Volume.GCEPersistentDisk != nil)
}

func (plugin *gcePersistentDiskPlugin) RequiresRemount() bool {
	return false
}

func (plugin *gcePersistentDiskPlugin) SupportsMountOption() bool {
	return true
}

func (plugin *gcePersistentDiskPlugin) SupportsBulkVolumeVerification() bool {
	return false
}

func (plugin *gcePersistentDiskPlugin) GetAccessModes() []v1.PersistentVolumeAccessMode {
	return []v1.PersistentVolumeAccessMode{
		v1.ReadWriteOnce,
		v1.ReadOnlyMany,
	}
}

func (plugin *gcePersistentDiskPlugin) NewMounter(spec *volume.Spec, pod *v1.Pod, _ volume.VolumeOptions) (volume.Mounter, error) {
	// Inject real implementations here, test through the internal function.
	return plugin.newMounterInternal(spec, pod.UID, &GCEDiskUtil{}, plugin.host.GetMounter(plugin.GetPluginName()))
}

func getVolumeSource(
	spec *volume.Spec) (*v1.GCEPersistentDiskVolumeSource, bool, error) {
	if spec.Volume != nil && spec.Volume.GCEPersistentDisk != nil {
		return spec.Volume.GCEPersistentDisk, spec.Volume.GCEPersistentDisk.ReadOnly, nil
	} else if spec.PersistentVolume != nil &&
		spec.PersistentVolume.Spec.GCEPersistentDisk != nil {
		return spec.PersistentVolume.Spec.GCEPersistentDisk, spec.ReadOnly, nil
	}

	return nil, false, fmt.Errorf("Spec does not reference a GCE volume type")
}

func (plugin *gcePersistentDiskPlugin) newMounterInternal(spec *volume.Spec, podUID types.UID, manager pdManager, mounter mount.Interface) (volume.Mounter, error) {
	// GCEPDs used directly in a pod have a ReadOnly flag set by the pod author.
	// GCEPDs used as a PersistentVolume gets the ReadOnly flag indirectly through the persistent-claim volume used to mount the PV
	volumeSource, readOnly, err := getVolumeSource(spec)
	if err != nil {
		return nil, err
	}

	pdName := volumeSource.PDName
	partition := ""
	if volumeSource.Partition != 0 {
		partition = strconv.Itoa(int(volumeSource.Partition))
	}

	return &gcePersistentDiskMounter{
		gcePersistentDisk: &gcePersistentDisk{
			podUID:          podUID,
			volName:         spec.Name(),
			pdName:          pdName,
			partition:       partition,
			mounter:         mounter,
			manager:         manager,
			plugin:          plugin,
			MetricsProvider: volume.NewMetricsStatFS(getPath(podUID, spec.Name(), plugin.host)),
		},
		readOnly: readOnly}, nil
}

func (plugin *gcePersistentDiskPlugin) NewUnmounter(volName string, podUID types.UID) (volume.Unmounter, error) {
	// Inject real implementations here, test through the internal function.
	return plugin.newUnmounterInternal(volName, podUID, &GCEDiskUtil{}, plugin.host.GetMounter(plugin.GetPluginName()))
}

func (plugin *gcePersistentDiskPlugin) newUnmounterInternal(volName string, podUID types.UID, manager pdManager, mounter mount.Interface) (volume.Unmounter, error) {
	return &gcePersistentDiskUnmounter{&gcePersistentDisk{
		podUID:          podUID,
		volName:         volName,
		manager:         manager,
		mounter:         mounter,
		plugin:          plugin,
		MetricsProvider: volume.NewMetricsStatFS(getPath(podUID, volName, plugin.host)),
	}}, nil
}

func (plugin *gcePersistentDiskPlugin) NewDeleter(spec *volume.Spec) (volume.Deleter, error) {
	return plugin.newDeleterInternal(spec, &GCEDiskUtil{})
}

func (plugin *gcePersistentDiskPlugin) newDeleterInternal(spec *volume.Spec, manager pdManager) (volume.Deleter, error) {
	if spec.PersistentVolume != nil && spec.PersistentVolume.Spec.GCEPersistentDisk == nil {
		return nil, fmt.Errorf("spec.PersistentVolumeSource.GCEPersistentDisk is nil")
	}
	return &gcePersistentDiskDeleter{
		gcePersistentDisk: &gcePersistentDisk{
			volName: spec.Name(),
			pdName:  spec.PersistentVolume.Spec.GCEPersistentDisk.PDName,
			manager: manager,
			plugin:  plugin,
		}}, nil
}

func (plugin *gcePersistentDiskPlugin) NewProvisioner(options volume.VolumeOptions) (volume.Provisioner, error) {
	return plugin.newProvisionerInternal(options, &GCEDiskUtil{})
}

func (plugin *gcePersistentDiskPlugin) newProvisionerInternal(options volume.VolumeOptions, manager pdManager) (volume.Provisioner, error) {
	return &gcePersistentDiskProvisioner{
		gcePersistentDisk: &gcePersistentDisk{
			manager: manager,
			plugin:  plugin,
		},
		options: options,
	}, nil
}

func (plugin *gcePersistentDiskPlugin) ConstructVolumeSpec(volumeName, mountPath string) (*volume.Spec, error) {
	mounter := plugin.host.GetMounter(plugin.GetPluginName())
	pluginDir := plugin.host.GetPluginDir(plugin.GetPluginName())
	sourceName, err := mounter.GetDeviceNameFromMount(mountPath, pluginDir)
	if err != nil {
		return nil, err
	}
	gceVolume := &v1.Volume{
		Name: volumeName,
		VolumeSource: v1.VolumeSource{
			GCEPersistentDisk: &v1.GCEPersistentDiskVolumeSource{
				PDName: sourceName,
			},
		},
	}
	return volume.NewSpecFromVolume(gceVolume), nil
}

// Abstract interface to PD operations.
type pdManager interface {
	// Creates a volume
	CreateVolume(provisioner *gcePersistentDiskProvisioner) (volumeID string, volumeSizeGB int, labels map[string]string, fstype string, err error)
	// Deletes a volume
	DeleteVolume(deleter *gcePersistentDiskDeleter) error
}

// gcePersistentDisk volumes are disk resources provided by Google Compute Engine
// that are attached to the kubelet's host machine and exposed to the pod.
type gcePersistentDisk struct {
	volName string
	podUID  types.UID
	// Unique identifier of the PD, used to find the disk resource in the provider.
	pdName string
	// Specifies the partition to mount
	partition string
	// Utility interface to provision and delete disks
	manager pdManager
	// Mounter interface that provides system calls to mount the global path to the pod local path.
	mounter mount.Interface
	plugin  *gcePersistentDiskPlugin
	volume.MetricsProvider
}

type gcePersistentDiskMounter struct {
	*gcePersistentDisk
	// Specifies whether the disk will be mounted as read-only.
	readOnly bool
}

var _ volume.Mounter = &gcePersistentDiskMounter{}

func (b *gcePersistentDiskMounter) GetAttributes() volume.Attributes {
	return volume.Attributes{
		ReadOnly:        b.readOnly,
		Managed:         !b.readOnly,
		SupportsSELinux: true,
	}
}

// Checks prior to mount operations to verify that the required components (binaries, etc.)
// to mount the volume are available on the underlying node.
// If not, it returns an error
func (b *gcePersistentDiskMounter) CanMount() error {
	return nil
}

// SetUp bind mounts the disk global mount to the volume path.
func (b *gcePersistentDiskMounter) SetUp(fsGroup *int64) error {
	return b.SetUpAt(b.GetPath(), fsGroup)
}

// SetUp bind mounts the disk global mount to the give volume path.
func (b *gcePersistentDiskMounter) SetUpAt(dir string, fsGroup *int64) error {
	// TODO: handle failed mounts here.
	notMnt, err := b.mounter.IsLikelyNotMountPoint(dir)
	glog.V(4).Infof("GCE PersistentDisk set up: Dir (%s) PD name (%q) Mounted (%t) Error (%v), ReadOnly (%t)", dir, b.pdName, !notMnt, err, b.readOnly)
	if err != nil && !os.IsNotExist(err) {
		glog.Errorf("cannot validate mount point: %s %v", dir, err)
		return err
	}
	if !notMnt {
		return nil
	}

	if err := os.MkdirAll(dir, 0750); err != nil {
		glog.Errorf("mkdir failed on disk %s (%v)", dir, err)
		return err
	}

	// Perform a bind mount to the full path to allow duplicate mounts of the same PD.
	options := []string{"bind"}
	if b.readOnly {
		options = append(options, "ro")
	}

	globalPDPath := makeGlobalPDName(b.plugin.host, b.pdName)
	glog.V(4).Infof("attempting to mount %s", dir)

	err = b.mounter.Mount(globalPDPath, dir, "", options)
	if err != nil {
		notMnt, mntErr := b.mounter.IsLikelyNotMountPoint(dir)
		if mntErr != nil {
			glog.Errorf("IsLikelyNotMountPoint check failed: %v", mntErr)
			return err
		}
		if !notMnt {
			if mntErr = b.mounter.Unmount(dir); mntErr != nil {
				glog.Errorf("Failed to unmount: %v", mntErr)
				return err
			}
			notMnt, mntErr := b.mounter.IsLikelyNotMountPoint(dir)
			if mntErr != nil {
				glog.Errorf("IsLikelyNotMountPoint check failed: %v", mntErr)
				return err
			}
			if !notMnt {
				// This is very odd, we don't expect it.  We'll try again next sync loop.
				glog.Errorf("%s is still mounted, despite call to unmount().  Will try again next sync loop.", dir)
				return err
			}
		}
		os.Remove(dir)
		glog.Errorf("Mount of disk %s failed: %v", dir, err)
		return err
	}

	if !b.readOnly {
		volume.SetVolumeOwnership(b, fsGroup)
	}

	glog.V(4).Infof("Successfully mounted %s", dir)
	return nil
}

func makeGlobalPDName(host volume.VolumeHost, devName string) string {
	return path.Join(host.GetPluginDir(gcePersistentDiskPluginName), mount.MountsInGlobalPDPath, devName)
}

func (b *gcePersistentDiskMounter) GetPath() string {
	return getPath(b.podUID, b.volName, b.plugin.host)
}

type gcePersistentDiskUnmounter struct {
	*gcePersistentDisk
}

var _ volume.Unmounter = &gcePersistentDiskUnmounter{}

func (c *gcePersistentDiskUnmounter) GetPath() string {
	return getPath(c.podUID, c.volName, c.plugin.host)
}

// Unmounts the bind mount, and detaches the disk only if the PD
// resource was the last reference to that disk on the kubelet.
func (c *gcePersistentDiskUnmounter) TearDown() error {
	return c.TearDownAt(c.GetPath())
}

// TearDownAt unmounts the bind mount
func (c *gcePersistentDiskUnmounter) TearDownAt(dir string) error {
	return util.UnmountPath(dir, c.mounter)
}

type gcePersistentDiskDeleter struct {
	*gcePersistentDisk
}

var _ volume.Deleter = &gcePersistentDiskDeleter{}

func (d *gcePersistentDiskDeleter) GetPath() string {
	return getPath(d.podUID, d.volName, d.plugin.host)
}

func (d *gcePersistentDiskDeleter) Delete() error {
	return d.manager.DeleteVolume(d)
}

type gcePersistentDiskProvisioner struct {
	*gcePersistentDisk
	options volume.VolumeOptions
}

var _ volume.Provisioner = &gcePersistentDiskProvisioner{}

func (c *gcePersistentDiskProvisioner) Provision() (*v1.PersistentVolume, error) {
	if !volume.AccessModesContainedInAll(c.plugin.GetAccessModes(), c.options.PVC.Spec.AccessModes) {
		return nil, fmt.Errorf("invalid AccessModes %v: only AccessModes %v are supported", c.options.PVC.Spec.AccessModes, c.plugin.GetAccessModes())
	}

	volumeID, sizeGB, labels, fstype, err := c.manager.CreateVolume(c)
	if err != nil {
		return nil, err
	}

	if fstype == "" {
		fstype = "ext4"
	}

	pv := &v1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{
			Name:   c.options.PVName,
			Labels: map[string]string{},
			Annotations: map[string]string{
				volumehelper.VolumeDynamicallyCreatedByKey: "gce-pd-dynamic-provisioner",
			},
		},
		Spec: v1.PersistentVolumeSpec{
			PersistentVolumeReclaimPolicy: c.options.PersistentVolumeReclaimPolicy,
			AccessModes:                   c.options.PVC.Spec.AccessModes,
			Capacity: v1.ResourceList{
				v1.ResourceName(v1.ResourceStorage): resource.MustParse(fmt.Sprintf("%dGi", sizeGB)),
			},
			PersistentVolumeSource: v1.PersistentVolumeSource{
				GCEPersistentDisk: &v1.GCEPersistentDiskVolumeSource{
					PDName:    volumeID,
					Partition: 0,
					ReadOnly:  false,
					FSType:    fstype,
				},
			},
			MountOptions: c.options.MountOptions,
		},
	}
	if len(c.options.PVC.Spec.AccessModes) == 0 {
		pv.Spec.AccessModes = c.plugin.GetAccessModes()
	}

	if len(labels) != 0 {
		if pv.Labels == nil {
			pv.Labels = make(map[string]string)
		}
		for k, v := range labels {
			pv.Labels[k] = v
		}
	}

	return pv, nil
}
