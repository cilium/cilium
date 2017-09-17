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

package volume

import (
	"time"

	"k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// Volume represents a directory used by pods or hosts on a node. All method
// implementations of methods in the volume interface must be idempotent.
type Volume interface {
	// GetPath returns the path to which the volume should be mounted for the
	// pod.
	GetPath() string

	// MetricsProvider embeds methods for exposing metrics (e.g.
	// used, available space).
	MetricsProvider
}

// MetricsProvider exposes metrics (e.g. used,available space) related to a
// Volume.
type MetricsProvider interface {
	// GetMetrics returns the Metrics for the Volume. Maybe expensive for
	// some implementations.
	GetMetrics() (*Metrics, error)
}

// Metrics represents the used and available bytes of the Volume.
type Metrics struct {
	// The time at which these stats were updated.
	Time metav1.Time

	// Used represents the total bytes used by the Volume.
	// Note: For block devices this maybe more than the total size of the files.
	Used *resource.Quantity

	// Capacity represents the total capacity (bytes) of the volume's
	// underlying storage. For Volumes that share a filesystem with the host
	// (e.g. emptydir, hostpath) this is the size of the underlying storage,
	// and will not equal Used + Available as the fs is shared.
	Capacity *resource.Quantity

	// Available represents the storage space available (bytes) for the
	// Volume. For Volumes that share a filesystem with the host (e.g.
	// emptydir, hostpath), this is the available space on the underlying
	// storage, and is shared with host processes and other Volumes.
	Available *resource.Quantity

	// InodesUsed represents the total inodes used by the Volume.
	InodesUsed *resource.Quantity

	// Inodes represents the total number of inodes available in the volume.
	// For volumes that share a filesystem with the host (e.g. emptydir, hostpath),
	// this is the inodes available in the underlying storage,
	// and will not equal InodesUsed + InodesFree as the fs is shared.
	Inodes *resource.Quantity

	// InodesFree represent the inodes available for the volume.  For Volumes that share
	// a filesystem with the host (e.g. emptydir, hostpath), this is the free inodes
	// on the underlying storage, and is shared with host processes and other volumes
	InodesFree *resource.Quantity
}

// Attributes represents the attributes of this mounter.
type Attributes struct {
	ReadOnly        bool
	Managed         bool
	SupportsSELinux bool
}

// Mounter interface provides methods to set up/mount the volume.
type Mounter interface {
	// Uses Interface to provide the path for Docker binds.
	Volume

	// CanMount is called immediately prior to Setup to check if
	// the required components (binaries, etc.) are available on
	// the underlying node to complete the subsequent SetUp (mount)
	// operation. If CanMount returns error, the mount operation is
	// aborted and an event is generated indicating that the node
	// does not have the required binaries to complete the mount.
	// If CanMount succeeds, the mount operation continues
	// normally. The CanMount check can be enabled or disabled
	// using the experimental-check-mount-binaries binary flag
	CanMount() error

	// SetUp prepares and mounts/unpacks the volume to a
	// self-determined directory path. The mount point and its
	// content should be owned by 'fsGroup' so that it can be
	// accessed by the pod. This may be called more than once, so
	// implementations must be idempotent.
	SetUp(fsGroup *int64) error
	// SetUpAt prepares and mounts/unpacks the volume to the
	// specified directory path, which may or may not exist yet.
	// The mount point and its content should be owned by
	// 'fsGroup' so that it can be accessed by the pod. This may
	// be called more than once, so implementations must be
	// idempotent.
	SetUpAt(dir string, fsGroup *int64) error
	// GetAttributes returns the attributes of the mounter.
	GetAttributes() Attributes
}

// Unmounter interface provides methods to cleanup/unmount the volumes.
type Unmounter interface {
	Volume
	// TearDown unmounts the volume from a self-determined directory and
	// removes traces of the SetUp procedure.
	TearDown() error
	// TearDown unmounts the volume from the specified directory and
	// removes traces of the SetUp procedure.
	TearDownAt(dir string) error
}

// Provisioner is an interface that creates templates for PersistentVolumes
// and can create the volume as a new resource in the infrastructure provider.
type Provisioner interface {
	// Provision creates the resource by allocating the underlying volume in a
	// storage system. This method should block until completion and returns
	// PersistentVolume representing the created storage resource.
	Provision() (*v1.PersistentVolume, error)
}

// Deleter removes the resource from the underlying storage provider. Calls
// to this method should block until the deletion is complete. Any error
// returned indicates the volume has failed to be reclaimed. A nil return
// indicates success.
type Deleter interface {
	Volume
	// This method should block until completion.
	// deletedVolumeInUseError returned from this function will not be reported
	// as error and it will be sent as "Info" event to the PV being deleted. The
	// volume controller will retry deleting the volume in the next periodic
	// sync. This can be used to postpone deletion of a volume that is being
	// detached from a node. Deletion of such volume would fail anyway and such
	// error would confuse users.
	Delete() error
}

// Attacher can attach a volume to a node.
type Attacher interface {
	// Attaches the volume specified by the given spec to the node with the given Name.
	// On success, returns the device path where the device was attached on the
	// node.
	Attach(spec *Spec, nodeName types.NodeName) (string, error)

	// VolumesAreAttached checks whether the list of volumes still attached to the specified
	// node. It returns a map which maps from the volume spec to the checking result.
	// If an error is occurred during checking, the error will be returned
	VolumesAreAttached(specs []*Spec, nodeName types.NodeName) (map[*Spec]bool, error)

	// WaitForAttach blocks until the device is attached to this
	// node. If it successfully attaches, the path to the device
	// is returned. Otherwise, if the device does not attach after
	// the given timeout period, an error will be returned.
	WaitForAttach(spec *Spec, devicePath string, pod *v1.Pod, timeout time.Duration) (string, error)

	// GetDeviceMountPath returns a path where the device should
	// be mounted after it is attached. This is a global mount
	// point which should be bind mounted for individual volumes.
	GetDeviceMountPath(spec *Spec) (string, error)

	// MountDevice mounts the disk to a global path which
	// individual pods can then bind mount
	MountDevice(spec *Spec, devicePath string, deviceMountPath string) error
}

type BulkVolumeVerifier interface {
	// BulkVerifyVolumes checks whether the list of volumes still attached to the
	// the clusters in the node. It returns a map which maps from the volume spec to the checking result.
	// If an error occurs during check - error should be returned and volume on nodes
	// should be assumed as still attached.
	BulkVerifyVolumes(volumesByNode map[types.NodeName][]*Spec) (map[types.NodeName]map[*Spec]bool, error)
}

// Detacher can detach a volume from a node.
type Detacher interface {
	// Detach the given device from the node with the given Name.
	Detach(deviceName string, nodeName types.NodeName) error

	// UnmountDevice unmounts the global mount of the disk. This
	// should only be called once all bind mounts have been
	// unmounted.
	UnmountDevice(deviceMountPath string) error
}

// NewDeletedVolumeInUseError returns a new instance of DeletedVolumeInUseError
// error.
func NewDeletedVolumeInUseError(message string) error {
	return deletedVolumeInUseError(message)
}

type deletedVolumeInUseError string

var _ error = deletedVolumeInUseError("")

// IsDeletedVolumeInUse returns true if an error returned from Delete() is
// deletedVolumeInUseError
func IsDeletedVolumeInUse(err error) bool {
	switch err.(type) {
	case deletedVolumeInUseError:
		return true
	default:
		return false
	}
}

func (err deletedVolumeInUseError) Error() string {
	return string(err)
}
