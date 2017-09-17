/*
Copyright 2016 The Kubernetes Authors.

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

// Package volumehelper contains consts and helper methods used by various
// volume components (attach/detach controller, kubelet, etc.).
package volumehelper

import (
	"fmt"
	"strings"

	"k8s.io/api/core/v1"
	"k8s.io/kubernetes/pkg/util/mount"
	"k8s.io/kubernetes/pkg/volume"
	"k8s.io/kubernetes/pkg/volume/util/types"
)

const (
	// ControllerManagedAttachAnnotation is the key of the annotation on Node
	// objects that indicates attach/detach operations for the node should be
	// managed by the attach/detach controller
	ControllerManagedAttachAnnotation string = "volumes.kubernetes.io/controller-managed-attach-detach"

	// KeepTerminatedPodVolumesAnnotation is the key of the annotation on Node
	// that decides if pod volumes are unmounted when pod is terminated
	KeepTerminatedPodVolumesAnnotation string = "volumes.kubernetes.io/keep-terminated-pod-volumes"

	// VolumeGidAnnotationKey is the of the annotation on the PersistentVolume
	// object that specifies a supplemental GID.
	VolumeGidAnnotationKey = "pv.beta.kubernetes.io/gid"

	// VolumeDynamicallyCreatedByKey is the key of the annotation on PersistentVolume
	// object created dynamically
	VolumeDynamicallyCreatedByKey = "kubernetes.io/createdby"
)

// GetUniquePodName returns a unique identifier to reference a pod by
func GetUniquePodName(pod *v1.Pod) types.UniquePodName {
	return types.UniquePodName(pod.UID)
}

// GetUniqueVolumeName returns a unique name representing the volume/plugin.
// Caller should ensure that volumeName is a name/ID uniquely identifying the
// actual backing device, directory, path, etc. for a particular volume.
// The returned name can be used to uniquely reference the volume, for example,
// to prevent operations (attach/detach or mount/unmount) from being triggered
// on the same volume.
func GetUniqueVolumeName(pluginName, volumeName string) v1.UniqueVolumeName {
	return v1.UniqueVolumeName(fmt.Sprintf("%s/%s", pluginName, volumeName))
}

// GetUniqueVolumeNameForNonAttachableVolume returns the unique volume name
// for a non-attachable volume.
func GetUniqueVolumeNameForNonAttachableVolume(
	podName types.UniquePodName, volumePlugin volume.VolumePlugin, volumeSpec *volume.Spec) v1.UniqueVolumeName {
	return v1.UniqueVolumeName(
		fmt.Sprintf("%s/%v-%s", volumePlugin.GetPluginName(), podName, volumeSpec.Name()))
}

// GetUniqueVolumeNameFromSpec uses the given VolumePlugin to generate a unique
// name representing the volume defined in the specified volume spec.
// This returned name can be used to uniquely reference the actual backing
// device, directory, path, etc. referenced by the given volumeSpec.
// If the given plugin does not support the volume spec, this returns an error.
func GetUniqueVolumeNameFromSpec(
	volumePlugin volume.VolumePlugin,
	volumeSpec *volume.Spec) (v1.UniqueVolumeName, error) {
	if volumePlugin == nil {
		return "", fmt.Errorf(
			"volumePlugin should not be nil. volumeSpec.Name=%q",
			volumeSpec.Name())
	}

	volumeName, err := volumePlugin.GetVolumeName(volumeSpec)
	if err != nil || volumeName == "" {
		return "", fmt.Errorf(
			"failed to GetVolumeName from volumePlugin for volumeSpec %q err=%v",
			volumeSpec.Name(),
			err)
	}

	return GetUniqueVolumeName(
			volumePlugin.GetPluginName(),
			volumeName),
		nil
}

// IsPodTerminated checks if pod is terminated
func IsPodTerminated(pod *v1.Pod, podStatus v1.PodStatus) bool {
	return podStatus.Phase == v1.PodFailed || podStatus.Phase == v1.PodSucceeded || (pod.DeletionTimestamp != nil && notRunning(podStatus.ContainerStatuses))
}

// notRunning returns true if every status is terminated or waiting, or the status list
// is empty.
func notRunning(statuses []v1.ContainerStatus) bool {
	for _, status := range statuses {
		if status.State.Terminated == nil && status.State.Waiting == nil {
			return false
		}
	}
	return true
}

// SplitUniqueName splits the unique name to plugin name and volume name strings. It expects the uniqueName to follow
// the fromat plugin_name/volume_name and the plugin name must be namespaced as descibed by the plugin interface,
// i.e. namespace/plugin containing exactly one '/'. This means the unique name will always be in the form of
// plugin_namespace/plugin/volume_name, see k8s.io/kubernetes/pkg/volume/plugins.go VolumePlugin interface
// description and pkg/volume/util/volumehelper/volumehelper.go GetUniqueVolumeNameFromSpec that constructs
// the unique volume names.
func SplitUniqueName(uniqueName v1.UniqueVolumeName) (string, string, error) {
	components := strings.SplitN(string(uniqueName), "/", 3)
	if len(components) != 3 {
		return "", "", fmt.Errorf("cannot split volume unique name %s to plugin/volume components", uniqueName)
	}
	pluginName := fmt.Sprintf("%s/%s", components[0], components[1])
	return pluginName, components[2], nil
}

// NewSafeFormatAndMountFromHost creates a new SafeFormatAndMount with Mounter
// and Exec taken from given VolumeHost.
func NewSafeFormatAndMountFromHost(pluginName string, host volume.VolumeHost) *mount.SafeFormatAndMount {
	mounter := host.GetMounter(pluginName)
	exec := host.GetExec(pluginName)
	return &mount.SafeFormatAndMount{Interface: mounter, Exec: exec}
}
