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

package kubelet

import (
	"fmt"
	"net"

	"k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/kubernetes/pkg/cloudprovider"
	"k8s.io/kubernetes/pkg/kubelet/configmap"
	"k8s.io/kubernetes/pkg/kubelet/secret"
	"k8s.io/kubernetes/pkg/util/io"
	"k8s.io/kubernetes/pkg/util/mount"
	"k8s.io/kubernetes/pkg/volume"
)

// NewInitializedVolumePluginMgr returns a new instance of
// volume.VolumePluginMgr initialized with kubelets implementation of the
// volume.VolumeHost interface.
//
// kubelet - used by VolumeHost methods to expose kubelet specific parameters
// plugins - used to initialize volumePluginMgr
func NewInitializedVolumePluginMgr(
	kubelet *Kubelet,
	secretManager secret.Manager,
	configMapManager configmap.Manager,
	plugins []volume.VolumePlugin,
	prober volume.DynamicPluginProber) (*volume.VolumePluginMgr, error) {
	kvh := &kubeletVolumeHost{
		kubelet:          kubelet,
		volumePluginMgr:  volume.VolumePluginMgr{},
		secretManager:    secretManager,
		configMapManager: configMapManager,
	}

	if err := kvh.volumePluginMgr.InitPlugins(plugins, prober, kvh); err != nil {
		return nil, fmt.Errorf(
			"Could not initialize volume plugins for KubeletVolumePluginMgr: %v",
			err)
	}

	return &kvh.volumePluginMgr, nil
}

// Compile-time check to ensure kubeletVolumeHost implements the VolumeHost interface
var _ volume.VolumeHost = &kubeletVolumeHost{}

func (kvh *kubeletVolumeHost) GetPluginDir(pluginName string) string {
	return kvh.kubelet.getPluginDir(pluginName)
}

type kubeletVolumeHost struct {
	kubelet          *Kubelet
	volumePluginMgr  volume.VolumePluginMgr
	secretManager    secret.Manager
	configMapManager configmap.Manager
}

func (kvh *kubeletVolumeHost) GetPodVolumeDir(podUID types.UID, pluginName string, volumeName string) string {
	return kvh.kubelet.getPodVolumeDir(podUID, pluginName, volumeName)
}

func (kvh *kubeletVolumeHost) GetPodPluginDir(podUID types.UID, pluginName string) string {
	return kvh.kubelet.getPodPluginDir(podUID, pluginName)
}

func (kvh *kubeletVolumeHost) GetKubeClient() clientset.Interface {
	return kvh.kubelet.kubeClient
}

func (kvh *kubeletVolumeHost) NewWrapperMounter(
	volName string,
	spec volume.Spec,
	pod *v1.Pod,
	opts volume.VolumeOptions) (volume.Mounter, error) {
	// The name of wrapper volume is set to "wrapped_{wrapped_volume_name}"
	wrapperVolumeName := "wrapped_" + volName
	if spec.Volume != nil {
		spec.Volume.Name = wrapperVolumeName
	}

	return kvh.kubelet.newVolumeMounterFromPlugins(&spec, pod, opts)
}

func (kvh *kubeletVolumeHost) NewWrapperUnmounter(volName string, spec volume.Spec, podUID types.UID) (volume.Unmounter, error) {
	// The name of wrapper volume is set to "wrapped_{wrapped_volume_name}"
	wrapperVolumeName := "wrapped_" + volName
	if spec.Volume != nil {
		spec.Volume.Name = wrapperVolumeName
	}

	plugin, err := kvh.kubelet.volumePluginMgr.FindPluginBySpec(&spec)
	if err != nil {
		return nil, err
	}

	return plugin.NewUnmounter(spec.Name(), podUID)
}

func (kvh *kubeletVolumeHost) GetCloudProvider() cloudprovider.Interface {
	return kvh.kubelet.cloud
}

func (kvh *kubeletVolumeHost) GetMounter(pluginName string) mount.Interface {
	return kvh.kubelet.mounter
}

func (kvh *kubeletVolumeHost) GetWriter() io.Writer {
	return kvh.kubelet.writer
}

func (kvh *kubeletVolumeHost) GetHostName() string {
	return kvh.kubelet.hostname
}

func (kvh *kubeletVolumeHost) GetHostIP() (net.IP, error) {
	return kvh.kubelet.GetHostIP()
}

func (kvh *kubeletVolumeHost) GetNodeAllocatable() (v1.ResourceList, error) {
	node, err := kvh.kubelet.getNodeAnyWay()
	if err != nil {
		return nil, fmt.Errorf("error retrieving node: %v", err)
	}
	return node.Status.Allocatable, nil
}

func (kvh *kubeletVolumeHost) GetSecretFunc() func(namespace, name string) (*v1.Secret, error) {
	return kvh.secretManager.GetSecret
}

func (kvh *kubeletVolumeHost) GetConfigMapFunc() func(namespace, name string) (*v1.ConfigMap, error) {
	return kvh.configMapManager.GetConfigMap
}

func (kvh *kubeletVolumeHost) GetNodeLabels() (map[string]string, error) {
	node, err := kvh.kubelet.GetNode()
	if err != nil {
		return nil, fmt.Errorf("error retrieving node: %v", err)
	}
	return node.Labels, nil
}

func (kvh *kubeletVolumeHost) GetExec(pluginName string) mount.Exec {
	return mount.NewOsExec()
}
