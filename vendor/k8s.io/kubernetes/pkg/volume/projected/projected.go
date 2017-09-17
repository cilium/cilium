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

package projected

import (
	"fmt"
	"sort"
	"strings"

	"github.com/golang/glog"
	"k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	utilstrings "k8s.io/kubernetes/pkg/util/strings"
	"k8s.io/kubernetes/pkg/volume"
	"k8s.io/kubernetes/pkg/volume/configmap"
	"k8s.io/kubernetes/pkg/volume/downwardapi"
	"k8s.io/kubernetes/pkg/volume/secret"
	volumeutil "k8s.io/kubernetes/pkg/volume/util"
)

// ProbeVolumePlugins is the entry point for plugin detection in a package.
func ProbeVolumePlugins() []volume.VolumePlugin {
	return []volume.VolumePlugin{&projectedPlugin{}}
}

const (
	projectedPluginName = "kubernetes.io/projected"
)

type projectedPlugin struct {
	host         volume.VolumeHost
	getSecret    func(namespace, name string) (*v1.Secret, error)
	getConfigMap func(namespace, name string) (*v1.ConfigMap, error)
}

var _ volume.VolumePlugin = &projectedPlugin{}

func wrappedVolumeSpec() volume.Spec {
	return volume.Spec{
		Volume: &v1.Volume{
			VolumeSource: v1.VolumeSource{
				EmptyDir: &v1.EmptyDirVolumeSource{Medium: v1.StorageMediumMemory},
			},
		},
	}
}

func getPath(uid types.UID, volName string, host volume.VolumeHost) string {
	return host.GetPodVolumeDir(uid, utilstrings.EscapeQualifiedNameForDisk(projectedPluginName), volName)
}

func (plugin *projectedPlugin) Init(host volume.VolumeHost) error {
	plugin.host = host
	plugin.getSecret = host.GetSecretFunc()
	plugin.getConfigMap = host.GetConfigMapFunc()
	return nil
}

func (plugin *projectedPlugin) GetPluginName() string {
	return projectedPluginName
}

func (plugin *projectedPlugin) GetVolumeName(spec *volume.Spec) (string, error) {
	_, _, err := getVolumeSource(spec)
	if err != nil {
		return "", err
	}

	return spec.Name(), nil
}

func (plugin *projectedPlugin) CanSupport(spec *volume.Spec) bool {
	return spec.Volume != nil && spec.Volume.Projected != nil
}

func (plugin *projectedPlugin) RequiresRemount() bool {
	return true
}

func (plugin *projectedPlugin) SupportsMountOption() bool {
	return false
}

func (plugin *projectedPlugin) SupportsBulkVolumeVerification() bool {
	return false
}

func (plugin *projectedPlugin) NewMounter(spec *volume.Spec, pod *v1.Pod, opts volume.VolumeOptions) (volume.Mounter, error) {
	return &projectedVolumeMounter{
		projectedVolume: &projectedVolume{
			volName: spec.Name(),
			sources: spec.Volume.Projected.Sources,
			podUID:  pod.UID,
			plugin:  plugin,
		},
		source: *spec.Volume.Projected,
		pod:    pod,
		opts:   &opts,
	}, nil
}

func (plugin *projectedPlugin) NewUnmounter(volName string, podUID types.UID) (volume.Unmounter, error) {
	return &projectedVolumeUnmounter{
		&projectedVolume{
			volName: volName,
			podUID:  podUID,
			plugin:  plugin,
		},
	}, nil
}

func (plugin *projectedPlugin) ConstructVolumeSpec(volumeName, mountPath string) (*volume.Spec, error) {
	projectedVolume := &v1.Volume{
		Name: volumeName,
		VolumeSource: v1.VolumeSource{
			Projected: &v1.ProjectedVolumeSource{},
		},
	}

	return volume.NewSpecFromVolume(projectedVolume), nil
}

type projectedVolume struct {
	volName string
	sources []v1.VolumeProjection
	podUID  types.UID
	plugin  *projectedPlugin
	volume.MetricsNil
}

var _ volume.Volume = &projectedVolume{}

func (sv *projectedVolume) GetPath() string {
	return getPath(sv.podUID, sv.volName, sv.plugin.host)
}

type projectedVolumeMounter struct {
	*projectedVolume

	source v1.ProjectedVolumeSource
	pod    *v1.Pod
	opts   *volume.VolumeOptions
}

var _ volume.Mounter = &projectedVolumeMounter{}

func (sv *projectedVolume) GetAttributes() volume.Attributes {
	return volume.Attributes{
		ReadOnly:        true,
		Managed:         true,
		SupportsSELinux: true,
	}

}

// Checks prior to mount operations to verify that the required components (binaries, etc.)
// to mount the volume are available on the underlying node.
// If not, it returns an error
func (s *projectedVolumeMounter) CanMount() error {
	return nil
}

func (s *projectedVolumeMounter) SetUp(fsGroup *int64) error {
	return s.SetUpAt(s.GetPath(), fsGroup)
}

func (s *projectedVolumeMounter) SetUpAt(dir string, fsGroup *int64) error {
	glog.V(3).Infof("Setting up volume %v for pod %v at %v", s.volName, s.pod.UID, dir)

	wrapped, err := s.plugin.host.NewWrapperMounter(s.volName, wrappedVolumeSpec(), s.pod, *s.opts)
	if err != nil {
		return err
	}
	if err := wrapped.SetUpAt(dir, fsGroup); err != nil {
		return err
	}

	data, err := s.collectData()
	if err != nil {
		glog.Errorf("Error preparing data for projected volume %v for pod %v/%v: %s", s.volName, s.pod.Namespace, s.pod.Name, err.Error())
		return err
	}

	writerContext := fmt.Sprintf("pod %v/%v volume %v", s.pod.Namespace, s.pod.Name, s.volName)
	writer, err := volumeutil.NewAtomicWriter(dir, writerContext)
	if err != nil {
		glog.Errorf("Error creating atomic writer: %v", err)
		return err
	}

	err = writer.Write(data)
	if err != nil {
		glog.Errorf("Error writing payload to dir: %v", err)
		return err
	}

	err = volume.SetVolumeOwnership(s, fsGroup)
	if err != nil {
		glog.Errorf("Error applying volume ownership settings for group: %v", fsGroup)
		return err
	}

	return nil
}

func (s *projectedVolumeMounter) collectData() (map[string]volumeutil.FileProjection, error) {
	if s.source.DefaultMode == nil {
		return nil, fmt.Errorf("No defaultMode used, not even the default value for it")
	}

	kubeClient := s.plugin.host.GetKubeClient()
	if kubeClient == nil {
		return nil, fmt.Errorf("Cannot setup projected volume %v because kube client is not configured", s.volName)
	}

	errlist := []error{}
	payload := make(map[string]volumeutil.FileProjection)
	for _, source := range s.source.Sources {
		if source.Secret != nil {
			optional := source.Secret.Optional != nil && *source.Secret.Optional
			secretapi, err := s.plugin.getSecret(s.pod.Namespace, source.Secret.Name)
			if err != nil {
				if !(errors.IsNotFound(err) && optional) {
					glog.Errorf("Couldn't get secret %v/%v: %v", s.pod.Namespace, source.Secret.Name, err)
					errlist = append(errlist, err)
					continue
				}
				secretapi = &v1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: s.pod.Namespace,
						Name:      source.Secret.Name,
					},
				}
			}
			secretPayload, err := secret.MakePayload(source.Secret.Items, secretapi, s.source.DefaultMode, optional)
			if err != nil {
				glog.Errorf("Couldn't get secret payload %v/%v: %v", s.pod.Namespace, source.Secret.Name, err)
				errlist = append(errlist, err)
				continue
			}
			for k, v := range secretPayload {
				payload[k] = v
			}
		} else if source.ConfigMap != nil {
			optional := source.ConfigMap.Optional != nil && *source.ConfigMap.Optional
			configMap, err := s.plugin.getConfigMap(s.pod.Namespace, source.ConfigMap.Name)
			if err != nil {
				if !(errors.IsNotFound(err) && optional) {
					glog.Errorf("Couldn't get configMap %v/%v: %v", s.pod.Namespace, source.ConfigMap.Name, err)
					errlist = append(errlist, err)
					continue
				}
				configMap = &v1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: s.pod.Namespace,
						Name:      source.ConfigMap.Name,
					},
				}
			}
			configMapPayload, err := configmap.MakePayload(source.ConfigMap.Items, configMap, s.source.DefaultMode, optional)
			if err != nil {
				glog.Errorf("Couldn't get configMap payload %v/%v: %v", s.pod.Namespace, source.ConfigMap.Name, err)
				errlist = append(errlist, err)
				continue
			}
			for k, v := range configMapPayload {
				payload[k] = v
			}
		} else if source.DownwardAPI != nil {
			downwardAPIPayload, err := downwardapi.CollectData(source.DownwardAPI.Items, s.pod, s.plugin.host, s.source.DefaultMode)
			if err != nil {
				errlist = append(errlist, err)
				continue
			}
			for k, v := range downwardAPIPayload {
				payload[k] = v
			}
		}
	}
	return payload, utilerrors.NewAggregate(errlist)
}

func sortLines(values string) string {
	splitted := strings.Split(values, "\n")
	sort.Strings(splitted)
	return strings.Join(splitted, "\n")
}

type projectedVolumeUnmounter struct {
	*projectedVolume
}

var _ volume.Unmounter = &projectedVolumeUnmounter{}

func (c *projectedVolumeUnmounter) TearDown() error {
	return c.TearDownAt(c.GetPath())
}

func (c *projectedVolumeUnmounter) TearDownAt(dir string) error {
	glog.V(3).Infof("Tearing down volume %v for pod %v at %v", c.volName, c.podUID, dir)

	wrapped, err := c.plugin.host.NewWrapperUnmounter(c.volName, wrappedVolumeSpec(), c.podUID)
	if err != nil {
		return err
	}
	return wrapped.TearDownAt(dir)
}

func getVolumeSource(spec *volume.Spec) (*v1.ProjectedVolumeSource, bool, error) {
	var readOnly bool
	var volumeSource *v1.ProjectedVolumeSource

	if spec.Volume != nil && spec.Volume.Projected != nil {
		volumeSource = spec.Volume.Projected
		readOnly = spec.ReadOnly
	}

	return volumeSource, readOnly, fmt.Errorf("Spec does not reference a projected volume type")
}
