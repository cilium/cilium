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

package secret

import (
	"fmt"

	"github.com/golang/glog"
	"k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ioutil "k8s.io/kubernetes/pkg/util/io"
	"k8s.io/kubernetes/pkg/util/mount"
	"k8s.io/kubernetes/pkg/util/strings"
	"k8s.io/kubernetes/pkg/volume"
	volumeutil "k8s.io/kubernetes/pkg/volume/util"
)

// ProbeVolumePlugin is the entry point for plugin detection in a package.
func ProbeVolumePlugins() []volume.VolumePlugin {
	return []volume.VolumePlugin{&secretPlugin{}}
}

const (
	secretPluginName = "kubernetes.io/secret"
)

// secretPlugin implements the VolumePlugin interface.
type secretPlugin struct {
	host      volume.VolumeHost
	getSecret func(namespace, name string) (*v1.Secret, error)
}

var _ volume.VolumePlugin = &secretPlugin{}

func wrappedVolumeSpec() volume.Spec {
	return volume.Spec{
		Volume: &v1.Volume{VolumeSource: v1.VolumeSource{EmptyDir: &v1.EmptyDirVolumeSource{Medium: v1.StorageMediumMemory}}},
	}
}

func getPath(uid types.UID, volName string, host volume.VolumeHost) string {
	return host.GetPodVolumeDir(uid, strings.EscapeQualifiedNameForDisk(secretPluginName), volName)
}

func (plugin *secretPlugin) Init(host volume.VolumeHost) error {
	plugin.host = host
	plugin.getSecret = host.GetSecretFunc()
	return nil
}

func (plugin *secretPlugin) GetPluginName() string {
	return secretPluginName
}

func (plugin *secretPlugin) GetVolumeName(spec *volume.Spec) (string, error) {
	volumeSource, _ := getVolumeSource(spec)
	if volumeSource == nil {
		return "", fmt.Errorf("Spec does not reference a Secret volume type")
	}

	return volumeSource.SecretName, nil
}

func (plugin *secretPlugin) CanSupport(spec *volume.Spec) bool {
	return spec.Volume != nil && spec.Volume.Secret != nil
}

func (plugin *secretPlugin) RequiresRemount() bool {
	return true
}

func (plugin *secretPlugin) SupportsMountOption() bool {
	return false
}

func (plugin *secretPlugin) SupportsBulkVolumeVerification() bool {
	return false
}

func (plugin *secretPlugin) NewMounter(spec *volume.Spec, pod *v1.Pod, opts volume.VolumeOptions) (volume.Mounter, error) {
	return &secretVolumeMounter{
		secretVolume: &secretVolume{
			spec.Name(),
			pod.UID,
			plugin,
			plugin.host.GetMounter(plugin.GetPluginName()),
			plugin.host.GetWriter(),
			volume.NewCachedMetrics(volume.NewMetricsDu(getPath(pod.UID, spec.Name(), plugin.host))),
		},
		source:    *spec.Volume.Secret,
		pod:       *pod,
		opts:      &opts,
		getSecret: plugin.getSecret,
	}, nil
}

func (plugin *secretPlugin) NewUnmounter(volName string, podUID types.UID) (volume.Unmounter, error) {
	return &secretVolumeUnmounter{
		&secretVolume{
			volName,
			podUID,
			plugin,
			plugin.host.GetMounter(plugin.GetPluginName()),
			plugin.host.GetWriter(),
			volume.NewCachedMetrics(volume.NewMetricsDu(getPath(podUID, volName, plugin.host))),
		},
	}, nil
}

func (plugin *secretPlugin) ConstructVolumeSpec(volName, mountPath string) (*volume.Spec, error) {
	secretVolume := &v1.Volume{
		Name: volName,
		VolumeSource: v1.VolumeSource{
			Secret: &v1.SecretVolumeSource{
				SecretName: volName,
			},
		},
	}
	return volume.NewSpecFromVolume(secretVolume), nil
}

type secretVolume struct {
	volName string
	podUID  types.UID
	plugin  *secretPlugin
	mounter mount.Interface
	writer  ioutil.Writer
	volume.MetricsProvider
}

var _ volume.Volume = &secretVolume{}

func (sv *secretVolume) GetPath() string {
	return getPath(sv.podUID, sv.volName, sv.plugin.host)
}

// secretVolumeMounter handles retrieving secrets from the API server
// and placing them into the volume on the host.
type secretVolumeMounter struct {
	*secretVolume

	source    v1.SecretVolumeSource
	pod       v1.Pod
	opts      *volume.VolumeOptions
	getSecret func(namespace, name string) (*v1.Secret, error)
}

var _ volume.Mounter = &secretVolumeMounter{}

func (sv *secretVolume) GetAttributes() volume.Attributes {
	return volume.Attributes{
		ReadOnly:        true,
		Managed:         true,
		SupportsSELinux: true,
	}
}

// Checks prior to mount operations to verify that the required components (binaries, etc.)
// to mount the volume are available on the underlying node.
// If not, it returns an error
func (b *secretVolumeMounter) CanMount() error {
	return nil
}

func (b *secretVolumeMounter) SetUp(fsGroup *int64) error {
	return b.SetUpAt(b.GetPath(), fsGroup)
}

func (b *secretVolumeMounter) SetUpAt(dir string, fsGroup *int64) error {
	glog.V(3).Infof("Setting up volume %v for pod %v at %v", b.volName, b.pod.UID, dir)

	// Wrap EmptyDir, let it do the setup.
	wrapped, err := b.plugin.host.NewWrapperMounter(b.volName, wrappedVolumeSpec(), &b.pod, *b.opts)
	if err != nil {
		return err
	}
	if err := wrapped.SetUpAt(dir, fsGroup); err != nil {
		return err
	}

	optional := b.source.Optional != nil && *b.source.Optional
	secret, err := b.getSecret(b.pod.Namespace, b.source.SecretName)
	if err != nil {
		if !(errors.IsNotFound(err) && optional) {
			glog.Errorf("Couldn't get secret %v/%v: %v", b.pod.Namespace, b.source.SecretName, err)
			return err
		}
		secret = &v1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: b.pod.Namespace,
				Name:      b.source.SecretName,
			},
		}
	}

	totalBytes := totalSecretBytes(secret)
	glog.V(3).Infof("Received secret %v/%v containing (%v) pieces of data, %v total bytes",
		b.pod.Namespace,
		b.source.SecretName,
		len(secret.Data),
		totalBytes)

	payload, err := MakePayload(b.source.Items, secret, b.source.DefaultMode, optional)
	if err != nil {
		return err
	}

	writerContext := fmt.Sprintf("pod %v/%v volume %v", b.pod.Namespace, b.pod.Name, b.volName)
	writer, err := volumeutil.NewAtomicWriter(dir, writerContext)
	if err != nil {
		glog.Errorf("Error creating atomic writer: %v", err)
		return err
	}

	err = writer.Write(payload)
	if err != nil {
		glog.Errorf("Error writing payload to dir: %v", err)
		return err
	}

	err = volume.SetVolumeOwnership(b, fsGroup)
	if err != nil {
		glog.Errorf("Error applying volume ownership settings for group: %v", fsGroup)
		return err
	}

	return nil
}

// Note: this function is exported so that it can be called from the projection volume driver
func MakePayload(mappings []v1.KeyToPath, secret *v1.Secret, defaultMode *int32, optional bool) (map[string]volumeutil.FileProjection, error) {
	if defaultMode == nil {
		return nil, fmt.Errorf("No defaultMode used, not even the default value for it")
	}

	payload := make(map[string]volumeutil.FileProjection, len(secret.Data))
	var fileProjection volumeutil.FileProjection

	if len(mappings) == 0 {
		for name, data := range secret.Data {
			fileProjection.Data = []byte(data)
			fileProjection.Mode = *defaultMode
			payload[name] = fileProjection
		}
	} else {
		for _, ktp := range mappings {
			content, ok := secret.Data[ktp.Key]
			if !ok {
				if optional {
					continue
				}
				err_msg := "references non-existent secret key"
				glog.Errorf(err_msg)
				return nil, fmt.Errorf(err_msg)
			}

			fileProjection.Data = []byte(content)
			if ktp.Mode != nil {
				fileProjection.Mode = *ktp.Mode
			} else {
				fileProjection.Mode = *defaultMode
			}
			payload[ktp.Path] = fileProjection
		}
	}
	return payload, nil
}

func totalSecretBytes(secret *v1.Secret) int {
	totalSize := 0
	for _, bytes := range secret.Data {
		totalSize += len(bytes)
	}

	return totalSize
}

// secretVolumeUnmounter handles cleaning up secret volumes.
type secretVolumeUnmounter struct {
	*secretVolume
}

var _ volume.Unmounter = &secretVolumeUnmounter{}

func (c *secretVolumeUnmounter) TearDown() error {
	return c.TearDownAt(c.GetPath())
}

func (c *secretVolumeUnmounter) TearDownAt(dir string) error {
	return volume.UnmountViaEmptyDir(dir, c.plugin.host, c.volName, wrappedVolumeSpec(), c.podUID)
}

func getVolumeSource(spec *volume.Spec) (*v1.SecretVolumeSource, bool) {
	var readOnly bool
	var volumeSource *v1.SecretVolumeSource

	if spec.Volume != nil && spec.Volume.Secret != nil {
		volumeSource = spec.Volume.Secret
		readOnly = spec.ReadOnly
	}

	return volumeSource, readOnly
}
