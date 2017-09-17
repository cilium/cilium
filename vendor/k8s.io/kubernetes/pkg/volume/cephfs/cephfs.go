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

package cephfs

import (
	"fmt"
	"os"
	"strings"

	"github.com/golang/glog"
	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/kubernetes/pkg/util/mount"
	utilstrings "k8s.io/kubernetes/pkg/util/strings"
	"k8s.io/kubernetes/pkg/volume"
	"k8s.io/kubernetes/pkg/volume/util"
)

// This is the primary entrypoint for volume plugins.
func ProbeVolumePlugins() []volume.VolumePlugin {
	return []volume.VolumePlugin{&cephfsPlugin{nil}}
}

type cephfsPlugin struct {
	host volume.VolumeHost
}

var _ volume.VolumePlugin = &cephfsPlugin{}

const (
	cephfsPluginName = "kubernetes.io/cephfs"
)

func (plugin *cephfsPlugin) Init(host volume.VolumeHost) error {
	plugin.host = host
	return nil
}

func (plugin *cephfsPlugin) GetPluginName() string {
	return cephfsPluginName
}

func (plugin *cephfsPlugin) GetVolumeName(spec *volume.Spec) (string, error) {
	mon, _, _, _, _, err := getVolumeSource(spec)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%v", mon), nil
}

func (plugin *cephfsPlugin) CanSupport(spec *volume.Spec) bool {
	return (spec.Volume != nil && spec.Volume.CephFS != nil) || (spec.PersistentVolume != nil && spec.PersistentVolume.Spec.CephFS != nil)
}

func (plugin *cephfsPlugin) RequiresRemount() bool {
	return false
}

func (plugin *cephfsPlugin) SupportsMountOption() bool {
	return true
}

func (plugin *cephfsPlugin) SupportsBulkVolumeVerification() bool {
	return false
}

func (plugin *cephfsPlugin) GetAccessModes() []v1.PersistentVolumeAccessMode {
	return []v1.PersistentVolumeAccessMode{
		v1.ReadWriteOnce,
		v1.ReadOnlyMany,
		v1.ReadWriteMany,
	}
}

func (plugin *cephfsPlugin) NewMounter(spec *volume.Spec, pod *v1.Pod, _ volume.VolumeOptions) (volume.Mounter, error) {
	secretName, secretNs, err := getSecretNameAndNamespace(spec, pod.Namespace)
	if err != nil {
		return nil, err
	}
	secret := ""
	if len(secretName) > 0 && len(secretNs) > 0 {
		// if secret is provideded, retrieve it
		kubeClient := plugin.host.GetKubeClient()
		if kubeClient == nil {
			return nil, fmt.Errorf("Cannot get kube client")
		}
		secrets, err := kubeClient.Core().Secrets(secretNs).Get(secretName, metav1.GetOptions{})
		if err != nil {
			err = fmt.Errorf("Couldn't get secret %v/%v err: %v", secretNs, secretName, err)
			return nil, err
		}
		for name, data := range secrets.Data {
			secret = string(data)
			glog.V(4).Infof("found ceph secret info: %s", name)
		}
	}
	return plugin.newMounterInternal(spec, pod.UID, plugin.host.GetMounter(plugin.GetPluginName()), secret)
}

func (plugin *cephfsPlugin) newMounterInternal(spec *volume.Spec, podUID types.UID, mounter mount.Interface, secret string) (volume.Mounter, error) {
	mon, path, id, secretFile, readOnly, err := getVolumeSource(spec)
	if err != nil {
		return nil, err
	}

	if id == "" {
		id = "admin"
	}
	if path == "" {
		path = "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	if secretFile == "" {
		secretFile = "/etc/ceph/" + id + ".secret"
	}

	return &cephfsMounter{
		cephfs: &cephfs{
			podUID:       podUID,
			volName:      spec.Name(),
			mon:          mon,
			path:         path,
			secret:       secret,
			id:           id,
			secret_file:  secretFile,
			readonly:     readOnly,
			mounter:      mounter,
			plugin:       plugin,
			mountOptions: volume.MountOptionFromSpec(spec),
		},
	}, nil
}

func (plugin *cephfsPlugin) NewUnmounter(volName string, podUID types.UID) (volume.Unmounter, error) {
	return plugin.newUnmounterInternal(volName, podUID, plugin.host.GetMounter(plugin.GetPluginName()))
}

func (plugin *cephfsPlugin) newUnmounterInternal(volName string, podUID types.UID, mounter mount.Interface) (volume.Unmounter, error) {
	return &cephfsUnmounter{
		cephfs: &cephfs{
			podUID:  podUID,
			volName: volName,
			mounter: mounter,
			plugin:  plugin},
	}, nil
}

func (plugin *cephfsPlugin) ConstructVolumeSpec(volumeName, mountPath string) (*volume.Spec, error) {
	cephfsVolume := &v1.Volume{
		Name: volumeName,
		VolumeSource: v1.VolumeSource{
			CephFS: &v1.CephFSVolumeSource{
				Monitors: []string{},
				Path:     volumeName,
			},
		},
	}
	return volume.NewSpecFromVolume(cephfsVolume), nil
}

// CephFS volumes represent a bare host file or directory mount of an CephFS export.
type cephfs struct {
	volName     string
	podUID      types.UID
	mon         []string
	path        string
	id          string
	secret      string
	secret_file string
	readonly    bool
	mounter     mount.Interface
	plugin      *cephfsPlugin
	volume.MetricsNil
	mountOptions []string
}

type cephfsMounter struct {
	*cephfs
}

var _ volume.Mounter = &cephfsMounter{}

func (cephfsVolume *cephfsMounter) GetAttributes() volume.Attributes {
	return volume.Attributes{
		ReadOnly:        cephfsVolume.readonly,
		Managed:         false,
		SupportsSELinux: false,
	}
}

// Checks prior to mount operations to verify that the required components (binaries, etc.)
// to mount the volume are available on the underlying node.
// If not, it returns an error
func (cephfsMounter *cephfsMounter) CanMount() error {
	return nil
}

// SetUp attaches the disk and bind mounts to the volume path.
func (cephfsVolume *cephfsMounter) SetUp(fsGroup *int64) error {
	return cephfsVolume.SetUpAt(cephfsVolume.GetPath(), fsGroup)
}

// SetUpAt attaches the disk and bind mounts to the volume path.
func (cephfsVolume *cephfsMounter) SetUpAt(dir string, fsGroup *int64) error {
	notMnt, err := cephfsVolume.mounter.IsLikelyNotMountPoint(dir)
	glog.V(4).Infof("CephFS mount set up: %s %v %v", dir, !notMnt, err)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if !notMnt {
		return nil
	}
	os.MkdirAll(dir, 0750)

	err = cephfsVolume.execMount(dir)
	if err == nil {
		return nil
	}

	// cleanup upon failure
	util.UnmountPath(dir, cephfsVolume.mounter)
	// return error
	return err
}

type cephfsUnmounter struct {
	*cephfs
}

var _ volume.Unmounter = &cephfsUnmounter{}

// TearDown unmounts the bind mount
func (cephfsVolume *cephfsUnmounter) TearDown() error {
	return cephfsVolume.TearDownAt(cephfsVolume.GetPath())
}

// TearDownAt unmounts the bind mount
func (cephfsVolume *cephfsUnmounter) TearDownAt(dir string) error {
	return util.UnmountPath(dir, cephfsVolume.mounter)
}

// GetPath creates global mount path
func (cephfsVolume *cephfs) GetPath() string {
	name := cephfsPluginName
	return cephfsVolume.plugin.host.GetPodVolumeDir(cephfsVolume.podUID, utilstrings.EscapeQualifiedNameForDisk(name), cephfsVolume.volName)
}

func (cephfsVolume *cephfs) execMount(mountpoint string) error {
	// cephfs mount option
	ceph_opt := ""
	// override secretfile if secret is provided
	if cephfsVolume.secret != "" {
		ceph_opt = "name=" + cephfsVolume.id + ",secret=" + cephfsVolume.secret
	} else {
		ceph_opt = "name=" + cephfsVolume.id + ",secretfile=" + cephfsVolume.secret_file
	}
	// build option array
	opt := []string{}
	if cephfsVolume.readonly {
		opt = append(opt, "ro")
	}
	opt = append(opt, ceph_opt)

	// build src like mon1:6789,mon2:6789,mon3:6789:/
	hosts := cephfsVolume.mon
	l := len(hosts)
	// pass all monitors and let ceph randomize and fail over
	i := 0
	src := ""
	for i = 0; i < l-1; i++ {
		src += hosts[i] + ","
	}
	src += hosts[i] + ":" + cephfsVolume.path

	mountOptions := volume.JoinMountOptions(cephfsVolume.mountOptions, opt)
	if err := cephfsVolume.mounter.Mount(src, mountpoint, "ceph", mountOptions); err != nil {
		return fmt.Errorf("CephFS: mount failed: %v", err)
	}

	return nil
}

func getVolumeSource(spec *volume.Spec) ([]string, string, string, string, bool, error) {
	if spec.Volume != nil && spec.Volume.CephFS != nil {
		mon := spec.Volume.CephFS.Monitors
		path := spec.Volume.CephFS.Path
		user := spec.Volume.CephFS.User
		secretFile := spec.Volume.CephFS.SecretFile
		readOnly := spec.Volume.CephFS.ReadOnly
		return mon, path, user, secretFile, readOnly, nil
	} else if spec.PersistentVolume != nil &&
		spec.PersistentVolume.Spec.CephFS != nil {
		mon := spec.PersistentVolume.Spec.CephFS.Monitors
		path := spec.PersistentVolume.Spec.CephFS.Path
		user := spec.PersistentVolume.Spec.CephFS.User
		secretFile := spec.PersistentVolume.Spec.CephFS.SecretFile
		readOnly := spec.PersistentVolume.Spec.CephFS.ReadOnly
		return mon, path, user, secretFile, readOnly, nil
	}

	return nil, "", "", "", false, fmt.Errorf("Spec does not reference a CephFS volume type")
}

func getSecretNameAndNamespace(spec *volume.Spec, defaultNamespace string) (string, string, error) {
	if spec.Volume != nil && spec.Volume.CephFS != nil {
		localSecretRef := spec.Volume.CephFS.SecretRef
		if localSecretRef != nil {
			return localSecretRef.Name, defaultNamespace, nil
		}
		return "", "", nil

	} else if spec.PersistentVolume != nil &&
		spec.PersistentVolume.Spec.CephFS != nil {
		secretRef := spec.PersistentVolume.Spec.CephFS.SecretRef
		secretNs := defaultNamespace
		if secretRef != nil {
			if len(secretRef.Namespace) != 0 {
				secretNs = secretRef.Namespace
			}
			return secretRef.Name, secretNs, nil
		}
		return "", "", nil
	}
	return "", "", fmt.Errorf("Spec does not reference an CephFS volume type")
}
