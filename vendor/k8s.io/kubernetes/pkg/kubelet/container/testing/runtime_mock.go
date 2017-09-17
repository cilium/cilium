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

package testing

import (
	"io"
	"time"

	"github.com/stretchr/testify/mock"
	"k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/remotecommand"
	"k8s.io/client-go/util/flowcontrol"
	. "k8s.io/kubernetes/pkg/kubelet/container"
	"k8s.io/kubernetes/pkg/volume"
)

type Mock struct {
	mock.Mock
}

var _ Runtime = new(Mock)

func (r *Mock) Start() error {
	args := r.Called()
	return args.Error(0)
}

func (r *Mock) Type() string {
	args := r.Called()
	return args.Get(0).(string)
}

func (r *Mock) Version() (Version, error) {
	args := r.Called()
	return args.Get(0).(Version), args.Error(1)
}

func (r *Mock) APIVersion() (Version, error) {
	args := r.Called()
	return args.Get(0).(Version), args.Error(1)
}

func (r *Mock) Status() (*RuntimeStatus, error) {
	args := r.Called()
	return args.Get(0).(*RuntimeStatus), args.Error(0)
}

func (r *Mock) GetPods(all bool) ([]*Pod, error) {
	args := r.Called(all)
	return args.Get(0).([]*Pod), args.Error(1)
}

func (r *Mock) SyncPod(pod *v1.Pod, apiStatus v1.PodStatus, status *PodStatus, secrets []v1.Secret, backOff *flowcontrol.Backoff) PodSyncResult {
	args := r.Called(pod, apiStatus, status, secrets, backOff)
	return args.Get(0).(PodSyncResult)
}

func (r *Mock) KillPod(pod *v1.Pod, runningPod Pod, gracePeriodOverride *int64) error {
	args := r.Called(pod, runningPod, gracePeriodOverride)
	return args.Error(0)
}

func (r *Mock) RunContainerInPod(container v1.Container, pod *v1.Pod, volumeMap map[string]volume.VolumePlugin) error {
	args := r.Called(pod, pod, volumeMap)
	return args.Error(0)
}

func (r *Mock) KillContainerInPod(container v1.Container, pod *v1.Pod) error {
	args := r.Called(pod, pod)
	return args.Error(0)
}

func (r *Mock) GetPodStatus(uid types.UID, name, namespace string) (*PodStatus, error) {
	args := r.Called(uid, name, namespace)
	return args.Get(0).(*PodStatus), args.Error(1)
}

func (r *Mock) ExecInContainer(containerID ContainerID, cmd []string, stdin io.Reader, stdout, stderr io.WriteCloser, tty bool, resize <-chan remotecommand.TerminalSize, timeout time.Duration) error {
	args := r.Called(containerID, cmd, stdin, stdout, stderr, tty)
	return args.Error(0)
}

func (r *Mock) AttachContainer(containerID ContainerID, stdin io.Reader, stdout, stderr io.WriteCloser, tty bool, resize <-chan remotecommand.TerminalSize) error {
	args := r.Called(containerID, stdin, stdout, stderr, tty)
	return args.Error(0)
}

func (r *Mock) GetContainerLogs(pod *v1.Pod, containerID ContainerID, logOptions *v1.PodLogOptions, stdout, stderr io.Writer) (err error) {
	args := r.Called(pod, containerID, logOptions, stdout, stderr)
	return args.Error(0)
}

func (r *Mock) PullImage(image ImageSpec, pullSecrets []v1.Secret) (string, error) {
	args := r.Called(image, pullSecrets)
	return image.Image, args.Error(0)
}

func (r *Mock) GetImageRef(image ImageSpec) (string, error) {
	args := r.Called(image)
	return args.Get(0).(string), args.Error(1)
}

func (r *Mock) ListImages() ([]Image, error) {
	args := r.Called()
	return args.Get(0).([]Image), args.Error(1)
}

func (r *Mock) RemoveImage(image ImageSpec) error {
	args := r.Called(image)
	return args.Error(0)
}

func (r *Mock) PortForward(pod *Pod, port uint16, stream io.ReadWriteCloser) error {
	args := r.Called(pod, port, stream)
	return args.Error(0)
}

func (r *Mock) GetNetNS(containerID ContainerID) (string, error) {
	args := r.Called(containerID)
	return "", args.Error(0)
}

func (r *Mock) GetPodContainerID(pod *Pod) (ContainerID, error) {
	args := r.Called(pod)
	return ContainerID{}, args.Error(0)
}

func (r *Mock) GarbageCollect(gcPolicy ContainerGCPolicy, ready bool, evictNonDeletedPods bool) error {
	args := r.Called(gcPolicy, ready, evictNonDeletedPods)
	return args.Error(0)
}

func (r *Mock) DeleteContainer(containerID ContainerID) error {
	args := r.Called(containerID)
	return args.Error(0)
}

func (r *Mock) ImageStats() (*ImageStats, error) {
	args := r.Called()
	return args.Get(0).(*ImageStats), args.Error(1)
}

// UpdatePodCIDR fulfills the cri interface.
func (r *Mock) UpdatePodCIDR(c string) error {
	return nil
}
