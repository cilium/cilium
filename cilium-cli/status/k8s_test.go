// Copyright 2020 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// +build !privileged_tests

package status

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/go-openapi/strfmt"
	"gopkg.in/check.v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func Test(t *testing.T) {
	check.TestingT(t)
}

type StatusSuite struct{}

var _ = check.Suite(&StatusSuite{})

type k8sStatusMockClient struct {
	daemonSet  map[string]*appsv1.DaemonSet
	deployment map[string]*appsv1.Deployment
	podList    map[string]*corev1.PodList
	status     map[string]*models.StatusResponse
}

func newK8sStatusMockClient() (c *k8sStatusMockClient) {
	c = &k8sStatusMockClient{}
	c.reset()
	return
}

func (c *k8sStatusMockClient) reset() {
	c.daemonSet = map[string]*appsv1.DaemonSet{}
	c.podList = map[string]*corev1.PodList{}
	c.status = map[string]*models.StatusResponse{}
}

func (c *k8sStatusMockClient) addPod(namespace, name, filter string, containers []corev1.Container, status corev1.PodStatus) {
	if c.podList[filter] == nil {
		c.podList[filter] = &corev1.PodList{}
	}

	c.podList[filter].Items = append(c.podList[filter].Items, corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: corev1.PodSpec{
			Containers: containers,
		},
		Status: status,
	})
}

func (c *k8sStatusMockClient) setDaemonSet(namespace, name, filter string, desired, ready, available, unavailable int32) {
	c.daemonSet = map[string]*appsv1.DaemonSet{}

	c.daemonSet[namespace+"/"+name] = &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Status: appsv1.DaemonSetStatus{
			DesiredNumberScheduled: desired,
			NumberReady:            ready,
			NumberAvailable:        available,
			NumberUnavailable:      unavailable,
		},
	}

	c.status = map[string]*models.StatusResponse{}

	for i := int32(0); i < available; i++ {
		podName := fmt.Sprintf("%s-%d", name, i)
		c.addPod(namespace, podName, filter, []corev1.Container{{Image: "cilium:1.8"}}, corev1.PodStatus{Phase: corev1.PodRunning})

		c.status[podName] = &models.StatusResponse{
			Kubernetes: &models.K8sStatus{
				State: "Warning",
				Msg:   "Error1",
			},
			Controllers: []*models.ControllerStatus{
				&models.ControllerStatus{Name: "c1", Status: &models.ControllerStatusStatus{ConsecutiveFailureCount: 1, LastFailureMsg: "Error1", LastFailureTimestamp: strfmt.DateTime(time.Now().Add(-time.Minute))}},
				&models.ControllerStatus{Name: "c2", Status: &models.ControllerStatusStatus{ConsecutiveFailureCount: 4, LastFailureMsg: "Error2", LastFailureTimestamp: strfmt.DateTime(time.Now().Add(-2 * time.Minute))}},
				&models.ControllerStatus{Name: "c3", Status: &models.ControllerStatusStatus{LastFailureTimestamp: strfmt.DateTime(time.Now().Add(-3 * time.Minute))}},
			},
		}
	}

	for i := int32(0); i < unavailable; i++ {
		podName := fmt.Sprintf("%s-%d", name, i+available)
		c.addPod(namespace, podName, filter, []corev1.Container{{Image: "cilium:1.9"}}, corev1.PodStatus{Phase: corev1.PodFailed})
		c.status[podName] = &models.StatusResponse{
			Kubernetes: &models.K8sStatus{
				State: "Warning",
				Msg:   "Error1",
			},
			Controllers: []*models.ControllerStatus{
				&models.ControllerStatus{Name: "c1", Status: &models.ControllerStatusStatus{ConsecutiveFailureCount: 1, LastFailureMsg: "Error1", LastFailureTimestamp: strfmt.DateTime(time.Now().Add(-time.Minute))}},
				&models.ControllerStatus{Name: "c2", Status: &models.ControllerStatusStatus{ConsecutiveFailureCount: 4, LastFailureMsg: "Error2", LastFailureTimestamp: strfmt.DateTime(time.Now().Add(-2 * time.Minute))}},
				&models.ControllerStatus{Name: "c3", Status: &models.ControllerStatusStatus{LastFailureTimestamp: strfmt.DateTime(time.Now().Add(-3 * time.Minute))}},
			},
		}
	}
}

func (c *k8sStatusMockClient) GetNamespace(ctx context.Context, namespace string, options metav1.GetOptions) (*corev1.Namespace, error) {
	return &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}}, nil
}

func (c *k8sStatusMockClient) GetDaemonSet(ctx context.Context, namespace, name string, options metav1.GetOptions) (*appsv1.DaemonSet, error) {
	return c.daemonSet[namespace+"/"+name], nil
}

func (c *k8sStatusMockClient) GetDeployment(ctx context.Context, namespace, name string, options metav1.GetOptions) (*appsv1.Deployment, error) {
	return c.deployment[namespace+"/"+name], nil
}

func (c *k8sStatusMockClient) ListPods(ctx context.Context, namespace string, options metav1.ListOptions) (*corev1.PodList, error) {
	return c.podList[options.LabelSelector], nil
}

func (c *k8sStatusMockClient) CiliumStatus(ctx context.Context, namespace, pod string) (*models.StatusResponse, error) {
	s, ok := c.status[pod]
	if !ok {
		return nil, fmt.Errorf("pod %s not found", pod)
	}
	return s, nil
}

func (b *StatusSuite) TestMockClient(c *check.C) {
	client := newK8sStatusMockClient()
	c.Assert(client, check.Not(check.IsNil))

	n, err := client.GetNamespace(context.Background(), "foo", metav1.GetOptions{})
	c.Assert(err, check.IsNil)
	c.Assert(n.Name, check.Equals, "foo")
}

func (b *StatusSuite) TestStatus(c *check.C) {
	client := newK8sStatusMockClient()
	c.Assert(client, check.Not(check.IsNil))

	collector, err := NewK8sStatusCollector(context.Background(), client, "kube-system")
	c.Assert(err, check.IsNil)
	c.Assert(collector, check.Not(check.IsNil))

	client.setDaemonSet("kube-system", ciliumDaemonSetName, "k8s-app=cilium", 10, 10, 10, 0)
	status, err := collector.Status(context.Background())
	c.Assert(err, check.IsNil)
	c.Assert(status, check.Not(check.IsNil))
	c.Assert(status.PodState[ciliumDaemonSetName].Desired, check.Equals, 10)
	c.Assert(status.PodState[ciliumDaemonSetName].Ready, check.Equals, 10)
	c.Assert(status.PodState[ciliumDaemonSetName].Available, check.Equals, 10)
	c.Assert(status.PodState[ciliumDaemonSetName].Unavailable, check.Equals, 0)
	c.Assert(status.PhaseCount[ciliumDaemonSetName][string(corev1.PodRunning)], check.Equals, 10)
	c.Assert(status.PhaseCount[ciliumDaemonSetName][string(corev1.PodFailed)], check.Equals, 0)
	c.Assert(len(status.CiliumStatus), check.Equals, 10)

	client.reset()
	client.setDaemonSet("kube-system", ciliumDaemonSetName, "k8s-app=cilium", 10, 5, 5, 5)
	status, err = collector.Status(context.Background())
	c.Assert(err, check.IsNil)
	c.Assert(status, check.Not(check.IsNil))
	c.Assert(status.PodState[ciliumDaemonSetName].Desired, check.Equals, 10)
	c.Assert(status.PodState[ciliumDaemonSetName].Ready, check.Equals, 5)
	c.Assert(status.PodState[ciliumDaemonSetName].Available, check.Equals, 5)
	c.Assert(status.PodState[ciliumDaemonSetName].Unavailable, check.Equals, 5)
	c.Assert(status.PhaseCount[ciliumDaemonSetName][string(corev1.PodRunning)], check.Equals, 5)
	c.Assert(status.PhaseCount[ciliumDaemonSetName][string(corev1.PodFailed)], check.Equals, 5)
	c.Assert(len(status.CiliumStatus), check.Equals, 5)

	client.reset()
	client.setDaemonSet("kube-system", ciliumDaemonSetName, "k8s-app=cilium", 10, 5, 5, 5)
	delete(client.status, "cilium-2")
	status, err = collector.Status(context.Background())
	c.Assert(err, check.IsNil)
	c.Assert(status, check.Not(check.IsNil))
	c.Assert(status.PodState[ciliumDaemonSetName].Desired, check.Equals, 10)
	c.Assert(status.PodState[ciliumDaemonSetName].Ready, check.Equals, 5)
	c.Assert(status.PodState[ciliumDaemonSetName].Available, check.Equals, 5)
	c.Assert(status.PodState[ciliumDaemonSetName].Unavailable, check.Equals, 5)
	c.Assert(status.PhaseCount[ciliumDaemonSetName][string(corev1.PodRunning)], check.Equals, 5)
	c.Assert(status.PhaseCount[ciliumDaemonSetName][string(corev1.PodFailed)], check.Equals, 5)
	c.Assert(len(status.CiliumStatus), check.Equals, 5)
	c.Assert(status.CiliumStatus["cilium-2"], check.IsNil)
}

func (b *StatusSuite) TestFormat(c *check.C) {
	client := newK8sStatusMockClient()
	c.Assert(client, check.Not(check.IsNil))

	collector, err := NewK8sStatusCollector(context.Background(), client, "kube-system")
	c.Assert(err, check.IsNil)
	c.Assert(collector, check.Not(check.IsNil))

	client.setDaemonSet("kube-system", ciliumDaemonSetName, "k8s-app=cilium", 10, 5, 5, 5)
	delete(client.status, "cilium-2")

	client.addPod("kube-system", "cilium-operator-1", "k8s-app=cilium-operator", []corev1.Container{{Image: "cilium-operator:1.9"}}, corev1.PodStatus{Phase: corev1.PodRunning})

	status, err := collector.Status(context.Background())
	c.Assert(err, check.IsNil)
	buf := status.Format()
	c.Assert(buf, check.Not(check.Equals), "")
	fmt.Println(buf)
}
