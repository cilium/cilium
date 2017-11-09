// Copyright 2016-2017 Authors of Cilium
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

package main

import (
	"fmt"

	"github.com/cilium/cilium/api/v1/models"
	. "github.com/cilium/cilium/api/v1/server/restapi/daemon"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/workloads/containerd"

	"github.com/go-openapi/runtime/middleware"
	k8sTypes "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (d *Daemon) getK8sStatus() *models.K8sStatus {
	if !k8s.IsEnabled() {
		return &models.K8sStatus{State: models.StatusStateDisabled}

	}

	var (
		k8sStatus *models.K8sStatus
		status    *k8sTypes.ComponentStatus
		err       error
	)
	if status, err = k8s.Client().CoreV1().ComponentStatuses().Get("controller-manager", metav1.GetOptions{}); err != nil {
		return &models.K8sStatus{State: models.StatusStateFailure, Msg: err.Error()}
	}
	switch {
	case len(status.Conditions) == 0:
		k8sStatus = &models.K8sStatus{
			State: models.StatusStateWarning,
			Msg:   "Unable to retrieve controller-manager's kubernetes status",
		}
	case status.Conditions[0].Status == k8sTypes.ConditionTrue:
		k8sStatus = &models.K8sStatus{
			State: models.StatusStateOk,
			Msg:   "OK",
		}
	default:
		k8sStatus = &models.K8sStatus{
			State: models.StatusStateFailure,
			Msg:   status.Conditions[0].Message,
		}
	}

	d.k8sAPIGroups.Range(func(key string, value bool) bool {
		if value {
			k8sStatus.K8sAPIVersions = append(k8sStatus.K8sAPIVersions, key)
		}
		return true
	})

	return k8sStatus
}

type getHealthz struct {
	daemon *Daemon
}

func NewGetHealthzHandler(d *Daemon) GetHealthzHandler {
	return &getHealthz{daemon: d}
}

func (h *getHealthz) Handle(params GetHealthzParams) middleware.Responder {
	d := h.daemon
	sr := models.StatusResponse{}

	if info, err := kvstore.Client().Status(); err != nil {
		sr.Kvstore = &models.Status{State: models.StatusStateFailure, Msg: fmt.Sprintf("Err: %s - %s", err, info)}
	} else {
		sr.Kvstore = &models.Status{State: models.StatusStateOk, Msg: info}
	}

	sr.ContainerRuntime = containerd.Status()

	sr.Kubernetes = d.getK8sStatus()

	if sr.Kvstore.State != models.StatusStateOk {
		sr.Cilium = &models.Status{
			State: sr.Kvstore.State,
			Msg:   "Kvstore service is not ready",
		}
	} else if sr.ContainerRuntime.State != models.StatusStateOk {
		sr.Cilium = &models.Status{
			State: sr.ContainerRuntime.State,
			Msg:   "Container runtime is not ready",
		}
	} else if k8s.IsEnabled() && sr.Kubernetes.State != models.StatusStateOk {
		sr.Cilium = &models.Status{
			State: sr.Kubernetes.State,
			Msg:   "Kubernetes service is not ready",
		}
	} else {
		sr.Cilium = &models.Status{State: models.StatusStateOk, Msg: "OK"}
	}

	if d.DebugEnabled() {
		sr.IPAM = d.DumpIPAM()
	}

	if nm := d.nodeMonitor; nm != nil {
		sr.NodeMonitor = d.nodeMonitor.State()
	}

	return NewGetHealthzOK().WithPayload(&sr)
}
