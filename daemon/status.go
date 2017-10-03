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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sTypes "k8s.io/client-go/pkg/api/v1"
)

func getK8sStatus() *models.Status {
	var k8sStatus *models.Status
	if k8s.IsEnabled() {
		if v, err := k8s.Client().CoreV1().ComponentStatuses().Get("controller-manager", metav1.GetOptions{}); err != nil {
			k8sStatus = &models.Status{State: models.StatusStateFailure, Msg: err.Error()}
		} else if len(v.Conditions) == 0 {
			k8sStatus = &models.Status{
				State: models.StatusStateWarning,
				Msg:   "Unable to retrieve controller-manager's kubernetes status",
			}
		} else {
			if v.Conditions[0].Status == k8sTypes.ConditionTrue {
				k8sStatus = &models.Status{
					State: models.StatusStateOk,
					Msg:   "OK",
				}
			} else {
				k8sStatus = &models.Status{
					State: models.StatusStateFailure,
					Msg:   v.Conditions[0].Message,
				}
			}
		}
	} else {
		k8sStatus = &models.Status{State: models.StatusStateDisabled}
	}
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

	sr.Kubernetes = getK8sStatus()

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

	sr.IPAM = d.DumpIPAM()

	if nm := d.nodeMonitor; nm != nil {
		sr.NodeMonitor = d.nodeMonitor.State()
	}

	return NewGetHealthzOK().WithPayload(&sr)
}
