//
// Copyright 2016 Authors of Cilium
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
//
package daemon

import (
	"fmt"

	"github.com/cilium/cilium/common/types"

	ctx "golang.org/x/net/context"
)

func (d *Daemon) GlobalStatus() (*types.StatusResponse, error) {
	sr := types.StatusResponse{}

	if info, err := d.kvClient.Status(); err != nil {
		sr.KVStore = types.Status{Code: types.Failure, Msg: fmt.Sprintf("Err: %s - %s", err, info)}
	} else {
		sr.KVStore = types.NewStatusOK(info)
	}

	if _, err := d.dockerClient.Info(ctx.Background()); err != nil {
		sr.Docker = types.Status{Code: types.Failure, Msg: err.Error()}
	} else {
		sr.Docker = types.NewStatusOK("")
	}

	if d.conf.IsK8sEnabled() {
		if v, err := d.k8sClient.ServerVersion(); err != nil {
			sr.Kubernetes = types.Status{Code: types.OK, Msg: err.Error()}
		} else {
			sr.Kubernetes = types.NewStatusOK(v.String())
		}
	} else {
		sr.Kubernetes = types.Status{Code: types.Disabled}
	}

	if sr.KVStore.Code != types.OK {
		sr.Cilium = types.Status{Code: sr.KVStore.Code, Msg: "KVStore service is not ready!"}
	} else if sr.Docker.Code != types.OK {
		sr.Cilium = types.Status{Code: sr.Docker.Code, Msg: "Docker service is not ready!"}
	} else if d.conf.IsK8sEnabled() && sr.Kubernetes.Code != types.OK {
		sr.Cilium = types.Status{Code: sr.Kubernetes.Code, Msg: "Kubernetes service is not ready!"}
	}

	// TODO Create a logstash status in its runnable function
	//Logstash   Status `json:"logstash"`

	sr.IPAMStatus = d.DumpIPAM()

	return &sr, nil
}
