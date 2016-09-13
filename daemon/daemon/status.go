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
)

func (d *Daemon) GlobalStatus() (*types.StatusResponse, error) {
	sr := types.StatusResponse{}

	if info, err := d.kvClient.Status(); err != nil {
		sr.Consul = types.Status{Code: types.Failure, Msg: fmt.Sprintf("Err: %s - %s", err, info)}
	} else {
		sr.Consul = types.NewStatusOK(info)
	}

	if _, err := d.dockerClient.Info(); err != nil {
		sr.Docker = types.Status{Code: types.Failure, Msg: err.Error()}
	} else {
		sr.Docker = types.NewStatusOK("")
	}

	if v, err := d.k8sClient.ServerVersion(); err != nil {
		sr.Kubernetes = types.Status{Code: types.Warning, Msg: err.Error()}
	} else {
		sr.Kubernetes = types.NewStatusOK(v.String())
	}

	if sr.Consul.Code != types.OK {
		sr.Cilium = types.Status{Code: sr.Consul.Code, Msg: "Consul service is not ready!"}
	} else if sr.Docker.Code != types.OK {
		sr.Cilium = types.Status{Code: sr.Docker.Code, Msg: "Docker service is not ready!"}
	} /* TODO add a flag to the main daemon so we known if kubernetes is supposed to be running or not
	else if sr.Kubernetes != types.OK {
		sr.Cilium = types.Status{Code: types.Warning, Msg: "Consul service is not ready!"}
	}*/

	// TODO Create a logstash status in its runnable function
	//Logstash   Status `json:"logstash"`

	return &sr, nil
}
