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

package endpoint

import (
	"fmt"

	"github.com/cilium/cilium/pkg/status"
)

type Status struct {
	Code  status.Code `json:"code"`
	Msg   string      `json:"msg"`
	Type  status.Type `json:"status-type"`
	State string      `json:"state"`
}

func (s Status) String() string {
	if s.Msg == "" {
		return fmt.Sprintf("%s", s.Code)
	}
	return fmt.Sprintf("%s - %s", s.Code, s.Msg)
}

type StatusResponse struct {
	KVStore    Status              `json:"kvstore"`
	Docker     Status              `json:"docker"`
	Kubernetes Status              `json:"kubernetes"`
	Logstash   Status              `json:"logstash"`
	Cilium     Status              `json:"cilium"`
	IPAMStatus map[string][]string `json:",omitempty"`
}
