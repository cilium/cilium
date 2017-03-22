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

	"github.com/cilium/cilium/common"
)

type StatusCode int

const (
	OK       StatusCode = 0
	Warning  StatusCode = -1
	Failure  StatusCode = -2
	Disabled StatusCode = -3
)

// StatusType represents the type for the given status, higher the value, higher
// the priority.
type StatusType int

const (
	BPF    StatusType = 200
	Policy StatusType = 100
	Other  StatusType = 0
)

func NewStatusOK(typ StatusType, info string) Status {
	return Status{Code: OK, Msg: info, Type: typ}
}

type Status struct {
	Code StatusCode `json:"code"`
	Msg  string     `json:"msg"`
	Type StatusType `json:"status-type"`
}

func (sc StatusCode) ColorString() string {
	var text string
	switch sc {
	case OK:
		text = common.Green("OK")
	case Warning:
		text = common.Yellow("Warning")
	case Failure:
		text = common.Red("Failure")
	case Disabled:
		text = common.Yellow("Disabled")
	default:
		text = "Unknown code"
	}
	return fmt.Sprintf("%s", text)
}

func (sc StatusCode) String() string {
	switch sc {
	case OK:
		return "OK"
	case Warning:
		return "Warning"
	case Failure:
		return "Failure"
	case Disabled:
		return "Disabled"
	default:
		return "Unknown code"
	}
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
