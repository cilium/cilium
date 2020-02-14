// Copyright 2019 Authors of Hubble
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

package tcp

import (
	"github.com/cilium/hubble/pkg/metrics/api"
)

type tcpPlugin struct{}

func (p *tcpPlugin) NewHandler() api.Handler {
	return &tcpHandler{}
}

func (p *tcpPlugin) HelpText() string {
	return `tcp - TCP metrics
Metrics related to the TCP protocol

Metrics:
  hubble_tcp_flags_total - Distribution of TCP flags

Options:` +
		api.ContextOptionsHelp
}

func init() {
	api.DefaultRegistry().Register("tcp", &tcpPlugin{})
}
