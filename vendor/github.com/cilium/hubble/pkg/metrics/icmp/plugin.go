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

package icmp

import (
	"github.com/cilium/hubble/pkg/metrics/api"
)

type icmpPlugin struct{}

func (p *icmpPlugin) NewHandler() api.Handler {
	return &icmpHandler{}
}

func (p *icmpPlugin) HelpText() string {
	return `icmp - icmp metrics
Reports metrics related to the Internet Control Message Protocol (ICMP) such as
message counts.

Metrics:
  hubble_icmp_total  Number of ICMP messages by prorocol family and type

Options:` +
		api.ContextOptionsHelp
}

func init() {
	api.DefaultRegistry().Register("icmp", &icmpPlugin{})
}
