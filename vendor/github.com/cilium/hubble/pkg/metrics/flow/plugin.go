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

package flow

import (
	"github.com/cilium/hubble/pkg/metrics/api"
)

type flowPlugin struct{}

func (p *flowPlugin) NewHandler() api.Handler {
	return &flowHandler{}
}

func (p *flowPlugin) HelpText() string {
	return `flow - Generic flow metrics
Reports metrics related to flow processing

Metrics:
  hubble_flows_processed_total  Number of flows processed

Options:` +
		api.ContextOptionsHelp
}

func init() {
	api.DefaultRegistry().Register("flow", &flowPlugin{})
}
