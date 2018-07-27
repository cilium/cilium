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

package client

import (
	"github.com/cilium/cilium/api/v1/client/daemon"
	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/api"
)

// ConfigGet returns a daemon configuration.
func (c *Client) ConfigGet() (*models.DaemonConfiguration, error) {
	resp, err := c.Daemon.GetConfig(nil)
	if err != nil {
		return nil, Hint(err)
	}
	return resp.Payload, nil
}

// ConfigPatch modifies the daemon configuration.
func (c *Client) ConfigPatch(cfg models.DaemonConfigurationSpec) error {
	fullCfg, err := c.ConfigGet()
	if err != nil {
		return err
	}

	for opt, value := range cfg.Options {
		fullCfg.Spec.Options[opt] = value
	}
	if cfg.PolicyEnforcement != "" {
		fullCfg.Spec.PolicyEnforcement = cfg.PolicyEnforcement
	}

	params := daemon.NewPatchConfigParams().WithConfiguration(fullCfg.Spec).WithTimeout(api.ClientTimeout)
	_, err = c.Daemon.PatchConfig(params)
	return Hint(err)
}
