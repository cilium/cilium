// SPDX-License-Identifier: Apache-2.0
// Copyright 2016-2017 Authors of Cilium

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
