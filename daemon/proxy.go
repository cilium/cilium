// Copyright 2016-2019 Authors of Cilium
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

	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	"github.com/cilium/cilium/pkg/logging/logfields"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/proxy/logger"
	"github.com/cilium/cilium/pkg/revert"
	"github.com/sirupsen/logrus"
)

// UpdateProxyRedirect updates the redirect rules in the proxy for a particular
// endpoint using the provided L4 filter. Returns the allocated proxy port
func (d *Daemon) UpdateProxyRedirect(e regeneration.EndpointUpdater, l4 *policy.L4Filter, proxyWaitGroup *completion.WaitGroup) (uint16, error, revert.FinalizeFunc, revert.RevertFunc) {
	if d.l7Proxy == nil {
		return 0, fmt.Errorf("can't redirect, proxy disabled"), nil, nil
	}

	port, err, finalizeFunc, revertFunc := d.l7Proxy.CreateOrUpdateRedirect(l4, e.ProxyID(l4), e, proxyWaitGroup)
	if err != nil {
		return 0, err, nil, nil
	}

	return port, nil, finalizeFunc, revertFunc
}

// RemoveProxyRedirect removes a previously installed proxy redirect for an
// endpoint
func (d *Daemon) RemoveProxyRedirect(e regeneration.EndpointInfoSource, id string, proxyWaitGroup *completion.WaitGroup) (error, revert.FinalizeFunc, revert.RevertFunc) {
	if d.l7Proxy == nil {
		return nil, nil, nil
	}

	log.WithFields(logrus.Fields{
		logfields.EndpointID: e.GetID(),
		logfields.L4PolicyID: id,
	}).Debug("Removing redirect to endpoint")
	return d.l7Proxy.RemoveRedirect(id, proxyWaitGroup)
}

// UpdateNetworkPolicy adds or updates a network policy in the set
// published to L7 proxies.
func (d *Daemon) UpdateNetworkPolicy(e regeneration.EndpointUpdater, policy *policy.L4Policy,
	proxyWaitGroup *completion.WaitGroup) (error, revert.RevertFunc) {
	if d.l7Proxy == nil {
		return fmt.Errorf("can't update network policy, proxy disabled"), nil
	}
	err, revertFunc := d.l7Proxy.UpdateNetworkPolicy(e, policy, e.GetIngressPolicyEnabledLocked(),
		e.GetEgressPolicyEnabledLocked(), proxyWaitGroup)
	return err, revert.RevertFunc(revertFunc)
}

// RemoveNetworkPolicy removes a network policy from the set published to
// L7 proxies.
func (d *Daemon) RemoveNetworkPolicy(e regeneration.EndpointInfoSource) {
	if d.l7Proxy == nil {
		return
	}
	d.l7Proxy.RemoveNetworkPolicy(e)
}

// NewProxyLogRecord is invoked by the proxy accesslog on each new access log entry
func (d *Daemon) NewProxyLogRecord(l *logger.LogRecord) error {
	return d.monitorAgent.SendEvent(monitorAPI.MessageTypeAccessLog, l.LogRecord)
}
