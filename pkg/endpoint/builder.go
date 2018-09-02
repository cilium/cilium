// Copyright 2016-2018 Authors of Cilium
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
	"github.com/cilium/cilium/pkg/buildqueue"
	"github.com/cilium/cilium/pkg/monitor"
	"github.com/cilium/cilium/pkg/option"
)

var (
	// BuildQueue is the endpoint build queue. It is also used to build
	// base programs
	BuildQueue = buildqueue.NewBuildQueue("endpoint-builder")
)

type endpointBuild struct {
	endpoint *Endpoint
	context  *RegenerationContext
	owner    Owner
}

func (e *Endpoint) newEndpointBuild(owner Owner, context *RegenerationContext) *endpointBuild {
	return &endpointBuild{
		endpoint: e,
		owner:    owner,
		context:  context,
	}
}

func (b *endpointBuild) GetUUID() string {
	return b.endpoint.GetUUID()
}

func (b *endpointBuild) BuildQueued() {
	if err := b.endpoint.LockAlive(); err == nil {
		b.endpoint.buildsWaiting++
		b.endpoint.updateState()
		b.endpoint.Unlock()
	}
}

func (b *endpointBuild) BuildsDequeued(nbuilds int, cancelled bool) {
	if err := b.endpoint.LockAlive(); err == nil {
		b.endpoint.buildsWaiting -= nbuilds
		b.endpoint.updateState()
		b.endpoint.Unlock()
	}
}

func (b *endpointBuild) Build() error {
	e := b.endpoint

	scopedLog := e.Logger()
	scopedLog.Debug("Dequeued endpoint from build queue")

	err := e.regenerate(b.owner, b.context)

	repr, reprerr := monitor.EndpointRegenRepr(e, err)
	if reprerr != nil {
		scopedLog.WithError(reprerr).Warn("Notifying monitor about endpoint regeneration failed")
	}

	if err != nil {
		scopedLog.WithError(err).Warn("Regeneration of endpoint program failed")
		e.LogStatus(BPF, Failure, "Error regenerating endpoint: "+err.Error())
		if reprerr == nil && !option.Config.DryMode {
			b.owner.SendNotification(monitor.AgentNotifyEndpointRegenerateFail, repr)
		}
	} else {
		e.LogStatusOK(BPF, "Successfully regenerated endpoint program due to "+b.context.Reason)
		if reprerr == nil && !option.Config.DryMode {
			b.owner.SendNotification(monitor.AgentNotifyEndpointRegenerateSuccess, repr)
		}
	}

	if err := e.LockAlive(); err == nil {
		if err == nil {
			e.initialBuildSuccessful = true
		}

		e.lastBuildFailed = err != nil
		e.updateState()
		e.Unlock()
	}

	return err
}
