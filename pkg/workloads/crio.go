// Copyright 2018 Authors of Cilium
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
package workloads

import (
	"context"
	"fmt"
	"net/url"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/endpoint"
)

const (
	CRIO workloadRuntimeType = "crio"

	// criOEndpoint is the default value for the crio socket
	criOEndpoint = "/var/run/crio.sock"
)

var (
	criOInstance = &criOModule{
		opts: workloadRuntimeOpts{
			epOpt: &workloadRuntimeOpt{
				description: "Address of cri-o endpoint",
				value:       criOEndpoint,
			},
		},
	}
)

type criOModule struct {
	opts workloadRuntimeOpts
}

func init() {
	registerWorkload(CRIO, criOInstance)
}

func (c *criOModule) getName() string {
	return string(CRIO)
}

func (c *criOModule) setConfigDummy() {
}

func (c *criOModule) setConfig(opts map[string]string) error {
	return setOpts(opts, c.opts)
}

func (c *criOModule) getConfig() map[string]string {
	return getOpts(c.opts)
}

func (c *criOModule) newClient() (WorkloadRuntime, error) {
	return newCRIOClient(c.opts)
}

type criOClient struct {
	cri *criClient
}

func newCRIOClient(opts workloadRuntimeOpts) (WorkloadRuntime, error) {
	ep := string(opts[epOpt].value)
	p, err := url.Parse(ep)
	if err != nil {
		return nil, err
	}
	if p.Scheme == "" {
		ep = "unix://" + ep
	}
	rsc, err := newCRIClient(context.WithValue(context.Background(), epOpt, ep))
	return &criOClient{rsc}, err
}

// IsRunning returns false if the provided endpoint cannot be associated with a
// running workload. The runtime must be reachable to make this decision.
func (c *criOClient) IsRunning(ep *endpoint.Endpoint) bool {
	return c.cri.IsRunning(ep)
}

// Status returns the status of the workload runtime
func (c *criOClient) Status() *models.Status {
	if c == nil {
		return &models.Status{State: models.StatusStateDisabled}
	}

	criStatus := c.cri.Status()
	criStatusMsg := fmt.Sprintf("cri-o client: %s - %s", criStatus.State, criStatus.Msg)

	return &models.Status{
		State: models.StatusStateOk,
		Msg:   fmt.Sprintf(criStatusMsg, models.StatusStateOk),
	}
}

// EnableEventListener watches for criO events. Performs the plumbing for
// the containers started or dead.
func (c *criOClient) EnableEventListener() (chan<- *EventMessage, error) {
	return c.cri.EnableEventListener()
}

func (c *criOClient) processEvents(events chan EventMessage) {
	c.cri.processEvents(events)
}

func (c *criOClient) handleCreateWorkload(id string, retry bool) {
	c.cri.handleCreateWorkload(id, retry)
}

// IgnoreRunningWorkloads checks for already running containers and checks
// their IP address, then adds the containers to the list of ignored containers
// and allocates the IPs they are using to prevent future collisions.
func (c *criOClient) IgnoreRunningWorkloads() {
	c.cri.IgnoreRunningWorkloads()
}

// workloadIDsList returns a list of running workload IDs.
func (c *criOClient) workloadIDsList(ctx context.Context) ([]string, error) {
	return c.cri.workloadIDsList(ctx)
}

// GetAllInfraContainersPID returns a map that maps container IDs to the PID
// of that container.
func (c *criOClient) GetAllInfraContainersPID() (map[string]int, error) {
	return c.cri.GetAllInfraContainersPID()
}
