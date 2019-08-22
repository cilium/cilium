// Copyright 2017-2018 Authors of Cilium
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

package workloads

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	"github.com/cilium/cilium/pkg/endpointmanager"
)

// WorkloadOwner is the interface that the owner of workloads must implement.
type WorkloadOwner interface {
	regeneration.Owner

	// DeleteEndpoint is called when the underlying workload has died
	DeleteEndpoint(id string) (int, error)
}

var (
	owner WorkloadOwner
)

// Owner returns the owner instance of all workloads
func Owner() WorkloadOwner {
	return owner
}

// Init initializes the workloads package
func Init(o WorkloadOwner) {
	owner = o
}

const (
	None WorkloadRuntimeType = "none"
	Auto WorkloadRuntimeType = "auto"
)

const (
	// EpOpt is the option name for path to endpoint
	EpOpt = "endpoint"
	// DatapathModeOpt is the option name for datapath mode
	DatapathModeOpt = "datapath-mode"
)

type workloadRuntimeOpt struct {
	// description is the description of the option
	description string

	// value is the value the option has been configured to
	value string

	// validate, if set, is called to validate the value before assignment
	validate func(value string) error
}

type workloadRuntimeOpts map[string]*workloadRuntimeOpt

// workloadModule is the interface that each workload module has to implement.
type workloadModule interface {
	// getName must return the name of the workload
	getName() string

	// setConfig must configure the workload with the specified options.
	// This function is called once before newClient().
	setConfig(opts map[string]string) error

	// setConfigDummy must configure the workload with dummy configuration
	// for testing purposes. This is a replacement for setConfig().
	setConfigDummy()

	// getConfig must return the workload configuration.
	getConfig() map[string]string

	// newClient must initializes the workload and create a new kvstore
	// client which implements the WorkloadRuntime interface
	newClient(epMgr *endpointmanager.EndpointManager) (WorkloadRuntime, error)
}

// WorkloadRuntimeType is the type of a container runtime
type WorkloadRuntimeType string

var (
	// registeredWorkloads is a slice of all workloads that have registered
	// itself via registerWorkload()
	registeredWorkloads = map[WorkloadRuntimeType]workloadModule{}
)

func unregisterWorkloads() {
	registeredWorkloads = map[WorkloadRuntimeType]workloadModule{}
}

func parseRuntimeType(str string) (WorkloadRuntimeType, error) {
	switch crt := WorkloadRuntimeType(strings.ToLower(str)); crt {
	case None, Auto:
		return crt, nil
	default:
		_, ok := registeredWorkloads[crt]
		if !ok {
			return None, fmt.Errorf("runtime '%s' is not available", crt)
		}
		return crt, nil
	}
}

// registerWorkload must be called by container runtimes to register themselves
func registerWorkload(name WorkloadRuntimeType, module workloadModule) {
	if _, ok := registeredWorkloads[name]; ok {
		log.Panicf("workload with name '%s' already registered", name)
	}

	registeredWorkloads[name] = module
}

// getWorkload finds a registered workload by name
func getWorkload(name WorkloadRuntimeType) workloadModule {
	if workload, ok := registeredWorkloads[name]; ok {
		return workload
	}

	return nil
}

// GetRuntimeDefaultOpt returns the default options for the given container
// runtime.
func GetRuntimeDefaultOpt(crt WorkloadRuntimeType, opt string) string {
	opts, ok := registeredWorkloads[crt]
	if !ok {
		return ""
	}
	return opts.getConfig()[opt]
}

// GetRuntimeOptions returns a string representation of the container runtimes
// stored and the list of options for each container runtime.
func GetRuntimeOptions() string {
	var crtStr []string

	crs := make([]string, 0, len(registeredWorkloads))
	for k := range registeredWorkloads {
		crs = append(crs, string(k))
	}
	sort.Strings(crs)

	for _, cr := range crs {
		rb := registeredWorkloads[WorkloadRuntimeType(cr)]
		cfg := rb.getConfig()
		keys := make([]string, 0, len(cfg))
		for k := range cfg {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			crtStr = append(crtStr, fmt.Sprintf("%s=%s", k, cfg[k]))
		}
	}
	return strings.Join(crtStr, ",")
}

// GetDefaultEPOptsStringWithPrefix returns the defaults options for each
// runtime with the given prefix.
func GetDefaultEPOptsStringWithPrefix(prefix string) string {
	strs := make([]string, 0, len(registeredWorkloads))
	crs := make([]string, 0, len(registeredWorkloads))

	for k := range registeredWorkloads {
		crs = append(crs, string(k))
	}
	sort.Strings(crs)

	for _, cr := range crs {
		v := registeredWorkloads[WorkloadRuntimeType(cr)].getConfig()
		strs = append(strs, fmt.Sprintf("%s%s=%s", prefix, cr, v[EpOpt]))
	}

	return strings.Join(strs, ", ")
}

// WorkloadRuntime are the individual workload runtime operations that each
// workload must implement.
type WorkloadRuntime interface {
	// EnableEventListener enables the event listener of the workload runtime
	// If the workload runtime does not support events, it will return a
	// events channel where the caller will be in charge of sending the
	// create and stop events.
	EnableEventListener() (eventsCh chan<- *EventMessage, err error)
	// Status returns the status of the workload runtime.
	Status() *models.Status
	// IsRunning returns true if the endpoint is available and in a running
	// state in the respective workload runtime.
	IsRunning(ep *endpoint.Endpoint) bool
	// IgnoreRunningWorkloads sets the runtime to ignore all running workloads.
	IgnoreRunningWorkloads()
	// processEvents processes events from the given event channel.
	processEvents(events chan EventMessage)
	// handleCreateWorkload handles the creation of the given workload, if
	// retry is set, it keeps retrying until the workload is found running or
	// until the workload runtime stops retrying.
	handleCreateWorkload(id string, retry bool)
	// workloadIDsList returns a list of workload IDs running in the workload
	// runtime.
	workloadIDsList(ctx context.Context) ([]string, error)
	// GetAllInfraContainersPID returns a list of workload IDs running in the
	// workload that represent a infra container.
	GetAllInfraContainersPID() (map[string]int, error)
}
