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

package api

import (
	"fmt"

	"github.com/cilium/cilium/pkg/lock"
)

var (
	probesMutex      lock.Mutex
	registeredProbes = []Probe{}
	loadedProbes     = []Probe{}
)

type Probe interface {
	ProbeProgInterface

	OnAttach() error
	OnDetach()
}

// Register registers a probe
func Register(probe Probe) {
	probesMutex.Lock()
	registeredProbes = append(registeredProbes, probe)
	probesMutex.Unlock()

	log.Debugf("Registered probe %s", probe.getSourceFilename())
}

// initProbes must be called with probesMutex held
func initProbes() error {
	for _, probe := range registeredProbes {
		if err := probe.LoadAndAttach(); err != nil {
			return fmt.Errorf("unable to attach probe: %s", err)
		}

		if err := probe.OnAttach(); err != nil {
			probe.Close()
			return fmt.Errorf("unable to run control plane for probe: %s", err)
		}

		loadedProbes = append(loadedProbes, probe)
	}

	return nil
}

func Init() {
	probesMutex.Lock()
	defer probesMutex.Unlock()

	if err := initProbes(); err != nil {
		for _, p := range loadedProbes {
			p.Close()
		}
		loadedProbes = []Probe{}

		log.WithError(err).Fatal("Unable to initialize and load probe")
	}
}

// closeLocked must be called with probesMutex held
func closeLocked() {
	for _, probe := range loadedProbes {
		probe.Close()
		probe.OnDetach()
	}

	loadedProbes = []Probe{}
}

// Close unloads and detaches all probes
func Close() {
	probesMutex.Lock()
	closeLocked()
	probesMutex.Unlock()
}
