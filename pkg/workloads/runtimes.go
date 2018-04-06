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

package workloads

import (
	"fmt"
	"strings"

	"github.com/cilium/cilium/pkg/lock"
)

func init() {
	containerRuntimes = make(map[containerRuntimeType]containerRuntimeOpts)
	runtimeDefaultsOpts = map[containerRuntimeType]containerRuntimeOpts{
		Docker: {
			Endpoint: "unix:///var/run/docker.sock",
		},
	}

}

const (
	None   containerRuntimeType = "none"
	Auto   containerRuntimeType = "auto"
	Docker containerRuntimeType = "docker"
)

var (
	runtimeDefaultsOpts    map[containerRuntimeType]containerRuntimeOpts
	containerRuntimesMutex lock.Mutex
	containerRuntimes      map[containerRuntimeType]containerRuntimeOpts
)

type containerRuntimeType string

type containerRuntimeOpts struct {
	Endpoint string
}

// GetRuntimeOpt returns the options for the given container runtime.
func GetRuntimeOpt(crt containerRuntimeType) *containerRuntimeOpts {
	containerRuntimesMutex.Lock()
	defer containerRuntimesMutex.Unlock()
	if opts, ok := containerRuntimes[crt]; ok {
		return &opts
	}
	return nil
}

// GetRuntimeDefaultOpt returns the default options for the given container
// runtime.
func GetRuntimeDefaultOpt(crt containerRuntimeType) *containerRuntimeOpts {
	if opts, ok := runtimeDefaultsOpts[crt]; ok {
		return &opts
	}
	return nil
}

// GetRuntimesString returns a string representation of the container runtimes
// stored and the list of options for each container runtime.
func GetRuntimesString() string {
	containerRuntimesMutex.Lock()
	defer containerRuntimesMutex.Unlock()
	crtStr := make([]string, 0, len(containerRuntimes))
	for k, v := range containerRuntimes {
		crtStr = append(crtStr, fmt.Sprintf("%q on endpoint %q", k, v.Endpoint))
	}
	return strings.Join(crtStr, ",")
}

func addRuntime(crt containerRuntimeType, opts containerRuntimeOpts) {
	containerRuntimesMutex.Lock()
	defer containerRuntimesMutex.Unlock()
	containerRuntimes[crt] = opts
}

func parseRuntimeType(str string) (containerRuntimeType, error) {
	switch crt := containerRuntimeType(strings.ToLower(str)); crt {
	case None, Auto, Docker:
		return crt, nil
	default:
		return None, fmt.Errorf("ContainerRuntime %s is not available", crt)
	}
}

// ParseConfig parses the containerRuntimes and the containerRuntime options
// and adds them to the internal containerRuntime maps.
// In case any containeRuntime does not exist an error is returned.
// If `auto` is set in containerRuntimes, the default options of each container
// runtime will be set. The user defined options of each particular runtime
// will overwrite defaults.
// If `none` is set, all containerRuntimes will be ignored.
func ParseConfig(containerRuntimes []string, containerRuntimesOpts map[string]string) error {
	for _, runtime := range containerRuntimes {
		crt, err := parseRuntimeType(runtime)
		if err != nil {
			return err
		}
		switch crt {
		case None:
			return nil
		case Auto:
			for crt, opt := range runtimeDefaultsOpts {
				addRuntime(crt, opt)
			}
		}
	}

	for runtime, opts := range containerRuntimesOpts {
		crt, err := parseRuntimeType(runtime)
		if err != nil {
			return err
		}
		switch crt {
		case None, Auto:
		default:
			if opts == "" {
				addRuntime(crt, runtimeDefaultsOpts[crt])
			} else {
				crtOpts := containerRuntimeOpts{
					Endpoint: opts,
				}
				addRuntime(crt, crtOpts)
			}
		}
	}
	return nil
}
