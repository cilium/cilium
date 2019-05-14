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

package workloads

import (
	"fmt"
	"net"
	"sync"

	"github.com/cilium/cilium/api/v1/models"
)

// setOpts validates the specified options against the selected workload runtime
// and then modifies the configuration
func setOpts(opts map[string]string, supportedOpts workloadRuntimeOpts) error {
	errors := 0

	for key, val := range opts {
		opt, ok := supportedOpts[key]
		if !ok {
			errors++
			log.Errorf("unknown workload runtime configuration key %q", key)
			continue
		}

		if opt.validate != nil {
			if err := opt.validate(val); err != nil {
				log.Errorf("invalid value for key %s: %s", key, err)
				errors++
			}
		}

	}

	// if errors have occurred, print the supported configuration keys to
	// the log
	if errors > 0 {
		log.Error("Supported configuration keys:")
		for key, val := range supportedOpts {
			log.Errorf("  %-12s %s", key, val.description)
		}

		return fmt.Errorf("invalid workload runtime configuration, see log for details")
	}

	// modify the configuration atomically after verification
	for key, val := range opts {
		supportedOpts[key].value = val
	}

	return nil
}

func getOpts(opts workloadRuntimeOpts) map[string]string {
	result := map[string]string{}

	for key, opt := range opts {
		result[key] = opt.value
	}

	return result
}

var (
	setupOnce sync.Once
	allocator allocatorInterface
)

func setupWorkload(workloadRuntime WorkloadRuntimeType, opts map[string]string) error {
	workloadMod := getWorkload(workloadRuntime)
	if workloadMod == nil {
		return fmt.Errorf("unknown workloadRuntime runtime type %s", workloadRuntime)
	}

	if err := workloadMod.setConfig(opts); err != nil {
		return err
	}

	return initClient(workloadMod)
}

type allocatorInterface interface {
	Blacklist(ip net.IP, owner string)
}

// Setup sets up the workload runtime specified in workloadRuntime and configures it
// with the options provided in opts
func Setup(a allocatorInterface, workloadRuntimes []string, opts map[WorkloadRuntimeType]map[string]string) error {
	return setup(a, workloadRuntimes, opts, false)
}

func setup(a allocatorInterface, workloadRuntimes []string, opts map[WorkloadRuntimeType]map[string]string, bypassStatusCheck bool) error {
	var (
		st  *models.Status
		err error
	)

	if bypassStatusCheck {
		st = &models.Status{State: models.StatusStateOk}
	}

	setupOnce.Do(
		func() {
			allocator = a

			var crt WorkloadRuntimeType
			for _, runtime := range workloadRuntimes {
				crt, err = parseRuntimeType(runtime)
				if err != nil {
					return
				}
				switch crt {
				case None:
					unregisterWorkloads()
					err = nil
					return
				}
			}

			for _, runtime := range workloadRuntimes {
				crt, err = parseRuntimeType(runtime)
				if err != nil {
					err = nil
				}
				switch crt {
				case Auto:
					var setupErr error
					for _, rt := range []WorkloadRuntimeType{Docker, ContainerD, CRIO} {
						setupErr = setupWorkload(rt, opts[rt])
						if !bypassStatusCheck {
							st = Status()
						}
						if setupErr == nil && st.State == models.StatusStateOk {
							return
						}
					}
					err = setupErr
					return
				default:
					err = setupWorkload(crt, opts[crt])
					return
				}
			}

		})

	return err
}
