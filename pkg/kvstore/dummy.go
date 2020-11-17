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

package kvstore

import "context"

// SetupDummy sets up kvstore for tests
func SetupDummy(dummyBackend string) {
	setupDummyWithConfigOpts(dummyBackend, nil)
}

// setupDummyWithConfigOpts sets up the dummy kvstore for tests but also
// configures the module with the provided opts.
func setupDummyWithConfigOpts(dummyBackend string, opts map[string]string) {
	module := getBackend(dummyBackend)
	if module == nil {
		log.Panicf("Unknown dummy kvstore backend %s", dummyBackend)
	}

	module.setConfigDummy()

	if opts != nil {
		err := module.setConfig(opts)
		if err != nil {
			log.WithError(err).Panic("Unable to set config options for kvstore backend module")
		}
	}

	if err := initClient(context.TODO(), module, nil); err != nil {
		log.WithError(err).Panic("Unable to initialize kvstore client")
	}
}
