// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

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
