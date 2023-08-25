// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package kvstore

import (
	"context"
	"fmt"
	"sync"

	"github.com/cilium/cilium/pkg/logging/logfields"
)

var (
	// selectedModule is the name of the selected backend module
	selectedModule string
)

// setOpts validates the specified options against the selected backend and
// then modifies the configuration
func setOpts(opts map[string]string, supportedOpts backendOptions) error {
	errors := 0

	for key, val := range opts {
		opt, ok := supportedOpts[key]
		if !ok {
			errors++
			log.WithField(logfields.Key, key).Error("unknown kvstore configuration key")
			continue
		}

		if opt.validate != nil {
			if err := opt.validate(val); err != nil {
				log.WithError(err).Errorf("invalid value for key %s", key)
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

		return fmt.Errorf("invalid kvstore configuration, see log for details")
	}

	// modify the configuration atomically after verification
	for key, val := range opts {
		supportedOpts[key].value = val
	}

	return nil
}

func getOpts(opts backendOptions) map[string]string {
	result := map[string]string{}

	for key, opt := range opts {
		result[key] = opt.value
	}

	return result
}

var (
	setupOnce sync.Once
)

func setup(ctx context.Context, selectedBackend string, opts map[string]string, goOpts *ExtraOptions) error {
	module := getBackend(selectedBackend)
	if module == nil {
		return fmt.Errorf("unknown key-value store type %q. See cilium.link/err-kvstore for details", selectedBackend)
	}

	if err := module.setConfig(opts); err != nil {
		return err
	}

	if err := module.setExtraConfig(goOpts); err != nil {
		return err
	}

	selectedModule = module.getName()

	return initClient(ctx, module, goOpts)
}

// Setup sets up the key-value store specified in kvStore and configures it
// with the options provided in opts
func Setup(ctx context.Context, selectedBackend string, opts map[string]string, goOpts *ExtraOptions) error {
	var err error

	setupOnce.Do(func() {
		err = setup(ctx, selectedBackend, opts, goOpts)
	})

	return err
}
