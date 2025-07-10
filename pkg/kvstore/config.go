// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package kvstore

import (
	"fmt"
	"log/slog"

	"github.com/cilium/cilium/pkg/logging/logfields"
)

// setOpts validates the specified options against the selected backend and
// then modifies the configuration
func setOpts(logger *slog.Logger, opts map[string]string, supportedOpts backendOptions) error {
	errors := 0

	for key, val := range opts {
		opt, ok := supportedOpts[key]
		if !ok {
			errors++
			logger.Error("unknown kvstore configuration key", logfields.Key, key)
			continue
		}

		if opt.validate != nil {
			if err := opt.validate(val); err != nil {
				logger.Error("invalid value for key",
					logfields.Error, err,
					logfields.Key, key,
				)
				errors++
			}
		}

	}

	// if errors have occurred, print the supported configuration keys to
	// the log
	if errors > 0 {
		logger.Error("Supported configuration keys:")
		for key, val := range supportedOpts {
			logger.Error(fmt.Sprintf("  %-12s %s", key, val.description))
		}

		return fmt.Errorf("invalid kvstore configuration, see log for details")
	}

	// modify the configuration atomically after verification
	for key, val := range opts {
		supportedOpts[key].value = val
	}

	return nil
}
