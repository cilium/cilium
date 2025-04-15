// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package config

import (
	"os"
	"strings"
)

const (
	// HUBBLE_COMPAT is an environment variable similar to GODEBUG.
	//
	// It allows us to preserve old CLI behavior in the presence of
	// breaking changes.
	compatEnvKey = "HUBBLE_COMPAT"

	// legacy-json-output uses the old "-o json" format present
	// in Hubble CLI v0.10 and older
	compatLegacyJSONOutput = "legacy-json-output"
)

// CompatOptions defines the available compatibility options
type CompatOptions struct {
	LegacyJSONOutput bool
}

// Compat contains the parsed HUBBLE_COMPAT options
var Compat = compatFromEnv()

func compatFromEnv() CompatOptions {
	c := CompatOptions{}

	for opt := range strings.SplitSeq(os.Getenv(compatEnvKey), ",") {
		switch strings.ToLower(opt) {
		case compatLegacyJSONOutput:
			c.LegacyJSONOutput = true
		default:
			// silently ignore unknown options for forward-compatibility
		}
	}

	return c
}
