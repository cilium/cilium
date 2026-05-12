// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cel

import "github.com/spf13/pflag"

// Config holds all tunable parameters for the CEL module.
type Config struct {
	// CompilerCacheMaxEntries is the maximum number of compiled expressions held in
	// the LRU cache. Entries are evicted in least-recently-used order once the
	// limit is reached.
	CompilerCacheMaxEntries int `mapstructure:"cel-compiler-cache-max-entries"`

	// ExpressionMaxCost is the maximum static (compile-time) worst-case cost
	// allowed for a CEL expression. Expressions whose estimated maximum cost
	// exceeds this value are rejected at compile time. Set to 0 to disable.
	ExpressionMaxCost uint64 `mapstructure:"cel-expression-max-cost"`

	// ProgramMaxCost is the maximum runtime cost budget for a single
	// expression evaluation. Evaluation is aborted with an error if the
	// actual accumulated cost exceeds this value. Set to 0 to disable.
	ProgramMaxCost uint64 `mapstructure:"cel-program-max-cost"`

	// ProgramInterruptCheckFrequency controls how often (in comprehension
	// iterations) CEL checks for context cancellation. Lower values make
	// cancellation more responsive at the expense of a small throughput cost.
	// Set to 0 to use CEL's default.
	ProgramInterruptCheckFrequency uint `mapstructure:"cel-program-interrupt-check-frequency"`
}

var DefaultConfig = Config{
	CompilerCacheMaxEntries:        128,
	ExpressionMaxCost:              10000,
	ProgramMaxCost:                 100000,
	ProgramInterruptCheckFrequency: 100,
}

func (def Config) Flags(flags *pflag.FlagSet) {
	flags.Int("cel-compiler-cache-max-entries", def.CompilerCacheMaxEntries,
		"Maximum entries in CEL expression compiler cache")
	flags.Uint64("cel-expression-max-cost", def.ExpressionMaxCost,
		"Maximum compile-time static cost estimate for a CEL expression (0 = disabled)")
	flags.Uint64("cel-program-max-cost", def.ProgramMaxCost,
		"Maximum runtime cost budget per CEL expression evaluation (0 = disabled)")
	flags.Uint("cel-program-interrupt-check-frequency", def.ProgramInterruptCheckFrequency,
		"How often (comprehension iterations) CEL checks for context cancellation (0 = default)")
}

func (cfg Config) CompilerCacheEnabled() bool {
	return cfg.CompilerCacheMaxEntries > 0
}
