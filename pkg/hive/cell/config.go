// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cell

import (
	"fmt"
	"strings"

	"github.com/mitchellh/mapstructure"
	"github.com/spf13/pflag"
	"go.uber.org/fx"
)

// Flagger is implemented by configuration structs to provide configuration
// for a cell.
type Flagger interface {
	// Flags registers the configuration options as command-line flags.
	//
	// By convention a flag name matches the field name
	// if they're the same under case-insensitive comparison when dashes are
	// removed. E.g. "my-config-flag" matches field "MyConfigFlag". The
	// correspondence to the flag can be also specified with the mapstructure
	// tag: MyConfigFlag `mapstructure:"my-config-flag"`.
	//
	// Exported fields that are not found from the viper settings will cause
	// hive.Run() to fail. Unexported fields are ignored.
	//
	// See https://pkg.go.dev/github.com/mitchellh/mapstructure for more info.
	Flags(*pflag.FlagSet)
}

// config is a cell for configuration. It registers the config's command-line
// flags and provides the parsed config to the hive.
type config struct {
	defaultConfig Flagger

	// flags registered for the cell. Populated after call to RegisterFlags().
	// Used to pick only the settings that are registered from the set of
	// all settings when unmarshalling config.
	flags []string
}

func (s *config) RegisterFlags(parent *pflag.FlagSet) {
	flags := pflag.NewFlagSet("", pflag.ContinueOnError)
	s.defaultConfig.Flags(flags)
	flags.VisitAll(func(f *pflag.Flag) {
		s.flags = append(s.flags, f.Name)
	})
	parent.AddFlagSet(flags)
}

func (s *config) unmarshalConfig(settings map[string]any) (any, error) {
	target := s.defaultConfig
	decoder, err := mapstructure.NewDecoder(decoderConfig(&target))
	if err != nil {
		return nil, fmt.Errorf("failed to create config decoder: %w", err)
	}

	// As input, only consider the flags declared by CellFlags.
	input := make(map[string]any)
	for _, flag := range s.flags {
		if v, ok := settings[flag]; ok {
			input[flag] = v
		} else {
			return nil, fmt.Errorf("internal error: cell flag %s not found from settings", flag)
		}
	}

	if err := decoder.Decode(input); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config struct %T: %w.\n"+
			"Hint: field 'FooBar' matches flag 'foo-bar', or use tag `mapstructure:\"flag-name\"` to match field with flag",
			target, err)
	}
	return target, nil
}

func decoderConfig(target *Flagger) *mapstructure.DecoderConfig {
	return &mapstructure.DecoderConfig{
		Metadata:         nil,
		Result:           target,
		WeaklyTypedInput: true,
		DecodeHook: mapstructure.ComposeDecodeHookFunc(
			mapstructure.StringToTimeDurationHookFunc(),
			mapstructure.StringToSliceHookFunc(","),
		),
		ZeroFields: true,
		// Error out if the config struct has fields that are
		// not found from input.
		ErrorUnset: true,
		// Error out also if settings from input are not used.
		ErrorUnused: true,
		// Match field FooBarBaz with "foo-bar-baz" by removing
		// the dashes from the flag.
		MatchName: func(mapKey, fieldName string) bool {
			return strings.EqualFold(
				strings.ReplaceAll(mapKey, "-", ""),
				fieldName)
		},
	}
}

func (s *config) ToOption(settings map[string]any) (fx.Option, error) {
	cfg, err := s.unmarshalConfig(settings)
	if err != nil {
		return nil, err
	}
	return fx.Supply(cfg), err
}

// Config constructs a new config cell.
//
// The configuration struct `T` needs to implement the Flags method that
// registers the flags. The structure is populated and provided via dependency
// injection by Hive.Run(). The underlying mechanism for populating the struct
// is viper's Unmarshal().
func Config(def Flagger) Cell {
	return &config{defaultConfig: def}
}
