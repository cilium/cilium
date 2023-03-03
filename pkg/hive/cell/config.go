// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cell

import (
	"fmt"
	"strings"

	"github.com/mitchellh/mapstructure"
	"github.com/spf13/pflag"
	"go.uber.org/dig"
)

// Config constructs a new config cell.
//
// The configuration struct `T` needs to implement the Flags method that
// registers the flags. The structure is populated and provided via dependency
// injection by Hive.Run(). The underlying mechanism for populating the struct
// is viper's Unmarshal().
func Config[Cfg Flagger](def Cfg) Cell {
	c := &config[Cfg]{defaultConfig: def, flags: pflag.NewFlagSet("", pflag.ContinueOnError)}
	def.Flags(c.flags)
	return c
}

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

type AllSettings map[string]any

// config is a cell for configuration. It registers the config's command-line
// flags and provides the parsed config to the hive.
type config[Cfg Flagger] struct {
	defaultConfig Cfg
	flags         *pflag.FlagSet
}

func (c *config[Cfg]) provideConfig(settings AllSettings) (Cfg, error) {
	target := c.defaultConfig
	decoder, err := mapstructure.NewDecoder(decoderConfig(&target))
	if err != nil {
		return target, fmt.Errorf("failed to create config decoder: %w", err)
	}

	// As input, only consider the declared flags.
	input := make(map[string]any)

	pflags := map[string]struct{}{}
	c.flags.VisitAll(func(f *pflag.Flag) {
		pflags[f.Name] = struct{}{}
	})
	for k, _ := range pflags {
		// If this flag is not lower case and there exists a lower case
		// flag that conflicts with this one, then we need to error out
		// to avoid ambigous flag mapping.
		if _, exists := pflags[strings.ToLower(k)]; strings.ToLower(k) != k && exists {
			return target, fmt.Errorf("flag %q conflicts with %q, all flags are matched in lower case",
				k, strings.ToLower(k))
		}
	}

	c.flags.VisitAll(func(f *pflag.Flag) {
		fname := strings.ToLower(f.Name)
		if v, ok := settings[fname]; ok {
			input[f.Name] = v
		} else {
			err = fmt.Errorf("internal error: %s not found from settings", fname)
		}
	})
	if err != nil {
		return target, err
	}
	if err := decoder.Decode(input); err != nil {
		return target, fmt.Errorf("failed to unmarshal config struct %T: %w.\n"+
			"Hint: field 'FooBar' matches flag 'foo-bar', or use tag `mapstructure:\"flag-name\"` to match field with flag",
			target, err)
	}
	return target, nil
}

func decoderConfig(target any) *mapstructure.DecoderConfig {
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

func (c *config[Cfg]) Apply(cont container) error {
	// Register the flags to the global set of all flags.
	err := cont.Invoke(
		func(allFlags *pflag.FlagSet) {
			allFlags.AddFlagSet(c.flags)
		})
	if err != nil {
		return err
	}
	// And provide the constructor for the config.
	return cont.Provide(c.provideConfig, dig.Export(true))
}

func (c *config[Cfg]) Info(cont container) (info Info) {
	cont.Invoke(func(cfg Cfg) {
		info = &InfoStruct{cfg}
	})
	return
}
