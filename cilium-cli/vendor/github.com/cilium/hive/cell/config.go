// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cell

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/cilium/hive/internal"
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
	return &config[Cfg]{defaultConfig: def}
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

// config is a cell for configuration. It registers the config's command-line
// flags and provides the parsed config to the hive.
type config[Cfg Flagger] struct {
	defaultConfig Cfg
}

type AllSettings map[string]any

type DecodeHooks []mapstructure.DecodeHookFunc

type configParams[Cfg Flagger] struct {
	dig.In
	AllSettings AllSettings
	DecodeHooks DecodeHooks `optional:"true"`
	Override    func(*Cfg)  `optional:"true"`
}

func provideConfig[Cfg Flagger](defaultConfig Cfg, flags *pflag.FlagSet) func(p configParams[Cfg]) (Cfg, error) {
	return func(p configParams[Cfg]) (Cfg, error) {
		settings := p.AllSettings
		target := defaultConfig
		decoder, err := mapstructure.NewDecoder(decoderConfig(&target, p.DecodeHooks))
		if err != nil {
			return target, fmt.Errorf("failed to create config decoder: %w", err)
		}

		// As input, only consider the declared flags.
		input := make(map[string]any)

		flags.VisitAll(func(f *pflag.Flag) {
			if v, ok := settings[f.Name]; ok {
				input[f.Name] = v
			} else {
				err = fmt.Errorf("internal error: %s not found from settings", f.Name)
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

		// See if the configuration was overridden with ConfigOverride. We check the override
		// after the decode to validate that the config struct is properly formed and all
		// flags are registered.
		if p.Override != nil {
			p.Override(&target)
		}

		return target, nil
	}
}

func decoderConfig(target any, extraHooks DecodeHooks) *mapstructure.DecoderConfig {
	decodeHooks := []mapstructure.DecodeHookFunc{
		// To unify the splitting of fields of a []string field across the input coming
		// from environment, configmap and pflag (command-line), we first split a string
		// (env/configmap) by comma, and then for all input methods we split a single
		// value []string by whitespace. Thus the following all result in the same slice:
		//
		// --string-slice=foo,bar,baz
		// --string-slice="foo bar baz"
		// CILIUM_STRING_SLICE="foo,bar,baz"
		// CILIUM_STRING_SLICE="foo bar baz"
		// /.../configmap/string_slice: "foo bar baz"
		// /.../configmap/string_slice: "foo,bar,baz"
		//
		// If both commas and whitespaces are present the commas take precedence:
		// "foo,bar baz" => []string{"foo", "bar baz"}
		mapstructure.StringToSliceHookFunc(","), // string->[]string is split by comma
		fixupStringSliceHookFunc,                // []string of length 1 is split again by whitespace

		mapstructure.StringToTimeDurationHookFunc(),
		stringToMapHookFunc,
	}
	decodeHooks = append(decodeHooks, extraHooks...)

	return &mapstructure.DecoderConfig{
		Metadata:         nil,
		Result:           target,
		WeaklyTypedInput: true,
		DecodeHook:       mapstructure.ComposeDecodeHookFunc(decodeHooks...),
		ZeroFields:       true,
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
	flags := pflag.NewFlagSet("", pflag.ContinueOnError)
	c.defaultConfig.Flags(flags)

	// Register the flags to the global set of all flags.
	err := cont.Invoke(
		func(allFlags *pflag.FlagSet) {
			allFlags.AddFlagSet(flags)
		})
	if err != nil {
		return err
	}
	// And provide the constructor for the config.
	return cont.Provide(
		provideConfig(c.defaultConfig, flags),
		dig.Export(true),
	)
}

func (c *config[Cfg]) Info(cont container) (info Info) {
	cont.Invoke(func(cfg Cfg) {
		info = &InfoStruct{cfg}
	})
	return
}

// stringToMapHookFunc is a DecodeHookFunc that converts string
// to map[string]string supporting both json and KV formats.
func stringToMapHookFunc(from reflect.Kind, to reflect.Kind, data interface{}) (interface{}, error) {
	if from != reflect.String || to != reflect.Map {
		return data, nil
	}
	return internal.ToStringMapStringE(data.(string))
}

// fixupStringSliceHookFunc takes a []string and if it's a single element splits it again
// by whitespace. This unifies the flag parsing behavior with StringSlice
// values coming from environment or configmap where both spaces or commas can be used to split.
func fixupStringSliceHookFunc(from reflect.Type, to reflect.Type, data interface{}) (interface{}, error) {
	if from.Kind() != reflect.Slice || to.Kind() != reflect.Slice {
		return data, nil
	}
	if from.Elem().Kind() != reflect.String || to.Elem().Kind() != reflect.String {
		return data, nil
	}

	raw := data.([]string)
	if len(raw) == 1 {
		// Flag was already split by commas (the default behavior), so split it
		// now by spaces.
		return strings.Fields(raw[0]), nil
	}
	return raw, nil
}
