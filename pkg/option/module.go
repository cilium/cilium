// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package option

import (
	"fmt"
	"os"
	"reflect"
	"sort"
	"time"

	"github.com/spf13/cast"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"go.uber.org/fx"
	"golang.org/x/exp/maps"

	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// The option module implements a modular configuration system that allows
// modules to register configuration structures to be parsed from command-line
// flags or configuration files.
//
// To create a config struct define the struct with fields of type Opt[T] and
// create a default to describe the flags:
//
//	type ThingConfig struct {
//	        Foo Opt[string]
//	        Bar Opt[bool]
//	        Baz Opt[[]string]
//	}
//
//	var thingConfigOpts = MyConfig{
//	        Foo: option.String("thing-foo", "the default foo", "Set the foo option"),
//	        Bar: option.Bool("thing-bar", true, "Enable bar").Hidden(),
//	        Baz: option.StringSlice("thing-bazes", []string{}, "Bazes").Deprecated("Bazes has been deprecated"),
//	}
//
// And then in the module definition, call RegisterConfig() to create the fx.Option
// to register the structure and provide a constructor for MyConfig:
//
//	var ThingModule = fx.Module(
//	      "thing",
//
//	       fx.Provide(
//	             option.Register(thingConfigOpts)),
//	             option.GetConfig[ThingConfig],
//	       ),
//	       fx.Provide(newThing),
//	)
//	func newThing(config ThingConfig) *Thing {
//	       if config.Bar.Get() { ... }
//	}
//
// The configuration structs are passed by value to stop post-parsing mutation of
// the configuration.
func Module() fx.Option {
	return fx.Module(
		"option",
		fx.Provide(newConfigProvider),
	)
}

// ConfigProvider provides access to parsed configurations. A configuration is a
// struct with fields of type Opt[T] that has been registered with RegisterConfig().
type ConfigProvider interface {
	// GetConfig retrieves the configuration for the structure of the given type.
	GetConfig(typeName string) (any, error)

	// DumpConfigs prints all registered configurations to stdout
	DumpConfigs()
}

type CommandLineArguments []string

type configProviderParams struct {
	fx.In

	Args    CommandLineArguments
	FlagSet *pflag.FlagSet

	// Registrations are all the configurations registered with Register().
	Registrations []ConfigRegistration `group:"configs"`
}

type configProvider struct {
	flagSet *pflag.FlagSet
	configs map[string]any
}

func (p *configProvider) GetConfig(typeName string) (any, error) {
	if cfg, ok := p.configs[typeName]; ok {
		return cfg, nil
	}
	return nil, fmt.Errorf("No configuration found for %s", typeName)
}

func newConfigProvider(in configProviderParams) (ConfigProvider, error) {
	configs := make(map[string]any)
	allOpts := []optInternal{}
	flags := in.FlagSet

	// Iterate over all registered configuration structs to build the flag set.
	for _, reg := range in.Registrations {
		val := reflect.ValueOf(reg.configStruct)
		typ := val.Type()
		configs[typ.PkgPath()+"."+typ.Name()] = reg.configStruct

		if val.Kind() != reflect.Struct {
			return nil, fmt.Errorf("%s is not a struct!", typ)
		}

		for i := 0; i < val.NumField(); i++ {
			if opt, ok := val.Field(i).Interface().(optInternal); ok {
				opt.register(flags)
				allOpts = append(allOpts, opt)
			}
		}
	}

	if err := flags.Parse(in.Args[1:]); err != nil {
		return nil, err
	}

	// Provide the parsed flags to viper
	viper.BindPFlags(flags)

	// Read in the configuration file if it is specified.
	configFile := viper.GetString(ConfigFile)
	if configFile != "" {
		viper.SetConfigFile(configFile)

		if err := viper.ReadInConfig(); err == nil {
			log.WithField(logfields.Path, viper.ConfigFileUsed()).
				Info("Using config from file")
		} else if Config.ConfigFile != "" {
			log.WithField(logfields.Path, Config.ConfigFile).
				Fatal("Error reading config file")
		} else {
			log.WithError(err).Debug("Skipped reading configuration file")
		}
	}

	// Read in the configuration directory.
	configDir := viper.GetString(ConfigDir)
	if configDir != "" {
		if _, err := os.Stat(configDir); os.IsNotExist(err) {
			return nil, fmt.Errorf("Non-existent configuration directory %s", Config.ConfigDir)
		}

		if m, err := ReadDirConfig(configDir); err != nil {
			log.WithError(err).Fatalf("Unable to read configuration directory %s", Config.ConfigDir)
		} else {
			// replace deprecated fields with new fields
			ReplaceDeprecatedFields(m)

			// validate the config-map
			if err := validateConfigMap(flags, m); err != nil {
				log.WithError(err).Fatal("Incorrect config-map flag value")
			}

			if err := MergeConfig(m); err != nil {
				log.WithError(err).Fatal("Unable to merge configuration")
			}
		}
	}

	// Iterate over all options and pull in the parsed values from viper.
	for _, opt := range allOpts {
		if err := opt.assign(viper.Get(opt.getFlag())); err != nil {
			return nil, fmt.Errorf("Error parsing %q: %s", opt.getFlag(), err)
		}
	}

	return &configProvider{flags, configs}, nil
}

func (p *configProvider) DumpConfigs() {
	fmt.Printf("Configurations:\n\n")

	keys := maps.Keys(p.configs)
	sort.Strings(keys)

	for _, name := range keys {
		cfg := p.configs[name]
		fmt.Printf("  %s:\n", name)

		val := reflect.ValueOf(cfg)
		typ := reflect.TypeOf(cfg)
		for i := 0; i < val.NumField(); i++ {
			if opt, ok := val.Field(i).Interface().(optInternal); ok {
				flag := p.flagSet.Lookup(opt.getFlag())
				v := fmt.Sprintf("%s=%s", flag.Name, flag.Value.String())
				fmt.Printf("    %-25s | %-30s | %s\n", v, typ.Field(i).Name+" "+val.Field(i).Type().Name(), flag.Usage)
			}
		}
		fmt.Println()
	}
}

type ConfigRegistration struct {
	configStruct any
}

// Register provides the constructor for registering a config for the
// ConfigProvider to parse. Use with fx.Provide.
//
// Note that we're not providing a wrapper function that does fx.Provide
// on both Register and GetConfig in order to have the correct package and
// function names in the dependency graph for ConfigRegistration and config.
func Register(configStruct any) fx.Annotated {
	return fx.Annotated{
		Group: "configs",
		Target: func() ConfigRegistration {
			return ConfigRegistration{configStruct}
		},
	}
}

// GetConfig pulls type T from the ConfigProvider and casts it to the concrete type
// in order to inject it into the dependency graph.
func GetConfig[T any](p ConfigProvider) (T, error) {
	var proto T
	typ := reflect.TypeOf(proto)
	typeName := typ.PkgPath() + "." + typ.Name()
	if cfgValue, err := p.GetConfig(typeName); err != nil {
		return proto, err
	} else {
		return cfgValue.(T), nil
	}
}

// Opt is a configuration option. An option can be created with a helper
// such as option.String or option.Bool etc. The value can be retrieved with Get().
type Opt[T any] interface {
	fmt.Stringer

	// Get returns the parsed value of the option. Use only on
	// configuration struct provided via RegisterConfig.
	Get() T
}

// OptBuilder is a configuration option on which further changes are possible.
// This type should not appear in configuration structs.
type OptBuilder[T any] interface {
	Opt[T]

	// Mark the option as deprecated with the given reason
	Deprecated(reason string) Opt[T]

	// Mark the option hidden
	Hidden() Opt[T]
}

// String creates a new string option
func String(flag, def, usage string) OptBuilder[string] {
	return newOpt(flag, func(flags *pflag.FlagSet) { flags.String(flag, def, usage) }, cast.ToStringE)
}

// StringSlice creates a new string slice option
func StringSlice(flag string, def []string, usage string) OptBuilder[[]string] {
	return newOpt(flag, func(flags *pflag.FlagSet) { flags.StringSlice(flag, def, usage) }, cast.ToStringSliceE)
}

// Int creates a new int option
func Int(flag string, def int, usage string) OptBuilder[int] {
	return newOpt(flag, func(flags *pflag.FlagSet) { flags.Int(flag, def, usage) }, cast.ToIntE)
}

// Uint creates a new uint option
func Uint(flag string, def uint, usage string) OptBuilder[uint] {
	return newOpt(flag, func(flags *pflag.FlagSet) { flags.Uint(flag, def, usage) }, cast.ToUintE)
}

// Uint16 creates a new uint option
func Uint16(flag string, def uint16, usage string) OptBuilder[uint16] {
	return newOpt(flag, func(flags *pflag.FlagSet) { flags.Uint16(flag, def, usage) }, cast.ToUint16E)
}

// Float64 creates a new float64 option
func Float64(flag string, def float64, usage string) OptBuilder[float64] {
	return newOpt(flag, func(flags *pflag.FlagSet) { flags.Float64(flag, def, usage) }, cast.ToFloat64E)
}

// Bool creates a new boolean option
func Bool(flag string, def bool, usage string) OptBuilder[bool] {
	return newOpt(flag, func(flags *pflag.FlagSet) { flags.Bool(flag, def, usage) }, cast.ToBoolE)
}

// Duration creates a new duration option
func Duration(flag string, def time.Duration, usage string) OptBuilder[time.Duration] {
	return newOpt(flag, func(flags *pflag.FlagSet) { flags.Duration(flag, def, usage) }, cast.ToDurationE)
}

// CIDR creates a new CIDR option
func CIDR(flag string, def *cidr.CIDR, usage string) OptBuilder[*cidr.CIDR] {
	defstr := ""
	if def != nil {
		defstr = def.String()
	}
	parse := func(v any) (*cidr.CIDR, error) {
		return cidr.ParseCIDR(cast.ToString(v))
	}
	return newOpt(flag,
		func(flags *pflag.FlagSet) { flags.String(flag, defstr, usage) },
		parse)
}

// CIDRs creates a new option for a slice of CIDRs
func CIDRs(flag string, def []*cidr.CIDR, usage string) OptBuilder[[]*cidr.CIDR] {
	defs := make([]string, len(def))
	for i := range def {
		defs[i] = def[i].String()
	}
	parse := func(v any) ([]*cidr.CIDR, error) {
		var cidrs []*cidr.CIDR
		vs, err := cast.ToStringSliceE(v)
		if err != nil {
			return nil, err
		}
		for _, s := range vs {
			cidr, err := cidr.ParseCIDR(s)
			if err != nil {
				return nil, err
			}
			cidrs = append(cidrs, cidr)
		}
		return cidrs, nil
	}
	return newOpt(flag,
		func(flags *pflag.FlagSet) { flags.StringSlice(flag, defs, usage) },
		parse)
}

type parser[T any] func(any) (T, error)

func newOpt[T any](flag string, register func(flags *pflag.FlagSet), parse parser[T]) OptBuilder[T] {
	if flag == "" {
		panic("empty flag")
	}
	return &opt[T]{flag: flag, registerFlag: register, parse: parse}
}

// optInternal are the internal methods implemented by opt[T] that are independent of T.
type optInternal interface {
	assign(v any) error
	register(flags *pflag.FlagSet)
	getFlag() string
}

type opt[T any] struct {
	// flag is the command-line flag associated with this option
	flag string

	// parse parses the option
	parse parser[T]

	// register the option to the flagset
	registerFlag func(flags *pflag.FlagSet)

	// deprecated if non-empty makes this option deprecated and if used
	// shows this usage text.
	deprecated string

	// hidden if set hides this option from command-line usage help.
	hidden bool

	// value is the retrieved from command-line flags or configuration
	// files for this option.
	value T

	// assigned is true if the option has been assigned.
	// Get() panics if this is false to catch uninitialized
	// use of Opt.
	assigned bool
}

func (o *opt[T]) Get() T {
	if !o.assigned {
		panic(fmt.Sprintf("%T.Get() called on unassigned option. See option.RegisterConfig()", o))
	}
	return o.value
}

func (o *opt[T]) Deprecated(reason string) Opt[T] {
	o.deprecated = reason
	return o
}

func (o *opt[T]) Hidden() Opt[T] {
	o.hidden = true
	return o
}

func (o *opt[T]) String() string {
	if !o.assigned {
		return fmt.Sprintf("%s=(unassigned)", o.flag)
	}
	return fmt.Sprintf("%s=%v", o.flag, o.value)
}

func (o *opt[T]) register(flags *pflag.FlagSet) {
	o.registerFlag(flags)
	BindEnv(o.flag)

	if o.hidden {
		flags.MarkHidden(o.flag)
	}

	if o.deprecated != "" {
		flags.MarkDeprecated(o.flag, o.deprecated)
	}
}

func (o *opt[T]) assign(v any) (err error) {
	o.value, err = o.parse(v)
	o.assigned = true
	return
}

func (o *opt[T]) getFlag() string {
	return o.flag
}
