// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package hive

import (
	"context"
	"errors"
	"fmt"
	"path"
	"reflect"
	"runtime"
	"strings"
	"time"

	"github.com/mitchellh/mapstructure"
	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"go.uber.org/fx"
	"go.uber.org/fx/fxevent"
	"go.uber.org/fx/fxtest"

	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "hive")
)

const (
	// defaultStartTimeout is the amount of time allotted for start hooks. After
	// this duration the context passed to the start hooks is cancelled.
	defaultStartTimeout = 5 * time.Minute

	// defaultStopTimeout is the amount of time allotted for stop hooks.
	defaultStopTimeout = time.Minute

	// defaultEnvPrefix is the default prefix for environment variables, e.g.
	// flag "foo" can be set with environment variable "CILIUM_FOO".
	defaultEnvPrefix = "CILIUM_"
)

// Hive is a modular application built from cells.
type Hive struct {
	app                       *fx.App
	cells                     []*Cell
	dotGraph                  fx.DotGraph
	envPrefix                 string
	flags                     *pflag.FlagSet
	fxLogger                  *logging.FxLogger
	lifecycle                 lifecycleProxy
	startTimeout, stopTimeout time.Duration
	viper                     *viper.Viper
}

// New returns a new hive that can be run, or inspected.
// The command-line flags from the cells are registered as part of this.
//
// The object graph is not constructed until methods of the hive are
// invoked.
func New(v *viper.Viper, flags *pflag.FlagSet, cells ...*Cell) *Hive {
	h := &Hive{
		envPrefix:    defaultEnvPrefix,
		fxLogger:     logging.NewFxLogger(log),
		cells:        cells,
		viper:        v,
		flags:        pflag.NewFlagSet("", pflag.ContinueOnError),
		startTimeout: defaultStartTimeout,
		stopTimeout:  defaultStopTimeout,
	}
	if err := h.registerFlags(flags); err != nil {
		log.Fatal(err)
	}
	return h
}

func (h *Hive) SetTimeouts(start, stop time.Duration) {
	h.startTimeout, h.stopTimeout = start, stop
}

func (h *Hive) SetEnvPrefix(prefix string) {
	h.envPrefix = prefix
}

// Run populates the cell configurations and runs the hive cells.
// If an error occurs when populating cell configurations this
// method panics.
// Interrupt signal will cause the hive to stop.
func (h *Hive) Run() {
	if h.app == nil {
		if err := h.createApp(); err != nil {
			log.Fatalf("Run failed: %s", err)
		}
	}
	h.app.Run()
}

func (h *Hive) Start(ctx context.Context) error {
	if h.app == nil {
		if err := h.createApp(); err != nil {
			log.Fatalf("Start failed: %s", err)
		}
	}
	return h.app.Start(ctx)
}

func (h *Hive) Stop(ctx context.Context) error {
	if h.app == nil {
		return errors.New("Hive was not started")
	}
	return h.app.Stop(ctx)
}

func (h *Hive) PrintObjects() {
	if err := h.createApp(); err != nil {
		log.Fatal(err)
	}
	h.fxLogger.PrintObjects()

	fmt.Printf("Start hooks:\n\n")
	for _, hook := range h.lifecycle.hooks {
		if hook.OnStart == nil {
			continue
		}
		fmt.Printf("  • %s\n", funcNameAndLocation(hook.OnStart))
	}

	fmt.Printf("\nStop hooks:\n\n")
	for i := len(h.lifecycle.hooks) - 1; i >= 0; i-- {
		hook := h.lifecycle.hooks[i]
		if hook.OnStop == nil {
			continue
		}
		fmt.Printf("  • %s\n", funcNameAndLocation(hook.OnStop))
	}

	fmt.Printf("\nConfigurations:\n\n")
	allSettings := h.viper.AllSettings()
	for _, cell := range h.cells {
		if cell.newConfig != nil {
			cfg := cell.newConfig()
			h.unmarshalConfig(allSettings, cell, &cfg)
			fmt.Printf("  ⚙ %s: %#v\n", cell.name, cfg)
		}
	}
}

func (h *Hive) PrintDotGraph() {
	if err := h.createApp(); err != nil {
		log.Fatal(err)
	}
	fmt.Print(h.dotGraph)
}

// getEnvName returns the environment variable to be used for the given option name.
func (h *Hive) getEnvName(option string) string {
	under := strings.Replace(option, "-", "_", -1)
	upper := strings.ToUpper(under)
	return h.envPrefix + upper
}

// registerCells registers the command-line flags from all the cells.
func (h *Hive) registerFlags(parent *pflag.FlagSet) error {
	for _, cell := range h.cells {
		flags := pflag.NewFlagSet("", pflag.ContinueOnError)
		cell.registerFlags(flags)
		h.flags.AddFlagSet(flags)
		flags.VisitAll(func(f *pflag.Flag) {
			cell.flags = append(cell.flags, f.Name)
		})
	}
	var err error
	h.flags.VisitAll(func(f *pflag.Flag) {
		if err != nil {
			return
		}
		if parent.Lookup(f.Name) != nil {
			err = fmt.Errorf("error registering flags: '%s' already registered", f.Name)
		} else {
			viper.BindEnv(f.Name, h.getEnvName(f.Name))
			parent.AddFlag(f)
		}
	})
	if err != nil {
		return err
	}
	return h.viper.BindPFlags(h.flags)
}

// populate creates the cell configurations from viper and returns the combined
// fx option for all cells and their configurations.
func (h *Hive) populate(overrides ...any) (fx.Option, error) {
	allSettings := h.viper.AllSettings()

	overridesMap := map[reflect.Type]any{}
	for _, cfg := range overrides {
		overridesMap[reflect.TypeOf(cfg)] = cfg
	}

	allOpts := []fx.Option{}
	for _, cell := range h.cells {
		cell := cell

		cellOpts := cell.opts
		if cell.newConfig != nil {
			cfg := cell.newConfig()

			if override, ok := overridesMap[reflect.TypeOf(cfg)]; ok {
				cfg = override
			} else {
				if err := h.unmarshalConfig(allSettings, cell, &cfg); err != nil {
					return nil, err
				}
			}
			cellOpts = append(cellOpts, fx.Supply(cfg))
		}

		var cellOpt fx.Option
		if cell.name != "" {
			// Provide a logger to the cell that has subsys set to the cell name.
			cellLogger := fx.Decorate(
				func(log logrus.FieldLogger) logrus.FieldLogger {
					return log.WithField(logfields.LogSubsys, cell.name)
				})
			cellOpts = append(cellOpts, cellLogger)
			cellOpt = fx.Module(cell.name, cellOpts...)
		} else {
			cellOpt = fx.Options(cellOpts...)
		}
		allOpts = append(allOpts, cellOpt)
	}
	return fx.Options(allOpts...), nil
}

// createApp creates the fx application, unless already created.
func (h *Hive) createApp() error {
	if h.app != nil {
		return nil
	}
	opts, err := h.populate()
	if err != nil {
		return err
	}
	h.app = fx.New(
		fx.WithLogger(func() fxevent.Logger { return h.fxLogger }),
		fx.Supply(fx.Annotate(log, fx.As(new(logrus.FieldLogger)))),
		fx.Decorate(func(parent fx.Lifecycle) fx.Lifecycle {
			h.lifecycle.parent = parent
			return &h.lifecycle
		}),
		fx.StartTimeout(h.startTimeout),
		fx.StopTimeout(h.stopTimeout),
		fx.Populate(&h.dotGraph),
		opts,
	)
	return h.app.Err()
}

// TestApp constructs a test application for the hive with given configuration
// overrides.
func (h *Hive) TestApp(tb fxtest.TB, configs ...any) (*fxtest.App, error) {
	opts, err := h.populate(configs...)
	if err != nil {
		return nil, err
	}
	return fxtest.New(tb,
		fx.Supply(fx.Annotate(log, fx.As(new(logrus.FieldLogger)))),
		opts), nil
}

func (h *Hive) unmarshalConfig(allSettings map[string]any, cell *Cell, target *any) error {
	decoder, err := mapstructure.NewDecoder(decoderConfig(target))
	if err != nil {
		return fmt.Errorf("failed to create config decoder: %w", err)
	}

	// As input, only consider the flags declared by CellFlags.
	input := make(map[string]any)
	for _, flag := range cell.flags {
		if v, ok := allSettings[flag]; ok {
			input[flag] = v
		} else {
			return fmt.Errorf("internal error: cell flag %s not found from settings", flag)
		}
	}

	if err := decoder.Decode(input); err != nil {
		return fmt.Errorf("failed to unmarshal config struct %T: %w.\n"+
			"Hint: field 'FooBar' matches flag 'foo-bar', or use tag `mapstructure:\"flag-name\"` to match field with flag",
			*target, err)
	}
	return nil
}

func decoderConfig(target *any) *mapstructure.DecoderConfig {
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

// lifecycleProxy collects the appended hooks so they can be shown
// in PrintObjects() as fx doesn't provide access to the hooks.
type lifecycleProxy struct {
	parent fx.Lifecycle
	hooks  []fx.Hook
}

func (p *lifecycleProxy) Append(hook fx.Hook) {
	p.hooks = append(p.hooks, hook)
	p.parent.Append(hook)
}

var _ fx.Lifecycle = &lifecycleProxy{}

func funcNameAndLocation(fn any) string {
	f := runtime.FuncForPC(reflect.ValueOf(fn).Pointer())
	file, line := f.FileLine(f.Entry())
	return fmt.Sprintf("%s (.../%s/%s:%d)", f.Name(), path.Base(path.Dir(file)), path.Base(file), line)
}
