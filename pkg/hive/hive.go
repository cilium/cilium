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

	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"go.uber.org/fx"
	"go.uber.org/fx/fxevent"
	"go.uber.org/fx/fxtest"

	"github.com/cilium/cilium/pkg/hive/cell"
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

// Hive is a framework building modular applications.
//
// It implements dependency injection using the fx library and adds on
// top of it the ability to register command-line flags for parsing prior to
// object graph construction.
//
// See pkg/hive/example for a runnable example application.
type Hive struct {
	app                       *fx.App
	cells                     []cell.Cell
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
func New(v *viper.Viper, flags *pflag.FlagSet, cells ...cell.Cell) *Hive {
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

// NewForTests returns a new hive for testing that does not register
// the flags declared by the cells. Use in combination with TestApp()
// to provide cell configurations.
func NewForTests(cells ...cell.Cell) *Hive {
	return New(viper.New(), pflag.NewFlagSet("", pflag.ContinueOnError), cells...)
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
		cell.RegisterFlags(h.flags)
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
func (h *Hive) populate() (fx.Option, error) {
	allSettings := h.viper.AllSettings()

	allOpts := []fx.Option{}
	for _, cell := range h.cells {
		opt, err := cell.ToOption(allSettings)
		if err != nil {
			return nil, err
		}
		allOpts = append(allOpts, opt)
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
		fx.StartTimeout(h.startTimeout),
		fx.StopTimeout(h.stopTimeout),
		fx.Populate(&h.dotGraph),
		fx.Decorate(func(parent fx.Lifecycle) fx.Lifecycle {
			h.lifecycle.parent = parent
			return &h.lifecycle
		}),
		opts,
	)
	return h.app.Err()
}

// TestApp constructs a test application for the hive with given configuration
// overrides.
func (h *Hive) TestApp(tb fxtest.TB) (*fxtest.App, error) {
	opts, err := h.populate()
	if err != nil {
		return nil, err
	}
	return fxtest.New(tb,
		fx.Supply(fx.Annotate(log, fx.As(new(logrus.FieldLogger)))),
		opts), nil
}

func funcNameAndLocation(fn any) string {
	f := runtime.FuncForPC(reflect.ValueOf(fn).Pointer())
	file, line := f.FileLine(f.Entry())
	return fmt.Sprintf("%s (.../%s/%s:%d)", f.Name(), path.Base(path.Dir(file)), path.Base(file), line)
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
