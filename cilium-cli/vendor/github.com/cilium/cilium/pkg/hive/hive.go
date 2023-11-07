// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package hive

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"reflect"
	"strings"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"go.uber.org/dig"

	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/hive/cell/lifecycle"
	"github.com/cilium/cilium/pkg/hive/metrics"
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
// It implements dependency injection using the dig library.
//
// See pkg/hive/example for a runnable example application.
type Hive struct {
	container                 *dig.Container
	cells                     []cell.Cell
	shutdown                  chan error
	envPrefix                 string
	startTimeout, stopTimeout time.Duration
	flags                     *pflag.FlagSet
	viper                     *viper.Viper
	lifecycle                 *DefaultLifecycle
	populated                 bool
	invokes                   []func() error
	configOverrides           []any
}

// New returns a new hive that can be run, or inspected.
// The command-line flags from the cells are registered as part of this.
//
// The object graph is not constructed until methods of the hive are
// invoked.
//
// Applications should call RegisterFlags() to register the hive's command-line
// flags. Likewise if configuration settings come from configuration files, then
// the Viper() method can be used to populate the hive's viper instance.
func New(cells ...cell.Cell) *Hive {
	h := &Hive{
		container:       dig.New(),
		envPrefix:       defaultEnvPrefix,
		cells:           cells,
		viper:           viper.New(),
		startTimeout:    defaultStartTimeout,
		stopTimeout:     defaultStopTimeout,
		flags:           pflag.NewFlagSet("", pflag.ContinueOnError),
		lifecycle:       &DefaultLifecycle{},
		shutdown:        make(chan error, 1),
		configOverrides: nil,
	}

	if err := h.provideDefaults(); err != nil {
		log.WithError(err).Fatal("Failed to provide default objects")
	}

	if err := metrics.Cell.Apply(h.container); err != nil {
		log.WithError(err).Fatal("Failed to apply Hive metrics cell")
	}

	// Use a single health provider for all cells, which is used to create
	// module scoped health reporters.
	if err := h.container.Provide(func(healthMetrics *metrics.HealthMetrics, lc Lifecycle) cell.Health {
		hp := cell.NewHealthProvider()
		updateStats := func() {
			for l, c := range hp.Stats() {
				healthMetrics.HealthStatusGauge.WithLabelValues(strings.ToLower(string(l))).Set(float64(c))
			}
		}
		lc.Append(Hook{
			OnStart: func(ctx HookContext) error {
				updateStats()
				hp.Subscribe(ctx, func(u cell.Update) {
					updateStats()
				}, func(err error) {})
				return nil
			},
			OnStop: func(ctx HookContext) error {
				return hp.Stop(ctx)
			},
		})
		return hp
	}); err != nil {
		log.WithError(err).Fatal("Failed to provide health provider")
	}

	// Apply all cells to the container. This registers all constructors
	// and adds all config flags. Invokes are delayed until Start() is
	// called.
	for _, cell := range cells {
		if err := cell.Apply(h.container); err != nil {
			log.WithError(err).Fatal("Failed to apply cell")
		}
	}

	// Bind the newly registered flags to viper.
	h.flags.VisitAll(func(f *pflag.Flag) {
		if err := h.viper.BindPFlag(f.Name, f); err != nil {
			log.Fatalf("BindPFlag: %s", err)
		}
		if err := h.viper.BindEnv(f.Name, h.getEnvName(f.Name)); err != nil {
			log.Fatalf("BindEnv: %s", err)
		}
	})

	return h
}

// RegisterFlags adds all flags in the hive to the given flag set.
// Fatals if a flag already exists in the given flag set.
// Use with e.g. cobra.Command:
//
//	cmd := &cobra.Command{...}
//	h.RegisterFlags(cmd.Flags())
func (h *Hive) RegisterFlags(flags *pflag.FlagSet) {
	h.flags.VisitAll(func(f *pflag.Flag) {
		if flags.Lookup(f.Name) != nil {
			log.Fatalf("Error registering flag: '%s' already registered", f.Name)
		}
		flags.AddFlag(f)
	})
}

// Viper returns the hive's viper instance.
func (h *Hive) Viper() *viper.Viper {
	return h.viper
}

type defaults struct {
	dig.Out

	Flags             *pflag.FlagSet
	Lifecycle         Lifecycle
	LifecycleInternal lifecycle.Lifecycle
	Logger            logrus.FieldLogger
	Shutdowner        Shutdowner
	InvokerList       cell.InvokerList
	EmptyFullModuleID cell.FullModuleID
}

type internalLifecycle struct {
	Lifecycle
}

func (i *internalLifecycle) Append(hook lifecycle.HookInterface) {
	h := Hook{
		OnStart: func(ctx HookContext) error {
			return hook.Start(ctx)
		},
		OnStop: func(ctx HookContext) error {
			return hook.Stop(ctx)
		},
	}
	i.Lifecycle.Append(h)
}

func (h *Hive) provideDefaults() error {
	return h.container.Provide(func() defaults {
		return defaults{
			Flags:             h.flags,
			Lifecycle:         h.lifecycle,
			LifecycleInternal: &internalLifecycle{h.lifecycle},
			Logger:            log,
			Shutdowner:        h,
			InvokerList:       h,
			EmptyFullModuleID: nil,
		}
	})
}

func (h *Hive) SetTimeouts(start, stop time.Duration) {
	h.startTimeout, h.stopTimeout = start, stop
}

func (h *Hive) SetEnvPrefix(prefix string) {
	h.envPrefix = prefix
}

// AddConfigOverride appends a config override function to modify
// a configuration after it has been parsed.
//
// This method is only meant to be used in tests.
func AddConfigOverride[Cfg cell.Flagger](h *Hive, override func(*Cfg)) {
	h.configOverrides = append(h.configOverrides, override)
}

// Run populates the cell configurations and runs the hive cells.
// Interrupt signal or call to Shutdowner.Shutdown() will cause the hive to stop.
func (h *Hive) Run() error {
	startCtx, cancel := context.WithTimeout(context.Background(), h.startTimeout)
	defer cancel()

	var errs error
	if err := h.Start(startCtx); err != nil {
		errs = errors.Join(errs, fmt.Errorf("failed to start: %w", err))
	}

	// If start was successful, wait for Shutdown() or interrupt.
	if errs == nil {
		errs = errors.Join(errs, h.waitForSignalOrShutdown())
	}

	stopCtx, cancel := context.WithTimeout(context.Background(), h.stopTimeout)
	defer cancel()

	if err := h.Stop(stopCtx); err != nil {
		errs = errors.Join(errs, fmt.Errorf("failed to stop: %w", err))
	}
	return errs
}

func (h *Hive) waitForSignalOrShutdown() error {
	signals := make(chan os.Signal, 1)
	defer signal.Stop(signals)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	select {
	case sig := <-signals:
		log.WithField("signal", sig).Info("Signal received")
		return nil
	case err := <-h.shutdown:
		return err
	}
}

// Populate instantiates the hive. Use for testing that the hive can
// be instantiated.
func (h *Hive) Populate() error {
	if h.populated {
		return nil
	}
	h.populated = true

	// Provide all the parsed settings to the config cells.
	err := h.container.Provide(
		func() cell.AllSettings {
			return cell.AllSettings(h.viper.AllSettings())
		})
	if err != nil {
		return err
	}

	// Provide config overriders if any
	for _, o := range h.configOverrides {
		v := reflect.ValueOf(o)
		// Check that the config override is of type func(*cfg) and
		// 'cfg' implements Flagger.
		t := v.Type()
		if t.Kind() != reflect.Func || t.NumIn() != 1 {
			return fmt.Errorf("config override has invalid type %T, expected func(*T)", o)
		}
		flaggerType := reflect.TypeOf((*cell.Flagger)(nil)).Elem()
		if !t.In(0).Implements(flaggerType) {
			return fmt.Errorf("config override function parameter (%T) does not implement Flagger", o)
		}

		// Construct the provider function: 'func() func(*cfg)'. This is
		// picked up by the config cell and called to mutate the config
		// after it has been parsed.
		providerFunc := func(in []reflect.Value) []reflect.Value {
			return []reflect.Value{v}
		}
		providerFuncType := reflect.FuncOf(nil, []reflect.Type{t}, false)
		pfv := reflect.MakeFunc(providerFuncType, providerFunc)
		if err := h.container.Provide(pfv.Interface()); err != nil {
			return fmt.Errorf("providing config override failed: %w", err)
		}
	}

	// Execute the invoke functions to construct the objects.
	for _, invoke := range h.invokes {
		if err := invoke(); err != nil {
			return err
		}
	}
	return nil
}

func (h *Hive) AppendInvoke(invoke func() error) {
	h.invokes = append(h.invokes, invoke)
}

// Start starts the hive. The context allows cancelling the start.
// If context is cancelled and the start hooks do not respect the cancellation
// then after 5 more seconds the process will be terminated forcefully.
func (h *Hive) Start(ctx context.Context) error {
	if err := h.Populate(); err != nil {
		return err
	}

	defer close(h.fatalOnTimeout(ctx))

	log.Info("Starting")

	return h.lifecycle.Start(ctx)
}

// Stop stops the hive. The context allows cancelling the stop.
// If context is cancelled and the stop hooks do not respect the cancellation
// then after 5 more seconds the process will be terminated forcefully.
func (h *Hive) Stop(ctx context.Context) error {
	defer close(h.fatalOnTimeout(ctx))
	log.Info("Stopping")
	return h.lifecycle.Stop(ctx)
}

func (h *Hive) fatalOnTimeout(ctx context.Context) chan struct{} {
	terminated := make(chan struct{}, 1)
	go func() {
		select {
		case <-terminated:
			// Start/stop terminated in time, nothing to do.
			return

		case <-ctx.Done():
		}

		// Context was cancelled. Give 5 more seconds and then
		// go fatal.
		select {
		case <-terminated:
		case <-time.After(5 * time.Second):
			log.Fatal("Start or stop failed to finish on time, aborting forcefully.")
		}
	}()
	return terminated
}

// Shutdown implements the Shutdowner interface and is provided
// for the cells to use for triggering a early shutdown.
func (h *Hive) Shutdown(opts ...ShutdownOption) {
	var o shutdownOptions
	for _, opt := range opts {
		opt.apply(&o)
	}

	// If there already is an error in the channel, no-op
	select {
	case h.shutdown <- o.err:
	default:
	}
}

func (h *Hive) PrintObjects() {
	if err := h.Populate(); err != nil {
		log.WithError(err).Fatal("Failed to populate object graph")
	}

	fmt.Printf("Cells:\n\n")
	ip := cell.NewInfoPrinter()
	for _, c := range h.cells {
		c.Info(h.container).Print(2, ip)
		fmt.Println()
	}
	h.lifecycle.PrintHooks()
}

func (h *Hive) PrintDotGraph() {
	if err := h.Populate(); err != nil {
		log.WithError(err).Fatal("Failed to populate object graph")
	}

	if err := dig.Visualize(h.container, os.Stdout); err != nil {
		log.WithError(err).Fatal("Failed to Visualize()")
	}
}

// getEnvName returns the environment variable to be used for the given option name.
func (h *Hive) getEnvName(option string) string {
	under := strings.Replace(option, "-", "_", -1)
	upper := strings.ToUpper(under)
	return h.envPrefix + upper
}
