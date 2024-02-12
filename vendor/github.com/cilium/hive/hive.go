// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package hive

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"reflect"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"go.uber.org/dig"

	"github.com/cilium/hive/cell"
)

type Options struct {
	Logger *slog.Logger

	// EnvPrefix is the prefix to use for environment variables, e.g.
	// with prefix "CILIUM" the flag "foo" can be set with environment
	// variable "CILIUM_FOO".
	EnvPrefix string

	// ModuleDecorator is an optional decorator function to use for each
	// module. This can be used to provide module-specific objects application
	// wide. For example:
	//
	// 	func(foo Foo, id cell.ModuleID) Foo {
	// 		return foo.With("moduleID", id)
	//	}
	//
	// The above would give each cell within a module an augmented version of 'Foo'.
	ModuleDecorator cell.ModuleDecorator

	// DecodeHooks are optional additional decode hooks to use with cell.Config
	// to decode a configuration flag into a config field. See existing hooks
	// in [cell/config.go] for examples.
	DecodeHooks cell.DecodeHooks

	StartTimeout time.Duration
	StopTimeout  time.Duration
}

var DefaultOptions = Options{
	Logger:          nil, // Will use slog.Default()
	EnvPrefix:       "",
	ModuleDecorator: nil,
	StartTimeout:    defaultStartTimeout,
	StopTimeout:     defaultStopTimeout,
}

const (
	// defaultStartTimeout is the amount of time allotted for start hooks. After
	// this duration the context passed to the start hooks is cancelled.
	defaultStartTimeout = 5 * time.Minute

	// defaultStopTimeout is the amount of time allotted for stop hooks.
	defaultStopTimeout = time.Minute
)

// Hive is a framework building modular applications.
//
// It implements dependency injection using the dig library.
//
// See pkg/hive/example for a runnable example application.
type Hive struct {
	log             *slog.Logger
	opts            Options
	container       *dig.Container
	cells           []cell.Cell
	shutdown        chan error
	flags           *pflag.FlagSet
	viper           *viper.Viper
	lifecycle       cell.Lifecycle
	populated       bool
	invokes         []func() error
	configOverrides []any
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
	return NewWithOptions(DefaultOptions, cells...)
}

func NewWithOptions(opts Options, cells ...cell.Cell) *Hive {
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	h := &Hive{
		log:             opts.Logger,
		opts:            opts,
		container:       dig.New(),
		cells:           cells,
		viper:           viper.New(),
		flags:           pflag.NewFlagSet("", pflag.ContinueOnError),
		lifecycle:       &cell.DefaultLifecycle{},
		shutdown:        make(chan error, 1),
		configOverrides: nil,
	}

	if err := h.provideDefaults(); err != nil {
		panic(fmt.Sprintf("Failed to provide defaults: %s", err))
	}

	// Apply all cells to the container. This registers all constructors
	// and adds all config flags. Invokes are delayed until Start() is
	// called.
	for _, cell := range cells {
		if err := cell.Apply(opts.Logger, h.container); err != nil {
			panic(fmt.Sprintf("Failed to apply cell: %s", err))
		}
	}

	// Bind the newly registered flags to viper.
	h.flags.VisitAll(func(f *pflag.Flag) {
		if err := h.viper.BindPFlag(f.Name, f); err != nil {
			panic(fmt.Sprintf("BindPFlag: %s", err))
		}
		if err := h.viper.BindEnv(f.Name, h.getEnvName(f.Name)); err != nil {
			panic(fmt.Sprintf("BindEnv: %s", err))
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
			panic(fmt.Sprintf("Error registering flag: '%s' already registered", f.Name))
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
	Lifecycle         cell.Lifecycle
	Logger            *slog.Logger
	Shutdowner        Shutdowner
	InvokerList       cell.InvokerList
	EmptyFullModuleID cell.FullModuleID
	DecodeHooks       cell.DecodeHooks
}

func (h *Hive) provideDefaults() error {
	return h.container.Provide(func() defaults {
		return defaults{
			Flags:             h.flags,
			Lifecycle:         h.lifecycle,
			Logger:            h.opts.Logger,
			Shutdowner:        h,
			InvokerList:       h,
			EmptyFullModuleID: nil,
			DecodeHooks:       h.opts.DecodeHooks,
		}
	})
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
	startCtx, cancel := context.WithTimeout(context.Background(), h.opts.StartTimeout)
	defer cancel()

	var errs error
	if err := h.Start(startCtx); err != nil {
		errs = errors.Join(errs, fmt.Errorf("failed to start: %w", err))
	}

	// If start was successful, wait for Shutdown() or interrupt.
	if errs == nil {
		errs = errors.Join(errs, h.waitForSignalOrShutdown())
	}

	stopCtx, cancel := context.WithTimeout(context.Background(), h.opts.StopTimeout)
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
		h.log.Info("Signal received", "signal", sig)
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

	h.log.Info("Starting")
	start := time.Now()
	err := h.lifecycle.Start(h.log, ctx)
	if err == nil {
		h.log.Info("Started", "duration", time.Since(start))
	} else {
		h.log.Error("Start failed", "error", err, "duration", time.Since(start))
	}
	return err
}

// Stop stops the hive. The context allows cancelling the stop.
// If context is cancelled and the stop hooks do not respect the cancellation
// then after 5 more seconds the process will be terminated forcefully.
func (h *Hive) Stop(ctx context.Context) error {
	defer close(h.fatalOnTimeout(ctx))
	h.log.Info("Stopping")
	return h.lifecycle.Stop(h.log, ctx)
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
			panic("Start or stop failed to finish on time, aborting forcefully.")
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
		panic(fmt.Sprintf("Failed to populate object graph: %s", err))
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
		panic(fmt.Sprintf("Failed to populate object graph: %s", err))
	}

	if err := dig.Visualize(h.container, os.Stdout); err != nil {
		panic(fmt.Sprintf("Failed to dig.Visualize(): %s", err))
	}
}

// getEnvName returns the environment variable to be used for the given option name.
func (h *Hive) getEnvName(option string) string {
	under := strings.Replace(option, "-", "_", -1)
	upper := strings.ToUpper(under)
	return h.opts.EnvPrefix + upper
}
