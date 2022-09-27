// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package hive

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"go.uber.org/dig"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/hive/internal"
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
}

// New returns a new hive that can be run, or inspected.
// The command-line flags from the cells are registered as part of this.
//
// The object graph is not constructed until methods of the hive are
// invoked.
func New(v *viper.Viper, flags *pflag.FlagSet, cells ...cell.Cell) *Hive {
	h := &Hive{
		container:    dig.New(),
		envPrefix:    defaultEnvPrefix,
		cells:        cells,
		viper:        v,
		startTimeout: defaultStartTimeout,
		stopTimeout:  defaultStopTimeout,
		flags:        pflag.NewFlagSet("", pflag.ContinueOnError),
		lifecycle:    &DefaultLifecycle{},
		shutdown:     make(chan error, 1),
	}

	if err := h.provideDefaults(); err != nil {
		log.WithError(err).Fatal("Failed to provide default objects")
	}

	// Apply all cells to the container. This registers all constructors
	// and adds all config flags. Invokes are delayed until Start() is
	// called.
	for _, cell := range cells {
		if err := cell.Apply(h.container); err != nil {
			log.WithError(err).Fatal("Failed to apply cell")
		}
	}

	// Bind the newly registered flags to viper and add them to parent
	// flag set.
	h.flags.VisitAll(func(f *pflag.Flag) {
		if flags.Lookup(f.Name) != nil {
			log.Fatalf("Error registering flag: '%s' already registered", f.Name)
		}
		flags.AddFlag(f)
		if err := v.BindPFlag(f.Name, f); err != nil {
			log.Fatalf("BindPFlag: %s", err)
		}
		if err := v.BindEnv(f.Name, h.getEnvName(f.Name)); err != nil {
			log.Fatalf("BindEnv: %s", err)
		}
	})

	return h
}

type defaults struct {
	dig.Out

	Flags       *pflag.FlagSet
	Lifecycle   Lifecycle
	Logger      logrus.FieldLogger
	Shutdowner  Shutdowner
	InvokerList cell.InvokerList
}

func (h *Hive) provideDefaults() error {
	return h.container.Provide(func() defaults {
		return defaults{
			Flags:       h.flags,
			Lifecycle:   h.lifecycle,
			Logger:      log,
			Shutdowner:  h,
			InvokerList: h,
		}
	})
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
	startCtx, cancel := context.WithTimeout(context.Background(), h.startTimeout)
	defer cancel()

	if err := h.Start(startCtx); err != nil {
		log.WithError(err).Fatal("Failed to start")
	}

	h.waitForSignalOrShutdown()

	stopCtx, cancel := context.WithTimeout(context.Background(), h.stopTimeout)
	defer cancel()

	if err := h.Stop(stopCtx); err != nil {
		log.WithError(err).Fatal("Failed to stop")
	}
}

func (h *Hive) waitForSignalOrShutdown() {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, unix.SIGINT, unix.SIGTERM)
	select {
	case <-signals:
		log.Error("Interrupt received")
	case err := <-h.shutdown:
		log.WithError(err).Error("Shutdown requested")
	}
}

func (h *Hive) populate() error {
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
	if err := h.populate(); err != nil {
		return err
	}

	terminated := h.fatalOnTimeout(ctx)

	// Execute the start hooks.
	err := h.lifecycle.Start(ctx)
	terminated <- true
	return err
}

// Stop stops the hive. The context allows cancelling the stop.
// If context is cancelled and the stop hooks do not respect the cancellation
// then after 5 more seconds the process will be terminated forcefully.
func (h *Hive) Stop(ctx context.Context) error {
	terminated := h.fatalOnTimeout(ctx)
	err := h.lifecycle.Stop(ctx)
	terminated <- true
	return err
}

func (h *Hive) fatalOnTimeout(ctx context.Context) chan bool {
	terminated := make(chan bool, 1)
	go func() {
		select {
		case <-ctx.Done():
		case <-terminated:
			close(terminated)
			return
		}
		// Give 5 more seconds.
		time.Sleep(5 * time.Second)

		select {
		case <-terminated:
		default:
			log.Fatal("Start or stop failed to finish on time, aborting forcefully.")
		}
	}()
	return terminated
}

// Shutdown implements the Shutdowner interface and is provided
// for the cells to use for triggering a early shutdown.
func (h *Hive) Shutdown(err error) {
	h.shutdown <- err
}

func (h *Hive) PrintObjects() {
	fmt.Printf("Cells:\n\n")
	for _, c := range h.cells {
		fmt.Println(internal.LeftPad(c.String(), 2))
	}

	if err := h.populate(); err != nil {
		log.WithError(err).Fatal("Failed to populate object graph")
	}

	fmt.Printf("Start hooks:\n\n")
	for _, hook := range h.lifecycle.hooks {
		if hook.OnStart == nil {
			continue
		}
		fmt.Printf("  • %s\n", internal.FuncNameAndLocation(hook.OnStart))
	}

	fmt.Printf("\nStop hooks:\n\n")
	for i := len(h.lifecycle.hooks) - 1; i >= 0; i-- {
		hook := h.lifecycle.hooks[i]
		if hook.OnStop == nil {
			continue
		}
		fmt.Printf("  • %s\n", internal.FuncNameAndLocation(hook.OnStop))
	}
}

func (h *Hive) PrintDotGraph() {
	if err := h.populate(); err != nil {
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

// NewForTests returns a new hive for testing that does not register
// the flags declared by the cells. Use in combination with TestApp()
// to provide cell configurations.
func NewForTests(cells ...cell.Cell) *Hive {
	return New(viper.New(), pflag.NewFlagSet("", pflag.ContinueOnError), cells...)
}

// TestRun starts and stops the hive.
func (h *Hive) TestRun(t *testing.T, timeout time.Duration) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if err := h.Start(ctx); err != nil {
		t.Fatalf("Start failed: %s", err)
	}
	if err := h.Stop(ctx); err != nil {
		t.Fatalf("Stop failed: %s", err)
	}
}
