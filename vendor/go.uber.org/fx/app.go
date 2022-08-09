// Copyright (c) 2020-2021 Uber Technologies, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

package fx

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"

	"go.uber.org/dig"
	"go.uber.org/fx/fxevent"
	"go.uber.org/fx/internal/fxclock"
	"go.uber.org/fx/internal/fxlog"
	"go.uber.org/fx/internal/fxreflect"
	"go.uber.org/fx/internal/lifecycle"
	"go.uber.org/multierr"
)

// DefaultTimeout is the default timeout for starting or stopping an
// application. It can be configured with the StartTimeout and StopTimeout
// options.
const DefaultTimeout = 15 * time.Second

// An Option configures an App using the functional options paradigm
// popularized by Rob Pike. If you're unfamiliar with this style, see
// https://commandcenter.blogspot.com/2014/01/self-referential-functions-and-design.html.
type Option interface {
	fmt.Stringer

	apply(*module)
}

// Error registers any number of errors with the application to short-circuit
// startup. If more than one error is given, the errors are combined into a
// single error.
//
// Similar to invocations, errors are applied in order. All Provide and Invoke
// options registered before or after an Error option will not be applied.
func Error(errs ...error) Option {
	return errorOption(errs)
}

type errorOption []error

func (errs errorOption) apply(mod *module) {
	mod.app.err = multierr.Append(mod.app.err, multierr.Combine(errs...))
}

func (errs errorOption) String() string {
	return fmt.Sprintf("fx.Error(%v)", multierr.Combine(errs...))
}

// Options converts a collection of Options into a single Option. This allows
// packages to bundle sophisticated functionality into easy-to-use Fx modules.
// For example, a logging package might export a simple option like this:
//
//	package logging
//
//	var Module = fx.Provide(func() *log.Logger {
//	  return log.New(os.Stdout, "", 0)
//	})
//
// A shared all-in-one microservice package could then use Options to bundle
// logging with similar metrics, tracing, and gRPC modules:
//
//	package server
//
//	var Module = fx.Options(
//	  logging.Module,
//	  metrics.Module,
//	  tracing.Module,
//	  grpc.Module,
//	)
//
// Since this all-in-one module has a minimal API surface, it's easy to add
// new functionality to it without breaking existing users. Individual
// applications can take advantage of all this functionality with only one
// line of code:
//
//	app := fx.New(server.Module)
//
// Use this pattern sparingly, since it limits the user's ability to customize
// their application.
func Options(opts ...Option) Option {
	return optionGroup(opts)
}

type optionGroup []Option

func (og optionGroup) apply(mod *module) {
	for _, opt := range og {
		opt.apply(mod)
	}
}

func (og optionGroup) String() string {
	items := make([]string, len(og))
	for i, opt := range og {
		items[i] = fmt.Sprint(opt)
	}
	return fmt.Sprintf("fx.Options(%s)", strings.Join(items, ", "))
}

// StartTimeout changes the application's start timeout.
func StartTimeout(v time.Duration) Option {
	return startTimeoutOption(v)
}

type startTimeoutOption time.Duration

func (t startTimeoutOption) apply(m *module) {
	if m.parent != nil {
		m.app.err = fmt.Errorf("fx.StartTimeout Option should be passed to top-level App, " +
			"not to fx.Module")
	} else {
		m.app.startTimeout = time.Duration(t)
	}
}

func (t startTimeoutOption) String() string {
	return fmt.Sprintf("fx.StartTimeout(%v)", time.Duration(t))
}

// StopTimeout changes the application's stop timeout.
func StopTimeout(v time.Duration) Option {
	return stopTimeoutOption(v)
}

type stopTimeoutOption time.Duration

func (t stopTimeoutOption) apply(m *module) {
	if m.parent != nil {
		m.app.err = fmt.Errorf("fx.StopTimeout Option should be passed to top-level App, " +
			"not to fx.Module")
	} else {
		m.app.stopTimeout = time.Duration(t)
	}
}

func (t stopTimeoutOption) String() string {
	return fmt.Sprintf("fx.StopTimeout(%v)", time.Duration(t))
}

// WithLogger specifies how Fx should build an fxevent.Logger to log its events
// to. The argument must be a constructor with one of the following return
// types.
//
//	fxevent.Logger
//	(fxevent.Logger, error)
//
// For example,
//
//	WithLogger(func(logger *zap.Logger) fxevent.Logger {
//	  return &fxevent.ZapLogger{Logger: logger}
//	})
func WithLogger(constructor interface{}) Option {
	return withLoggerOption{
		constructor: constructor,
		Stack:       fxreflect.CallerStack(1, 0),
	}
}

type withLoggerOption struct {
	constructor interface{}
	Stack       fxreflect.Stack
}

func (l withLoggerOption) apply(m *module) {
	if m.parent != nil {
		// loggers shouldn't differ based on Module.
		m.app.err = fmt.Errorf("fx.WithLogger Option should be passed to top-level App, " +
			"not to fx.Module")
	} else {
		m.app.logConstructor = &provide{
			Target: l.constructor,
			Stack:  l.Stack,
		}
	}
}

func (l withLoggerOption) String() string {
	return fmt.Sprintf("fx.WithLogger(%s)", fxreflect.FuncName(l.constructor))
}

// Printer is the interface required by Fx's logging backend. It's implemented
// by most loggers, including the one bundled with the standard library.
//
// Note, this will be deprecate with next release and you will need to implement
// fxevent.Logger interface instead.
type Printer interface {
	Printf(string, ...interface{})
}

// Logger redirects the application's log output to the provided printer.
// Deprecated: use WithLogger instead.
func Logger(p Printer) Option {
	return loggerOption{p}
}

type loggerOption struct{ p Printer }

func (l loggerOption) apply(m *module) {
	if m.parent != nil {
		m.app.err = fmt.Errorf("fx.StartTimeout Option should be passed to top-level App, " +
			"not to fx.Module")
	} else {
		np := writerFromPrinter(l.p)
		m.app.log = fxlog.DefaultLogger(np) // assuming np is thread-safe.
	}
}

func (l loggerOption) String() string {
	return fmt.Sprintf("fx.Logger(%v)", l.p)
}

// NopLogger disables the application's log output. Note that this makes some
// failures difficult to debug, since no errors are printed to console.
var NopLogger = WithLogger(func() fxevent.Logger { return fxevent.NopLogger })

// An App is a modular application built around dependency injection. Most
// users will only need to use the New constructor and the all-in-one Run
// convenience method. In more unusual cases, users may need to use the Err,
// Start, Done, and Stop methods by hand instead of relying on Run.
//
// New creates and initializes an App. All applications begin with a
// constructor for the Lifecycle type already registered.
//
// In addition to that built-in functionality, users typically pass a handful
// of Provide options and one or more Invoke options. The Provide options
// teach the application how to instantiate a variety of types, and the Invoke
// options describe how to initialize the application.
//
// When created, the application immediately executes all the functions passed
// via Invoke options. To supply these functions with the parameters they
// need, the application looks for constructors that return the appropriate
// types; if constructors for any required types are missing or any
// invocations return an error, the application will fail to start (and Err
// will return a descriptive error message).
//
// Once all the invocations (and any required constructors) have been called,
// New returns and the application is ready to be started using Run or Start.
// On startup, it executes any OnStart hooks registered with its Lifecycle.
// OnStart hooks are executed one at a time, in order, and must all complete
// within a configurable deadline (by default, 15 seconds). For details on the
// order in which OnStart hooks are executed, see the documentation for the
// Start method.
//
// At this point, the application has successfully started up. If started via
// Run, it will continue operating until it receives a shutdown signal from
// Done (see the Done documentation for details); if started explicitly via
// Start, it will operate until the user calls Stop. On shutdown, OnStop hooks
// execute one at a time, in reverse order, and must all complete within a
// configurable deadline (again, 15 seconds by default).
type App struct {
	err       error
	clock     fxclock.Clock
	lifecycle *lifecycleWrapper

	container *dig.Container
	root      *module
	modules   []*module

	// Used to setup logging within fx.
	log            fxevent.Logger
	logConstructor *provide // set only if fx.WithLogger was used
	// Timeouts used
	startTimeout time.Duration
	stopTimeout  time.Duration
	// Decides how we react to errors when building the graph.
	errorHooks []ErrorHandler
	validate   bool
	// Used to signal shutdowns.
	donesMu     sync.Mutex // guards dones and shutdownSig
	dones       []chan os.Signal
	shutdownSig os.Signal

	osExit func(code int) // os.Exit override; used for testing only
}

// provide is a single constructor provided to Fx.
type provide struct {
	// Constructor provided to Fx. This may be an fx.Annotated.
	Target interface{}

	// Stack trace of where this provide was made.
	Stack fxreflect.Stack

	// IsSupply is true when the Target constructor was emitted by fx.Supply.
	IsSupply   bool
	SupplyType reflect.Type // set only if IsSupply
}

// invoke is a single invocation request to Fx.
type invoke struct {
	// Function to invoke.
	Target interface{}

	// Stack trace of where this invoke was made.
	Stack fxreflect.Stack
}

// ErrorHandler handles Fx application startup errors.
type ErrorHandler interface {
	HandleError(error)
}

// ErrorHook registers error handlers that implement error handling functions.
// They are executed on invoke failures. Passing multiple ErrorHandlers appends
// the new handlers to the application's existing list.
func ErrorHook(funcs ...ErrorHandler) Option {
	return errorHookOption(funcs)
}

type errorHookOption []ErrorHandler

func (eho errorHookOption) apply(m *module) {
	m.app.errorHooks = append(m.app.errorHooks, eho...)
}

func (eho errorHookOption) String() string {
	items := make([]string, len(eho))
	for i, eh := range eho {
		items[i] = fmt.Sprint(eh)
	}
	return fmt.Sprintf("fx.ErrorHook(%v)", strings.Join(items, ", "))
}

type errorHandlerList []ErrorHandler

func (ehl errorHandlerList) HandleError(err error) {
	for _, eh := range ehl {
		eh.HandleError(err)
	}
}

// validate sets *App into validation mode without running invoked functions.
func validate(validate bool) Option {
	return &validateOption{
		validate: validate,
	}
}

type validateOption struct {
	validate bool
}

func (o validateOption) apply(m *module) {
	if m.parent != nil {
		m.app.err = fmt.Errorf("fx.validate Option should be passed to top-level App, " +
			"not to fx.Module")
	} else {
		m.app.validate = o.validate
	}
}

func (o validateOption) String() string {
	return fmt.Sprintf("fx.validate(%v)", o.validate)
}

// ValidateApp validates that supplied graph would run and is not missing any dependencies. This
// method does not invoke actual input functions.
func ValidateApp(opts ...Option) error {
	opts = append(opts, validate(true))
	app := New(opts...)

	return app.Err()
}

// Builds and connects the custom logger, returning an error if it failed.
func (app *App) constructCustomLogger(buffer *logBuffer) (err error) {
	p := app.logConstructor
	fname := fxreflect.FuncName(p.Target)
	defer func() {
		app.log.LogEvent(&fxevent.LoggerInitialized{
			Err:             err,
			ConstructorName: fname,
		})
	}()

	if err := app.root.scope.Provide(p.Target); err != nil {
		return fmt.Errorf("fx.WithLogger(%v) from:\n%+vFailed: %v",
			fname, p.Stack, err)
	}

	// TODO: Use dig.FillProvideInfo to inspect the provided constructor
	// and fail the application if its signature didn't match.

	return app.root.scope.Invoke(func(log fxevent.Logger) {
		app.log = log
		buffer.Connect(log)
	})
}

// New creates and initializes an App, immediately executing any functions
// registered via Invoke options. See the documentation of the App struct for
// details on the application's initialization, startup, and shutdown logic.
func New(opts ...Option) *App {
	logger := fxlog.DefaultLogger(os.Stderr)

	app := &App{
		// We start with a logger that writes to stderr. One of the
		// following three things can change this:
		//
		// - fx.Logger was provided to change the output stream
		// - fx.WithLogger was provided to change the logger
		//   implementation
		// - Both, fx.Logger and fx.WithLogger were provided
		//
		// The first two cases are straightforward: we use what the
		// user gave us. For the last case, however, we need to fall
		// back to what was provided to fx.Logger if fx.WithLogger
		// fails.
		log:          logger,
		clock:        fxclock.System,
		startTimeout: DefaultTimeout,
		stopTimeout:  DefaultTimeout,
	}
	app.root = &module{app: app}
	app.modules = append(app.modules, app.root)

	for _, opt := range opts {
		opt.apply(app.root)
	}

	// There are a few levels of wrapping on the lifecycle here. To quickly
	// cover them:
	//
	// - lifecycleWrapper ensures that we don't unintentionally expose the
	//   Start and Stop methods of the internal lifecycle.Lifecycle type
	// - lifecycleWrapper also adapts the internal lifecycle.Hook type into
	//   the public fx.Hook type.
	// - appLogger ensures that the lifecycle always logs events to the
	//   "current" logger associated with the fx.App.
	app.lifecycle = &lifecycleWrapper{
		lifecycle.New(appLogger{app}, app.clock),
	}

	var (
		bufferLogger *logBuffer // nil if WithLogger was not used

		// Logger we fall back to if the custom logger fails to build.
		// This will be a DefaultLogger that writes to stderr if the
		// user didn't use fx.Logger, and a DefaultLogger that writes
		// to their output stream if they did.
		fallbackLogger fxevent.Logger
	)
	if app.logConstructor != nil {
		// Since user supplied a custom logger, use a buffered logger
		// to hold all messages until user supplied logger is
		// instantiated. Then we flush those messages after fully
		// constructing the custom logger.
		bufferLogger = new(logBuffer)
		fallbackLogger, app.log = app.log, bufferLogger
	}

	app.container = dig.New(
		dig.DeferAcyclicVerification(),
		dig.DryRun(app.validate),
	)

	for _, m := range app.modules {
		m.build(app, app.container)
	}

	for _, m := range app.modules {
		m.provideAll()
	}

	frames := fxreflect.CallerStack(0, 0) // include New in the stack for default Provides
	app.root.provide(provide{
		Target: func() Lifecycle { return app.lifecycle },
		Stack:  frames,
	})
	app.root.provide(provide{Target: app.shutdowner, Stack: frames})
	app.root.provide(provide{Target: app.dotGraph, Stack: frames})

	// Run decorators before executing any Invokes -- including the one
	// inside constructCustomLogger.
	app.err = multierr.Append(app.err, app.root.decorate())

	// If you are thinking about returning here after provides: do not (just yet)!
	// If a custom logger was being used, we're still buffering messages.
	// We'll want to flush them to the logger.

	// If WithLogger and Printer are both provided, WithLogger takes
	// precedence.
	if app.logConstructor != nil {
		// If we failed to build the provided logger, flush the buffer
		// to the fallback logger instead.
		if err := app.constructCustomLogger(bufferLogger); err != nil {
			app.err = multierr.Append(app.err, err)
			app.log = fallbackLogger
			bufferLogger.Connect(fallbackLogger)
			return app
		}
	}

	// This error might have come from the provide loop above. We've
	// already flushed to the custom logger, so we can return.
	if app.err != nil {
		return app
	}

	if err := app.root.executeInvokes(); err != nil {
		app.err = err

		if dig.CanVisualizeError(err) {
			var b bytes.Buffer
			dig.Visualize(app.container, &b, dig.VisualizeError(err))
			err = errorWithGraph{
				graph: b.String(),
				err:   err,
			}
		}
		errorHandlerList(app.errorHooks).HandleError(err)
	}

	return app
}

// DotGraph contains a DOT language visualization of the dependency graph in
// an Fx application. It is provided in the container by default at
// initialization. On failure to build the dependency graph, it is attached
// to the error and if possible, colorized to highlight the root cause of the
// failure.
type DotGraph string

type errWithGraph interface {
	Graph() DotGraph
}

type errorWithGraph struct {
	graph string
	err   error
}

func (err errorWithGraph) Graph() DotGraph {
	return DotGraph(err.graph)
}

func (err errorWithGraph) Error() string {
	return err.err.Error()
}

// VisualizeError returns the visualization of the error if available.
func VisualizeError(err error) (string, error) {
	if e, ok := err.(errWithGraph); ok && e.Graph() != "" {
		return string(e.Graph()), nil
	}
	return "", errors.New("unable to visualize error")
}

// Exits the application with the given exit code.
func (app *App) exit(code int) {
	osExit := os.Exit
	if app.osExit != nil {
		osExit = app.osExit
	}
	osExit(code)
}

// Run starts the application, blocks on the signals channel, and then
// gracefully shuts the application down. It uses DefaultTimeout to set a
// deadline for application startup and shutdown, unless the user has
// configured different timeouts with the StartTimeout or StopTimeout options.
// It's designed to make typical applications simple to run.
//
// However, all of Run's functionality is implemented in terms of the exported
// Start, Done, and Stop methods. Applications with more specialized needs
// can use those methods directly instead of relying on Run.
func (app *App) Run() {
	// Historically, we do not os.Exit(0) even though most applications
	// cede control to Fx with they call app.Run. To avoid a breaking
	// change, never os.Exit for success.
	if code := app.run(app.Done()); code != 0 {
		app.exit(code)
	}
}

func (app *App) run(done <-chan os.Signal) (exitCode int) {
	startCtx, cancel := app.clock.WithTimeout(context.Background(), app.StartTimeout())
	defer cancel()

	if err := app.Start(startCtx); err != nil {
		return 1
	}

	sig := <-done
	app.log.LogEvent(&fxevent.Stopping{Signal: sig})

	stopCtx, cancel := app.clock.WithTimeout(context.Background(), app.StopTimeout())
	defer cancel()

	if err := app.Stop(stopCtx); err != nil {
		return 1
	}

	return 0
}

// Err returns any error encountered during New's initialization. See the
// documentation of the New method for details, but typical errors include
// missing constructors, circular dependencies, constructor errors, and
// invocation errors.
//
// Most users won't need to use this method, since both Run and Start
// short-circuit if initialization failed.
func (app *App) Err() error {
	return app.err
}

var (
	_onStartHook = "OnStart"
	_onStopHook  = "OnStop"
)

// Start kicks off all long-running goroutines, like network servers or
// message queue consumers. It does this by interacting with the application's
// Lifecycle.
//
// By taking a dependency on the Lifecycle type, some of the user-supplied
// functions called during initialization may have registered start and stop
// hooks. Because initialization calls constructors serially and in dependency
// order, hooks are naturally registered in serial and dependency order too.
//
// Start executes all OnStart hooks registered with the application's
// Lifecycle, one at a time and in order. This ensures that each constructor's
// start hooks aren't executed until all its dependencies' start hooks
// complete. If any of the start hooks return an error, Start short-circuits,
// calls Stop, and returns the inciting error.
//
// Note that Start short-circuits immediately if the New constructor
// encountered any errors in application initialization.
func (app *App) Start(ctx context.Context) (err error) {
	defer func() {
		app.log.LogEvent(&fxevent.Started{Err: err})
	}()

	if app.err != nil {
		// Some provides failed, short-circuit immediately.
		return app.err
	}

	return withTimeout(ctx, &withTimeoutParams{
		hook:      _onStartHook,
		callback:  app.start,
		lifecycle: app.lifecycle,
		log:       app.log,
	})
}

func (app *App) start(ctx context.Context) error {
	if err := app.lifecycle.Start(ctx); err != nil {
		// Start failed, rolling back.
		app.log.LogEvent(&fxevent.RollingBack{StartErr: err})

		stopErr := app.lifecycle.Stop(ctx)
		app.log.LogEvent(&fxevent.RolledBack{Err: stopErr})

		if stopErr != nil {
			return multierr.Append(err, stopErr)
		}

		return err
	}
	return nil
}

// Stop gracefully stops the application. It executes any registered OnStop
// hooks in reverse order, so that each constructor's stop hooks are called
// before its dependencies' stop hooks.
//
// If the application didn't start cleanly, only hooks whose OnStart phase was
// called are executed. However, all those hooks are executed, even if some
// fail.
func (app *App) Stop(ctx context.Context) (err error) {
	defer func() {
		app.log.LogEvent(&fxevent.Stopped{Err: err})
	}()

	return withTimeout(ctx, &withTimeoutParams{
		hook:      _onStopHook,
		callback:  app.lifecycle.Stop,
		lifecycle: app.lifecycle,
		log:       app.log,
	})
}

// Done returns a channel of signals to block on after starting the
// application. Applications listen for the SIGINT and SIGTERM signals; during
// development, users can send the application SIGTERM by pressing Ctrl-C in
// the same terminal as the running process.
//
// Alternatively, a signal can be broadcast to all done channels manually by
// using the Shutdown functionality (see the Shutdowner documentation for details).
func (app *App) Done() <-chan os.Signal {
	c := make(chan os.Signal, 1)

	app.donesMu.Lock()
	defer app.donesMu.Unlock()
	// If shutdown signal has been received already
	// send it and return. If not, wait for user to send a termination
	// signal.
	if app.shutdownSig != nil {
		c <- app.shutdownSig
		return c
	}

	signal.Notify(c, os.Interrupt, _sigINT, _sigTERM)
	app.dones = append(app.dones, c)
	return c
}

// StartTimeout returns the configured startup timeout. Apps default to using
// DefaultTimeout, but users can configure this behavior using the
// StartTimeout option.
func (app *App) StartTimeout() time.Duration {
	return app.startTimeout
}

// StopTimeout returns the configured shutdown timeout. Apps default to using
// DefaultTimeout, but users can configure this behavior using the StopTimeout
// option.
func (app *App) StopTimeout() time.Duration {
	return app.stopTimeout
}

func (app *App) dotGraph() (DotGraph, error) {
	var b bytes.Buffer
	err := dig.Visualize(app.container, &b)
	return DotGraph(b.String()), err
}

type withTimeoutParams struct {
	log       fxevent.Logger
	hook      string
	callback  func(context.Context) error
	lifecycle *lifecycleWrapper
}

// errHookCallbackExited is returned when a hook callback does not finish executing
var errHookCallbackExited = fmt.Errorf("goroutine exited without returning")

func withTimeout(ctx context.Context, param *withTimeoutParams) error {
	c := make(chan error, 1)
	go func() {
		// If runtime.Goexit() is called from within the callback
		// then nothing is written to the chan.
		// However the defer will still be called, so we can write to the chan,
		// to avoid hanging until the timeout is reached.
		callbackExited := false
		defer func() {
			if !callbackExited {
				c <- errHookCallbackExited
			}
		}()

		c <- param.callback(ctx)
		callbackExited = true
	}()

	var err error

	select {
	case <-ctx.Done():
		err = ctx.Err()
	case err = <-c:
		// If the context finished at the same time as the callback
		// prefer the context error.
		// This eliminates non-determinism in select-case selection.
		if ctx.Err() != nil {
			err = ctx.Err()
		}
	}
	if err != context.DeadlineExceeded && err != errHookCallbackExited {
		return err
	}
	// On timeout, report running hook's caller and recorded
	// runtimes of hooks successfully run till end.
	var r lifecycle.HookRecords
	if param.hook == _onStartHook {
		r = param.lifecycle.startHookRecords()
	} else {
		r = param.lifecycle.stopHookRecords()
	}
	caller := param.lifecycle.runningHookCaller()
	// TODO: Once this is integrated into fxevent, we can
	// leave error unchanged and send this to fxevent.Logger, whose
	// implementation can then determine how the error is presented.
	if len(r) > 0 {
		sort.Sort(r)
		return fmt.Errorf("%v hook added by %v failed: %w\n%+v",
			param.hook,
			caller,
			err,
			r)
	}
	return fmt.Errorf("%v hook added by %v failed: %w",
		param.hook,
		caller,
		err)
}

// appLogger logs events to the given Fx app's "current" logger.
//
// Use this with lifecycle, for example, to ensure that events always go to the
// correct logger.
type appLogger struct{ app *App }

func (l appLogger) LogEvent(ev fxevent.Event) {
	l.app.log.LogEvent(ev)
}
