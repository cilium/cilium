.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _guide-to-the-hive:

Guide to the Hive
=================

Introduction
~~~~~~~~~~~~

Cilium is using dependency injection (via ``pkg/hive``) to wire up the
initialization, starting and stopping of its components. 

`Dependency injection <https://en.wikipedia.org/wiki/Dependency_injection>`_ (DI) is a
technique for separating the use of objects from their creation and
initialization. Essentially dependency injection is about automating the
manual management of dependencies. Object constructors only need to declare
their dependencies as function parameters and the rest is handled by the library. This
helps with building a loosely-coupled modular architecture as it removes the
need for centralization of initialization and configuration. It also reduces
the inclination to use global variables over explicit passing of objects,
which is often a source of bugs (due to unexpected initialization order)
and difficult to deal with in tests (as the state needs to be restored for
the next test). With dependency injection components are described as plain
values (``Cell`` in our flavor of DI) enabling visualization of inter-component
dependencies and opening the internal architecture up for inspection.

Dependency injection and the machinery described here are only a tool to
help us towards the real goal: a modular software architecture that can be
easily understood, extended, repurposed, tested and refactored by a large
group of developers with minimal overlap between modules. To achieve this we
also need to have modularity in mind when designing the architecture and APIs.

Hive and Cells
~~~~~~~~~~~~~~

Cilium applications are composed using runtime dependency injection from a set
of modular components called cells that compose together to form a hive (as in
bee hive). A hive can then be supplied with configuration and executed. To provide
a feel for what this is about, here is how a simple modular HTTP server application 
would leverage hive:

.. code-block:: go

    package server

    // The server cell implements a generic HTTP server. Provides the 'Server' API
    // for registering request handlers.
    //
    // Module() creates a named collection of cells.
    var Cell = cell.Module(
       "http-server", // Module identifier (for e.g. logging and tracing)
       "HTTP Server", // Module title (for documentation)

       // Provide the application the constructor for the server.
       cell.Provide(New),

       // Config registers a configuration when provided with the defaults 
       // and an implementation of Flags() for registering the configuration flags.
       cell.Config(defaultServerConfig),
    )

    // Server allows registering request handlers with the HTTP server
    type Server interface {
        ListenAddress() string
        RegisterHandler(path string, fn http.HandlerFunc)
    }

    func New(lc hive.Lifecycle, cfg ServerConfig) Server { 
      // Initialize http.Server, register Start and Stop hooks to Lifecycle 
      // for starting and stopping the server and return an implementation of
      // 'Server' for other cells for registering handlers.
      // ...
    }

    type ServerConfig struct {
        ServerPort uint16
    }

    var defaultServerConfig = ServerConfig{
        ServerPort: 8080,
    }

    func (def ServerConfig) Flags(flags *pflag.FlagSet) {
        // Register the "server-port" flag. Hive by convention maps the flag to the ServerPort 
        // field.
        flags.Uint16("server-port",  def.ServerPort, "Sets the HTTP server listen port")
    }

With the above generic HTTP server in the ``server`` package, we can now implement a simple handler
for /hello in the ``hello`` package:

.. code-block:: go

    package hello

    // The hello cell implements and registers a hello handler to the HTTP server.
    //
    // This cell isn't a Module, but rather just a plain Invoke. An Invoke
    // is a cell that, unlike Provide, is always executed. Invoke functions
    // can depend on values that constructors registered with Provide() can
    // return. These constructors are then called and their results remembered.
    var Cell = cell.Invoke(registerHelloHandler)

    func helloHandler(w http.ResponseWriter, req *http.Request) {
        w.Write([]byte("hello"))
    }

    func registerHelloHandler(srv server.Server) {
        srv.RegisterHandler("/hello", helloHandler)
    }
  
And then put the two together into a simple application:

.. code-block:: go

    package main

    var (
        // exampleHive is an application with an HTTP server and a handler
        // at /hello.
        exampleHive = hive.New(
            server.Cell,
            hello.Cell,
        )

        // cmd is the root command for this application. Runs
        // exampleHive when executed.
        cmd *cobra.Command = &cobra.Command{
            Use: "example",
            Run: func(cmd *cobra.Command, args []string) {
                // Run() will execute all invoke functions, followed by start hooks
                // and will then wait for interrupt signal before executing stop hooks
                // and returning.
                exampleHive.Run()
            },
        }
    )
       
    func main() {
         // Register all command-line flags from each config cell to the
         // flag-set of our command.
     	 exampleHive.RegisterFlags(cmd.Flags())

         // Add the "hive" sub-command for inspecting the application. 
         cmd.AddCommand(exampleHive.Command()))

         // Execute the root command.
         cmd.Execute()
    }


If you prefer to learn by example you can find a more complete and runnable example
application from ``pkg/hive/example``. Try running it with ``go run .`` and also try
``go run . hive``. And if you're interested in how all this is implemented internally,
see ``pkg/hive/example/mini``, a minimal example of how to do dependency injection with reflection.

The Hive API
~~~~~~~~~~~~

With the example hopefully having now whetted the appetite, we'll take a proper look at
the hive API. 

`pkg/hive <https://pkg.go.dev/github.com/cilium/cilium/pkg/hive>`_ provides the Hive type and 
`hive.New <https://pkg.go.dev/github.com/cilium/cilium/pkg/hive#New>`_ constructor. 
The ``hive.Hive`` type can be thought of as an application container, composed from cells:

.. code-block:: go

    var myHive = hive.New(foo.Cell, bar.Cell)

    // Call Run() to run the hive.     
    myHive.Run() // Start(), wait for signal (ctrl-c) and then Stop() 

    // Hive can also be started and stopped directly. Useful in tests.
    if err := myHive.Start(ctx); err != nil { /* ... */ }
    if err := myHive.Stop(ctx); err != nil { /* ... */ }

    // Hive's configuration can be registered with a Cobra command:
    hive.RegisterFlags(cmd.Flags())

    // Hive also provides a sub-command for inspecting it:
    cmd.AddCommand(hive.Command())

`pkg/hive/cell <https://pkg.go.dev/github.com/cilium/cilium/pkg/hive/cell>`_ defines the Cell interface that 
``hive.New()`` consumes and the following functions for creating cells:

- :ref:`api_module`: A named set of cells.
- :ref:`api_provide`: Provides constructor(s) to the hive.  Lazy and only invoked if referenced by an Invoke function (directly or indirectly via other constructor).
- :ref:`ProvidePrivate <api_module>`: Provides private constructor(s) to a module and its sub-modules.
- :ref:`api_decorate`: Wraps a set of cells with a decorator function to provide these cells with augmented objects.
- :ref:`api_config`: Provides a configuration struct to the hive.
- :ref:`api_invoke`: Registers an invoke function to instantiate and initialize objects.

Hive also by default provides the following globally available objects:

- :ref:`api_lifecycle`: Methods for registering Start and Stop functions that are executed when Hive is started and stopped. 
  The hooks are appended to it in dependency order (since the constructors are invoked in dependency order).
- :ref:`api_shutdowner`: Allows gracefully shutting down the hive from anywhere in case of a fatal error post-start.
- ``logrus.FieldLogger``: Interface to the logger. Module() decorates it with ``subsys=<module id>``.

.. _api_provide:

Provide
^^^^^^^

We'll now take a look at each of the different kinds of cells, starting with Provide(),
which registers one or more constructors with the hive:

.. code-block:: go

    // func Provide(ctors any...) Cell

    type A interface {}
    func NewA() A { return A{} }
    
    type B interface {}
    func NewB(A) B { return B{} }

    // simpleCell provides A and B
    var simpleCell cell.Cell = cell.Provide(NewA, NewB) 

If the constructors take many parameters, we'll want to group them into a struct with ``cell.In``,
and conversely if there are many return values, into a struct with ``cell.Out``. This tells
hive to unpack them:

.. code-block:: go

    type params struct {
    	cell.In
    
        A A
        B B
        Lifecycle hive.Lifecycle
    }
    
    type out struct {
        cell.Out
    
        C C
	D D
        E E
    }
    func NewCDE(params params) out { ... }
    
    var Cell = cell.Provide(NewCDE)

Sometimes we want to depend on a group of values sharing the same type, e.g. to collect API handlers or metrics. This can be done with 
`value groups <https://pkg.go.dev/go.uber.org/dig#hdr-Value_Groups>`_ by combining ``cell.In``
and ``cell.Out`` with the ``group`` struct tag:

.. code-block:: go

    type HandlerOut struct {
        cell.Out

        Handler Handler `group:"handlers"`
    }
    func NewHelloHandler() HandlerOut { ... }
    func NewEventHandler(src events.Source) HandlerOut { ... }

    type ServerParams struct {
        cell.In
    
        Handlers []Handler `group:"handlers"`
    }

    func NewServer(params ServerParams) Server {
      // params.Handlers will have the "Handlers" from NewHelloHandler and 
      // NewEventHandler.
    }

    var Hive = hive.New(
      cell.Provide(NewHelloHandler, NewEventHandler, NewServer)
    )

For a working example of group values this, see ``pkg/hive/example``.

Use ``Provide()`` when you want to expose an object or an interface to the application. If there is nothing meaningful
to expose, consider instead using ``Invoke()`` to register lifecycle hooks for an unexported object.

.. _api_invoke:

Invoke
^^^^^^

Invoke is used to invoke a function to initialize some part of the application. The provided constructors
won't be called unless an invoke function references them, either directly or indirectly via another
constructor:

.. code-block:: go

    // func Invoke(funcs ...any) Cell

    cell.Invoke(
        // Construct both B and C and then introduce them to each other.
        func(b B, c C) {
           b.SetHandler(c)
           c.SetOwner(b)
        },

        // Construct D for its side-effects only (e.g. start and stop hooks).
        // Avoid this if you can and use Invoke() to register hooks instead of Provide() if 
        // there's no API to provide.
        func(D){},
    )

.. _api_module:

Module
^^^^^^

Cells can be grouped into modules (a named set of cells):

.. code-block:: go

    // func Module(id, title string, cells ...Cell) Cell

    var Cell = cell.Module(
    	"example",           // short identifier (for use in e.g. logging and tracing)
	"An example module", // one-line description (for documentation)
    
        cell.Provide(New),

        innerModule,         // modules can contain other modules
    )

    var innerModule cell.Cell = cell.Module(
        "example-inner",
        "An inner module",

        cell.Provide(newInner),
    )


Module() also provides the wrapped cells with a personalized ``logrus.FieldLogger``
with the ``subsys`` field set to module identifier ("example" above).

The scope created by Module() is useful when combined with ProvidePrivate():

.. code-block:: go

    var Cell = cell.Module(
        "example",
        "An example module",
    
        cell.ProvidePrivate(NewA), // A only accessible from this module (or sub-modules)
        cell.Provide(NewB),        // B is accessible from anywhere
    )

.. _api_decorate:

Decorate
^^^^^^^^

Sometimes one may want to use a modified object inside a module, for example how above Module()
provided the cells with a personalized logger. This can be done with a decorator:

.. code-block:: go

    // func Decorate(dtor any, cells ...Cell) Cell

    var Cell = cell.Decorate(
        myLogger, // The decoration function

	// These cells will see the objects returned by the 'myLogger' decorator
        // rather than the objects on the outside.
        foo.Cell, 
        bar.Cell,
    )

    // myLogger is a decorator that can depend on one or more objects in the application
    // and return one or more objects. The input parameters don't necessarily need to match
    // the output types.
    func myLogger(log logrus.FieldLogger) logrus.FieldLogger {
        return log.WithField("lasers", "stun")
    }


.. _api_config:

Config
^^^^^^

Cilium applications use the `cobra <https://github.com/spf13/cobra>`_ and
`pflag <https://github.com/spf13/pflag>`_ libraries for implementing the command-line
interface. With Cobra, one defines a ``Command``, with optional sub-commands. Each command
has an associated FlagSet which must be populated before a command is executed in order to
parse or to produce usage documentation. Hive bridges to Cobra with ``cell.Config``, which
takes a value that implements ``cell.Flagger`` for adding flags to a command's FlagSet and
returns a cell that "provides" the parsed configuration to the application:

.. code-block:: go

    // type Flagger interface {
    //    Flags(flags *pflag.FlagSet)
    // }
    // func Config[Cfg Flagger](defaultConfig Cfg) cell.Cell

    type MyConfig struct {
        MyOption string

        SliceOption []string
        MapOption map[string]string
    }

    func (def MyConfig) Flags(flags *pflag.FlagSet) {
        // Register the "my-option" flag. This matched against the MyOption field
        // by removing any dashes and doing case insensitive comparison.
        flags.String("my-option", def.MyOption, "My config option")

        // Flags are supported for representing complex types such as slices and maps.
        // * Slices are obtained splitting the input string on commas.
        // * Maps support different formats based on how they are provided:
        //   - CLI: key=value format, separated by commas; the flag can be
        //     repeated multiple times.
        //   - Environment variable or configuration file: either JSON encoded
        //     or comma-separated key=value format.
        flags.StringSlice("slice-option", def.SliceOption, "My slice config option")
        flags.StringToString("map-option", def.MapOption, "My map config option")
    }

    var defaultMyConfig = MyConfig{
        MyOption: "the default value",
    }

    func New(cfg MyConfig) MyThing

    var Cell = cell.Module(
        "module-with-config",
        "A module with a config",

        cell.Config(defaultMyConfig),
        cell.Provide(New),
    )

In tests the configuration can be populated in various ways:

.. code-block:: go

    func TestCell(t *testing.T) {
        h := hive.New(Cell)

	// Options can be set via Viper
        h.Viper().Set("my-option", "test-value")

        // Or via pflags
        flags := pflag.NewFlagSet("", pflag.ContinueOnError)
        h.RegisterFlags(flags)
        flags.Set("my-option", "test-value")
	flags.Parse("--my-option=test-value")

	// Or the preferred way with a config override:
	h = hive.New(
            Cell,
        )
        AddConfigOverride(
            h,
            func(cfg *MyConfig) {
                cfg.MyOption = "test-override"
            })

	// To validate that the Cell can be instantiated and the configuration
        // struct is well-formed without starting you can call Populate():
        if err := h.Populate(); err != nil {
            t.Fatalf("Failed to populate: %s", err)
        }
    }

.. _api_lifecycle:

Lifecycle
^^^^^^^^^

In addition to cells an important building block in hive is the lifecycle. A
lifecycle is a list of start and stop hook pairs that are executed in order
(reverse when stopping) when running the hive.

.. code-block:: go

    package hive

    type Lifecycle {
        Append(HookInterface)
    }
    type HookContext context.Context

    type HookInterface interface {
        Start(HookContext) error
        Stop(HookContext) error
    }

    type Hook struct {
        OnStart func(HookContext) error
        OnStop func(HookContext) error
    }

    func (h Hook) Start(ctx HookContext) error { ... }
    func (h Hook) Stop(ctx HookContext) error { ... }

The lifecycle hooks can be implemented either by implementing the HookInterface methods,
or using the Hook struct. Lifecycle is accessible from any cell:

.. code-block:: go

    var ExampleCell = cell.Module(
        "example",
        "Example module",
    
        cell.Provide(New),
    )
    
    type Example struct { /* ... */ }
    func (e *Example) Start(ctx HookContext) error { /* ... */ }
    func (e *Example) Stop(ctx HookContext) error { /* ... */ }
    
    func New(lc hive.Lifecycle) *Example {
        e := &Example{}
        lc.Append(e)
        return e
    }

These hooks are executed when hive.Run() is called. The HookContext given to
these hooks is there to allow graceful aborting of the starting or stopping,
either due to user pressing ``Control-C`` or due to a timeout. By default Hive has
5 minute start timeout and 1 minute stop timeout, but these are configurable
with SetTimeouts(). A grace time of 5 seconds is given on top of the timeout
after which the application is forcefully terminated, regardless of whether
the hook has finished or not.

.. _api_shutdowner:

Shutdowner
^^^^^^^^^^

Sometimes there's nothing else to do but crash. If a fatal error is encountered
in a ``Start()`` hook it's easy: just return the error and abort the start. After
starting one can initiate a shutdown using the ``hive.Shutdowner``:

.. code-block:: go

    package hive

    type Shutdowner interface {
        Shutdown(...ShutdownOption)
    }

    func ShutdownWithError(err error) ShutdownOption { /* ... */ }

    package example

    type Example struct {
        /* ... */
        Shutdowner hive.Shutdowner
    }

    func (e *Example) eventLoop() {
        for { 
            /* ... */
            if err != nil {
                // Uh oh, this is really bad, we've got to crash.
                e.Shutdowner.Shutdown(hive.ShutdownWithError(err))
            }
        }
    }     

Creating and running a hive
~~~~~~~~~~~~~~~~~~~~~~~~~~~

A hive is created using ``hive.New()``:

.. code-block:: go

    // func New(cells ...cell.Cell) *Hive
    var myHive = hive.New(FooCell, BarCell)

``New()`` creates a new hive and registers all providers to it. Invoke
functions are not yet executed as our application may have multiple hives
and we need to delay object instantiation to until we know which hive to use.

However ``New`` does execute an invoke function to gather all command-line flags from
all configuration cells. These can be then registered with a Cobra command:

.. code-block:: go

    var cmd *cobra.Command = /* ... */
    myHive.RegisterFlags(cmd.Flags())

After that the hive can be started with ``myHive.Run()``.

Run() will first construct the parsed configurations and will then execute
all invoke functions to instantiate all needed objects. As part of this the
lifecycle hooks will have been appended (in dependency order). After that
the start hooks can be executed one after the other to start the hive. Once
started, Run() waits for SIGTERM and SIGINT signals and upon receiving one
will execute the stop hooks in reverse order to bring the hive down.

Now would be a good time to try this out in practice. You'll find a small example
application in `pkg/hive/example <https://github.com/cilium/cilium/tree/main/pkg/hive/example>`_.
Try running it with ``go run .`` and exploring the implementation (try what happens if a provider is commented out!).

Inspecting a hive
~~~~~~~~~~~~~~~~~

The ``hive.Hive`` can be inspected with the 'hive' command after it's
been registered with cobra:

.. code-block:: go

    var rootCmd *cobra.Command = /* ... */
    rootCmd.AddCommand(myHive.Command())

.. code-block:: shell-session

    cilium$ go run ./daemon hive
    Cells:

    Ⓜ️ agent (Cilium Agent):
      Ⓜ️ infra (Infrastructure):
        Ⓜ️ k8s-client (Kubernetes Client):
             ⚙️ (client.Config) {
                 K8sAPIServer: (string) "",
                 K8sKubeConfigPath: (string) "",
                 K8sClientQPS: (float32) 0,
                 K8sClientBurst: (int) 0,
                 K8sHeartbeatTimeout: (time.Duration) 30s,
                 EnableK8sAPIDiscovery: (bool) false
             }
 
             🚧 client.newClientset (cell.go:109):
                 ⇨ client.Config, hive.Lifecycle, logrus.FieldLogger 
                 ⇦ client.Clientset 
    ...

    Start hooks:

        • gops.registerGopsHooks.func1 (cell.go:44)
        • cmd.newDatapath.func1 (daemon_main.go:1625)
        ...

    Stop hooks:
        ...
   

The hive command prints out the cells, showing what modules, providers,
configurations etc. exist and what they're requiring and providing.
Finally the command prints out all registered start and stop hooks.
Note that these hooks often depend on the configuration (e.g. k8s-client
will not insert a hook unless e.g. --k8s-kubeconfig-path is given). The
hive command takes the same command-line flags as the root command.

The provider dependencies in a hive can also be visualized as a graphviz dot-graph:

.. code-block:: bash

    cilium$ go run ./daemon hive dot-graph | dot -Tx11

Guidelines
~~~~~~~~~~

Few guidelines one should strive to follow when implementing larger cells:

* A constructor function should only do validation and allocation. Spawning
  of goroutines or I/O operations must not be performed from constructors,
  but rather via the Start hook. This is required as we want to inspect the
  object graph (e.g. ``hive.PrintObjects``) and side-effectful constructors would
  cause undesired effects.

* Stop functions should make sure to block until all resources
  (goroutines, file handles, …) created by the module have been cleaned
  up (with e.g. ``sync.WaitGroup``). This makes sure that independent
  tests in the same test suite are not affecting each other. Use
  `goleak <https://github.com/uber-go/goleak>`_ to check that goroutines
  are not leaked.

* Preferably each non-trivial cell would come with a test that validates that
  it implements its public API correctly. The test also serves
  as an example of how the cell's API is used and it also validates the
  correctness of the cells  it depends on which helps with refactoring.

* Utility cells should not Invoke(). Since cells may be used in many
  applications it makes sense to make them lazy to allow bundling useful
  utilities into one collection. If a utility cell has an invoke, it may be
  instantiated even if it is never used.

* For large cells, provide interfaces and not struct pointers. A cell
  can be thought of providing a service to the rest of the application. To
  make it accessible, one should think about what APIs the module provides and
  express these as well documented interface types. If the interface is large,
  try breaking it up into multiple small ones. Interface types also allows
  integration testing with mock implementations. The rational here is the same as
  with "return structs, accept interfaces": since hive works with the names of types,
  we want to "inject" interfaces into the object graph and not struct
  pointers. Extra benefit is that separating the API implemented by a module
  into one or more interfaces it is easier to document and easier to inspect
  as all public method declarations are in one place.

* Use parameter (cell.In) and result (cell.Out) objects liberally. If a
  constructor takes more than two parameters, consider using a parameter
  struct instead.

Internals: Dependency injection with reflection
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Hive is built on top of `uber/dig <https://github.com/uber-go/dig>`_, a reflection based library for building
dependency injection frameworks. In dig, you create a container, add in your
constructors and then "invoke" to create objects:

.. code-block:: go

    func NewA() (A, error) { /* ... */ }
    func NewB() B { /* ... */ }
    func NewC(A, B) (C, error) { /* ... */ }
    func setupC(C) error

    // Create a new container for our constructors.
    c := dig.New(dig.DeferAcyclicVerification())

    // Add in the constructors. Order does not matter.
    c.Provide(NewC)
    c.Provide(NewB)
    c.Provide(NewA)

    // Invoke a function that can depend on any of the values supplied by the
    // registered constructors.
    // Since this depends on "C", dig will construct first A and B
    // (as C depends on them), and then C.
    c.Invoke(func(c *C) {
        // Do something with C
    })


This is the basis on top of which Hive is built. Hive calls dig’s Provide()
for each of the constructors registered with cell.Provide and then calls
invoke functions to construct the needed objects. The results from the
constructors are cached, so each constructor is called only once.

``uber/dig`` uses Go’s "reflect" package that provides access to the
type information of the provide and invoke functions. For example, the
`Provide <https://pkg.go.dev/go.uber.org/dig#Container.Provide>`_ method does
something akin to this under the hood:

.. code-block:: go

    // 'constructor' has type "func(...) ..."
    typ := reflect.TypeOf(constructor)
    if typ.Kind() != reflect.Func { /* error */ }

    in := make([]reflect.Type, 0, typ.NumIn())
    for i := 0; i < typ.NumIn(); i++ { 
        in[i] = typ.In(i) 
    }

    out := make([]reflect.Type, 0, typ.NumOut())
    for i := 0; i < typ.NumOut(); i++ {
        out[i] = typ.Out(i) 
    }

    container.providers = append(container.providers, &provider{constructor, in, out})


`Invoke <https://pkg.go.dev/go.uber.org/dig#Container.Invoke>`_ will similarly
reflect on the function value to find out what are the required inputs and
then find the required constructors for the input objects and recursively
their inputs.

While building this on reflection is flexible, the downside is that missing
dependencies lead to runtime errors. Luckily dig produces excellent errors and
suggests closely matching object types in case of typos. Due to the desire
to avoid these runtime errors the constructed hive should be as static
as possible, e.g. the set of constructors and invoke functions should be
determined at compile time and not be dependent on runtime configuration. This
way the hive can be validated once with a simple unit test (``daemon/cmd/cells_test.go``).

Cell showcase
~~~~~~~~~~~~~

Logging
^^^^^^^

Logging is provided to all cells by default with the ``logrus.FieldLogger`` interface type. The log lines will include the field ``subsys=<module id>``.

.. code-block:: go

    cell.Module(
        "example",
        "log example module",
    
        cell.Provide(
      	    func(log logrus.FieldLogger) Example {
    	  	log.Info("Hello") // subsys=example message=Hello
                return Example{log: log}
    	    },
        ),
    )

Kubernetes client
^^^^^^^^^^^^^^^^^

The `client package <https://pkg.go.dev/github.com/cilium/cilium/pkg/k8s/client>`_ provides the ``Clientset`` API 
that combines the different clientsets used by Cilium into one composite value. Also provides ``FakeClientCell``
for writing integration tests for cells that interact with the K8s api-server.

.. code-block:: go

    var Cell = cell.Provide(New)

    func New(cs client.Clientset) Example {
         return Example{cs: cs}
    }

    func (e Example) CreateIdentity(id *ciliumv2.CiliumIdentity) error {
        return e.cs.CiliumV2().CiliumIdentities().Create(e.ctx, id, metav1.CreateOptions{})
    }

Resource and the store (see below) is the preferred way of accessing Kubernetes object
state to minimize traffic to the api-server. The Clientset should usually
only be used for creating and updating objects.

Kubernetes Resource and Store
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

While not a cell by itself, `pkg/k8s/resource <https://pkg.go.dev/github.com/cilium/cilium/pkg/k8s/resource>`_ 
provides an useful abstraction for providing shared event-driven access
to Kubernetes objects. Implemented on top of the client-go informer,
``workqueue`` and store to codify the suggested pattern for controllers in a
type-safe way. This shared abstraction provides a simpler API to write and
test against and allows central control over what data (and at what rate)
is pulled from the api-server and how it’s stored (in-memory or persisted).

The resources are usually made available centrally for the application,
e.g. in cilium-agent they’re provided from `pkg/k8s/shared_resources.go <https://github.com/cilium/cilium/blob/main/pkg/k8s/shared_resources.go>`_.
See also the runnable example in `pkg/k8s/resource/example <https://github.com/cilium/cilium/tree/main/pkg/k8s/resource/example>`_.

.. code-block:: go

    import "github.com/cilium/cilium/pkg/k8s/resource"

    var nodesCell = cell.Provide(
        func(lc hive.Lifecycle, cs client.Clientset) resource.Resource[v1.Node] {
            lw := utils.ListerWatcherFromTyped[*v1.NodeList](cs.CoreV1().Nodes())
            return resource.New[*v1.Node](lc, lw) 
        },
    )

    var Cell = cell.Module(
        "resource-example",
        "Example of how to use Resource",

        nodesCell,
        cell.Invoke(printNodeUpdates),
    )

    func printNodeUpdates(nodes resource.Resource[*v1.Node]) {
        // Store() returns a typed locally synced store of the objects.
        // This call blocks until the store has been synchronized.
        store, err := nodes.Store()
        ...
        obj, exists, err := store.Get("my-node")
        ...
        objs, err := store.List()
        ...

        // Events() returns a channel of object change events. Closes
        // when 'ctx' is cancelled.
        // type Event[T] struct { Kind Kind; Key Key; Object T; Done func(err error) }
        for ev := range nodes.Events(ctx) {
            switch ev.Kind {
            case resource.Sync:
              // The store has now synced with api-server and
              // the set of observed upsert events forms a coherent
              // snapshot. Usually some sort of garbage collection or
              // reconciliation is performed.
            case resource.Upsert:
                fmt.Printf("Node %s has updated: %v\n", ev.Key, ev.Object)
            case resource.Delete:
                fmt.Printf("Node %s has been deleted\n", key)
            }
            // Each event must be marked as handled. If non-nil error
            // is given, the processing for this key is retried later
            // according to rate-limiting and retry policy. The built-in
            // retrying is often used if we perform I/O operations (like API client
            // calls) from the handler and retrying makes sense. It should not
            // be used on parse errors and similar.
            ev.Done(nil)
        }
    }

Job groups
^^^^^^^^^^

The `job package <https://pkg.go.dev/github.com/cilium/cilium/pkg/hive/job>`_ contains logic that 
makes it easy to manage units of work that the package refers to as "jobs". These jobs are 
scheduled as part of a job group. These jobs themselves come in several varieties.

Every job is a callback function provided by the user with additional logic which
differs slightly for each job type. The jobs and groups manage a lot of the boilerplate
surrounding lifecycle management. The callbacks are called from the job to perform the actual
work.

Consider the following example:

.. code-block:: go

    package job_example

    import (
        "context"
        "fmt"
        "math/rand"
        "runtime/pprof"
        "time"

        "github.com/cilium/cilium/pkg/hive"
        "github.com/cilium/cilium/pkg/hive/cell"
        "github.com/cilium/cilium/pkg/hive/job"
        "github.com/cilium/cilium/pkg/stream"
        "github.com/sirupsen/logrus"
        "k8s.io/client-go/util/workqueue"
    )

    var Cell = cell.Provide(newExampleCell)

    type exampleCell struct {
        jobGroup job.Group
        workChan chan struct{}
        trigger  job.Trigger
        logger   logrus.FieldLogger
    }

    func newExampleCell(
        lifecycle hive.Lifecycle, 
        logger logrus.FieldLogger, 
        registry job.Registry,
    ) *exampleCell {
        ex := exampleCell{
            jobGroup: registry.NewGroup(
                job.WithLogger(logger),
                job.WithPprofLabels(pprof.Labels("cell", "example")),
            ),
            workChan: make(chan struct{}, 3),
            trigger:  job.NewTrigger(),
            logger:   logger,
        }

        ex.jobGroup.Add(
            job.OneShot(
                "sync-on-startup",
                ex.sync,
                job.WithRetry(3, workqueue.DefaultControllerRateLimiter()),
                job.WithShutdown(), // if the retries fail, shutdown the hive
            ),
            job.OneShot("daemon", ex.daemon),
            job.Timer("timer", ex.timer, 5*time.Second, job.WithTrigger(ex.trigger)),
            job.Observer("observer", ex.observer, stream.FromChannel(ex.workChan)),
        )

        lifecycle.Append(ex.jobGroup)

        return &ex
    }

    func (ex *exampleCell) sync(ctx context.Context) error {
        for i := 0; i < 3; i++ {
            if err := ex.doSomeWork(); err != nil {
                return fmt.Errorf("doSomeWork: %w", err)
            }
        }

        return nil
    }

    func (ex *exampleCell) daemon(ctx context.Context) error {
        for {
            randomTimeout := time.NewTimer(time.Duration(rand.Intn(3000)) * time.Millisecond)
            select {
            case <-ctx.Done():
                return nil

            case <-randomTimeout.C:
                ex.doSomeWork()
            }
        }
    }

    func (ex *exampleCell) timer(ctx context.Context) error {
        if err := ex.doSomeWork(); err != nil {
            return fmt.Errorf("doSomeWork: %w", err)
        }

        return nil
    }

    func (ex *exampleCell) Trigger() {
        ex.trigger.Trigger()
    }

    func (ex *exampleCell) observer(ctx context.Context, event struct{}) error {
        ex.logger.Info("Observed event")
        return nil
    }

    func (ex *exampleCell) HeavyLifting() {
        ex.jobGroup.Add(job.OneShot("long-running-job", func(ctx context.Context) error {
            for i := 0; i < 1_000_000; i++ {
                // Do some heavy lifting
            }
            return nil
        }))
    }

    func (ex *exampleCell) doSomeWork() error {
        ex.workChan <- struct{}{}
        return nil
    }


The preceding example shows a number of use cases in one cell. The cell starts by requesting the job.Registry
by way of the constructor. The registry can create job groups; in most cases, one is enough.
You can add jobs in the constructor to this group. Any jobs added in the constructor are queued
until the lifecycle of the cell starts. The group is added to the lifecycle and manages jobs 
internally. You can also add jobs at runtime, which can be handy for dynamic workloads while still
guaranteeing a clean shutdown.

A job group cancels the context to all jobs when the lifecycle ends. Any job callbacks are 
expected to exit as soon as the ``ctx`` is "Done". The group makes sure that all
jobs are properly shut down before the cell stops. Callbacks that do not stop within a reasonable 
amount of time may cause the hive to perform a hard shutdown.

There are 3 job types: one-shot jobs, timer jobs, and observer jobs. One-shot jobs run a limited 
number of times: use them for brief jobs, or for jobs that span the entire lifecycle.
Once the callback exits without error, it is never called again. Optionally, a one-shot job can include retry
logic and/or trigger hive shutdown if it fails. Timers are called on a specified interval but they
can also be externally triggered. Lastly, observer jobs are invoked for every event
on a ``stream.Observable``.
