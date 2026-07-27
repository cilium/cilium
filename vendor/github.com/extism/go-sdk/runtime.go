package extism

import (
	"context"

	"github.com/tetratelabs/wazero/api"
)

// TODO: test runtime initialization for WASI and Haskell

type runtimeType uint8

const (
	None runtimeType = iota
	Haskell
	Wasi
)

type guestRuntime struct {
	mainRuntime moduleRuntime
	runtimes    map[string]moduleRuntime
	init        func(ctx context.Context) error
	initialized bool
}

type moduleRuntime struct {
	runtimeType runtimeType
	init        func(ctx context.Context) error
	initialized bool
}

// detectGuestRuntime detects the runtime of the main module and all other modules
// it returns a guest runtime with an initialization function specific that invokes
// the initialization function of all the modules, with the main module last.
func detectGuestRuntime(p *Plugin) guestRuntime {
	r := guestRuntime{runtimes: make(map[string]moduleRuntime)}

	r.mainRuntime = detectModuleRuntime(p, p.mainModule)
	for k, m := range p.modules {
		r.runtimes[k] = detectModuleRuntime(p, m)
	}

	r.init = func(ctx context.Context) error {

		for k, v := range r.runtimes {
			p.Logf(LogLevelDebug, "Initializing runtime for module %v", k)
			err := v.init(ctx)
			if err != nil {
				return err
			}
			v.initialized = true
		}

		m := r.mainRuntime
		p.Logf(LogLevelDebug, "Initializing runtime for main module")
		err := m.init(ctx)
		if err != nil {
			return err
		}
		m.initialized = true

		return nil
	}

	return r
}

// detectModuleRuntime detects the specific runtime of a given module
// it returns a module runtime with an initialization function specific to that module
func detectModuleRuntime(p *Plugin, m api.Module) moduleRuntime {
	runtime, ok := haskellRuntime(p, m)
	if ok {
		return runtime
	}

	runtime, ok = wasiRuntime(p, m)
	if ok {
		return runtime
	}

	p.Log(LogLevelTrace, "No runtime detected")
	return moduleRuntime{runtimeType: None, init: func(_ context.Context) error { return nil }, initialized: true}
}

// Check for Haskell runtime initialization functions
// Initialize Haskell runtime if `hs_init` and `hs_exit` are present,
// by calling the `hs_init` export
func haskellRuntime(p *Plugin, m api.Module) (moduleRuntime, bool) {
	initFunc := m.ExportedFunction("hs_init")
	if initFunc == nil {
		return moduleRuntime{}, false
	}

	params := initFunc.Definition().ParamTypes()

	if len(params) != 2 || params[0] != api.ValueTypeI32 || params[1] != api.ValueTypeI32 {
		p.Logf(LogLevelTrace, "hs_init function found with type %v", params)
	}

	reactorInit := m.ExportedFunction("_initialize")

	init := func(ctx context.Context) error {
		if reactorInit != nil {
			_, err := reactorInit.Call(ctx)
			if err != nil {
				p.Logf(LogLevelError, "Error running reactor _initialize: %s", err.Error())
			}
		}
		_, err := initFunc.Call(ctx, 0, 0)
		if err == nil {
			p.Log(LogLevelDebug, "Initialized Haskell language runtime.")
		}

		return err
	}

	p.Log(LogLevelTrace, "Haskell runtime detected")
	return moduleRuntime{runtimeType: Haskell, init: init}, true
}

// Check for initialization functions defined by the WASI standard
func wasiRuntime(p *Plugin, m api.Module) (moduleRuntime, bool) {
	if !p.hasWasi {
		return moduleRuntime{}, false
	}

	// WASI supports two modules: Reactors and Commands
	// we prioritize Reactors over Commands
	// see: https://github.com/WebAssembly/WASI/blob/main/legacy/application-abi.md
	if r, ok := reactorModule(m, p); ok {
		return r, ok
	}

	return commandModule(m, p)
}

// Check for `_initialize` this is used by WASI to initialize certain interfaces.
func reactorModule(m api.Module, p *Plugin) (moduleRuntime, bool) {
	init := findFunc(m, p, "_initialize")
	if init == nil {
		return moduleRuntime{}, false
	}

	p.Logf(LogLevelTrace, "WASI runtime detected")
	p.Logf(LogLevelTrace, "Reactor module detected")

	return moduleRuntime{runtimeType: Wasi, init: init}, true
}

// Check for `__wasm__call_ctors`, this is used by WASI to
// initialize certain interfaces.
func commandModule(m api.Module, p *Plugin) (moduleRuntime, bool) {
	init := findFunc(m, p, "__wasm_call_ctors")
	if init == nil {
		return moduleRuntime{}, false
	}

	p.Logf(LogLevelTrace, "WASI runtime detected")
	p.Logf(LogLevelTrace, "Command module detected")

	return moduleRuntime{runtimeType: Wasi, init: init}, true
}

func findFunc(m api.Module, p *Plugin, name string) func(context.Context) error {
	initFunc := m.ExportedFunction(name)
	if initFunc == nil {
		return nil
	}

	params := initFunc.Definition().ParamTypes()
	if len(params) != 0 {
		p.Logf(LogLevelTrace, "%v function found with type %v", name, params)
		return nil
	}

	return func(ctx context.Context) error {
		p.Logf(LogLevelDebug, "Calling %v", name)
		_, err := initFunc.Call(ctx)
		return err
	}
}

func equal(actual []byte, expected []byte) bool {
	if len(actual) != len(expected) {
		return false
	}

	for i, k := range actual {
		if expected[i] != k {
			return false
		}
	}

	return true
}
