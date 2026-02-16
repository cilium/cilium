// new
package extism

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"time"

	observe "github.com/dylibso/observe-sdk/go"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

type CompiledPlugin struct {
	runtime wazero.Runtime
	main    wazero.CompiledModule
	extism  wazero.CompiledModule
	env     api.Module
	modules map[string]wazero.CompiledModule

	// when a module (main) is instantiated, it may have a module name that's added
	// to the data section of the wasm. If this is the case, we won't be able to
	// instantiate that module more than once. This counter acts as the module name
	// incrementing each time we instantiate the module.
	instanceCount atomic.Uint64

	// this is the raw wasm bytes of the provided module, it is required when using a tracing observeAdapter.
	// If an adapter is not provided, this field will be nil.
	wasmBytes      []byte
	hasWasi        bool
	manifest       Manifest
	observeAdapter *observe.AdapterBase
	observeOptions *observe.Options

	maxHttp                   int64
	maxVar                    int64
	enableHttpResponseHeaders bool
}

type PluginConfig struct {
	RuntimeConfig             wazero.RuntimeConfig
	EnableWasi                bool
	ObserveAdapter            *observe.AdapterBase
	ObserveOptions            *observe.Options
	EnableHttpResponseHeaders bool

	// ModuleConfig is only used when a plugins are built using the NewPlugin
	// function. In this function, the plugin is both compiled, and an instance
	// of the plugin is instantiated, and the ModuleConfig is passed to the
	// instance.
	//
	// When plugins are built using NewCompiledPlugin, the ModuleConfig has no
	// effect because the instance is not created. Instead, the ModuleConfig is
	// passed directly in calls to the CompiledPlugin.Instance method.
	//
	// NOTE: Module name and start functions are ignored as they are overridden by Extism, also if Manifest contains
	// non-empty AllowedPaths, then FS is also ignored. If EXTISM_ENABLE_WASI_OUTPUT is set, then stdout and stderr are
	// set to os.Stdout and os.Stderr respectively (ignoring user defined module config).
	ModuleConfig wazero.ModuleConfig
}

// NewPlugin creates compiles and instantiates a plugin that is ready
// to be used. Plugins are not thread-safe. If you need to use a plugin
// across multiple goroutines, use NewCompiledPlugin and create instances
// of the plugin using the CompiledPlugin.Instance method.
func NewPlugin(
	ctx context.Context,
	manifest Manifest,
	config PluginConfig,
	functions []HostFunction,
) (*Plugin, error) {
	c, err := NewCompiledPlugin(ctx, manifest, config, functions)
	if err != nil {
		return nil, err
	}
	p, err := c.Instance(ctx, PluginInstanceConfig{
		ModuleConfig: config.ModuleConfig,
	})
	if err != nil {
		return nil, err
	}
	p.close = append(p.close, c.Close)
	return p, nil
}

func calculateMaxHttp(manifest Manifest) int64 {
	// Default is 50MB
	maxHttp := int64(1024 * 1024 * 50)
	if manifest.Memory != nil && manifest.Memory.MaxHttpResponseBytes >= 0 {
		maxHttp = manifest.Memory.MaxHttpResponseBytes
	}
	return maxHttp
}

func calculateMaxVar(manifest Manifest) int64 {
	// Default is 1MB
	maxVar := int64(1024 * 1024)
	if manifest.Memory != nil && manifest.Memory.MaxVarBytes >= 0 {
		maxVar = manifest.Memory.MaxVarBytes
	}
	return maxVar
}

// NewCompiledPlugin creates a compiled plugin that is ready to be instantiated.
// You can instantiate the plugin multiple times using the CompiledPlugin.Instance
// method and run those instances concurrently.
func NewCompiledPlugin(
	ctx context.Context,
	manifest Manifest,
	config PluginConfig,
	funcs []HostFunction,
) (*CompiledPlugin, error) {
	count := len(manifest.Wasm)
	if count == 0 {
		return nil, fmt.Errorf("manifest can't be empty")
	}

	runtimeConfig := config.RuntimeConfig
	if runtimeConfig == nil {
		runtimeConfig = wazero.NewRuntimeConfig()
	}

	// Make sure function calls are cancelled if the context is cancelled
	if manifest.Timeout > 0 {
		runtimeConfig = runtimeConfig.WithCloseOnContextDone(true)
	}

	if manifest.Memory != nil {
		if manifest.Memory.MaxPages > 0 {
			runtimeConfig = runtimeConfig.WithMemoryLimitPages(manifest.Memory.MaxPages)
		}
	}

	p := CompiledPlugin{
		manifest:                  manifest,
		runtime:                   wazero.NewRuntimeWithConfig(ctx, runtimeConfig),
		observeAdapter:            config.ObserveAdapter,
		observeOptions:            config.ObserveOptions,
		enableHttpResponseHeaders: config.EnableHttpResponseHeaders,
		modules:                   make(map[string]wazero.CompiledModule),
		maxHttp:                   calculateMaxHttp(manifest),
		maxVar:                    calculateMaxVar(manifest),
	}

	if config.EnableWasi {
		wasi_snapshot_preview1.MustInstantiate(ctx, p.runtime)
		p.hasWasi = true
	}

	// Build host modules
	hostModules := make(map[string][]HostFunction)
	for _, f := range funcs {
		hostModules[f.Namespace] = append(hostModules[f.Namespace], f)
	}
	for name, funcs := range hostModules {
		_, err := buildHostModule(ctx, p.runtime, name, funcs)
		if err != nil {
			return nil, fmt.Errorf("building host module: %w", err)
		}
	}

	// Compile the extism module
	var err error
	p.extism, err = p.runtime.CompileModule(ctx, extismRuntimeWasm)
	if err != nil {
		return nil, fmt.Errorf("instantiating extism module: %w", err)
	}

	// Build and instantiate extism:host/env module
	p.env, err = instantiateEnvModule(ctx, p.runtime)
	if err != nil {
		return nil, err
	}

	// Try to find the main module:
	//  - There is always one main module
	//  - If a Wasm value has the Name field set to "main" then use that module
	//  - If there is only one module in the manifest then that is the main module by default
	//  - Otherwise the last module listed is the main module

	foundMain := false
	for i, wasm := range manifest.Wasm {
		data, err := wasm.ToWasmData(ctx)
		if err != nil {
			return nil, err
		}

		if (data.Name == "" || i == len(manifest.Wasm)-1) && !foundMain {
			data.Name = "main"
		}

		_, okm := p.modules[data.Name]

		if data.Name == "extism:host/env" || okm {
			return nil, fmt.Errorf("module name collision: '%s'", data.Name)
		}

		if data.Hash != "" {
			calculatedHash := calculateHash(data.Data)
			if data.Hash != calculatedHash {
				return nil, fmt.Errorf("hash mismatch for module '%s'", data.Name)
			}
		}

		if p.observeAdapter != nil {
			p.wasmBytes = data.Data
		}

		compiledModule, err := p.runtime.CompileModule(ctx, data.Data)
		if err != nil {
			return nil, err
		}

		if data.Name == "main" {
			if foundMain {
				return nil, errors.New("can't have more than one main module")
			}
			p.main = compiledModule
			foundMain = true
		} else {
			// Store compiled module for instantiation
			p.modules[data.Name] = compiledModule
			// Create wrapper with original name that will forward calls to the actual module instance. See createModuleWrapper for more details.
			_, err = createModuleWrapper(ctx, p.runtime, data.Name, compiledModule)
			if err != nil {
				return nil, fmt.Errorf("failed to create wrapper for %s: %w", data.Name, err)
			}
		}
	}

	if p.main == nil {
		return nil, errors.New("no main module found")
	}

	// We no longer need the wasm in the manifest so nil it
	// to make the slice eligible for garbage collection.
	p.manifest.Wasm = nil

	return &p, nil
}

// createModuleWrapper creates a host module that acts as a proxy for module instances.
// In Wazero, modules with the same name cannot be instantiated multiple times in the same runtime.
// However, we need each Plugin instance to have its own copy of each module for isolation. To solve this, we:
//  1. Create a host module wrapper that keeps the original module name (needed for imports to work)
//  2. Instantiate actual module copies with unique names for each Plugin
//  3. The wrapper forwards function calls to the correct module instance for each Plugin
func createModuleWrapper(ctx context.Context, rt wazero.Runtime, name string, compiled wazero.CompiledModule) (api.Module, error) {
	builder := rt.NewHostModuleBuilder(name)

	// Create proxy functions for each exported function from the original module.
	// These proxies will forward calls to the appropriate module instance.
	for _, export := range compiled.ExportedFunctions() {
		exportName := export.Name()

		// Skip wrapping the _start function since it's automatically called by wazero during instantiation.
		// The wrapper functions require a Plugin instance in the context to work, but during wrapper
		// instantiation there is no Plugin instance yet.
		if exportName == "_start" {
			continue
		}

		// Create a proxy function that:
		// 1. Gets the calling Plugin instance from context
		// 2. Looks up that Plugin's copy of this module
		// 3. Forwards the call to the actual function
		wrapper := func(callCtx context.Context, mod api.Module, stack []uint64) {
			// Get the Plugin instance that's making this call
			plugin, ok := callCtx.Value(PluginCtxKey("plugin")).(*Plugin)
			if !ok {
				panic("Invalid context, `plugin` key not found")
			}

			// Get this Plugin's instance of the module
			actualModule, ok := plugin.modules[name]
			if !ok {
				panic(fmt.Sprintf("module %s not found in plugin", name))
			}

			// Forward the call to the actual module instance
			fn := actualModule.ExportedFunction(exportName)
			if fn == nil {
				panic(fmt.Sprintf("function %s not found in module %s", exportName, name))
			}

			err := fn.CallWithStack(callCtx, stack)
			if err != nil {
				panic(err)
			}
		}

		// Export the proxy function with the same name and signature as the original
		builder.NewFunctionBuilder().
			WithGoModuleFunction(api.GoModuleFunc(wrapper), export.ParamTypes(), export.ResultTypes()).
			Export(exportName)
	}

	return builder.Instantiate(ctx)
}

func (p *CompiledPlugin) Close(ctx context.Context) error {
	return p.runtime.Close(ctx)
}

func (p *CompiledPlugin) Instance(ctx context.Context, config PluginInstanceConfig) (*Plugin, error) {
	instanceNum := p.instanceCount.Add(1)

	var closers []func(ctx context.Context) error

	moduleConfig := config.ModuleConfig
	if moduleConfig == nil {
		moduleConfig = wazero.NewModuleConfig()
	}

	// NOTE: we don't want wazero to call the start function, we will initialize
	// the guest runtime manually.
	// See: https://github.com/extism/go-sdk/pull/1#issuecomment-1650527495
	moduleConfig = moduleConfig.WithStartFunctions()

	if len(p.manifest.AllowedPaths) > 0 {
		// NOTE: this is only necessary for guest modules because
		// host modules have the same access privileges as the host itself
		fs := wazero.NewFSConfig()
		for host, guest := range p.manifest.AllowedPaths {
			if strings.HasPrefix(host, "ro:") {
				trimmed := strings.TrimPrefix(host, "ro:")
				fs = fs.WithReadOnlyDirMount(trimmed, guest)
			} else {
				fs = fs.WithDirMount(host, guest)
			}
		}
		moduleConfig = moduleConfig.WithFSConfig(fs)
	}

	_, wasiOutput := os.LookupEnv("EXTISM_ENABLE_WASI_OUTPUT")
	if p.hasWasi && wasiOutput {
		moduleConfig = moduleConfig.WithStderr(os.Stderr).WithStdout(os.Stdout)
	}

	var trace *observe.TraceCtx
	var err error
	if p.observeAdapter != nil {
		trace, err = p.observeAdapter.NewTraceCtx(ctx, p.runtime, p.wasmBytes, p.observeOptions)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize Observe Adapter: %v", err)
		}
	}

	// Compile and instantiate the extism runtime. This runtime is stateful and needs to be
	// instantiated on a per-instance basis. We don't provide a name because the module needs
	// to be anonymous -- you cannot instantiate multiple modules with the same name into the
	// same runtime. It is okay that this is anonymous, because this module is only called
	// from Go host functions and not from the Wasm module itself.
	extism, err := p.runtime.InstantiateModule(ctx, p.extism, wazero.NewModuleConfig())
	if err != nil {
		return nil, fmt.Errorf("instantiating extism module: %w", err)
	}

	closers = append(closers, extism.Close)

	// Instantiate all non-main modules first
	instancedModules := make(map[string]api.Module)
	for name, compiledModule := range p.modules {
		uniqueName := fmt.Sprintf("%s_%d", name, instanceNum)
		instance, err := p.runtime.InstantiateModule(ctx, compiledModule, moduleConfig.WithName(uniqueName))
		if err != nil {
			for _, closer := range closers {
				closer(ctx)
			}
			return nil, fmt.Errorf("instantiating module %s: %w", name, err)
		}
		instancedModules[name] = instance
		closers = append(closers, instance.Close)
	}

	mainModuleName := fmt.Sprintf("main_%d", instanceNum)
	main, err := p.runtime.InstantiateModule(ctx, p.main, moduleConfig.WithName(mainModuleName))
	if err != nil {
		for _, closer := range closers {
			closer(ctx)
		}

		return nil, fmt.Errorf("instantiating module: %w", err)
	}

	closers = append(closers, main.Close)

	var headers map[string]string = nil
	if p.enableHttpResponseHeaders {
		headers = map[string]string{}
	}

	instance := &Plugin{
		close:                closers,
		extism:               extism,
		hasWasi:              p.hasWasi,
		mainModule:           main,
		modules:              instancedModules,
		Timeout:              time.Duration(p.manifest.Timeout) * time.Millisecond,
		Config:               p.manifest.Config,
		Var:                  make(map[string][]byte),
		AllowedHosts:         p.manifest.AllowedHosts,
		AllowedPaths:         p.manifest.AllowedPaths,
		LastStatusCode:       0,
		LastResponseHeaders:  headers,
		MaxHttpResponseBytes: p.maxHttp,
		MaxVarBytes:          p.maxVar,
		guestRuntime:         guestRuntime{},
		Adapter:              p.observeAdapter,
		log:                  logStd,
		traceCtx:             trace,
	}
	instance.guestRuntime = detectGuestRuntime(instance)

	return instance, nil
}
