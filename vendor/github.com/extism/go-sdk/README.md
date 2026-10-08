# Extism Go SDK

This repo houses the Go SDK for integrating with the [Extism](https://extism.org/) runtime. Install this library into your host Go applications to run Extism plugins.

Join the [Extism Discord](https://extism.org/discord) and chat with us!

## Installation

Install via `go get`:

```
go get github.com/extism/go-sdk
```

## Reference Docs

You can find the reference docs at [https://pkg.go.dev/github.com/extism/go-sdk](https://pkg.go.dev/github.com/extism/go-sdk).

## Getting Started

This guide should walk you through some of the concepts in Extism and this Go library.

### Creating A Plug-in

The primary concept in Extism is the [plug-in](https://extism.org/docs/concepts/plug-in). You can think of a plug-in as a code module stored in a `.wasm` file.

Plug-in code can come from a file on disk, object storage or any number of places. Since you may not have one handy let's load a demo plug-in from the web. Let's
start by creating a main func and loading an Extism Plug-in:

```go
package main

import (
	"context"
	"fmt"
	"github.com/extism/go-sdk"
	"os"
)

func main() {
	manifest := extism.Manifest{
		Wasm: []extism.Wasm{
			extism.WasmUrl{
				Url: "https://github.com/extism/plugins/releases/latest/download/count_vowels.wasm",
			},
		},
	}

	ctx := context.Background()
	config := extism.PluginConfig{}
	plugin, err := extism.NewPlugin(ctx, manifest, config, []extism.HostFunction{})

	if err != nil {
		fmt.Printf("Failed to initialize plugin: %v\n", err)
		os.Exit(1)
	}
}
```
> **Note**: See [the Manifest docs](https://pkg.go.dev/github.com/extism/go-sdk#Manifest) as it has a rich schema and a lot of options.

### Calling A Plug-in's Exports

This plug-in was written in Rust and it does one thing, it counts vowels in a string. As such, it exposes one "export" function: `count_vowels`. We can call exports using [extism.Plugin.Call](https://pkg.go.dev/github.com/extism/go-sdk#Plugin.Call).
Let's add that code to our main func:

```go
func main() {
    // ...

	data := []byte("Hello, World!")
	exit, out, err := plugin.Call("count_vowels", data)
	if err != nil {
		fmt.Println(err)
		os.Exit(int(exit))
	}

	response := string(out)
	fmt.Println(response)
    // => {"count": 3, "total": 3, "vowels": "aeiouAEIOU"}
}
```

Running this should print out the JSON vowel count report:

```bash
$ go run main.go
# => {"count":3,"total":3,"vowels":"aeiouAEIOU"}
```

All exports have a simple interface of optional bytes in, and optional bytes out. This plug-in happens to take a string and return a JSON encoded string with a report of results.

> **Note**: If you want to pass a custom `context.Context` when calling a plugin function, you can use the [extism.Plugin.CallWithContext](https://pkg.go.dev/github.com/extism/go-sdk#Plugin.CallWithContext) method instead.


### Plug-in State

Plug-ins may be stateful or stateless. Plug-ins can maintain state between calls by the use of variables. Our count vowels plug-in remembers the total number of vowels it's ever counted in the "total" key in the result. You can see this by making subsequent calls to the export:

```go
func main () {
    // ...

    exit, out, err := plugin.Call("count_vowels", []byte("Hello, World!"))
    if err != nil {
        fmt.Println(err)
        os.Exit(int(exit))
    }
    fmt.Println(string(out))
    // => {"count": 3, "total": 6, "vowels": "aeiouAEIOU"}

    exit, out, err = plugin.Call("count_vowels", []byte("Hello, World!"))
    if err != nil {
        fmt.Println(err)
        os.Exit(int(exit))
    }
    fmt.Println(string(out))
    // => {"count": 3, "total": 9, "vowels": "aeiouAEIOU"}
}

```

These variables will persist until this plug-in is freed or you initialize a new one.

### Configuration

Plug-ins may optionally take a configuration object. This is a static way to configure the plug-in. Our count-vowels plugin takes an optional configuration to change out which characters are considered vowels. Example:

```go
func main() {
    manifest := extism.Manifest{
        Wasm: []extism.Wasm{
            extism.WasmUrl{
                Url: "https://github.com/extism/plugins/releases/latest/download/count_vowels.wasm",
            },
        },
        Config: map[string]string{
            "vowels": "aeiouyAEIOUY",
        },
    }

    ctx := context.Background()
    config := extism.PluginConfig{}

    plugin, err := extism.NewPlugin(ctx, manifest, config, []extism.HostFunction{})

    if err != nil {
        fmt.Printf("Failed to initialize plugin: %v\n", err)
        os.Exit(1)
    }

    exit, out, err := plugin.Call("count_vowels", []byte("Yellow, World!"))
    if err != nil {
        fmt.Println(err)
        os.Exit(int(exit))
    }

    fmt.Println(string(out))
    // => {"count": 4, "total": 4, "vowels": "aeiouAEIOUY"}
}
```

### Host Functions

Let's extend our count-vowels example a little bit: Instead of storing the `total` in an ephemeral plug-in var, let's store it in a persistent key-value store!

Wasm can't use our KV store on it's own. This is where [Host Functions](https://extism.org/docs/concepts/host-functions) come in.

[Host functions](https://extism.org/docs/concepts/host-functions) allow us to grant new capabilities to our plug-ins from our application. They are simply some Go functions you write which can be passed down and invoked from any language inside the plug-in.

Let's load the manifest like usual but load up this `count_vowels_kvstore` plug-in:

```go
manifest := extism.Manifest{
    Wasm: []extism.Wasm{
        extism.WasmUrl{
            Url: "https://github.com/extism/plugins/releases/latest/download/count_vowels_kvstore.wasm",
        },
    },
}
```

> *Note*: The source code for this is [here](https://github.com/extism/plugins/blob/main/count_vowels_kvstore/src/lib.rs) and is written in rust, but it could be written in any of our PDK languages.

Unlike our previous plug-in, this plug-in expects you to provide host functions that satisfy our its import interface for a KV store.

We want to expose two functions to our plugin, `kv_write(key string, value []bytes)` which writes a bytes value to a key and `kv_read(key string) []byte` which reads the bytes at the given `key`.
```go
// pretend this is Redis or something :)
kvStore := make(map[string][]byte)

kvRead := extism.NewHostFunctionWithStack(
    "kv_read",
    func(ctx context.Context, p *extism.CurrentPlugin, stack []uint64) {
        key, err := p.ReadString(stack[0])
        if err != nil {
            panic(err)
        }

        value, success := kvStore[key]
        if !success {
            value = []byte{0, 0, 0, 0}
        }

        stack[0], err = p.WriteBytes(value)
    },
    []ValueType{ValueTypePTR},
    []ValueType{ValueTypePTR},
)

kvWrite := extism.NewHostFunctionWithStack(
    "kv_write",
    func(ctx context.Context, p *extism.CurrentPlugin, stack []uint64) {
        key, err := p.ReadString(stack[0])
        if err != nil {
            panic(err)
        }

        value, err := p.ReadBytes(stack[1])
        if err != nil {
            panic(err)
        }

        kvStore[key] = value
    },
    []ValueType{ValueTypePTR, ValueTypePTR},
    []ValueType{},
)
```

> *Note*: In order to write host functions you should get familiar with the methods on the [extism.CurrentPlugin](https://pkg.go.dev/github.com/extism/go-sdk#CurrentPlugin) type. The `p` parameter is an instance of this type.

We need to pass these imports to the plug-in to create them. All imports of a plug-in must be satisfied for it to be initialized:

```go
plugin, err := extism.NewPlugin(ctx, manifest, config, []extism.HostFunction{kvRead, kvWrite});
```

Now we can invoke the event:

```go
exit, out, err := plugin.Call("count_vowels", []byte("Hello, World!"))
// => Read from key=count-vowels"
// => Writing value=3 from key=count-vowels"
// => {"count": 3, "total": 3, "vowels": "aeiouAEIOU"}

exit, out, err = plugin.Call("count_vowels", []byte("Hello, World!"))
// => Read from key=count-vowels"
// => Writing value=6 from key=count-vowels"
// => {"count": 3, "total": 6, "vowels": "aeiouAEIOU"}
```

### Enabling Compilation Cache
While Wazero (the underlying Wasm runtime) is very fast in initializing modules, you can make subsequent initializations even faster by enabling the compilation cache:

```go
ctx := context.Background()
cache := wazero.NewCompilationCache()
defer cache.Close(ctx)

manifest := Manifest{Wasm: []Wasm{WasmFile{Path: "wasm/noop.wasm"}}}

config := PluginConfig{
    EnableWasi:    true,
    ModuleConfig:  wazero.NewModuleConfig(),
    RuntimeConfig: wazero.NewRuntimeConfig().WithCompilationCache(cache),
}

_, err := NewPlugin(ctx, manifest, config, []HostFunction{})
```

### Integrate with Dylibso Observe SDK
Dylibso provides [observability SDKs](https://github.com/dylibso/observe-sdk) for WebAssembly (Wasm), enabling continuous monitoring of WebAssembly code as it executes within a runtime. It provides developers with the tools necessary to capture and emit telemetry data from Wasm code, including function execution and memory allocation traces, logs, and metrics.

While Observe SDK has adapters for many popular observability platforms, it also ships with an stdout adapter:

```
ctx := context.Background()

adapter := stdout.NewStdoutAdapter()
adapter.Start(ctx)

manifest := manifest("nested.c.instr.wasm")

config := PluginConfig{
    ModuleConfig:   wazero.NewModuleConfig().WithSysWalltime(),
    EnableWasi:     true,
    ObserveAdapter: adapter.AdapterBase,
}

plugin, err := NewPlugin(ctx, manifest, config, []HostFunction{})
if err != nil {
    panic(err)
}

meta := map[string]string{
    "http.url":         "https://example.com/my-endpoint",
    "http.status_code": "200",
    "http.client_ip":   "192.168.1.0",
}

plugin.TraceCtx.Metadata(meta)

_, _, _ = plugin.Call("_start", []byte("hello world"))
plugin.Close()
```

### Enable filesystem access

WASM plugins can read/write files outside the runtime. To do this we add `AllowedPaths` mapping of "HOST:PLUGIN" to the `extism.Manifest` of our plugin.

```go
package main

import (
	"context"
	"fmt"
	"os"

	extism "github.com/extism/go-sdk"
)

func main() {
	manifest := extism.Manifest{
		AllowedPaths: map[string]string{
			// Here we specifify a host directory data to be linked
			// to the /mnt directory inside the wasm runtime
			"data": "/mnt",
		},
		Wasm: []extism.Wasm{
			extism.WasmFile{
				Path: "fs_plugin.wasm",
			},
		},
	}

	ctx := context.Background()
	config := extism.PluginConfig{
		EnableWasi: true,
	}
	plugin, err := extism.NewPlugin(ctx, manifest, config, []extism.HostFunction{})

	if err != nil {
		fmt.Printf("Failed to initialize plugin: %v\n", err)
		os.Exit(1)
	}

	data := []byte("Hello world, this is written from within our wasm plugin.")
	exit, _, err := plugin.Call("write_file", data)
	if err != nil {
		fmt.Println(err)
		os.Exit(int(exit))
	}
}
```

> *Note*: In order for filesystem APIs to work the plugin needs to be compiled with WASI target. Source code for the plugin can be found [here](https://github.com/extism/go-pdk/blob/main/example/fs/main.go) and is written in Go, but it could be written in any of our PDK languages.

## Build example plugins

Since our [example plugins](./plugins/) are also written in Go, for compiling them we use [TinyGo](https://tinygo.org/):

```sh
cd plugins/config
tinygo build -target wasi -o ../wasm/config.wasm main.go
```
