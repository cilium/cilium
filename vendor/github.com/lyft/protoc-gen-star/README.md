# protoc-gen-star (PG*) [![Build Status](https://travis-ci.org/lyft/protoc-gen-star.svg?branch=master)](https://travis-ci.org/lyft/protoc-gen-star) [![GoDoc](https://godoc.org/github.com/lyft/protoc-gen-star?status.svg)](https://godoc.org/github.com/lyft/protoc-gen-star)

**!!! THIS PROJECT IS A WORK-IN-PROGRESS | THE API SHOULD BE CONSIDERED UNSTABLE !!!**

_PG* is a protoc plugin library for efficient proto-based code generation_

```go
package main

import "github.com/lyft/protoc-gen-star"

func main() {
  pgs.Init(pgs.DebugEnv("DEBUG")).
    RegisterModule(&myPGSModule{}).
    RegisterPostProcessor(&myPostProcessor{}).
    Render()
}
```

## Features

### Documentation

While this README seeks to describe many of the nuances of `protoc` plugin development and using PG*, the true documentation source is the code itself. The Go language is self-documenting and provides tools for easily reading through it and viewing examples. The docs can be viewed on [GoDoc](https://godoc.org/github.com/lyft/protoc-gen-star) or locally by running `make docs`, which will start a `godoc` server and open them in the default browser.

### Roadmap

- [x] Interface-based and fully-linked dependency graph with access to raw descriptors
- [x] Built-in context-aware debugging capabilities
- [x] Exhaustive, near 100% unit test coverage
- [x] End-to-end testable via overrideable IO & Interface based API
- [x] [`Visitor`][visitor] pattern and helpers for efficiently walking the dependency graph
- [x] [`BuildContext`][context] to facilitate complex generation
- [x] Parsed, typed command-line [`Parameters`][params] access
- [x] Extensible `ModuleBase` for quickly creating `Modules` and facilitating code generation
- [x] Configurable post-processing (eg, gofmt) of generated files
- [x] Support processing proto files from multiple packages
- [x] Load comments (via SourceCodeInfo) from proto files into gathered AST for easy access
- [x] Language-specific helper subpackages for handling common, nuanced generation tasks
- [ ] Load plugins/modules at runtime using Go shared libraries

### Examples

[`protoc-gen-example`][pge], can be found in the `testdata` directory. It includes two `Module` implementations using a variety of the features available. It's `protoc` execution is included in the `testdata/generated` [Makefile][make] target. Examples are also accessible via the documentation by running `make docs`.

## How It Works

### The `protoc` Flow

Because the process is somewhat confusing, this section will cover the entire flow of how proto files are converted to generated code, using a hypothetical PG* plugin: `protoc-gen-myplugin`. A typical execution looks like this:

```sh
protoc \
  -I . \
  --myplugin_out="foo=bar:../generated" \
  ./pkg/*.proto
```

`protoc`, the PB compiler, is configured using a set of flags (documented under `protoc -h`) and handed a set of files as arguments. In this case, the `I` flag can be specified multiple times and is the lookup path it uses for imported dependencies in a proto file. By default, the official descriptor protos are already included.

`myplugin_out` tells `protoc` to use the `protoc-gen-myplugin` protoc-plugin. These plugins are automatically resolved from the system's `PATH` environment variable, or can be explicitly specified with another flag. The official protoc-plugins (eg, `protoc-gen-python`) are already registered with `protoc`. The flag's value is specific to the particular plugin, with the exception of the `:../generated` suffix. This suffix indicates the root directory in which `protoc` will place the generated files from that package (relative to the current working directory). This generated output directory is _not_ propagated to `protoc-gen-myplugin`, however, so it needs to be duplicated in the left-hand side of the flag. PG* supports this via an `output_path` parameter.

`protoc` parses the passed in proto files, ensures they are syntactically correct, and loads any imported dependencies. It converts these files and the dependencies into descriptors (which are themselves PB messages) and creates a `CodeGeneratorRequest` (yet another PB). `protoc` serializes this request and then executes each configured protoc-plugin, sending the payload via `stdin`.

`protoc-gen-myplugin` starts up, receiving the request payload, which it unmarshals. There are two phases to a PG*-based protoc-plugin. First, PG* unmarshals the `CodeGeneratorRequest` received from `protoc`, and creates a fully connected abstract syntax tree (AST) of each file and all its contained entities. Any parameters specified for this plugin are also parsed for later consumption.

When this step is complete, PG* then executes any registered `Modules`, handing it the constructed AST. `Modules` can be written to generate artifacts (eg, files) or just performing some form of validation over the provided graph without any other side effects. `Modules` provide the great flexibility in terms of operating against the PBs.

Once all `Modules` are run, PG* writes any custom artifacts to the file system or serializes generator-specific ones into a `CodeGeneratorResponse` and sends the data to its `stdout`. `protoc` receives this payload, unmarshals it, and persists any requested files to disk after all its plugins have returned. This whole flow looks something like this:

```
foo.proto → protoc → CodeGeneratorRequest → protoc-gen-myplugin → CodeGeneratorResponse → protoc → foo.pb.go
```

The PG* library hides away nearly all of this complexity required to implement a protoc-plugin!

### Modules

PG* `Modules` are handed a complete AST for those files that are targeted for generation as well as all dependencies. A `Module` can then add files to the protoc `CodeGeneratorResponse` or write files directly to disk as `Artifacts`.

PG* provides a `ModuleBase` struct to simplify developing modules. Out of the box, it satisfies the interface for a `Module`, only requiring the creation of `Name` and `Execute` methods. `ModuleBase` is best used as an anonyomous embedded field of a wrapping `Module` implementation. A minimal module would look like the following:

```go
// ReportModule creates a report of all the target messages generated by the
// protoc run, writing the file into the /tmp directory.
type reportModule struct {
  *pgs.ModuleBase
}

// New configures the module with an instance of ModuleBase
func New() pgs.Module { return &reportModule{&pgs.ModuleBase{}} }

// Name is the identifier used to identify the module. This value is
// automatically attached to the BuildContext associated with the ModuleBase.
func (m *reportModule) Name() string { return "reporter" }

// Execute is passed the target files as well as its dependencies in the pkgs
// map. The implementation should return a slice of Artifacts that represent
// the files to be generated. In this case, "/tmp/report.txt" will be created
// outside of the normal protoc flow.
func (m *reportModule) Execute(targets map[string]pgs.File, pkgs map[string]Package) []pgs.Artifact {
  buf := &bytes.Buffer{}

  for _, f := range targets {
    m.Push(f.Name().String()).Debug("reporting")

    fmt.Fprintf(buf, "--- %v ---", f.Name())

    for i, msg := range f.AllMessages() {
      fmt.Fprintf(buf, "%03d. %v\n", i, msg.Name())
    }

    m.Pop()
  }

  m.OverwriteCustomFile(
    "/tmp/report.txt",
    buf.String(),
    0644,
  )

  return m.Artifacts()
}
```

`ModuleBase` exposes a PG* [`BuildContext`][context] instance, already prefixed with the module's name. Calling `Push` and `Pop` allows adding further information to error and debugging messages. Above, each file from the target package is pushed onto the context before logging the "reporting" debug message.

The base also provides helper methods for adding or overwriting both protoc-generated and custom files. The above execute method creates a custom file at `/tmp/report.txt` specifying that it should overwrite an existing file with that name. If it instead called `AddCustomFile` and the file existed, no file would have been generated (though a debug message would be logged out). Similar methods exist for adding generator files, appends, and injections. Likewise, methods such as `AddCustomTemplateFile` allows for `Templates` to be rendered instead.

After all modules have been executed, the returned `Artifacts` are either placed into the `CodeGenerationResponse` payload for protoc or written out to the file system. For testing purposes, the file system has been abstracted such that a custom one (such as an in-memory FS) can be provided to the PG* generator with the `FileSystem` `InitOption`.

#### Post Processing

`Artifacts` generated by `Modules` sometimes require some mutations prior to writing to disk or sending in the response to protoc. This could range from running `gofmt` against Go source or adding copyright headers to all generated source files. To simplify this task in PG*, a `PostProcessor` can be utilized. A minimal looking `PostProcessor` implementation might look like this:

```go
// New returns a PostProcessor that adds a copyright comment to the top
// of all generated files.
func New(owner string) pgs.PostProcessor { return copyrightPostProcessor{owner} }

type copyrightPostProcessor struct {
  owner string
}

// Match returns true only for Custom and Generated files (including templates).
func (cpp copyrightPostProcessor) Match(a pgs.Artifact) bool {
  switch a := a.(type) {
  case pgs.GeneratorFile, pgs.GeneratorTemplateFile,
    pgs.CustomFile, pgs.CustomTemplateFile:
      return true
  default:
      return false
  }
}

// Process attaches the copyright header to the top of the input bytes
func (cpp copyrightPostProcessor) Process(in []byte) (out []byte, err error) {
  cmt := fmt.Sprintf("// Copyright © %d %s. All rights reserved\n",
    time.Now().Year(),
    cpp.owner)

  return append([]byte(cmt), in...), nil
}
```

The `copyrightPostProcessor` struct satisfies the `PostProcessor` interface by implementing the `Match` and `Process` methods. After PG* recieves all `Artifacts`, each is handed in turn to each registered processor's `Match` method. In the above case, we return `true` if the file is a part of the targeted Artifact types. If `true` is returned, `Process` is immediately called with the rendered contents of the file. This method mutates the input, returning the modified value to out or an error if something goes wrong. Above, the notice is prepended to the input.

PostProcessors are registered with PG* similar to `Modules`:

```go
g := pgs.Init(pgs.IncludeGo())
g.RegisterModule(some.NewModule())
g.RegisterPostProcessor(copyright.New("PG* Authors"))
```

## Protocol Buffer AST

While `protoc` ensures that all the dependencies required to generate a proto file are loaded in as descriptors, it's up to the protoc-plugins to recognize the relationships between them. To get around this, PG* uses constructs an abstract syntax tree (AST) of all the `Entities` loaded into the plugin. This AST is provided to every `Module` to facilitate code generation.

### Hierarchy

The hierarchy generated by the PG* `gatherer` is fully linked, starting at a top-level `Package` down to each individual `Field` of a `Message`. The AST can be represented with the following digraph:

 <p align=center><img src="/testdata/ast/ast.png"></p>

A `Package` describes a set of `Files` loaded within the same namespace. As would be expected, a `File` represents a single proto file, which contains any number of `Message`, `Enum` or `Service` entities. An `Enum` describes an integer-based enumeration type, containing each individual `EnumValue`. A `Service` describes a set of RPC `Methods`, which in turn refer to their input and output `Messages`.

A `Message` can contain other nested `Messages` and `Enums` as well as each of its `Fields`. For non-scalar types, a `Field` may also reference its `Message` or `Enum` type. As a mechanism for achieving union types, a `Message` can also contain `OneOf` entities that refer to some of its `Fields`.

### Visitor Pattern

The structure of the AST can be fairly complex and unpredictable. Likewise, `Module's` are typically concerned with only a subset of the entities in the graph. To separate the `Module's` algorithm from understanding and traversing the structure of the AST, PG* implements the `Visitor` pattern to decouple the two. Implementing this interface is straightforward and can greatly simplify code generation.

Two base `Visitor` structs are provided by PG* to simplify developing implementations. First, the `NilVisitor` returns an instance that short-circuits execution for all Entity types. This is useful when certain branches of the AST are not interesting to code generation. For instance, if the `Module` is only concerned with `Services`, it can use a `NilVisitor` as an anonymous field and only implement the desired interface methods:

```go
// ServiceVisitor logs out each Method's name
type serviceVisitor struct {
  pgs.Visitor
  pgs.DebuggerCommon
}

func New(d pgs.DebuggerCommon) pgs.Visitor {
  return serviceVistor{
    Visitor:        pgs.NilVisitor(),
    DebuggerCommon: d,
  }
}

// Passthrough Packages, Files, and Services. All other methods can be
// ignored since Services can only live in Files and Files can only live in a
// Package.
func (v serviceVisitor) VisitPackage(pgs.Package) (pgs.Visitor, error) { return v, nil }
func (v serviceVisitor) VisitFile(pgs.File) (pgs.Visitor, error)       { return v, nil }
func (v serviceVisitor) VisitService(pgs.Service) (pgs.Visitor, error) { return v, nil }

// VisitMethod logs out ServiceName#MethodName for m.
func (v serviceVisitor) VisitMethod(m pgs.Method) (pgs.Vistitor, error) {
  v.Logf("%v#%v", m.Service().Name(), m.Name())
  return nil, nil
}
```

If access to deeply nested `Nodes` is desired, a `PassthroughVisitor` can be used instead. Unlike `NilVisitor` and as the name suggests, this implementation passes through all nodes instead of short-circuiting on the first unimplemented interface method. Setup of this type as an anonymous field is a bit more complex but avoids implementing each method of the interface explicitly:

```go
type fieldVisitor struct {
  pgs.Visitor
  pgs.DebuggerCommon
}

func New(d pgs.DebuggerCommon) pgs.Visitor {
  v := &fieldVisitor{DebuggerCommon: d}
  v.Visitor = pgs.PassThroughVisitor(v)
  return v
}

func (v *fieldVisitor) VisitField(f pgs.Field) (pgs.Visitor, error) {
  v.Logf("%v.%v", f.Message().Name(), f.Name())
  return nil, nil
}
```

Walking the AST with any `Visitor` is straightforward:

```go
v := visitor.New(d)
err := pgs.Walk(v, pkg)
```

All `Entity` types and `Package` can be passed into `Walk`, allowing for starting a `Visitor` lower than the top-level `Package` if desired.

## Build Context

`Modules` registered with the PG* `Generator` are initialized with an instance of `BuildContext` that encapsulates contextual paths, debugging, and parameter information.

### Output Paths

The `BuildContext's` `OutputPath` method returns the output directory that the PG* plugin is targeting. This path is also initially `.` but refers to the directory in which `protoc` is executed. This default behavior can be overridden by providing an `output_path` in the flag.

The `OutputPath` can be used to create file names for `Artifacts`, using `JoinPath(name ...string)` which is essentially an alias for `filepath.Join(ctx.OutputPath(), name...)`. Manually tracking directories relative to the `OutputPath` can be tedious, especially if the names are dynamic. Instead, a `BuildContext` can manage these, via `PushDir` and `PopDir`.

```go
ctx.OutputPath()                // foo
ctx.JoinPath("fizz", "buzz.go") // foo/fizz/buzz.go

ctx = ctx.PushDir("bar/baz")
ctx.OutputPath()                // foo/bar/baz
ctx.JoinPath("quux.go")         // foo/bar/baz/quux.go

ctx = ctx.PopDir()
ctx.OutputPath()                // foo
```

`ModuleBase` wraps these methods to mutate their underlying `BuildContexts`. Those methods should be used instead of the ones on the contained `BuildContext` directly.

### Debugging

The `BuildContext` exposes a `DebuggerCommon` interface which provides utilities for logging, error checking, and assertions. `Log` and the formatted `Logf` print messages to `os.Stderr`, typically prefixed with the `Module` name. `Debug` and `Debugf` behave the same, but only print if enabled via the `DebugMode` or `DebugEnv` `InitOptions`.

`Fail` and `Failf` immediately stops execution of the protoc-plugin and causes `protoc` to fail generation with the provided message. `CheckErr` and `Assert` also fail with the provided messages if an error is passed in or if an expression evaluates to false, respectively.

Additional contextual prefixes can be provided by calling `Push` and `Pop` on the `BuildContext`. This behavior is similar to `PushDir` and `PopDir` but only impacts log messages. `ModuleBase` wraps these methods to mutate their underlying `BuildContexts`. Those methods should be used instead of the ones on the contained `BuildContext` directly.

### Parameters

The `BuildContext` also provides access to the pre-processed `Parameters` from the specified protoc flag. The only PG*-specific key expected is "output_path", which is utilized by a module's `BuildContext` for its `OutputPath`.

PG* permits mutating the `Parameters` via the `MutateParams` `InitOption`. By passing in a `ParamMutator` function here, these KV pairs can be modified or verified prior to the PGG workflow begins.

## Language-Specific Subpackages

While implemented in Go, PG* seeks to be language agnostic in what it can do. Therefore, beyond the pre-generated base descriptor types, PG* has no dependencies on the protoc-gen-go (PGG) package. However, there are many nuances that each language's protoc-plugin introduce that can be generalized. For instance, PGG package naming, import paths, and output paths are a complex interaction of the proto package name, the `go_package` file option, and parameters passed to protoc. While PG*'s core API should not be overloaded with many language-specific methods, subpackages can be provided that can operate on `Parameters` and `Entities` to derive the appropriate results.

PG* currently implements the [pgsgo](https://godoc.org/github.com/lyft/protoc-gen-star/lang/go/) subpackage to provide these utilities to plugins targeting the Go language. Future subpackages are planned to support a variety of languages.

## PG* Development & Make Targets

PG* seeks to provide all the tools necessary to rapidly and ergonomically extend and build on top of the Protocol Buffer IDL. Whether the goal is to modify the official protoc-gen-go output or create entirely new files and packages, this library should offer a user-friendly wrapper around the complexities of the PB descriptors and the protoc-plugin workflow.

### Setup

For developing on PG*, you should install the package within the `GOPATH`. PG* uses [glide][glide] for dependency management.

```sh
go get -u github.com/lyft/protoc-gen-star
cd $GOPATH/src/github.com/lyft/protoc-gen-star
make vendor
```

To upgrade dependencies, please make the necessary modifications in `glide.yaml` and run `glide update`.

### Linting & Static Analysis

To avoid style nits and also to enforce some best practices for Go packages, PG* requires passing `golint`, `go vet`, and `go fmt -s` for all code changes.

```sh
make lint
```

### Testing

PG* strives to have near 100% code coverage by unit tests. Most unit tests are run in parallel to catch potential race conditions. There are three ways of running unit tests, each taking longer than the next but providing more insight into test coverage:

```sh
# run code generation for the data used by the tests
make testdata

# run unit tests without race detection or code coverage reporting
make quick

# run unit tests with race detection and code coverage
make tests

# run unit tests with race detection and generates a code coverage report, opening in a browser
make cover
```

#### protoc-gen-debug

PG* comes with a specialized protoc-plugin, `protoc-gen-debug`. This plugin captures the CodeGeneratorRequest from a protoc execution and saves the serialized PB to disk. These files can be used as inputs to prevent calling protoc from tests.

### Documentation

Go is a self-documenting language, and provides a built in utility to view locally: `godoc`. The following command starts a godoc server and opens a browser window to this package's documentation. If you see a 404 or unavailable page initially, just refresh.

```sh
make docs
```

### Demo

PG* comes with a "kitchen sink" example: [`protoc-gen-example`][pge]. This protoc plugin built on top of PG* prints out the target package's AST as a tree to stderr. This provides an end-to-end way of validating each of the nuanced types and nesting in PB descriptors:

```sh
# create the example PG*-based plugin
make bin/protoc-gen-example

# run protoc-gen-example against the demo protos
make testdata/generated
```

#### CI

PG* uses [TravisCI][travis] to validate all code changes. Please view the [configuration][travis.yml] for what tests are involved in the validation.

[glide]: http://glide.sh
[pgg]: https://github.com/golang/protobuf/tree/master/protoc-gen-go
[pge]: https://github.com/lyft/protoc-gen-star/tree/master/testdata/protoc-gen-example
[travis]: https://travis-ci.com/lyft/protoc-gen-star
[travis.yml]: https://github.com/lyft/protoc-gen-star/tree/master/.travis.yml
[module]: https://github.com/lyft/protoc-gen-star/blob/master/module.go
[pb]: https://developers.google.com/protocol-buffers/
[context]: https://github.com/lyft/protoc-gen-star/tree/master/build_context.go
[visitor]: https://github.com/lyft/protoc-gen-star/tree/master/node.go
[params]: https://github.com/lyft/protoc-gen-star/tree/master/parameters.go
[make]: https://github.com/lyft/protoc-gen-star/blob/master/Makefile
[single]: https://github.com/golang/protobuf/pull/40
