# :bee: Hive [![GoDoc](https://pkg.go.dev/badge/github.com/cilium/hive)](https://pkg.go.dev/github.com/cilium/hive) 

Hive is a dependency injection framework for Go. To build an application
in Hive you tell it your object constructors and then ask it to invoke
functions that make use of those constructors. Hive figures out what constructors
to call and in what order.

Hive is built on top of `uber/dig` and is similar to `uber/fx`.
The main difference to `uber/fx` is opinionated way to provide configuration
and command-line inspection tooling (`go run ./example hive`). Hive was built
for the needs of the Cilium project to improve modularity of the Cilium codebase.

To get started, see the [documentation](https://pkg.go.dev/github.com/cilium/hive)
and explore the [example](example).
