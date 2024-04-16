// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

/*
Package hive provides the infrastructure for building Cilium applications from modular components (cells).

Hive is implemented using the uber/dig library, which provides the dependency injection for
objects in the hive. It is similar to uber/fx, but adds an opinionated approach to configuration.

The configuration for cells is extracted from Viper. By default the field names are assumed to correspond
to flag names, e.g. field 'MyOption' corresponds to '--my-option' flag.

The hive constructor, New(), takes the viper instance and the pflag FlagSet as parameters and registers
the flags from all cells and binds them to viper variables. Once the FlagSet and viper configuration has been
parsed one can call Populate() to pull the values from viper and construct the application. The hive can
then be Run().

# Example

For a runnable example see pkg/hive/example.

Try running:

	example$ go run .
	(ctrl-c stops)

	example$ go run . --dot-graph | dot -Tx11

Try also commenting out cell.Provide lines and seeing what the dependency errors look like.
*/
package hive
