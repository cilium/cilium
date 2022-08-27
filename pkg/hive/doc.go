// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

/*
Package hive provides the infrastructure for building Cilium applications from modular components (cells).

Hive is implemented as a wrapper around the uber/fx library, which provides the dependency injection for
objects in the hive. Hive adds to uber/fx the ability to associate configuration with command-line flags
with a module.

The configuration for cells is extracted from Viper. By default the field names are assumed to correspond
to flag names, e.g. field 'MyOption' corresponds to '--my-option' flag.

The hive constructor, New(), takes the viper instance and the pflag FlagSet as parameters and registers
the flags from all cells and binds them to viper variables. Once the FlagSet and viper configuration has been
parsed one can call Populate() to pull the values from viper and construct the application. The hive can
then be Run().

For details related to uber/fx refer to https://pkg.go.dev/go.uber.org/fx.

# Cells

Cells are what make up the hive. They're a thin wrapper around fx.Module that include an optional
configuration structure that knows how to register its associated command-line flags.

# Example program

	type Config struct {
		Hello string
	}

	func (Config) CellFlags(flags *pflag.FlagSet) {
		flags.String("hello", "hello world", "sets the greeting")
	}

	func hello(cfg Config) {
		fmt.Println(cfg.Hello)
	}

	var helloCell = hive.NewCellWithConfig[Config](
		"hello",
		fx.Invoke(hello),
	)

	func main() {
		hive := hive.New(
			viper.GetViper(), pflag.CommandLine,

			helloCell,
		)

		pflag.Parse()

		if err := hive.Populate(); err != nil {
			log.Fatal(err)
		}

		hive.Run()
	}
*/
package hive
