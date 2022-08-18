// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !privileged_tests

package hive

import (
	"testing"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"go.uber.org/fx"
)

type Config struct {
	Hello string
}

func (Config) CellFlags(flags *pflag.FlagSet) {
	flags.String("hello", "hello world", "sets the greeting")
}

func TestHive(t *testing.T) {
	flags := pflag.NewFlagSet("", pflag.ContinueOnError)
	viper := viper.New()

	var cfg Config
	cell := NewCellWithConfig[Config](
		"test-cell",
		fx.Populate(&cfg),
	)

	hive := New(viper, flags, cell)

	flags.Set("hello", "test")

	// Test with config coming from flags.
	app, err := hive.TestApp(t)
	if err != nil {
		t.Fatalf("TestApp(): %s", err)
	}
	app.RequireStart().RequireStop()
	if cfg.Hello != "test" {
		t.Fatalf("Config not set correctly, expected 'test', got %v", cfg)
	}

	// Test with config override
	app, err = hive.TestApp(t, Config{Hello: "override"})
	if err != nil {
		t.Fatalf("TestApp(): %s", err)
	}
	app.RequireStart().RequireStop()
	if cfg.Hello != "override" {
		t.Fatalf("Config not set correctly, expected 'override', got %v", cfg)
	}

}
