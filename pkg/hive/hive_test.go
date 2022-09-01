// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !privileged_tests

package hive

import (
	"strings"
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
	var receivedConfig bool

	hive := New(viper, flags,
		cell,
		OnStart(func(c Config) error {
			receivedConfig = true
			return nil
		}))

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

	if !receivedConfig {
		t.Fatal("OnStart hook not called")
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

// BadConfig has a field that matches no flags, and CellFlags
// declares a flag that matches no field.
type BadConfig struct {
	Bar string
}

func (BadConfig) CellFlags(flags *pflag.FlagSet) {
	flags.String("foo", "foobar", "foo")
}

func TestHiveBadConfig(t *testing.T) {
	flags := pflag.NewFlagSet("", pflag.ContinueOnError)
	viper := viper.New()

	var cfg BadConfig
	cell := NewCellWithConfig[BadConfig](
		"test-cell",
		fx.Populate(&cfg),
	)

	hive := New(viper, flags, cell)
	_, err := hive.TestApp(t)
	if err == nil {
		t.Fatal("Expected TestApp() to fail")
	}

	if !strings.Contains(err.Error(), "has invalid keys: foo") {
		t.Fatalf("Expected 'invalid keys' error, got: %s", err)
	}
	if !strings.Contains(err.Error(), "has unset fields: Bar") {
		t.Fatalf("Expected 'unset fields' error, got: %s", err)
	}
}
