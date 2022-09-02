// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !privileged_tests

package hive_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"go.uber.org/fx"

	"github.com/cilium/cilium/pkg/hive"
)

type Config struct {
	Hello string
}

func (Config) Flags(flags *pflag.FlagSet) {
	flags.String("hello", "hello world", "sets the greeting")
}

func (Config) Validate() error {
	return nil
}

func TestHive(t *testing.T) {
	flags := pflag.NewFlagSet("", pflag.ContinueOnError)
	viper := viper.New()

	var cfg Config
	cell := hive.NewCellWithConfig(
		"test-cell",
		Config{},
		fx.Populate(&cfg),
	)

	hive := hive.New(viper, flags, cell)

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

// BadConfig has a field that matches no flags, and CellFlags
// declares a flag that matches no field.
type BadConfig struct {
	Bar string
}

func (BadConfig) Flags(flags *pflag.FlagSet) {
	flags.String("foo", "foobar", "foo")
}

func (BadConfig) Validate() error {
	return nil
}

func TestHiveBadConfig(t *testing.T) {
	flags := pflag.NewFlagSet("", pflag.ContinueOnError)
	viper := viper.New()

	var cfg BadConfig
	cell := hive.NewCellWithConfig(
		"test-cell",
		BadConfig{},
		fx.Populate(&cfg),
	)

	hive := hive.New(viper, flags, cell)
	_, err := hive.TestApp(t)
	if err == nil {
		t.Fatal("Expected TestApp() to fail")
	}

	if !strings.Contains(err.Error(), ": Bar") {
		t.Fatalf("Expected 'unused keys' error, got: %s", err)
	}
	if !strings.Contains(err.Error(), ": foo") {
		t.Fatalf("Expected 'unset fields' error, got: %s", err)
	}
}

type BadConfig2 struct {
	Foo string
}

func (BadConfig2) Flags(flags *pflag.FlagSet) {
	flags.String("foo", "foobar", "foo")
}

var validateErr = errors.New("fail")

func (BadConfig2) Validate() error {
	return validateErr
}

func TestHiveValidateConfig(t *testing.T) {
	flags := pflag.NewFlagSet("", pflag.ContinueOnError)
	viper := viper.New()

	var cfg BadConfig2
	cell := hive.NewCellWithConfig(
		"test-cell",
		BadConfig2{},
		fx.Populate(&cfg),
	)

	hive := hive.New(viper, flags, cell)
	_, err := hive.TestApp(t)
	if err == nil {
		t.Fatal("Expected TestApp() to fail")
	}

	if !errors.Is(err, validateErr) {
		t.Fatalf("Expected config validation error, got: %s", err)
	}
}

type MutConfig struct {
	Foo int

	derivedFoo int
}

func (m *MutConfig) GetDerived() int {
	return m.derivedFoo
}

func (*MutConfig) Flags(flags *pflag.FlagSet) {
	flags.Int("foo", 0, "foo")
}

func (m *MutConfig) Validate() error {
	m.Foo = 123
	m.derivedFoo = m.Foo * 2
	return nil
}

func TestHiveValidateMutates(t *testing.T) {
	flags := pflag.NewFlagSet("", pflag.ContinueOnError)
	viper := viper.New()

	var cfg MutConfig
	cell := hive.NewCellWithConfig(
		"test-cell",
		&MutConfig{},
		fx.Populate(&cfg),
	)

	hive := hive.New(viper, flags, cell)
	_, err := hive.TestApp(t)
	if err != nil {
		t.Fatalf("Expected TestApp() to succeed, got %s", err)
	}

	if cfg.Foo != 123 {
		t.Fatalf("expected Foo=123, got Foo=%d", cfg.Foo)
	}

	if cfg.GetDerived() != 246 {
		t.Fatalf("expected derivedFoo=246, got %d", cfg.GetDerived())
	}
}
