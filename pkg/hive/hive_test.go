// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package hive

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/cilium/cilium/pkg/hive/cell"
)

type Config struct {
	Hello string
}

func (Config) Flags(flags *pflag.FlagSet) {
	flags.String("hello", "hello world", "sets the greeting")
}

func TestHive(t *testing.T) {
	flags := pflag.NewFlagSet("", pflag.ContinueOnError)
	viper := viper.New()

	var cfg Config
	testCell := cell.Module(
		"test",
		cell.Config(Config{}),
		cell.Invoke(func(c Config) {
			cfg = c
		}),
	)

	hive := New(viper, flags, testCell)

	flags.Set("hello", "test")

	err := hive.Start(context.TODO())
	if err != nil {
		t.Fatal(err)
	}

	err = hive.Stop(context.TODO())
	if err != nil {
		t.Fatal(err)
	}

	if cfg.Hello != "test" {
		t.Fatalf("Config not set correctly, expected 'test', got %v", cfg)
	}
}

// BadConfig has a field that matches no flags, and Flags
// declares a flag that matches no field.
type BadConfig struct {
	Bar string
}

func (BadConfig) Flags(flags *pflag.FlagSet) {
	flags.String("foo", "foobar", "foo")
}

func TestHiveBadConfig(t *testing.T) {
	testCell := cell.Module(
		"test",
		cell.Config(BadConfig{}),
		cell.Invoke(func(c BadConfig) {}),
	)

	hive := NewForTests(testCell)

	err := hive.Start(context.TODO())

	if !strings.Contains(err.Error(), "has invalid keys: foo") {
		t.Fatalf("Expected 'invalid keys' error, got: %s", err)
	}
	if !strings.Contains(err.Error(), "has unset fields: Bar") {
		t.Fatalf("Expected 'unset fields' error, got: %s", err)
	}
}

type SomeObject struct {
	X int
}

func TestProvideInvoke(t *testing.T) {
	invoked := false

	checkObject := func(o *SomeObject) error {
		if o.X != 10 {
			return errors.New("Not 10")
		}
		invoked = true
		return nil
	}

	testCell := cell.Module(
		"test",
		cell.Provide(func() *SomeObject { return &SomeObject{10} }),
		cell.Invoke(checkObject),
	)

	NewForTests(testCell).TestRun(t, time.Minute)

	if !invoked {
		t.Fatal("expected invoke to be called, but it was not")
	}
}

func TestDecorator(t *testing.T) {
	invoked := false

	checkObject := func(o *SomeObject) error {
		if o.X != 42 {
			return errors.New("Not 42 inside decorated cell")
		}
		invoked = true
		return nil
	}

	testCell := cell.Decorate(
		func(*SomeObject) *SomeObject {
			return &SomeObject{X: 42}
		},
		cell.Invoke(checkObject),
	)

	hive := NewForTests(
		cell.Provide(func() *SomeObject { return &SomeObject{10} }),

		// Here *SomeObject is not decorated.
		cell.Invoke(func(o *SomeObject) error {
			if o.X != 10 {
				return errors.New("Not 10")
			}
			return nil
		}),
		testCell,
	)

	hive.TestRun(t, time.Minute)

	if !invoked {
		t.Fatal("expected checkObject to be called, but it was not")
	}
}
