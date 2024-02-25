// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package hive_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
)

type Config struct {
	Foo string
	Bar int
}

func (Config) Flags(flags *pflag.FlagSet) {
	flags.String("foo", "hello world", "sets the greeting")
	flags.Int("bar", 123, "bar")
}

func TestHiveGoodConfig(t *testing.T) {
	var cfg Config
	testCell := cell.Module(
		"test",
		"Test Module",
		cell.Config(Config{}),
		cell.Invoke(func(c Config) {
			cfg = c
		}),
	)

	hive := hive.New(testCell)

	flags := pflag.NewFlagSet("", pflag.ContinueOnError)
	hive.RegisterFlags(flags)

	// Test the two ways of setting it
	flags.Set("foo", "test")
	hive.Viper().Set("bar", 13)

	err := hive.Start(context.TODO())
	assert.NoError(t, err, "expected Start to succeed")

	err = hive.Stop(context.TODO())
	assert.NoError(t, err, "expected Stop to succeed")

	assert.Equal(t, "test", cfg.Foo, "Config.Foo not set correctly")
	assert.Equal(t, 13, cfg.Bar, "Config.Bar not set correctly")
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
		"Test Module",
		cell.Config(BadConfig{}),
		cell.Invoke(func(c BadConfig) {}),
	)

	hive := hive.New(testCell)

	err := hive.Start(context.TODO())
	assert.ErrorContains(t, err, "has invalid keys: foo", "expected 'invalid keys' error")
	assert.ErrorContains(t, err, "has unset fields: Bar", "expected 'unset fields' error")
}

type MapConfig struct {
	Foo map[string]string
}

func (MapConfig) Flags(flags *pflag.FlagSet) {
	flags.StringToString("foo", nil, "foo")
}

func TestHiveStringMapConfig(t *testing.T) {
	runnable := func(setter func(t *testing.T, flags *pflag.FlagSet, vp *viper.Viper), expected map[string]string) func(t *testing.T) {
		return func(t *testing.T) {
			defer os.Unsetenv("CILIUM_FOO")

			var cfg MapConfig
			testCell := cell.Module(
				"test",
				"Test Module",
				cell.Config(MapConfig{}),
				cell.Invoke(func(c MapConfig) {
					cfg = c
				}),
			)

			hive := hive.New(testCell)

			flags := pflag.NewFlagSet("", pflag.ContinueOnError)
			hive.RegisterFlags(flags)

			setter(t, flags, hive.Viper())

			err := hive.Start(context.TODO())
			require.NoError(t, err, "expected Start to succeed")

			err = hive.Stop(context.TODO())
			require.NoError(t, err, "expected Stop to succeed")

			require.Equal(t, expected, cfg.Foo, "Config.Foo not set correctly")
		}
	}

	t.Run("unset", runnable(func(t *testing.T, flags *pflag.FlagSet, vp *viper.Viper) {
	}, map[string]string{}))

	t.Run("flag-kv", runnable(func(t *testing.T, flags *pflag.FlagSet, vp *viper.Viper) {
		require.NoError(t, flags.Set("foo", "foo=bar,baz=qux"))
		require.NoError(t, flags.Set("foo", "fred=thud"))
	}, map[string]string{"foo": "bar", "baz": "qux", "fred": "thud"}))

	t.Run("env-kv", runnable(func(t *testing.T, flags *pflag.FlagSet, vp *viper.Viper) {
		require.NoError(t, os.Setenv("CILIUM_FOO", "foo=bar,baz=qux"))
	}, map[string]string{"foo": "bar", "baz": "qux"}))

	t.Run("env-json", runnable(func(t *testing.T, flags *pflag.FlagSet, vp *viper.Viper) {
		require.NoError(t, os.Setenv("CILIUM_FOO", `{"foo":"bar","baz":"qux"}`))
	}, map[string]string{"foo": "bar", "baz": "qux"}))

	t.Run("config-yaml", runnable(func(t *testing.T, flags *pflag.FlagSet, vp *viper.Viper) {
		vp.SetConfigType("yaml")
		reader := strings.NewReader("foo:\n  foo: bar\n  baz: qux")
		require.NoError(t, vp.ReadConfig(reader), "Failed reading config file")
	}, map[string]string{"foo": "bar", "baz": "qux"}))

	t.Run("config-json", runnable(func(t *testing.T, flags *pflag.FlagSet, vp *viper.Viper) {
		vp.SetConfigType("json")
		reader := strings.NewReader(`{"foo": {"foo":"bar","baz":"qux"}}`)
		require.NoError(t, vp.ReadConfig(reader), "Failed reading config file")
	}, map[string]string{"foo": "bar", "baz": "qux"}))

	t.Run("cm-json", runnable(func(t *testing.T, flags *pflag.FlagSet, vp *viper.Viper) {
		require.NoError(t, vp.MergeConfigMap(map[string]interface{}{"foo": `{"foo":"bar","baz":"qux"}`}))
	}, map[string]string{"foo": "bar", "baz": "qux"}))

	t.Run("cm-kv", runnable(func(t *testing.T, flags *pflag.FlagSet, vp *viper.Viper) {
		require.NoError(t, vp.MergeConfigMap(map[string]interface{}{"foo": "foo=bar,baz=qux"}))
	}, map[string]string{"foo": "bar", "baz": "qux"}))

	t.Run("cm-json", runnable(func(t *testing.T, flags *pflag.FlagSet, vp *viper.Viper) {
		require.NoError(t, vp.MergeConfigMap(map[string]interface{}{"foo": `{"foo":"bar","baz":"qux"}`}))
	}, map[string]string{"foo": "bar", "baz": "qux"}))

	t.Run("cm-map", runnable(func(t *testing.T, flags *pflag.FlagSet, vp *viper.Viper) {
		require.NoError(t, vp.MergeConfigMap(map[string]interface{}{"foo": map[string]string{"foo": "bar", "baz": "qux"}}))
	}, map[string]string{"foo": "bar", "baz": "qux"}))
}

func TestHiveConfigOverride(t *testing.T) {
	var cfg Config
	h := hive.New(
		cell.Config(Config{}),
		cell.Invoke(func(c Config) {
			cfg = c
		}),
	)
	hive.AddConfigOverride(
		h,
		func(cfg *Config) {
			cfg.Foo = "override"
		})

	// Set "foo" flag via Viper. This should be ignored.
	h.Viper().Set("foo", "viper")

	err := h.Start(context.TODO())
	assert.NoError(t, err, "expected Start to succeed")

	err = h.Stop(context.TODO())
	assert.NoError(t, err, "expected Stop to succeed")

	assert.Equal(t, "override", cfg.Foo, "Config.Foo not set correctly")
}

type CIDRSliceConfig struct {
	Foo []*cidr.CIDR
}

func (CIDRSliceConfig) Flags(flags *pflag.FlagSet) {
	flags.StringSlice("foo", nil, "foo")
}

func TestHiveCIDRSlice(t *testing.T) {
	var cfg CIDRSliceConfig
	testCell := cell.Module(
		"test",
		"Test Module",
		cell.Config(CIDRSliceConfig{}),
		cell.Invoke(func(c CIDRSliceConfig) {
			cfg = c
		}),
	)
	hive := hive.New(testCell)

	flags := pflag.NewFlagSet("", pflag.ContinueOnError)
	hive.RegisterFlags(flags)
	flags.Set("foo", "1.2.3.4/24,2001:db8::/64")

	err := hive.Start(context.TODO())
	require.NoError(t, err, "expected Start to succeed")
	err = hive.Stop(context.TODO())
	require.NoError(t, err, "expected Stop to succeed")

	require.Len(t, cfg.Foo, 2)
	require.Equal(t, cidr.MustParseCIDR("1.2.3.4/24"), cfg.Foo[0], "Config.Foo not set correctly")
	require.Equal(t, cidr.MustParseCIDR("2001:db8::/64"), cfg.Foo[1], "Config.Foo not set correctly")
}

type StringSliceConfig struct {
	SpacesFlag, CommasFlag []string
	SpacesMap, CommasMap   []string
	Mixed                  []string
	StringFlag             string
}

func (StringSliceConfig) Flags(flags *pflag.FlagSet) {
	flags.StringSlice("spaces-flag", nil, "split by spaces via pflag")
	flags.StringSlice("commas-flag", nil, "split by commas via pflag")
	flags.StringSlice("spaces-map", nil, "split by spaces via configmap")
	flags.StringSlice("commas-map", nil, "split by commas via configmap")

	// One can also use just flags.String against a []string config field and
	// it will be parsed the same way as via configmap.
	flags.String("mixed", "", "mixed")

	flags.String("string-flag", "", "plain string untouched")
}

func TestHiveStringSlice(t *testing.T) {
	var cfg StringSliceConfig
	testCell := cell.Module(
		"test",
		"Test Module",
		cell.Config(StringSliceConfig{}),
		cell.Invoke(func(c StringSliceConfig) {
			cfg = c
		}),
	)
	hive := hive.New(testCell)

	flags := pflag.NewFlagSet("", pflag.ContinueOnError)
	hive.RegisterFlags(flags)

	spaces := "foo bar baz"
	commas := "foo,bar,baz"
	expected := []string{"foo", "bar", "baz"}

	// When the values are provided via the flags then the value given
	// to Viper is already a []string as parsed by pflag. This will be
	// processed by stringSliceToStringSliceHookFunc to re-split if needed.
	flags.Set("spaces-flag", spaces)
	flags.Set("commas-flag", commas)

	// Plain string flags are not split in any way.
	flags.Set("string-flag", "foo, bar, baz")

	// If spaces and commas are mixed then commas take precedence.
	flags.Set("mixed", "foo bar,baz")

	// When the values are provided via the configmap or environment they're
	// given to Viper as plain strings that will be processed by stringToSliceHookFunc.
	hive.Viper().MergeConfigMap(
		map[string]any{
			"spaces-map": spaces,
			"commas-map": commas,
		})

	err := hive.Start(context.TODO())
	require.NoError(t, err, "expected Start to succeed")
	err = hive.Stop(context.TODO())
	require.NoError(t, err, "expected Stop to succeed")

	assert.ElementsMatch(t, cfg.SpacesFlag, expected, "unexpected SpacesFlag")
	assert.ElementsMatch(t, cfg.SpacesMap, expected, "unexpected SpacesMap")
	assert.ElementsMatch(t, cfg.CommasFlag, expected, "unexpected CommasFlag")
	assert.ElementsMatch(t, cfg.CommasMap, expected, "unexpected CommasMap")
	assert.ElementsMatch(t, cfg.Mixed, []string{"foo bar", "baz"}, "unexpected Mixed")
	assert.Equal(t, cfg.StringFlag, "foo, bar, baz", "unexpected StringFlag")
}

type SomeObject struct {
	X int
}

type OtherObject struct {
	Y int
}

func TestProvideInvoke(t *testing.T) {
	invoked := false

	testCell := cell.Module(
		"test",
		"Test Module",
		cell.Provide(func() *SomeObject { return &SomeObject{10} }),
		cell.Invoke(func(*SomeObject) { invoked = true }),
	)

	err := hive.New(
		testCell,
		shutdownOnStartCell,
	).Run()
	assert.NoError(t, err, "expected Run to succeed")

	assert.True(t, invoked, "expected invoke to be called, but it was not")
}

func TestModuleID(t *testing.T) {
	invoked := false
	inner := cell.Module(
		"inner",
		"inner module",
		cell.Invoke(func(id cell.ModuleID, fid cell.FullModuleID) error {
			invoked = true
			if id != "inner" {
				return fmt.Errorf("inner id mismatch, expected 'inner', got %q", id)
			}
			if fid.String() != "outer.inner" {
				return fmt.Errorf("outer id mismatch, expected 'outer.inner', got %q", fid)
			}
			return nil
		}),
	)

	outer := cell.Module(
		"outer",
		"outer module",
		inner,
	)

	err := hive.New(
		outer,
		shutdownOnStartCell,
	).Run()
	assert.NoError(t, err, "expected Run to succeed")

	assert.True(t, invoked, "expected invoke to be called, but it was not")

}

func TestProvideHealthReporter(t *testing.T) {
	// Module provided health reporter should be injected and be scoped to the
	// module ID.
	// As well, should contain state about last update and whether modules where
	// stopped.
	testCell := cell.Module(
		"test",
		"Test Module",
		cell.Invoke(func(s cell.Scope) {
			hr := cell.GetHealthReporter(s, "test")
			hr.OK("all good")
			hr.Stopped("stopped")
		}),
	)
	testCell2 := cell.Module(
		"test2",
		"Test Module 2",
		cell.Invoke(func(s cell.Scope) {
			hr := cell.GetHealthReporter(s, "test")
			hr.Degraded("degraded", nil)
		}),
	)
	unknown := cell.Module(
		"unknown",
		"Reports no status",
		cell.Invoke(func(s cell.Scope) {}),
	)

	var chp cell.Health
	h := hive.New(
		testCell,
		testCell2,
		unknown,
		cell.Invoke(func(lc cell.Lifecycle, _ hive.Shutdowner, hp cell.Health) {
			lc.Append(cell.Hook{
				OnStop: func(cell.HookContext) error {
					chp = hp
					return nil
				}})
		}),
		shutdownOnStartCell,
	)

	assert.NoError(t, h.Run(), "expected Run to succeed")
	s1, err := chp.Get(cell.FullModuleID{"test"})
	assert.NoError(t, err)
	s2, err := chp.Get(cell.FullModuleID{"test2"})
	assert.NoError(t, err)
	s3, err := chp.Get(cell.FullModuleID{"unknown"})
	assert.NoError(t, err)
	assert.Len(t, chp.All(), 3, "expected two health reports")
	assert.Equal(t, cell.StatusOK, s1.Level())

	//assert.Equal(t, s1.FullModuleID, cell.FullModuleID{"test"})
	assert.Equal(t, cell.StatusDegraded, s2.Level())
	//assert.Equal(t, s2.FullModuleID, cell.FullModuleID{"test2"})
	assert.Equal(t, cell.StatusUnknown, s3.Level())
}

func TestGroup(t *testing.T) {
	sum := 0

	testCell := cell.Group(
		cell.Provide(func() *SomeObject { return &SomeObject{10} }),
		cell.Provide(func() *OtherObject { return &OtherObject{5} }),
	)
	err := hive.New(
		testCell,
		cell.Invoke(func(a *SomeObject, b *OtherObject) { sum = a.X + b.Y }),
		shutdownOnStartCell,
	).Run()
	assert.NoError(t, err, "expected Run to succeed")
	assert.Equal(t, 15, sum)
}

func TestProvidePrivate(t *testing.T) {
	invoked := false

	testCell := cell.Module(
		"test",
		"Test Module",
		cell.ProvidePrivate(func() *SomeObject { return &SomeObject{10} }),
		cell.Invoke(func(*SomeObject) { invoked = true }),
	)

	// Test happy path.
	err := hive.New(
		testCell,
		shutdownOnStartCell,
	).Run()
	assert.NoError(t, err, "expected Start to succeed")

	if !invoked {
		t.Fatal("expected invoke to be called, but it was not")
	}

	// Now test that we can't access it from root scope.
	h := hive.New(
		testCell,
		cell.Invoke(func(*SomeObject) {}),
		shutdownOnStartCell,
	)
	err = h.Start(context.TODO())
	assert.ErrorContains(t, err, "missing type: *hive_test.SomeObject", "expected Start to fail to find *SomeObject")
}

func TestDecorate(t *testing.T) {
	invoked := false

	testCell := cell.Decorate(
		func(o *SomeObject) *SomeObject {
			return &SomeObject{X: o.X + 1}
		},
		cell.Invoke(
			func(o *SomeObject) error {
				if o.X != 2 {
					return errors.New("X != 2")
				}
				invoked = true
				return nil
			}),
	)

	hive := hive.New(
		cell.Provide(func() *SomeObject { return &SomeObject{1} }),

		// Here *SomeObject is not decorated.
		cell.Invoke(func(o *SomeObject) error {
			if o.X != 1 {
				return errors.New("X != 1")
			}
			return nil
		}),

		testCell,

		shutdownOnStartCell,
	)

	assert.NoError(t, hive.Run(), "expected Run() to succeed")
	assert.True(t, invoked, "expected decorated invoke function to be called")
}

func TestShutdown(t *testing.T) {
	//
	// Happy paths without a shutdown error:
	//

	// Test from a start hook
	h := hive.New(
		cell.Invoke(func(lc cell.Lifecycle, shutdowner hive.Shutdowner) {
			lc.Append(cell.Hook{
				OnStart: func(cell.HookContext) error {
					shutdowner.Shutdown()
					return nil
				}})
		}),
	)
	assert.NoError(t, h.Run(), "expected Run() to succeed")

	// Test from a goroutine forked from start hook
	h = hive.New(
		cell.Invoke(func(lc cell.Lifecycle, shutdowner hive.Shutdowner) {
			lc.Append(cell.Hook{
				OnStart: func(cell.HookContext) error {
					go shutdowner.Shutdown()
					return nil
				}})
		}),
	)
	assert.NoError(t, h.Run(), "expected Run() to succeed")

	// Test from an invoke. Shouldn't really be used, but should still work.
	h = hive.New(
		cell.Invoke(func(lc cell.Lifecycle, shutdowner hive.Shutdowner) {
			shutdowner.Shutdown()
		}),
	)
	assert.NoError(t, h.Run(), "expected Run() to succeed")

	//
	// Unhappy paths that fatal with an error:
	//

	shutdownErr := errors.New("shutdown error")

	// Test from a start hook
	h = hive.New(
		cell.Invoke(func(lc cell.Lifecycle, shutdowner hive.Shutdowner) {
			lc.Append(cell.Hook{
				OnStart: func(cell.HookContext) error {
					shutdowner.Shutdown(hive.ShutdownWithError(shutdownErr))
					return nil
				}})
		}),
	)
	assert.ErrorIs(t, h.Run(), shutdownErr, "expected Run() to fail with shutdownErr")
}

func TestRunRollback(t *testing.T) {
	var started, stopped int
	h := hive.New(
		cell.Invoke(func(lc cell.Lifecycle, shutdowner hive.Shutdowner) {
			lc.Append(cell.Hook{
				OnStart: func(ctx cell.HookContext) error {
					started++
					return nil
				},
				OnStop: func(ctx cell.HookContext) error {
					stopped++
					return nil
				},
			})
			lc.Append(cell.Hook{
				OnStart: func(ctx cell.HookContext) error {
					started++
					<-ctx.Done()
					return ctx.Err()
				},
				OnStop: func(cell.HookContext) error {
					// Should not be called.
					t.Fatal("unexpected call to second OnStop")
					return nil
				},
			})
		}),
	)
	h.SetTimeouts(time.Millisecond, time.Minute)

	err := h.Run()
	assert.ErrorIs(t, err, context.DeadlineExceeded, "expected Run() to fail with timeout")

	// We should see 2 start hooks invoked, and then 1 stop hook as first
	// one is rolled back.
	assert.Equal(t, 2, started)
	assert.Equal(t, 1, stopped)
}

var shutdownOnStartCell = cell.Invoke(func(lc cell.Lifecycle, shutdowner hive.Shutdowner) {
	lc.Append(cell.Hook{
		OnStart: func(cell.HookContext) error {
			shutdowner.Shutdown()
			return nil
		}})
})

// Assert that we can reuse the same cell as part of multiple hives
func TestSameCellMultipleHives(t *testing.T) {
	var (
		got1 string
		got2 int
	)

	common := cell.Group(
		cell.Config(Config{}),
		cell.Provide(func() int { return 10 }),
		cell.Invoke(func(_ Config, in1 string, in2 int) { got1, got2 = in1, in2 }),
	)

	h1 := hive.New(common, cell.Provide(func() string { return "foo" }))
	h2 := hive.New(common, cell.Provide(func() string { return "bar" }))

	require.NoError(t, h1.Start(context.TODO()))
	require.Equal(t, "foo", got1)
	require.Equal(t, 10, got2)
	require.NoError(t, h2.Start(context.TODO()))
	require.Equal(t, "bar", got1)
	require.Equal(t, 10, got2)

	require.NoError(t, h1.Stop(context.TODO()))
	require.NoError(t, h1.Stop(context.TODO()))
}
