// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !privileged_tests

package option

import (
	"os"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"go.uber.org/fx"
	"go.uber.org/fx/fxtest"
	"gopkg.in/check.v1"

	"github.com/cilium/cilium/pkg/checker"
	"github.com/cilium/cilium/pkg/cidr"
)

type TestConfig struct {
	TString               Opt[string]
	TStringDefault        Opt[string]
	TStringSlice          Opt[[]string]
	TStringSliceConfigDir Opt[[]string]
	TInt                  Opt[int]
	TBool                 Opt[bool]
	TFloat64              Opt[float64]
	TCIDR                 Opt[*cidr.CIDR]
	TCIDRDefault          Opt[*cidr.CIDR]
	TCIDREnv              Opt[*cidr.CIDR]
	TCIDRsConfig          Opt[[]*cidr.CIDR]
}

var testConfig = TestConfig{
	TString:               String("test-string", "", "string option"),
	TStringDefault:        String("test-string-with-default", "hello", "string with a default"),
	TStringSlice:          StringSlice("test-string-slice", nil, "string slice"),
	TStringSliceConfigDir: StringSlice("test-string-slice-dir", nil, "string slices from config dir"),
	TInt:                  Int("test-int", 0, "int option"),
	TBool:                 Bool("test-bool", false, "bool option"),
	TFloat64:              Float64("test-float64", 123.123, "float option"),
	TCIDR:                 CIDR("test-cidr", nil, "cidr option"),
	TCIDRDefault:          CIDR("test-cidr-default", cidr.MustParseCIDR("10.0.0.0/8"), "cidr option"),
	TCIDREnv:              CIDR("test-cidr-env", nil, "cidr option via environment variable"),
	TCIDRsConfig:          CIDRs("test-cidrs", nil, "cidrs via config file"),
}

func (s *OptionSuite) TestOptionModule(c *check.C) {
	defer viper.Reset()

	args := []string{
		"test",
		"--test-string=test",
		"--test-string-slice=foo,bar,baz",
		"--test-int", "10",
		"--test-bool=true",
		"--test-float64=10.1",
		"--test-cidr=172.16.0.0/24",
	}

	// Try setting an option through an environment variable
	os.Setenv("CILIUM_TEST_CIDR_ENV", "1.2.3.0/24")

	// And also via configuration file and directory
	viper.Set(ConfigFile, "testdata/test.yaml")
	viper.Set(ConfigDir, "testdata/configdir")

	var cfg TestConfig
	app := fxtest.New(c,
		fx.Supply(CommandLineArguments(args), pflag.NewFlagSet("test", pflag.ContinueOnError)),
		Module(),

		// Register the config options and pull the parsed config.
		fx.Provide(
			Register(testConfig),
			GetConfig[TestConfig],
		),

		fx.Populate(&cfg),
	)

	app.RequireStart()
	app.RequireStop()

	c.Assert(cfg.TString.Get(), checker.Equals, "test")
	c.Assert(cfg.TStringDefault.Get(), checker.Equals, "hello")
	c.Assert(cfg.TStringSlice.Get(), checker.DeepEquals, []string{"foo", "bar", "baz"})
	c.Assert(cfg.TStringSliceConfigDir.Get(), checker.DeepEquals, []string{"foo", "bar", "baz", "quux"})
	c.Assert(cfg.TInt.Get(), checker.Equals, 10)
	c.Assert(cfg.TBool.Get(), checker.Equals, true)
	c.Assert(cfg.TFloat64.Get(), checker.Equals, 10.1)
	c.Assert(cfg.TCIDR.Get().String(), checker.Equals, "172.16.0.0/24")
	c.Assert(cfg.TCIDRDefault.Get().String(), checker.Equals, "10.0.0.0/8")
	c.Assert(cfg.TCIDREnv.Get().String(), checker.Equals, "1.2.3.0/24")
}
