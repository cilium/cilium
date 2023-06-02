// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package option

import (
	"fmt"
	"testing"

	. "github.com/cilium/checkmate"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/checker"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	TestingT(t)
}

type OptionSuite struct{}

var _ = Suite(&OptionSuite{})

func (s *OptionSuite) TestGetValue(c *C) {
	k1, k2 := "foo", "bar"
	v1 := OptionSetting(7)

	o := IntOptions{
		Opts: OptionMap{
			k1: v1,
			k2: OptionEnabled,
		},
	}

	c.Assert(o.GetValue(k1), Equals, v1)
	c.Assert(o.GetValue(k2), Equals, OptionEnabled)
	c.Assert(o.GetValue("unknown"), Equals, OptionDisabled)
}

func (s *OptionSuite) TestIsEnabled(c *C) {
	k1, k2 := "foo", "bar"

	o := IntOptions{
		Opts: OptionMap{
			k1: OptionEnabled,
			k2: OptionDisabled,
		},
	}

	c.Assert(o.IsEnabled(k1), Equals, true)
	c.Assert(o.IsEnabled(k2), Equals, false)
	c.Assert(o.IsEnabled("unknown"), Equals, false)
}

func (s *OptionSuite) TestSetValidated(c *C) {
	k1, k2 := "foo", "bar"

	o := IntOptions{
		Opts: OptionMap{
			k1: OptionEnabled,
		},
	}

	c.Assert(o.IsEnabled(k1), Equals, true)
	c.Assert(o.IsEnabled(k2), Equals, false)

	o.SetValidated(k1, OptionDisabled)
	o.SetValidated(k2, OptionEnabled)
	c.Assert(o.IsEnabled(k1), Equals, false)
	c.Assert(o.IsEnabled(k2), Equals, true)
}

func (s *OptionSuite) TestSetBool(c *C) {
	k1, k2, k3 := "foo", "bar", "baz"

	o := IntOptions{
		Opts: OptionMap{
			k1: OptionEnabled,
			k2: OptionDisabled,
		},
	}

	o.SetBool(k1, false)
	o.SetBool(k2, true)
	o.SetBool(k3, true)
	c.Assert(o.GetValue(k1), Equals, OptionDisabled)
	c.Assert(o.GetValue(k2), Equals, OptionEnabled)
	c.Assert(o.GetValue(k3), Equals, OptionEnabled)
}

func (s *OptionSuite) TestDelete(c *C) {
	k1, k2 := "foo", "bar"

	o := IntOptions{
		Opts: OptionMap{
			k1: OptionEnabled,
			k2: OptionEnabled,
		},
	}

	o.Delete(k1)
	c.Assert(o.GetValue(k1), Equals, OptionDisabled)
	c.Assert(o.GetValue(k2), Equals, OptionEnabled)
}

func (s *OptionSuite) TestSetIfUnset(c *C) {
	k1, k2 := "foo", "bar"

	o := IntOptions{
		Opts: OptionMap{
			k1: OptionDisabled,
		},
	}

	o.SetIfUnset(k1, OptionEnabled)
	o.SetIfUnset(k2, OptionEnabled)
	c.Assert(o.GetValue(k1), Equals, OptionDisabled)
	c.Assert(o.GetValue(k2), Equals, OptionEnabled)
}

func (s *OptionSuite) TestInheritDefault(c *C) {
	k := "foo"

	o := IntOptions{
		Opts: OptionMap{},
	}
	parent := IntOptions{
		Opts: OptionMap{
			k: OptionEnabled,
		},
	}

	c.Assert(o.GetValue(k), Equals, OptionDisabled)
	o.InheritDefault(&parent, k)
	c.Assert(o.GetValue(k), Equals, OptionEnabled)
}

func (s *OptionSuite) TestParseKeyValueWithDefaultParseFunc(c *C) {
	k := "foo"

	l := OptionLibrary{
		k: &Option{
			Define:      "TEST_DEFINE",
			Description: "This is a test",
		},
	}

	_, res, err := ParseKeyValue(&l, k, "on")
	c.Assert(err, IsNil)
	c.Assert(res, Equals, OptionEnabled)
}

func (s *OptionSuite) TestParseKeyValue(c *C) {
	k := "foo"

	l := OptionLibrary{
		k: &Option{
			Define:      "TEST_DEFINE",
			Description: "This is a test",
			Parse: func(value string) (OptionSetting, error) {
				if value == "yes" {
					return OptionEnabled, nil
				}
				return OptionDisabled, fmt.Errorf("invalid option value %s", value)
			},
		},
	}

	_, _, err := ParseKeyValue(&l, k, "true")
	c.Assert(err, NotNil)

	_, res, err := ParseKeyValue(&l, k, "yes")
	c.Assert(err, IsNil)
	c.Assert(res, Equals, OptionEnabled)

	_, _, err = ParseKeyValue(&l, "unknown", "yes")
	c.Assert(err, NotNil)
}

func (s *OptionSuite) TestParseOption(c *C) {
	k := "foo"
	arg := k + "=enabled"

	OptionTest := Option{
		Define:      "TEST_DEFINE",
		Description: "This is a test",
	}

	l := OptionLibrary{
		k: &OptionTest,
	}

	_, _, err := ParseOption(k+":enabled", &l)
	c.Assert(err, NotNil)

	_, res, err := ParseOption(arg, &l)
	c.Assert(err, IsNil)
	c.Assert(res, Equals, OptionEnabled)

	_, _, err = ParseOption("!"+arg, &l)
	c.Assert(err, NotNil)

	OptionTest.Immutable = true
	_, _, err = ParseOption(arg, &l)
	c.Assert(err, NotNil)
	OptionTest.Immutable = false
}

func (s *OptionSuite) TestGetFmtOpts(c *C) {
	OptionTest := Option{
		Define:      "TEST_DEFINE",
		Description: "This is a test",
	}

	o := IntOptions{
		Opts: OptionMap{
			"test": OptionEnabled,
			"BAR":  OptionDisabled,
			"foo":  OptionEnabled,
			"bar":  OptionDisabled,
		},
		Library: &OptionLibrary{
			"test": &OptionTest,
		},
	}

	fmtList := o.GetFmtList()
	fmtList2 := o.GetFmtList()

	// Both strings should be equal because the formatted options should be sorted.
	c.Assert(fmtList, Equals, fmtList2)

	o2 := IntOptions{
		Opts: OptionMap{
			"foo":  OptionEnabled,
			"BAR":  OptionDisabled,
			"bar":  OptionDisabled,
			"test": OptionEnabled,
		},
		Library: &OptionLibrary{
			"test": &OptionTest,
		},
	}

	fmtListO := o.GetFmtList()
	fmtListO2 := o2.GetFmtList()

	// Both strings should be equal because the formatted options should be sorted.
	c.Assert(fmtListO, Equals, fmtListO2)
}

func (s *OptionSuite) TestGetFmtOpt(c *C) {
	OptionTest := Option{
		Define:      "TEST_DEFINE",
		Description: "This is a test",
	}

	o := IntOptions{
		Opts: OptionMap{
			"test":  OptionEnabled,
			"BAR":   OptionDisabled,
			"alice": 2,
		},
		Library: &OptionLibrary{
			"test":  &OptionTest,
			"alice": &OptionTest,
		},
	}
	o.optsMU.Lock()
	c.Assert(o.getFmtOpt("test"), Equals, "#define TEST_DEFINE 1")
	c.Assert(o.getFmtOpt("BAR"), Equals, "#undef BAR")
	c.Assert(o.getFmtOpt("BAZ"), Equals, "#undef BAZ")
	c.Assert(o.getFmtOpt("alice"), Equals, "#define TEST_DEFINE 2")
	o.optsMU.Unlock()
}

func (s *OptionSuite) TestGetImmutableModel(c *C) {
	k := "foo"

	OptionTest := Option{
		Define:      "TEST_DEFINE",
		Description: "This is a test",
	}

	o := IntOptions{
		Opts: OptionMap{
			k: OptionEnabled,
		},
		Library: &OptionLibrary{
			k: &OptionTest,
		},
	}

	cfg := o.GetImmutableModel()
	c.Assert(cfg, NotNil)
	c.Assert(cfg, checker.DeepEquals, &models.ConfigurationMap{})
}

func (s *OptionSuite) TestGetMutableModel(c *C) {
	k1, k2, k3 := "foo", "bar", "baz"

	OptionDefaultFormat := Option{
		Define:      "TEST_DEFINE",
		Description: "This is a test",
	}
	OptionCustomFormat := Option{
		Define:      "TEST_DEFINE",
		Description: "This is a test",
		Format: func(value OptionSetting) string {
			return "ok"
		},
	}

	o := IntOptions{
		Opts: OptionMap{
			k1: OptionEnabled,
			k2: OptionDisabled,
			k3: OptionEnabled,
		},
		Library: &OptionLibrary{
			k1: &OptionDefaultFormat,
			k2: &OptionDefaultFormat,
			k3: &OptionCustomFormat,
		},
	}

	cfg := o.GetMutableModel()
	c.Assert(cfg, NotNil)
	c.Assert(cfg, checker.DeepEquals, &models.ConfigurationMap{
		k1: "Enabled",
		k2: "Disabled",
		k3: "ok",
	})

	o2 := IntOptions{}
	cfg2 := o2.GetMutableModel()
	c.Assert(cfg2, NotNil)
	c.Assert(cfg2, checker.DeepEquals, &models.ConfigurationMap{})
}

func (s *OptionSuite) TestValidate(c *C) {
	k1, k2, k3, k4 := "foo", "bar", "baz", "qux"

	OptionTest := Option{
		Define:      "TEST_DEFINE",
		Description: "This is a test",
	}
	OptionCustomVerify := Option{
		Define:      "TEST_DEFINE",
		Description: "This is a test",
		Verify: func(key string, value string) error {
			return fmt.Errorf("invalid key value %s %s", key, value)

		},
	}
	OptionImmutable := Option{
		Define:      "TEST_DEFINE",
		Description: "This is a test",
		Immutable:   true,
	}

	o := IntOptions{
		Opts: OptionMap{
			k1: OptionEnabled,
			k2: OptionEnabled,
			k3: OptionDisabled,
			k4: OptionEnabled,
		},
		Library: &OptionLibrary{
			k1: &OptionTest,
			k2: &OptionCustomVerify,
			k3: &OptionCustomVerify,
			k4: &OptionImmutable,
		},
	}

	c.Assert(o.Validate(models.ConfigurationMap{k1: "on"}), IsNil)
	c.Assert(o.Validate(models.ConfigurationMap{"unknown": "on"}), NotNil)
	c.Assert(o.Validate(models.ConfigurationMap{k4: "on"}), NotNil)
	c.Assert(o.Validate(models.ConfigurationMap{k1: "on", k2: "on"}), IsNil)
	c.Assert(o.Validate(models.ConfigurationMap{k1: "on", k3: "on"}), NotNil)
}

func (s *OptionSuite) TestApplyValidated(c *C) {
	k1, k2, k3, k4, k5, k6 := "foo", "bar", "baz", "qux", "quux", "corge"

	OptionDefault := Option{
		Define:      "TEST_DEFINE",
		Description: "This is a test",
	}
	Option2 := Option{
		Define:      "TEST_DEFINE",
		Description: "This is a test",
		Requires:    []string{k1},
	}
	Option3 := Option{
		Define:      "TEST_DEFINE",
		Description: "This is a test",
		Requires:    []string{k4},
	}

	o := IntOptions{
		Opts: OptionMap{
			k1: OptionEnabled,
			k2: OptionEnabled,
			k3: OptionDisabled,
			k4: OptionDisabled,
			k5: OptionDisabled,
		},
		Library: &OptionLibrary{
			k1: &OptionDefault,
			k2: &Option2,
			k3: &Option3,
			k4: &OptionDefault,
			k5: &OptionDefault,
			k6: &OptionDefault,
		},
	}

	cfg := models.ConfigurationMap{
		k1: "off",
		k3: "on",
		k5: "off",
		k6: "on",
	}
	c.Assert(o.Validate(cfg), IsNil)

	expectedChanges := OptionMap{
		k1: OptionDisabled,
		k3: OptionEnabled,
		k6: OptionEnabled,
	}
	actualChanges := OptionMap{}
	var changed ChangedFunc = func(key string, value OptionSetting, data interface{}) {
		c.Assert(data, Equals, &cfg)
		actualChanges[key] = value
	}

	om, err := o.Library.ValidateConfigurationMap(cfg)
	c.Assert(err, IsNil)
	c.Assert(o.ApplyValidated(om, changed, &cfg), Equals, len(expectedChanges))
	c.Assert(actualChanges, checker.DeepEquals, expectedChanges)

	expectedOpts := OptionMap{
		k1: OptionDisabled,
		k2: OptionDisabled,
		k3: OptionEnabled,
		k4: OptionEnabled,
		k5: OptionDisabled,
		k6: OptionEnabled,
	}
	for k, v := range expectedOpts {
		c.Assert(o.GetValue(k), Equals, v)
	}
}
