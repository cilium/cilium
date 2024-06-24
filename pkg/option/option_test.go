// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package option

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/api/v1/models"
)

func TestGetValue(t *testing.T) {
	k1, k2 := "foo", "bar"
	v1 := OptionSetting(7)

	o := IntOptions{
		opts: OptionMap{
			k1: v1,
			k2: OptionEnabled,
		},
	}

	require.Equal(t, v1, o.GetValue(k1))
	require.Equal(t, OptionEnabled, o.GetValue(k2))
	require.Equal(t, OptionDisabled, o.GetValue("unknown"))
}

func TestIsEnabled(t *testing.T) {
	k1, k2 := "foo", "bar"

	o := IntOptions{
		opts: OptionMap{
			k1: OptionEnabled,
			k2: OptionDisabled,
		},
	}

	require.True(t, o.IsEnabled(k1))
	require.False(t, o.IsEnabled(k2))
	require.False(t, o.IsEnabled("unknown"))
}

func TestSetValidated(t *testing.T) {
	k1, k2 := "foo", "bar"

	o := IntOptions{
		opts: OptionMap{
			k1: OptionEnabled,
		},
	}

	require.True(t, o.IsEnabled(k1))
	require.False(t, o.IsEnabled(k2))

	o.SetValidated(k1, OptionDisabled)
	o.SetValidated(k2, OptionEnabled)
	require.False(t, o.IsEnabled(k1))
	require.True(t, o.IsEnabled(k2))
}

func TestSetBool(t *testing.T) {
	k1, k2, k3 := "foo", "bar", "baz"

	o := IntOptions{
		opts: OptionMap{
			k1: OptionEnabled,
			k2: OptionDisabled,
		},
	}

	o.SetBool(k1, false)
	o.SetBool(k2, true)
	o.SetBool(k3, true)
	require.Equal(t, OptionDisabled, o.GetValue(k1))
	require.Equal(t, OptionEnabled, o.GetValue(k2))
	require.Equal(t, OptionEnabled, o.GetValue(k3))
}

func TestDelete(t *testing.T) {
	k1, k2 := "foo", "bar"

	o := IntOptions{
		opts: OptionMap{
			k1: OptionEnabled,
			k2: OptionEnabled,
		},
	}

	o.Delete(k1)

	require.Equal(t, OptionDisabled, o.GetValue(k1))
	require.Equal(t, OptionEnabled, o.GetValue(k2))
}

func TestSetIfUnset(t *testing.T) {
	k1, k2 := "foo", "bar"

	o := IntOptions{
		opts: OptionMap{
			k1: OptionDisabled,
		},
	}

	o.SetIfUnset(k1, OptionEnabled)
	o.SetIfUnset(k2, OptionEnabled)

	require.Equal(t, OptionDisabled, o.GetValue(k1))
	require.Equal(t, OptionEnabled, o.GetValue(k2))
}

func TestInheritDefault(t *testing.T) {
	k := "foo"

	o := IntOptions{
		opts: OptionMap{},
	}
	parent := IntOptions{
		opts: OptionMap{
			k: OptionEnabled,
		},
	}
	require.Equal(t, OptionDisabled, o.GetValue(k))
	o.InheritDefault(&parent, k)
	require.Equal(t, OptionEnabled, o.GetValue(k))
}

func TestParseKeyValueWithDefaultParseFunc(t *testing.T) {
	k := "foo"

	l := OptionLibrary{
		k: &Option{
			Define:      "TEST_DEFINE",
			Description: "This is a test",
		},
	}

	_, res, err := ParseKeyValue(&l, k, "on")
	require.Nil(t, err)
	require.Equal(t, OptionEnabled, res)
}

func TestParseKeyValue(t *testing.T) {
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
	require.NotNil(t, err)

	_, res, err := ParseKeyValue(&l, k, "yes")
	require.Nil(t, err)
	require.Equal(t, OptionEnabled, res)

	_, _, err = ParseKeyValue(&l, "unknown", "yes")
	require.NotNil(t, err)
}

func TestParseOption(t *testing.T) {
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
	require.NotNil(t, err)

	_, res, err := ParseOption(arg, &l)
	require.Nil(t, err)
	require.Equal(t, OptionEnabled, res)

	_, _, err = ParseOption("!"+arg, &l)
	require.NotNil(t, err)

	OptionTest.Immutable = true
	_, _, err = ParseOption(arg, &l)
	require.NotNil(t, err)
	OptionTest.Immutable = false
}

func TestGetFmtOpts(t *testing.T) {
	OptionTest := Option{
		Define:      "TEST_DEFINE",
		Description: "This is a test",
	}

	o := IntOptions{
		opts: OptionMap{
			"test": OptionEnabled,
			"BAR":  OptionDisabled,
			"foo":  OptionEnabled,
			"bar":  OptionDisabled,
		},
		library: &OptionLibrary{
			"test": &OptionTest,
		},
	}

	fmtList := o.GetFmtList()
	fmtList2 := o.GetFmtList()

	// Both strings should be equal because the formatted options should be sorted.
	require.Equal(t, fmtList, fmtList2)

	o2 := IntOptions{
		opts: OptionMap{
			"foo":  OptionEnabled,
			"BAR":  OptionDisabled,
			"bar":  OptionDisabled,
			"test": OptionEnabled,
		},
		library: &OptionLibrary{
			"test": &OptionTest,
		},
	}

	fmtListO := o.GetFmtList()
	fmtListO2 := o2.GetFmtList()

	// Both strings should be equal because the formatted options should be sorted.
	require.Equal(t, fmtListO, fmtListO2)
}

func TestGetFmtOpt(t *testing.T) {
	OptionTest := Option{
		Define:      "TEST_DEFINE",
		Description: "This is a test",
	}

	o := IntOptions{
		opts: OptionMap{
			"test":  OptionEnabled,
			"BAR":   OptionDisabled,
			"alice": 2,
		},
		library: &OptionLibrary{
			"test":  &OptionTest,
			"alice": &OptionTest,
		},
	}
	o.optsMU.Lock()
	require.Equal(t, o.getFmtOpt("test"), "#define TEST_DEFINE 1")
	require.Equal(t, o.getFmtOpt("BAR"), "#undef BAR")
	require.Equal(t, o.getFmtOpt("BAZ"), "#undef BAZ")
	require.Equal(t, o.getFmtOpt("alice"), "#define TEST_DEFINE 2")
	o.optsMU.Unlock()
}

func TestGetImmutableModel(t *testing.T) {
	k := "foo"

	OptionTest := Option{
		Define:      "TEST_DEFINE",
		Description: "This is a test",
	}

	o := IntOptions{
		opts: OptionMap{
			k: OptionEnabled,
		},
		library: &OptionLibrary{
			k: &OptionTest,
		},
	}

	cfg := o.GetImmutableModel()
	require.NotNil(t, cfg)
	require.Equal(t, &models.ConfigurationMap{}, cfg)
}

func TestGetMutableModel(t *testing.T) {
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
		opts: OptionMap{
			k1: OptionEnabled,
			k2: OptionDisabled,
			k3: OptionEnabled,
		},
		library: &OptionLibrary{
			k1: &OptionDefaultFormat,
			k2: &OptionDefaultFormat,
			k3: &OptionCustomFormat,
		},
	}

	cfg := o.GetMutableModel()
	require.NotNil(t, cfg)
	require.Equal(t, &models.ConfigurationMap{
		k1: "Enabled",
		k2: "Disabled",
		k3: "ok",
	}, cfg)

	o2 := IntOptions{}
	cfg2 := o2.GetMutableModel()
	require.NotNil(t, cfg2)
	require.Equal(t, &models.ConfigurationMap{}, cfg2)
}

func TestValidate(t *testing.T) {
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
		opts: OptionMap{
			k1: OptionEnabled,
			k2: OptionEnabled,
			k3: OptionDisabled,
			k4: OptionEnabled,
		},
		library: &OptionLibrary{
			k1: &OptionTest,
			k2: &OptionCustomVerify,
			k3: &OptionCustomVerify,
			k4: &OptionImmutable,
		},
	}

	require.Nil(t, o.Validate(models.ConfigurationMap{k1: "on"}))
	require.NotNil(t, o.Validate(models.ConfigurationMap{"unknown": "on"}))
	require.NotNil(t, o.Validate(models.ConfigurationMap{k4: "on"}))
	require.Nil(t, o.Validate(models.ConfigurationMap{k1: "on", k2: "on"}))
	require.NotNil(t, o.Validate(models.ConfigurationMap{k1: "on", k3: "on"}))
}

func TestApplyValidated(t *testing.T) {
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
		opts: OptionMap{
			k1: OptionEnabled,
			k2: OptionEnabled,
			k3: OptionDisabled,
			k4: OptionDisabled,
			k5: OptionDisabled,
		},
		library: &OptionLibrary{
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
	require.Nil(t, o.Validate(cfg))

	expectedChanges := OptionMap{
		k1: OptionDisabled,
		k3: OptionEnabled,
		k6: OptionEnabled,
	}
	actualChanges := OptionMap{}
	var changed ChangedFunc = func(key string, value OptionSetting, data interface{}) {
		require.Equal(t, &cfg, data)
		actualChanges[key] = value
	}

	om, err := o.library.ValidateConfigurationMap(cfg)
	require.NoError(t, err)
	require.Equal(t, len(expectedChanges), o.ApplyValidated(om, changed, &cfg))
	require.Equal(t, expectedChanges, actualChanges)

	expectedOpts := OptionMap{
		k1: OptionDisabled,
		k2: OptionDisabled,
		k3: OptionEnabled,
		k4: OptionEnabled,
		k5: OptionDisabled,
		k6: OptionEnabled,
	}
	for k, v := range expectedOpts {
		require.Equal(t, v, o.GetValue(k))
	}
}
