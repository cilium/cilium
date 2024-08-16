// Copyright 2016-2018 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package option

import (
	"fmt"
	"sort"
	"strings"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/lock"
)

// VerifyFunc validates option key with value and may return an error if the
// option should not be applied
type VerifyFunc func(key string, value string) error

// ParseFunc parses the option value and may return an error if the option
// cannot be parsed or applied.
type ParseFunc func(value string) (OptionSetting, error)

// FormatFunc formats the specified value as textual representation option.
type FormatFunc func(value OptionSetting) string

// Option is the structure used to specify the semantics of a configurable
// boolean option
type Option struct {
	// Define is the name of the #define used for BPF programs
	Define string
	// Description is a short human readable description
	Description string
	// Immutable marks an option which is read-only
	Immutable bool
	// Requires is a list of required options, such options will be
	// automatically enabled as required.
	Requires []string
	// Parse is called to parse the option. If not specified, defaults to
	// NormalizeBool().
	Parse ParseFunc
	// FormatFunc is called to format the value for an option. If not
	// specified, defaults to formatting 0 as "Disabled" and other values
	// as "Enabled".
	Format FormatFunc
	// Verify is called prior to applying the option
	Verify VerifyFunc
}

// OptionSetting specifies the different choices each Option has.
type OptionSetting int

const (
	OptionDisabled OptionSetting = iota
	OptionEnabled
)

// RequiresOption returns true if the option requires the specified option `name`.
func (o Option) RequiresOption(name string) bool {
	for _, o := range o.Requires {
		if o == name {
			return true
		}
	}

	return false
}

type OptionLibrary map[string]*Option

func (l OptionLibrary) Lookup(name string) (string, *Option) {
	nameLower := strings.ToLower(name)

	for k := range l {
		if strings.ToLower(k) == nameLower {
			return k, l[k]
		}
	}

	return "", nil
}

func (l OptionLibrary) Define(name string) string {
	if _, ok := l[name]; ok {
		return l[name].Define
	}

	return name
}

func NormalizeBool(value string) (OptionSetting, error) {
	switch strings.ToLower(value) {
	case "true", "on", "enable", "enabled", "1":
		return OptionEnabled, nil
	case "false", "off", "disable", "disabled", "0":
		return OptionDisabled, nil
	default:
		return OptionDisabled, fmt.Errorf("invalid option value %s", value)
	}
}

// ValidateConfigurationMap validates a given configuration map based on the
// option library
func (l *OptionLibrary) ValidateConfigurationMap(n models.ConfigurationMap) (OptionMap, error) {
	o := make(OptionMap)
	for k, v := range n {
		_, newVal, err := ParseKeyValue(l, k, v)
		if err != nil {
			return nil, err
		}

		if err := l.Validate(k, v); err != nil {
			return nil, err
		}
		o[k] = newVal
	}

	return o, nil
}

func (l OptionLibrary) Validate(name string, value string) error {
	key, spec := l.Lookup(name)
	if key == "" {
		return fmt.Errorf("unknown option %s", name)
	}

	if spec.Immutable {
		return fmt.Errorf("specified option is immutable (read-only)")
	}

	if spec.Verify != nil {
		return spec.Verify(key, value)
	}

	return nil
}

type OptionMap map[string]OptionSetting

func (om OptionMap) DeepCopy() OptionMap {
	cpy := make(OptionMap, len(om))
	for k, v := range om {
		cpy[k] = v
	}
	return cpy
}

// IntOptions member functions with external access do not require
// locking by the caller, while functions with internal access presume
// the caller to have taken care of any locking needed.
type IntOptions struct {
	optsMU  lock.RWMutex   // Protects all variables from this structure below this line
	Opts    OptionMap      `json:"map"`
	Library *OptionLibrary `json:"-"`
}

// GetImmutableModel returns the set of immutable options as a ConfigurationMap API model.
func (o *IntOptions) GetImmutableModel() *models.ConfigurationMap {
	immutableCfg := make(models.ConfigurationMap)
	return &immutableCfg
}

// GetMutableModel returns the set of mutable options as a ConfigurationMap API model.
func (o *IntOptions) GetMutableModel() *models.ConfigurationMap {
	mutableCfg := make(models.ConfigurationMap)
	o.optsMU.RLock()
	for k, v := range o.Opts {
		_, config := o.Library.Lookup(k)

		// It's possible that an option has since been removed and thus has
		// no corresponding configuration; need to check if configuration is
		// nil accordingly.
		if config != nil {
			if config.Format == nil {
				if v == OptionDisabled {
					mutableCfg[k] = "Disabled"
				} else {
					mutableCfg[k] = "Enabled"
				}
			} else {
				mutableCfg[k] = config.Format(v)
			}
		}
	}
	o.optsMU.RUnlock()

	return &mutableCfg
}

func (o *IntOptions) DeepCopy() *IntOptions {
	o.optsMU.RLock()
	cpy := &IntOptions{
		Opts:    o.Opts.DeepCopy(),
		Library: o.Library,
	}
	o.optsMU.RUnlock()
	return cpy
}

func NewIntOptions(lib *OptionLibrary) *IntOptions {
	return &IntOptions{
		Opts:    OptionMap{},
		Library: lib,
	}
}

func (o *IntOptions) getValue(key string) OptionSetting {
	value, exists := o.Opts[key]
	if !exists {
		return OptionDisabled
	}
	return value
}

func (o *IntOptions) GetValue(key string) OptionSetting {
	o.optsMU.RLock()
	v := o.getValue(key)
	o.optsMU.RUnlock()
	return v
}

func (o *IntOptions) IsEnabled(key string) bool {
	return o.GetValue(key) != OptionDisabled
}

// SetValidated sets the option `key` to the specified value. The caller is
// expected to have validated the input to this function.
func (o *IntOptions) SetValidated(key string, value OptionSetting) {
	o.optsMU.Lock()
	o.Opts[key] = value
	o.optsMU.Unlock()
}

// SetBool sets the specified option to Enabled.
func (o *IntOptions) SetBool(key string, value bool) {
	intValue := OptionDisabled
	if value {
		intValue = OptionEnabled
	}
	o.optsMU.Lock()
	o.Opts[key] = intValue
	o.optsMU.Unlock()
}

func (o *IntOptions) Delete(key string) {
	o.optsMU.Lock()
	delete(o.Opts, key)
	o.optsMU.Unlock()
}

func (o *IntOptions) SetIfUnset(key string, value OptionSetting) {
	o.optsMU.Lock()
	if _, exists := o.Opts[key]; !exists {
		o.Opts[key] = value
	}
	o.optsMU.Unlock()
}

func (o *IntOptions) InheritDefault(parent *IntOptions, key string) {
	o.optsMU.RLock()
	o.Opts[key] = parent.GetValue(key)
	o.optsMU.RUnlock()
}

func ParseOption(arg string, lib *OptionLibrary) (string, OptionSetting, error) {
	result := OptionEnabled

	if arg[0] == '!' {
		result = OptionDisabled
		arg = arg[1:]
	}

	optionSplit := strings.SplitN(arg, "=", 2)
	arg = optionSplit[0]
	if len(optionSplit) > 1 {
		if result == OptionDisabled {
			return "", OptionDisabled, fmt.Errorf("invalid boolean format")
		}

		return ParseKeyValue(lib, arg, optionSplit[1])
	}

	return "", OptionDisabled, fmt.Errorf("invalid option format")
}

func ParseKeyValue(lib *OptionLibrary, arg, value string) (string, OptionSetting, error) {
	var result OptionSetting

	key, spec := lib.Lookup(arg)
	if key == "" {
		return "", OptionDisabled, fmt.Errorf("unknown option %q", arg)
	}

	var err error
	if spec.Parse != nil {
		result, err = spec.Parse(value)
	} else {
		result, err = NormalizeBool(value)
	}
	if err != nil {
		return "", OptionDisabled, err
	}

	if spec.Immutable {
		return "", OptionDisabled, fmt.Errorf("specified option is immutable (read-only)")
	}

	return key, result, nil
}

// getFmtOpt returns #define name if option exists and is set to true in endpoint's Opts
// map or #undef name if option does not exist or exists but is set to false
func (o *IntOptions) getFmtOpt(name string) string {
	define := o.Library.Define(name)
	if define == "" {
		return ""
	}

	value := o.getValue(name)
	if value != OptionDisabled {
		return fmt.Sprintf("#define %s %d", o.Library.Define(name), value)
	}
	return "#undef " + o.Library.Define(name)
}

func (o *IntOptions) GetFmtList() string {
	txt := ""

	o.optsMU.RLock()
	opts := []string{}
	for k := range o.Opts {
		opts = append(opts, k)
	}
	sort.Strings(opts)

	for _, k := range opts {
		def := o.getFmtOpt(k)
		if def != "" {
			txt += def + "\n"
		}
	}
	o.optsMU.RUnlock()

	return txt
}

func (o *IntOptions) Dump() {
	if o == nil {
		return
	}

	o.optsMU.RLock()
	opts := []string{}
	for k := range o.Opts {
		opts = append(opts, k)
	}
	sort.Strings(opts)

	for _, k := range opts {
		var text string
		_, option := o.Library.Lookup(k)
		if option == nil || option.Format == nil {
			if o.Opts[k] == OptionDisabled {
				text = "Disabled"
			} else {
				text = "Enabled"
			}
		} else {
			text = option.Format(o.Opts[k])
		}

		fmt.Printf("%-24s %s\n", k, text)
	}
	o.optsMU.RUnlock()
}

// Validate validates a given configuration map based on the option library
func (o *IntOptions) Validate(n models.ConfigurationMap) error {
	o.optsMU.RLock()
	defer o.optsMU.RUnlock()
	for k, v := range n {
		_, newVal, err := ParseKeyValue(o.Library, k, v)
		if err != nil {
			return err
		}

		// Ignore validation if value is identical
		if oldVal, ok := o.Opts[k]; ok && oldVal == newVal {
			continue
		}

		if err := o.Library.Validate(k, v); err != nil {
			return err
		}
	}

	return nil
}

// ChangedFunc is called by `Apply()` for each option changed
type ChangedFunc func(key string, value OptionSetting, data interface{})

// enable enables the option `name` with all its dependencies
func (o *IntOptions) enable(name string) {
	if o.Library != nil {
		if _, opt := o.Library.Lookup(name); opt != nil {
			for _, dependency := range opt.Requires {
				o.enable(dependency)
			}
		}
	}

	o.Opts[name] = OptionEnabled
}

// set enables the option `name` with all its dependencies, and sets the
// integer level of the option to `value`.
func (o *IntOptions) set(name string, value OptionSetting) {
	o.enable(name)
	o.Opts[name] = value
}

// disable disables the option `name`. All options which depend on the option
// to be disabled will be disabled. Options which have previously been enabled
// as a dependency will not be automatically disabled.
func (o *IntOptions) disable(name string) {
	o.Opts[name] = OptionDisabled

	if o.Library != nil {
		// Disable all options which have a dependency on the option
		// that was just disabled
		for key, opt := range *o.Library {
			if opt.RequiresOption(name) && o.Opts[key] != OptionDisabled {
				o.disable(key)
			}
		}
	}
}

type changedOptions struct {
	key   string
	value OptionSetting
}

// ApplyValidated takes a configuration map and applies the changes. For an
// option which is changed, the `ChangedFunc` function is called with the
// `data` argument passed in as well. Returns the number of options changed if
// any.
//
// The caller is expected to have validated the configuration options prior to
// calling this function.
func (o *IntOptions) ApplyValidated(n OptionMap, changed ChangedFunc, data interface{}) int {
	changes := make([]changedOptions, 0, len(n))

	o.optsMU.Lock()
	for k, optVal := range n {
		val, ok := o.Opts[k]

		if optVal == OptionDisabled {
			/* Only disable if enabled already */
			if ok && val != OptionDisabled {
				o.disable(k)
				changes = append(changes, changedOptions{key: k, value: optVal})
			}
		} else {
			/* Only enable if not enabled already */
			if !ok || val == OptionDisabled {
				o.set(k, optVal)
				changes = append(changes, changedOptions{key: k, value: optVal})
			}
		}
	}
	o.optsMU.Unlock()

	for _, change := range changes {
		changed(change.key, change.value, data)
	}

	return len(changes)
}
