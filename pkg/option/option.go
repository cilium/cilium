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
	"github.com/cilium/cilium/pkg/color"
	"github.com/cilium/cilium/pkg/lock"
)

// VerifyFunc validates option key with value and may return an error if the
// option should not be applied
type VerifyFunc func(key string, value string) error

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
	// Verify is called prior to applying the option
	Verify VerifyFunc
}

const (
	OptionDisabled = iota
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

func NormalizeBool(value string) (int, error) {
	switch strings.ToLower(value) {
	case "true", "on", "enable", "enabled", "1":
		return OptionEnabled, nil
	case "false", "off", "disable", "disabled", "0":
		return OptionDisabled, nil
	default:
		return OptionDisabled, fmt.Errorf("Invalid option value %s", value)
	}
}

func (l OptionLibrary) Validate(name string, value string) error {
	key, spec := l.Lookup(name)
	if key == "" {
		return fmt.Errorf("Unknown option %s", name)
	}

	if spec.Immutable {
		return fmt.Errorf("Specified option is immutable (read-only)")
	}

	if spec.Verify != nil {
		return spec.Verify(key, value)
	}

	return nil
}

type OptionMap map[string]int

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
func (io *IntOptions) GetImmutableModel() *models.ConfigurationMap {
	immutableCfg := make(models.ConfigurationMap)
	return &immutableCfg
}

// GetMutableModel returns the set of mutable options as a ConfigurationMap API model.
func (io *IntOptions) GetMutableModel() *models.ConfigurationMap {
	mutableCfg := make(models.ConfigurationMap)
	io.optsMU.RLock()
	for k, v := range io.Opts {
		if v == OptionDisabled {
			mutableCfg[k] = fmt.Sprintf("Disabled")
		} else {
			mutableCfg[k] = fmt.Sprintf("Enabled")
		}
	}
	io.optsMU.RUnlock()

	return &mutableCfg
}

func (io *IntOptions) DeepCopy() *IntOptions {
	io.optsMU.RLock()
	cpy := &IntOptions{
		Opts:    io.Opts.DeepCopy(),
		Library: io.Library,
	}
	io.optsMU.RUnlock()
	return cpy
}

func NewIntOptions(lib *OptionLibrary) *IntOptions {
	return &IntOptions{
		Opts:    OptionMap{},
		Library: lib,
	}
}

func (io *IntOptions) GetValue(key string) int {
	value, exists := io.Opts[key]
	if !exists {
		return OptionDisabled
	}
	return value
}

func (io *IntOptions) IsEnabled(key string) bool {
	io.optsMU.RLock()
	defer io.optsMU.RUnlock()
	return io.GetValue(key) != OptionDisabled
}

// SetValidated sets the option `key` to the specified value. The caller is
// expected to have validated the input to this function.
func (io *IntOptions) SetValidated(key string, value int) {
	io.optsMU.Lock()
	io.Opts[key] = value
	io.optsMU.Unlock()
}

// SetBool sets the specified option to Enabled.
func (io *IntOptions) SetBool(key string, value bool) {
	intValue := OptionDisabled
	if value {
		intValue = OptionEnabled
	}
	io.optsMU.Lock()
	io.Opts[key] = intValue
	io.optsMU.Unlock()
}

func (io *IntOptions) Delete(key string) {
	io.optsMU.Lock()
	delete(io.Opts, key)
	io.optsMU.Unlock()
}

func (io *IntOptions) SetIfUnset(key string, value int) {
	io.optsMU.Lock()
	if _, exists := io.Opts[key]; !exists {
		io.Opts[key] = value
	}
	io.optsMU.Unlock()
}

func (io *IntOptions) InheritDefault(parent *IntOptions, key string) {
	io.optsMU.RLock()
	io.Opts[key] = parent.GetValue(key)
	io.optsMU.RUnlock()
}

func ParseOption(arg string, lib *OptionLibrary) (string, int, error) {
	result := OptionEnabled

	if arg[0] == '!' {
		result = OptionDisabled
		arg = arg[1:]
	}

	optionSplit := strings.SplitN(arg, "=", 2)
	arg = optionSplit[0]
	if len(optionSplit) > 1 {
		if result == OptionDisabled {
			return "", OptionDisabled, fmt.Errorf("Invalid boolean format")
		}

		return ParseKeyValue(lib, arg, optionSplit[1], result)
	}

	return "", OptionDisabled, fmt.Errorf("Invalid option format")
}

func ParseKeyValue(lib *OptionLibrary, arg, value string, defaultValue int) (string, int, error) {
	result := defaultValue

	key, spec := lib.Lookup(arg)
	if key == "" {
		return "", OptionDisabled, fmt.Errorf("Unknown option %q", arg)
	}

	result, err := NormalizeBool(value)
	if err != nil {
		return "", OptionDisabled, err
	}

	if spec.Immutable {
		return "", OptionDisabled, fmt.Errorf("Specified option is immutable (read-only)")
	}

	return key, result, nil
}

// getFmtOpt returns #define name if option exists and is set to true in endpoint's Opts
// map or #undef name if option does not exist or exists but is set to false
func (io *IntOptions) getFmtOpt(name string) string {
	define := io.Library.Define(name)
	if define == "" {
		return ""
	}

	if io.GetValue(name) != OptionDisabled {
		return "#define " + io.Library.Define(name)
	}
	return "#undef " + io.Library.Define(name)
}

func (io *IntOptions) GetFmtList() string {
	txt := ""

	io.optsMU.RLock()
	opts := []string{}
	for k := range io.Opts {
		opts = append(opts, k)
	}
	sort.Strings(opts)

	for _, k := range opts {
		def := io.getFmtOpt(k)
		if def != "" {
			txt += def + "\n"
		}
	}
	io.optsMU.RUnlock()

	return txt
}

func (io *IntOptions) Dump() {
	if io == nil {
		return
	}

	io.optsMU.RLock()
	opts := []string{}
	for k := range io.Opts {
		opts = append(opts, k)
	}
	sort.Strings(opts)

	for _, k := range opts {
		var text string
		if io.Opts[k] == OptionDisabled {
			text = color.Red("Disabled")
		} else {
			text = color.Green("Enabled")
		}

		fmt.Printf("%-24s %s\n", k, text)
	}
	io.optsMU.RUnlock()
}

// Validate validates a given configuration map based on the option library
func (io *IntOptions) Validate(n models.ConfigurationMap) error {
	io.optsMU.RLock()
	defer io.optsMU.RUnlock()
	for k, v := range n {
		_, newVal, err := ParseKeyValue(io.Library, k, v, OptionDisabled)
		if err != nil {
			return err
		}

		// Ignore validation if value is identical
		if oldVal, ok := io.Opts[k]; ok && oldVal == newVal {
			continue
		}

		if err := io.Library.Validate(k, v); err != nil {
			return err
		}
	}

	return nil
}

// ChangedFunc is called by `Apply()` for each option changed
type ChangedFunc func(key string, value int, data interface{})

// enable enables the option `name` with all its dependencies
func (io *IntOptions) enable(name string) {
	if io.Library != nil {
		if _, opt := io.Library.Lookup(name); opt != nil {
			for _, dependency := range opt.Requires {
				io.enable(dependency)
			}
		}
	}

	io.Opts[name] = OptionEnabled
}

// set enables the option `name` with all its dependencies, and sets the
// integer level of the option to `value`.
func (io *IntOptions) set(name string, value int) {
	io.enable(name)
	io.Opts[name] = value
}

// disable disables the option `name`. All options which depend on the option
// to be disabled will be disabled. Options which have previously been enabled
// as a dependency will not be automatically disabled.
func (io *IntOptions) disable(name string) {
	io.Opts[name] = OptionDisabled

	if io.Library != nil {
		// Disable all options which have a dependency on the option
		// that was just disabled
		for key, opt := range *io.Library {
			if opt.RequiresOption(name) && io.Opts[key] != OptionDisabled {
				io.disable(key)
			}
		}
	}
}

type changedOptions struct {
	key   string
	value int
}

// ApplyValidated takes a configuration map and applies the changes. For an
// option which is changed, the `ChangedFunc` function is called with the
// `data` argument passed in as well. Returns the number of options changed if
// any.
//
// The caller is expected to have validated the configuration options prior to
// calling this function.
func (io *IntOptions) ApplyValidated(n models.ConfigurationMap, changed ChangedFunc, data interface{}) int {
	changes := []changedOptions{}

	io.optsMU.Lock()
	for k, v := range n {
		val, ok := io.Opts[k]

		// Ignore the error here because the option was already validated.
		_, optVal, _ := ParseKeyValue(io.Library, k, v, OptionDisabled)
		if optVal == OptionDisabled {
			/* Only disable if enabled already */
			if ok && val != OptionDisabled {
				io.disable(k)
				changes = append(changes, changedOptions{key: k, value: optVal})
			}
		} else {
			/* Only enable if not enabled already */
			if !ok || val == OptionDisabled {
				io.set(k, optVal)
				changes = append(changes, changedOptions{key: k, value: optVal})
			}
		}
	}
	io.optsMU.Unlock()

	for _, change := range changes {
		changed(change.key, change.value, data)
	}

	return len(changes)
}
