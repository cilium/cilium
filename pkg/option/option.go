// Copyright 2016-2017 Authors of Cilium
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
	"sync"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/common"

	"github.com/op/go-logging"
)

var (
	log = logging.MustGetLogger("cilium-option")
)

// VerifyFunc validates option key with value and may return an error if the
// option should not be applied
type VerifyFunc func(key string, value bool) error

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

func NormalizeBool(value string) (bool, error) {
	switch strings.ToLower(value) {
	case "true", "on", "enable", "enabled":
		return true, nil
	case "false", "off", "disable", "disabled":
		return false, nil
	default:
		return false, fmt.Errorf("Invalid option value %s", value)
	}
}

func (l OptionLibrary) Validate(name string, value bool) error {
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

type OptionMap map[string]bool

func (om OptionMap) DeepCopy() OptionMap {
	cpy := make(OptionMap, len(om))
	for k, v := range om {
		cpy[k] = v
	}
	return cpy
}

type BoolOptions struct {
	optsMU  sync.RWMutex   // Protects all variables from this structure below this line
	Opts    OptionMap      `json:"map"`
	Library *OptionLibrary `json:"-"`
}

func (bo *BoolOptions) GetModel() *models.Configuration {
	cfg := models.Configuration{
		Immutable: make(models.ConfigurationMap),
		Mutable:   make(models.ConfigurationMap),
	}

	bo.optsMU.RLock()
	for k, v := range bo.Opts {
		if v {
			cfg.Mutable[k] = "Enabled"
		} else {
			cfg.Mutable[k] = "Disabled"
		}
	}
	bo.optsMU.RUnlock()

	return &cfg
}

func (bo *BoolOptions) DeepCopy() *BoolOptions {
	bo.optsMU.RLock()
	cpy := &BoolOptions{
		Opts:    bo.Opts.DeepCopy(),
		Library: bo.Library,
	}
	bo.optsMU.RUnlock()
	return cpy
}

func NewBoolOptions(lib *OptionLibrary) *BoolOptions {
	return &BoolOptions{
		Opts:    OptionMap{},
		Library: lib,
	}
}

func (bo *BoolOptions) IsEnabled(key string) bool {
	bo.optsMU.RLock()
	set, exists := bo.Opts[key]
	bo.optsMU.RUnlock()
	return exists && set
}

func (bo *BoolOptions) Set(key string, value bool) {
	bo.optsMU.Lock()
	bo.Opts[key] = value
	bo.optsMU.Unlock()
}

func (bo *BoolOptions) Delete(key string) {
	bo.optsMU.Lock()
	delete(bo.Opts, key)
	bo.optsMU.Unlock()
}

func (bo *BoolOptions) SetIfUnset(key string, value bool) {
	bo.optsMU.Lock()
	if _, exists := bo.Opts[key]; !exists {
		bo.Opts[key] = value
	}
	bo.optsMU.Unlock()
}

func (bo *BoolOptions) InheritDefault(parent *BoolOptions, key string) {
	bo.Set(key, parent.IsEnabled(key))
}

func ParseOption(arg string, lib *OptionLibrary) (string, bool, error) {
	enabled := true

	if arg[0] == '!' {
		enabled = false
		arg = arg[1:]
	}

	optionSplit := strings.SplitN(arg, "=", 2)
	arg = optionSplit[0]
	if len(optionSplit) > 1 {
		if !enabled {
			return "", false, fmt.Errorf("Invalid boolean format")
		}

		var err error
		enabled, err = NormalizeBool(optionSplit[1])
		if err != nil {
			return "", false, err
		}
	}

	key, spec := lib.Lookup(arg)
	if key == "" {
		return "", false, fmt.Errorf("Unknown endpoint option %s", arg)
	}

	if spec.Immutable {
		return "", false, fmt.Errorf("Specified option is immutable (read-only)")
	}

	return key, enabled, nil
}

// getFmtOpt returns #define name if option exists and is set to true in endpoint's Opts
// map or #undef name if option does not exist or exists but is set to false
func (bo *BoolOptions) getFmtOpt(name string) string {
	define := bo.Library.Define(name)
	if define == "" {
		return ""
	}

	if bo.IsEnabled(name) {
		return "#define " + bo.Library.Define(name)
	}
	return "#undef " + bo.Library.Define(name)
}

func (bo *BoolOptions) GetFmtList() string {
	txt := ""

	bo.optsMU.RLock()
	for k := range bo.Opts {
		def := bo.getFmtOpt(k)
		if def != "" {
			txt += def + "\n"
		}
	}
	bo.optsMU.RUnlock()

	return txt
}

func (bo *BoolOptions) Dump() {
	if bo == nil {
		return
	}

	bo.optsMU.RLock()
	opts := []string{}
	for k := range bo.Opts {
		opts = append(opts, k)
	}
	sort.Strings(opts)

	for _, k := range opts {
		text := common.Green("Enabled")

		if !bo.Opts[k] {
			text = common.Red("Disabled")
		}

		fmt.Printf("%-24s %s\n", k, text)
	}
	bo.optsMU.RUnlock()
}

// Validate validates a given configuration map based on the option library
func (bo *BoolOptions) Validate(n models.ConfigurationMap) error {
	bo.optsMU.RLock()
	defer bo.optsMU.RUnlock()
	for k, v := range n {
		if val, err := NormalizeBool(v); err != nil {
			return err
		} else if err := bo.Library.Validate(k, val); err != nil {
			return err
		}
	}

	return nil
}

// ChangedFunc is called by `Apply()` for each option changed
type ChangedFunc func(key string, value bool, data interface{})

// enable enables the option `name` with all its dependencies
func (bo *BoolOptions) enable(name string) {
	if bo.Library != nil {
		if _, opt := bo.Library.Lookup(name); opt != nil {
			for _, dependency := range opt.Requires {
				bo.enable(dependency)
			}
		}
	}

	bo.Opts[name] = true
}

// disable disables the option `name`. All options which depend on the option
// to be disabled will be disabled. Options which have previously been enabled
// as a dependency will not be automatically disabled.
func (bo *BoolOptions) disable(name string) {
	bo.Opts[name] = false

	if bo.Library != nil {
		// Disable all options which have a dependency on the option
		// that was just disabled
		for key, opt := range *bo.Library {
			if opt.RequiresOption(name) && bo.Opts[key] {
				bo.disable(key)
			}
		}
	}
}

// Apply takes a configuration map and applies the changes. For an option
// which is changed, the `ChangedFunc` function is called with the `data`
// argument passed in as well. Returns the number of options changed if any.
func (bo *BoolOptions) Apply(n models.ConfigurationMap, changed ChangedFunc, data interface{}) int {
	changes := 0

	bo.optsMU.Lock()
	for k, v := range n {
		val, ok := bo.Opts[k]

		if boolVal, _ := NormalizeBool(v); boolVal {
			/* Only enable if not enabled already */
			if !ok || !val {
				bo.enable(k)
				changes++
				changed(k, true, data)
			}
		} else {
			/* Only disable if enabled already */
			if ok && val {
				bo.disable(k)
				changes++
				changed(k, false, data)
			}
		}
	}
	bo.optsMU.Unlock()

	return changes
}
