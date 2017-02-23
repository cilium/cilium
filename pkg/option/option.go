//
// Copyright 2016 Authors of Cilium
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
//
package option

import (
	"fmt"
	"sort"
	"strings"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/common"

	"github.com/op/go-logging"
)

var (
	log = logging.MustGetLogger("cilium-option")
)

type Option struct {
	Define      string
	Description string
	Immutable   bool
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

func (l OptionLibrary) Validate(name string) error {
	key, spec := l.Lookup(name)
	if key == "" {
		return fmt.Errorf("Unknown option %s", name)
	}

	if spec.Immutable {
		return fmt.Errorf("Specified option is immutable (read-only)")
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
	Opts    OptionMap      `json:"map"`
	Library *OptionLibrary `json:"-"`
}

func (bo *BoolOptions) GetModel() *models.Configuration {
	cfg := models.Configuration{
		Immutable: make(models.ConfigurationMap),
		Mutable:   make(models.ConfigurationMap),
	}

	for k, v := range bo.Opts {
		if v {
			cfg.Mutable[k] = "Enabled"
		} else {
			cfg.Mutable[k] = "Disabled"
		}
	}

	return &cfg
}

func (bo *BoolOptions) DeepCopy() *BoolOptions {
	cpy := &BoolOptions{
		Opts:    bo.Opts.DeepCopy(),
		Library: bo.Library,
	}
	return cpy
}

func NewBoolOptions(lib *OptionLibrary) *BoolOptions {
	return &BoolOptions{
		Opts:    OptionMap{},
		Library: lib,
	}
}

func (o *BoolOptions) IsEnabled(key string) bool {
	set, exists := o.Opts[key]
	return exists && set
}

func (o *BoolOptions) Set(key string, value bool) {
	o.Opts[key] = value
}

func (o *BoolOptions) Delete(key string) {
	delete(o.Opts, key)
}

func (o *BoolOptions) SetIfUnset(key string, value bool) {
	if _, exists := o.Opts[key]; !exists {
		o.Opts[key] = value
	}
}

func (o *BoolOptions) InheritDefault(parent *BoolOptions, key string) {
	o.Set(key, parent.IsEnabled(key))
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

// GetFmtOpt returns #define name if option exists and is set to true in endpoint's Opts
// map or #undef name if option does not exist or exists but is set to false
func (o *BoolOptions) GetFmtOpt(name string) string {
	define := o.Library.Define(name)
	if define == "" {
		return ""
	}

	if o.IsEnabled(name) {
		return "#define " + o.Library.Define(name)
	} else {
		return "#undef " + o.Library.Define(name)
	}
}

func (o *BoolOptions) GetFmtList() string {
	txt := ""

	for k := range o.Opts {
		def := o.GetFmtOpt(k)
		if def != "" {
			txt += def + "\n"
		}
	}

	return txt
}

func (o *BoolOptions) Dump() {
	if o == nil {
		return
	}

	opts := []string{}
	for k := range o.Opts {
		opts = append(opts, k)
	}
	sort.Strings(opts)

	for _, k := range opts {
		text := common.Green("Enabled")

		if !o.Opts[k] {
			text = common.Red("Disabled")
		}

		fmt.Printf("%-24s %s\n", k, text)
	}
}

func (o *BoolOptions) Validate(n models.ConfigurationMap) error {
	for k, v := range n {
		if _, err := NormalizeBool(v); err != nil {
			return err
		}

		if err := o.Library.Validate(k); err != nil {
			return err
		}
	}

	return nil
}

type ChangedFunc func(key string, value bool, data interface{})

func (o *BoolOptions) Apply(n models.ConfigurationMap, changed ChangedFunc, data interface{}) int {
	changes := 0

	for k, v := range n {
		val, ok := o.Opts[k]

		if boolVal, _ := NormalizeBool(v); boolVal {
			/* Only enable if not enabled already */
			if !ok || !val {
				o.Opts[k] = true
				changes++
				changed(k, true, data)
			}
		} else {
			/* Only disable if enabled already */
			if ok && val {
				o.Opts[k] = false
				changes++
				changed(k, false, data)
			}
		}
	}

	return changes
}
