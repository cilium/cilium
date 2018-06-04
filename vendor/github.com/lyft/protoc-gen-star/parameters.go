package pgs

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	importPrefixKey    = "import_prefix"
	importPathKey      = "import_path"
	outputPathKey      = "output_path"
	importMapKeyPrefix = "M"
	pluginsKey         = "plugins"
	pluginsSep         = "+"
)

// PathType describes how the generated file paths should be constructed.
type PathType string

const (
	// PathTypeParam is the plugin param that allows specifying the path type
	// mode used in code generation.
	pathTypeKey = "paths"

	// ImportPath is the default and outputs the file based off the go import
	// path defined in the go_package option.
	ImportPath PathType = ""

	// SourceRelative indicates files should be output relative to the path of
	// the source file.
	SourceRelative PathType = "source_relative"
)

// Parameters provides a convenience for accessing and modifying the parameters
// passed into the protoc-gen-star plugin.
type Parameters map[string]string

// ParseParameters converts the raw params string provided to protoc into a
// representative mapping.
func ParseParameters(p string) (params Parameters) {
	parts := strings.Split(p, ",")
	params = make(map[string]string, len(parts))

	for _, p = range parts {
		if i := strings.Index(p, "="); i < 0 {
			params[p] = ""
		} else {
			params[p[:i]] = p[i+1:]
		}
	}

	return
}

// Plugins returns the sub-plugins enabled for this protoc plugin. If the all
// value is true, all registered plugins are considered enabled (ie, protoc was
// called with an empty "plugins" parameter). Otherwise, plugins contains the
// list of plugins enabled by name.
func (p Parameters) Plugins() (plugins []string, all bool) {
	s, ok := p[pluginsKey]
	if !ok {
		return
	}

	if all = s == ""; all {
		return
	}

	plugins = strings.Split(s, pluginsSep)
	return
}

// HasPlugin returns true if the plugin name is enabled in the parameters. This
// method will always return true if all plugins are enabled.
func (p Parameters) HasPlugin(name string) bool {
	plugins, all := p.Plugins()
	if all {
		return true
	}

	for _, pl := range plugins {
		if pl == name {
			return true
		}
	}

	return false
}

// AddPlugin adds name to the list of plugins in the parameters. If all plugins
// are enabled, this method is a noop.
func (p Parameters) AddPlugin(name ...string) {
	if len(name) == 0 {
		return
	}

	plugins, all := p.Plugins()
	if all {
		return
	}

	p.SetStr(pluginsKey, strings.Join(append(plugins, name...), pluginsSep))
}

// EnableAllPlugins changes the parameters to enable all registered sub-plugins.
func (p Parameters) EnableAllPlugins() { p.SetStr(pluginsKey, "") }

// ImportPrefix returns the protoc-gen-go parameter. This prefix is added onto
// the beginning of all Go import paths. This is useful for things like
// generating protos in a subdirectory, or regenerating vendored protobufs
// in-place. By default, this method returns an empty string.
//
// See: https://github.com/golang/protobuf#parameters
func (p Parameters) ImportPrefix() string { return p.Str(importPrefixKey) }

// SetImportPrefix sets the protoc-gen-go ImportPrefix parameter. This is
// useful for overriding the behavior of the ImportPrefix at runtime.
func (p Parameters) SetImportPrefix(prefix string) { p.SetStr(importPrefixKey, prefix) }

// ImportPath returns the protoc-gen-go parameter. This value is used as the
// package if the input proto files do not declare a go_package option. If it
// contains slashes, everything up to the rightmost slash is ignored.
//
// See: https://github.com/golang/protobuf#parameters
func (p Parameters) ImportPath() string { return p.Str(importPathKey) }

// SetImportPath sets the protoc-gen-go ImportPath parameter. This is useful
// for overriding the behavior of the ImportPath at runtime.
func (p Parameters) SetImportPath(path string) { p.SetStr(importPathKey, path) }

// Paths returns the protoc-gen-go parameter. This value is used to switch the
// mode used to determine the output paths of the generated code. By default,
// paths are derived from the import path specified by go_package. It can be
// overridden to be "source_relative", ignoring the import path using the
// source path exclusively.
func (p Parameters) Paths() PathType { return PathType(p.Str(pathTypeKey)) }

// SetPaths sets the protoc-gen-go Paths parameter. This is useful for
// overriding the behavior of Paths at runtime.
func (p Parameters) SetPaths(pt PathType) { p.SetStr(pathTypeKey, string(pt)) }

// ImportMap returns the protoc-gen-go import map overrides. Each entry in the
// map keys off a proto file (as loaded by protoc) with values of the Go
// package to use. These values will be prefixed with the value of ImportPrefix
// when generating the Go code.
func (p Parameters) ImportMap() map[string]string {
	out := map[string]string{}

	for k, v := range p {
		if strings.HasPrefix(k, importMapKeyPrefix) {
			out[k[1:]] = v
		}
	}

	return out
}

// AddImportMapping adds a proto file to Go package import mapping to the
// parameters.
func (p Parameters) AddImportMapping(proto, pkg string) {
	p[fmt.Sprintf("%s%s", importMapKeyPrefix, proto)] = pkg
}

// OutputPath returns the protoc-gen-star special parameter. If not set in the
// execution of protoc, "." is returned, indicating that output is relative to
// the (unknown) output location for sub-plugins or the directory where protoc
// is executed for a Module. Setting "output_path" during the protoc execution
// ensures that Modules can know absolutely where to generate code.
func (p Parameters) OutputPath() string { return p.StrDefault(outputPathKey, ".") }

// SetOutputPath sets the protoc-gen-star OutputPath parameter. This is useful
// for overriding the behavior of the ImportPath at runtime.
func (p Parameters) SetOutputPath(path string) { p.SetStr(outputPathKey, path) }

// String satisfies the string.Stringer interface. This method returns p in the
// format it is providing to the protoc execution.
func (p Parameters) String() string {
	parts := make([]string, 0, len(p))

	for k, v := range p {
		if v == "" {
			parts = append(parts, k)
		} else {
			parts = append(parts, fmt.Sprintf("%s=%s", k, v))
		}
	}

	sort.Strings(parts)

	return strings.Join(parts, ",")
}

// Str returns the parameter with name, returning an empty string if it is not
// set.
func (p Parameters) Str(name string) string { return p.StrDefault(name, "") }

// StrDefault returns the parameter with name, or if it is unset, returns the
// def default value.
func (p Parameters) StrDefault(name string, def string) string {
	if s, ok := p[name]; ok {
		return s
	}

	return def
}

// SetStr sets the parameter name to s.
func (p Parameters) SetStr(name string, s string) { p[name] = s }

// Int returns the parameter with name, returning zero if it is not set. An
// error is returned if the value cannot be parsed as an int.
func (p Parameters) Int(name string) (int, error) { return p.IntDefault(name, 0) }

// IntDefault returns the parameter with name, or if it is unset, returns the
// def default value. An error is returned if the value cannot be parsed as an
// int.
func (p Parameters) IntDefault(name string, def int) (int, error) {
	if s, ok := p[name]; ok {
		return strconv.Atoi(s)
	}
	return def, nil
}

// SetInt sets the parameter name to i.
func (p Parameters) SetInt(name string, i int) { p[name] = strconv.Itoa(i) }

// Uint returns the parameter with name, returning zero if it is not set. An
// error is returned if the value cannot be parsed as a base-10 uint.
func (p Parameters) Uint(name string) (uint, error) { return p.UintDefault(name, 0) }

// UintDefault returns the parameter with name, or if it is unset, returns the
// def default value. An error is returned if the value cannot be parsed as a
// base-10 uint.
func (p Parameters) UintDefault(name string, def uint) (uint, error) {
	if s, ok := p[name]; ok {
		ui, err := strconv.ParseUint(s, 10, strconv.IntSize)
		return uint(ui), err
	}
	return def, nil
}

// SetUint sets the parameter name to ui.
func (p Parameters) SetUint(name string, ui uint) { p[name] = strconv.FormatUint(uint64(ui), 10) }

// Float returns the parameter with name, returning zero if it is
// not set. An error is returned if the value cannot be parsed as a float64
func (p Parameters) Float(name string) (float64, error) { return p.FloatDefault(name, 0) }

// FloatDefault returns the parameter with name, or if it is unset, returns the
// def default value. An error is returned if the value cannot be parsed as a
// float64.
func (p Parameters) FloatDefault(name string, def float64) (float64, error) {
	if s, ok := p[name]; ok {
		return strconv.ParseFloat(s, 64)
	}
	return def, nil
}

// SetFloat sets the parameter name to f.
func (p Parameters) SetFloat(name string, f float64) { p[name] = strconv.FormatFloat(f, 'g', -1, 64) }

// Bool returns the parameter with name, returning false if it is not set. An
// error is returned if the value cannot be parsed as a boolean. Empty values
// are considered true.
func (p Parameters) Bool(name string) (bool, error) { return p.BoolDefault(name, false) }

// BoolDefault returns the parameter with name, or if it is unset, returns the
// def default value. An error is returned if the value cannot be parsed as a
// boolean. Empty values are considered true.
func (p Parameters) BoolDefault(name string, def bool) (bool, error) {
	if s, ok := p[name]; ok {
		if strings.TrimSpace(s) == "" {
			return true, nil
		}
		return strconv.ParseBool(s)
	}

	return def, nil
}

// SetBool sets the parameter name to b.
func (p Parameters) SetBool(name string, b bool) { p[name] = strconv.FormatBool(b) }

// Duration returns the parameter with name, returning zero if it is not set.
// An error is returned if the value cannot be parsed as a time.Duration.
func (p Parameters) Duration(name string) (time.Duration, error) { return p.DurationDefault(name, 0) }

// DurationDefault returns the parameter with name, or if it is unset, returns
// the def default value. An error is returned if the value cannot be parsed as
// a time.Duration.
func (p Parameters) DurationDefault(name string, def time.Duration) (time.Duration, error) {
	if s, ok := p[name]; ok {
		return time.ParseDuration(s)
	}
	return def, nil
}

// SetDuration sets the parameter name to d.
func (p Parameters) SetDuration(name string, d time.Duration) { p[name] = d.String() }
