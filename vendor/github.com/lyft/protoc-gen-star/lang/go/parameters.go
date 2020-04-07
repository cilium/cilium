package pgsgo

import (
	"fmt"
	"strings"

	pgs "github.com/lyft/protoc-gen-star"
)

const (
	importPrefixKey    = "import_prefix"
	importPathKey      = "import_path"
	importMapKeyPrefix = "M"
	pathTypeKey        = "paths"
	pluginsKey         = "plugins"
	pluginsSep         = "+"
)

// PathType describes how the generated output file paths should be constructed.
type PathType string

const (
	// ImportPathRelative is the default and outputs the file based off the go
	// import path defined in the go_package option.
	ImportPathRelative PathType = ""

	// SourceRelative indicates files should be output relative to the path of
	// the source file.
	SourceRelative PathType = "source_relative"
)

// Plugins returns the sub-plugins enabled for this protoc plugin. If the all
// value is true, all registered plugins are considered enabled (ie, protoc was
// called with an empty "plugins" parameter). Otherwise, plugins contains the
// list of plugins enabled by name.
func Plugins(p pgs.Parameters) (plugins []string, all bool) {
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
func HasPlugin(p pgs.Parameters, name string) bool {
	plugins, all := Plugins(p)
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
func AddPlugin(p pgs.Parameters, name ...string) {
	if len(name) == 0 {
		return
	}

	plugins, all := Plugins(p)
	if all {
		return
	}

	p.SetStr(pluginsKey, strings.Join(append(plugins, name...), pluginsSep))
}

// EnableAllPlugins changes the parameters to enable all registered sub-plugins.
func EnableAllPlugins(p pgs.Parameters) { p.SetStr(pluginsKey, "") }

// ImportPrefix returns the protoc-gen-go parameter. This prefix is added onto
// the beginning of all Go import paths. This is useful for things like
// generating protos in a subdirectory, or regenerating vendored protobufs
// in-place. By default, this method returns an empty string.
//
// See: https://github.com/golang/protobuf#parameters
func ImportPrefix(p pgs.Parameters) string { return p.Str(importPrefixKey) }

// SetImportPrefix sets the protoc-gen-go ImportPrefix parameter. This is
// useful for overriding the behavior of the ImportPrefix at runtime.
func SetImportPrefix(p pgs.Parameters, prefix string) { p.SetStr(importPrefixKey, prefix) }

// ImportPath returns the protoc-gen-go parameter. This value is used as the
// package if the input proto files do not declare a go_package option. If it
// contains slashes, everything up to the rightmost slash is ignored.
//
// See: https://github.com/golang/protobuf#parameters
func ImportPath(p pgs.Parameters) string { return p.Str(importPathKey) }

// SetImportPath sets the protoc-gen-go ImportPath parameter. This is useful
// for overriding the behavior of the ImportPath at runtime.
func SetImportPath(p pgs.Parameters, path string) { p.SetStr(importPathKey, path) }

// Paths returns the protoc-gen-go parameter. This value is used to switch the
// mode used to determine the output paths of the generated code. By default,
// paths are derived from the import path specified by go_package. It can be
// overridden to be "source_relative", ignoring the import path using the
// source path exclusively.
func Paths(p pgs.Parameters) PathType { return PathType(p.Str(pathTypeKey)) }

// SetPaths sets the protoc-gen-go Paths parameter. This is useful for
// overriding the behavior of Paths at runtime.
func SetPaths(p pgs.Parameters, pt PathType) { p.SetStr(pathTypeKey, string(pt)) }

// MappedImport returns the protoc-gen-go import overrides for the specified proto
// file. Each entry in the map keys off a proto file (as loaded by protoc) with
// values of the Go package to use. These values will be prefixed with the
// value of ImportPrefix when generating the Go code.
func MappedImport(p pgs.Parameters, proto string) (string, bool) {
	imp, ok := p[fmt.Sprintf("%s%s", importMapKeyPrefix, proto)]
	return imp, ok
}

// AddImportMapping adds a proto file to Go package import mapping to the
// parameters.
func AddImportMapping(p pgs.Parameters, proto, pkg string) {
	p[fmt.Sprintf("%s%s", importMapKeyPrefix, proto)] = pkg
}
