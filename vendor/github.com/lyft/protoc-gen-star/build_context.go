package pgs

import "path/filepath"

// BuildContext tracks code generation relative to an output path. By default,
// BuildContext's path is relative to the output location specified when
// executing protoc (an absolute path to this location is not available within
// protoc plugins). Specifying a custom output path permits using an absolute
// path and or a different location from protoc's designated output location.
type BuildContext interface {
	DebuggerCommon

	// OutputPath is the path where files should be generated to. This path may
	// be relative or absolute, if it is relative, the path is based off the
	// (unknown) output destination specified during execution of protoc. If it
	// is absolute, the path may be outside of the target directory for protoc.
	OutputPath() string

	// JoinPath returns name relative to the value of OutputPath.
	JoinPath(name ...string) string

	// Push adds an arbitrary prefix to the Debugger output. The Outpath value is
	// unchanged.
	Push(prefix string) BuildContext

	// PushDir changes the BuildContext's OutputPath to dir. If dir is relative,
	// it is applied relative to the current value of OutputPath.
	PushDir(dir string) BuildContext

	// Pop returns the previous state of the BuildContext. This may or may not
	// change the value of OutputPath. This method will cause the plugin to fail
	// if the root context is popped.
	Pop() BuildContext

	// PopDir behaves like Pop but returns the last previous state of OutputPath,
	// skipping over any prefix changes in-between. If at the root context, this
	// method will always return the root context.
	PopDir() BuildContext

	// Parameters returns the command line parameters passed in from protoc,
	// mutated with any provided ParamMutators via InitOptions.
	Parameters() Parameters
}

// Context creates a new BuildContext with the provided debugger and initial
// output path. For protoc-gen-go plugins, output is typically ".", while
// Module's may use a custom path.
func Context(d Debugger, params Parameters, output string) BuildContext {
	return rootContext{
		dirContext: dirContext{
			prefixContext: prefixContext{parent: nil, d: d},
			p:             filepath.Clean(output),
		},
		params: params,
	}
}

func initPrefixContext(c BuildContext, d Debugger, prefix string) prefixContext {
	return prefixContext{
		parent: c,
		d:      d.Push(prefix),
	}
}

func (c prefixContext) Log(v ...interface{})                   { c.d.Log(v...) }
func (c prefixContext) Logf(format string, v ...interface{})   { c.d.Logf(format, v...) }
func (c prefixContext) Debug(v ...interface{})                 { c.d.Debug(v...) }
func (c prefixContext) Debugf(format string, v ...interface{}) { c.d.Debugf(format, v...) }
func (c prefixContext) Fail(v ...interface{})                  { c.d.Fail(v...) }
func (c prefixContext) Failf(format string, v ...interface{})  { c.d.Failf(format, v...) }
func (c prefixContext) CheckErr(err error, v ...interface{})   { c.d.CheckErr(err, v...) }
func (c prefixContext) Assert(expr bool, v ...interface{})     { c.d.Assert(expr, v...) }
func (c prefixContext) Exit(code int)                          { c.d.Exit(code) }

func (c prefixContext) Parameters() Parameters          { return c.parent.Parameters() }
func (c prefixContext) OutputPath() string              { return c.parent.OutputPath() }
func (c prefixContext) JoinPath(name ...string) string  { return c.parent.JoinPath(name...) }
func (c prefixContext) PushDir(dir string) BuildContext { return initDirContext(c, c.d, dir) }
func (c prefixContext) Push(prefix string) BuildContext { return initPrefixContext(c, c.d, prefix) }
func (c prefixContext) Pop() BuildContext               { return c.parent }
func (c prefixContext) PopDir() BuildContext            { return c.parent.PopDir() }

type dirContext struct {
	prefixContext
	p string
}

func initDirContext(c BuildContext, d Debugger, dir string) dirContext {
	dc := dirContext{
		prefixContext: prefixContext{parent: c, d: d},
		p:             filepath.Clean(dir),
	}

	c.Debug("push:", dc.parent.OutputPath(), "→", dc.OutputPath())

	return dc
}

func (c dirContext) OutputPath() string              { return filepath.Join(c.parent.OutputPath(), c.p) }
func (c dirContext) PushDir(dir string) BuildContext { return initDirContext(c, c.d, dir) }
func (c dirContext) Push(prefix string) BuildContext { return initPrefixContext(c, c.d, prefix) }
func (c dirContext) PopDir() BuildContext            { return c.Pop() }
func (c dirContext) Pop() BuildContext {
	c.Debug("pop:", c.OutputPath(), "→", c.parent.OutputPath())
	return c.parent
}

func (c dirContext) JoinPath(name ...string) string {
	return filepath.Join(append([]string{c.OutputPath()}, name...)...)
}

type prefixContext struct {
	parent BuildContext
	d      Debugger
}

type rootContext struct {
	dirContext
	params Parameters
}

func (c rootContext) OutputPath() string              { return c.p }
func (c rootContext) PushDir(dir string) BuildContext { return initDirContext(c, c.d, dir) }
func (c rootContext) Push(prefix string) BuildContext { return initPrefixContext(c, c.d, prefix) }
func (c rootContext) Parameters() Parameters          { return c.params }
func (c rootContext) PopDir() BuildContext            { return c }
func (c rootContext) Pop() BuildContext {
	c.Fail("attempted to pop the root build context")
	return nil
}

func (c rootContext) JoinPath(name ...string) string {
	return filepath.Join(append([]string{c.OutputPath()}, name...)...)
}
