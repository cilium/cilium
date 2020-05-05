package pgs

import "os"

// Module describes the interface for a domain-specific code generation module
// that can be registered with the PG* generator.
type Module interface {
	// The Name of the Module, used when establishing the build context and used
	// as the base prefix for all debugger output.
	Name() string

	// InitContext is called on a Module with a pre-configured BuildContext that
	// should be stored and used by the Module.
	InitContext(c BuildContext)

	// Execute is called on the module with the target Files as well as all
	// loaded Packages from the gatherer. The module should return a slice of
	// Artifacts that it would like to be generated.
	Execute(targets map[string]File, packages map[string]Package) []Artifact
}

// ModuleBase provides utility methods and a base implementation for a
// protoc-gen-star Module. ModuleBase should be used as an anonymously embedded
// field of an actual Module implementation. The only methods that need to be
// overridden are Name and Execute.
//
//   type MyModule {
//       *pgs.ModuleBase
//   }
//
//   func InitMyModule() *MyModule { return &MyModule{ &pgs.ModuleBase{} } }
//
//   func (m *MyModule) Name() string { return "MyModule" }
//
//   func (m *MyModule) Execute(...) []pgs.Artifact { ... }
//
type ModuleBase struct {
	BuildContext
	artifacts []Artifact
}

// InitContext populates this Module with the BuildContext from the parent
// Generator, allowing for easy debug logging, error checking, and output path
// management. This method is called prior to Execute for modules registered
// with the generator.
func (m *ModuleBase) InitContext(c BuildContext) {
	m.BuildContext = c
	m.Debug("initializing")
}

// Name satisfies the Module interface, however this method will panic and must
// be overridden by a parent struct.
func (m *ModuleBase) Name() string {
	panic("Name method is not implemented for this module")
}

// Execute satisfies the Module interface, however this method will fail and
// must be overridden by a parent struct.
func (m *ModuleBase) Execute(targets map[string]File, packages map[string]Package) []Artifact {
	m.Fail("Execute method is not implemented for this module")
	return m.Artifacts()
}

// Push adds a prefix to the Module's BuildContext. Pop should be called when
// the context is complete.
func (m *ModuleBase) Push(prefix string) BuildContext {
	m.BuildContext = m.BuildContext.Push(prefix)
	return m
}

// PushDir changes the OutputPath of the Module's BuildContext. Pop (or PopDir)
// should be called when that context is complete.
func (m *ModuleBase) PushDir(dir string) BuildContext {
	m.BuildContext = m.BuildContext.PushDir(dir)
	return m
}

// Pop removes the last push from the Module's BuildContext. This method should
// only be called after a paired Push or PushDir.
func (m *ModuleBase) Pop() BuildContext {
	m.BuildContext = m.BuildContext.Pop()
	return m
}

// PopDir removes the last PushDir from the Module's BuildContext. This method
// should only be called after a paired PushDir.
func (m *ModuleBase) PopDir() BuildContext {
	m.BuildContext = m.BuildContext.PopDir()
	return m
}

// Artifacts returns the slice of generation artifacts that have been captured
// by the Module. This method should/can be the return value of its Execute
// method. Subsequent calls will return a nil slice until more artifacts are
// added.
func (m *ModuleBase) Artifacts() []Artifact {
	out := m.artifacts
	m.artifacts = nil
	return out
}

// AddArtifact adds an Artifact to this Module's collection of generation
// artifacts. This method is available as a convenience but the other Add &
// Overwrite methods should be used preferentially.
func (m *ModuleBase) AddArtifact(a ...Artifact) { m.artifacts = append(m.artifacts, a...) }

// AddGeneratorFile adds a file with the provided name and contents to the code
// generation response payload to protoc. Name must be a path relative to and
// within the protoc-plugin's output destination, which may differ from the
// BuildContext's OutputPath value. If another Module or Plugin has added a
// file with the same name, protoc will produce an error.
func (m *ModuleBase) AddGeneratorFile(name, content string) {
	m.AddArtifact(GeneratorFile{
		Name:     name,
		Contents: content,
	})
}

// OverwriteGeneratorFile behaves the same as AddGeneratorFile, however if a
// previously executed Module has created a file with the same name, it will be
// overwritten with this one.
func (m *ModuleBase) OverwriteGeneratorFile(name, content string) {
	m.AddArtifact(GeneratorFile{
		Name:      name,
		Contents:  content,
		Overwrite: true,
	})
}

// AddGeneratorTemplateFile behaves the same as AddGeneratorFile, however the
// contents are rendered from the provided tpl and data.
func (m *ModuleBase) AddGeneratorTemplateFile(name string, tpl Template, data interface{}) {
	m.AddArtifact(GeneratorTemplateFile{
		Name: name,
		TemplateArtifact: TemplateArtifact{
			Template: tpl,
			Data:     data,
		},
	})
}

// OverwriteGeneratorTemplateFile behaves the same as OverwriteGeneratorFile,
// however the contents are rendered from the provided tpl and data.
func (m *ModuleBase) OverwriteGeneratorTemplateFile(name string, tpl Template, data interface{}) {
	m.AddArtifact(GeneratorTemplateFile{
		Name:      name,
		Overwrite: true,
		TemplateArtifact: TemplateArtifact{
			Template: tpl,
			Data:     data,
		},
	})
}

// AddGeneratorAppend attempts to append content to the specified file name.
// Name must be a path relative to and within the protoc-plugin's output
// destination, which may differ from the BuildContext's OutputPath value. If
// the file is not generated by this protoc-plugin, execution will fail.
func (m *ModuleBase) AddGeneratorAppend(name, content string) {
	m.AddArtifact(GeneratorAppend{
		FileName: name,
		Contents: content,
	})
}

// AddGeneratorTemplateAppend behaves the same as AddGeneratorAppend, however
// the contents are rendered from the provided tpl and data.
func (m *ModuleBase) AddGeneratorTemplateAppend(name string, tpl Template, data interface{}) {
	m.AddArtifact(GeneratorTemplateAppend{
		FileName: name,
		TemplateArtifact: TemplateArtifact{
			Template: tpl,
			Data:     data,
		},
	})
}

// AddGeneratorInjection attempts to inject content into the file with name at
// the specified insertion point. Name must be a path relative to and within
// the protoc-plugin's output destination, which may differ from the
// BuildContext's OutputPath value. The file does not need to be generated by
// this protoc-plugin but the generating plugin must be called first in the
// protoc execution.
//
// See: https://godoc.org/github.com/golang/protobuf/protoc-gen-go/plugin#CodeGeneratorResponse_File
func (m *ModuleBase) AddGeneratorInjection(name, point, content string) {
	m.AddArtifact(GeneratorInjection{
		FileName:       name,
		InsertionPoint: point,
		Contents:       content,
	})
}

// AddGeneratorTemplateInjection behaves the same as AddGeneratorInjection,
// however the contents are rendered from the provided tpl and data.
func (m *ModuleBase) AddGeneratorTemplateInjection(name, point string, tpl Template, data interface{}) {
	m.AddArtifact(GeneratorTemplateInjection{
		FileName:       name,
		InsertionPoint: point,
		TemplateArtifact: TemplateArtifact{
			Template: tpl,
			Data:     data,
		},
	})
}

// AddCustomFile creates a file directly on the file system with the provided
// content and perms. Unlike AddGeneratorFile, this method does not use protoc
// to generate the file. If name is a relative path, it is related to the
// directory in which protoc was executed; name can also be an absolute path.
// If a file already exists with the specified name, the file will not be
// created and there will be no generation error.
func (m *ModuleBase) AddCustomFile(name, content string, perms os.FileMode) {
	m.AddArtifact(CustomFile{
		Name:     name,
		Contents: content,
		Perms:    perms,
	})
}

// OverwriteCustomFile behaves the same as AddCustomFile, however if the file
// already exists, it will be overwritten with this one.
func (m *ModuleBase) OverwriteCustomFile(name, content string, perms os.FileMode) {
	m.AddArtifact(CustomFile{
		Name:      name,
		Contents:  content,
		Perms:     perms,
		Overwrite: true,
	})
}

// AddCustomTemplateFile behaves the same as AddCustomFile, however the
// contents are rendered from the provided tpl and data.
func (m *ModuleBase) AddCustomTemplateFile(name string, tpl Template, data interface{}, perms os.FileMode) {
	m.AddArtifact(CustomTemplateFile{
		Name:  name,
		Perms: perms,
		TemplateArtifact: TemplateArtifact{
			Template: tpl,
			Data:     data,
		},
	})
}

// OverwriteCustomTemplateFile behaves the same as OverwriteCustomFile, however
// the contents are rendered from the provided tpl and data.
func (m *ModuleBase) OverwriteCustomTemplateFile(name string, tpl Template, data interface{}, perms os.FileMode) {
	m.AddArtifact(CustomTemplateFile{
		Name:      name,
		Perms:     perms,
		Overwrite: true,
		TemplateArtifact: TemplateArtifact{
			Template: tpl,
			Data:     data,
		},
	})
}

// AddError adds a string to the `errors` field of the created
// CodeGeneratorResponse. Multiple calls to AddError will cause the errors to
// be concatenated (separated by "; ").
func (m *ModuleBase) AddError(message string) {
	m.AddArtifact(GeneratorError{Message: message})
}

var _ Module = (*ModuleBase)(nil)
