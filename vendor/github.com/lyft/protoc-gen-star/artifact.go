package pgs

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/golang/protobuf/proto"
	plugin_go "github.com/golang/protobuf/protoc-gen-go/plugin"
)

// An Artifact describes the output for a Module. Typically this is the creation
// of a file either directly against the file system or via protoc.
type Artifact interface {
	artifact()
}

// A Template to use for rendering artifacts. Either text/template or
// html/template Template types satisfy this interface.
type Template interface {
	Execute(w io.Writer, data interface{}) error
}

// GeneratorArtifact describes an Artifact that uses protoc for code generation.
// GeneratorArtifacts must be valid UTF8. To create binary files, use one of
// the "custom" Artifact types.
type GeneratorArtifact interface {
	Artifact

	// ProtoFile converts the GeneratorArtifact to a CodeGeneratorResponse_File,
	// which is handed to protoc to actually write the file to disk. An error is
	// returned if Artifact cannot be converted.
	ProtoFile() (*plugin_go.CodeGeneratorResponse_File, error)
}

// TemplateArtifact contains the shared logic used by Artifacts that render
// their contents using a Template.
type TemplateArtifact struct {
	// The Template to use for rendering. Either text/template or html/template
	// Template types are supported.
	Template Template

	// Data is arbitrary data passed into the Template's Execute method.
	Data interface{}
}

func (ta TemplateArtifact) render() (string, error) {
	buf := &bytes.Buffer{}

	if err := ta.Template.Execute(buf, ta.Data); err != nil {
		return "", err
	}

	return buf.String(), nil
}

// A GeneratorFile Artifact describes a file to be generated using protoc.
type GeneratorFile struct {
	GeneratorArtifact

	// Name of the file to generate, relative to the protoc-plugin's generation
	// output directory.
	Name string

	// Contents are the body of the file.
	Contents string

	// Overwrite specifies whether or not this file should replace another file
	// with the same name if a prior Plugin or Module has created one.
	Overwrite bool
}

// ProtoFile satisfies the GeneratorArtifact interface. An error is returned if
// the name field is not a path relative to and within the protoc-plugin's
// generation output directory.
func (f GeneratorFile) ProtoFile() (*plugin_go.CodeGeneratorResponse_File, error) {
	name, err := cleanGeneratorFileName(f.Name)
	if err != nil {
		return nil, err
	}

	return &plugin_go.CodeGeneratorResponse_File{
		Name:    proto.String(name),
		Content: proto.String(f.Contents),
	}, nil
}

// A GeneratorTemplateFile describes a file to be generated using protoc from
// a Template.
type GeneratorTemplateFile struct {
	GeneratorArtifact
	TemplateArtifact

	// Name of the file to generate, relative to the protoc-plugin's generation
	// output directory.
	Name string

	// Overwrite specifies whether or not this file should replace another file
	// with the same name if a prior Plugin or Module has created one.
	Overwrite bool
}

// ProtoFile satisfies the GeneratorArtifact interface. An error is returned if
// the name field is not a path relative to and within the protoc-plugin's
// generation output directory or if there is an error executing the Template.
func (f GeneratorTemplateFile) ProtoFile() (*plugin_go.CodeGeneratorResponse_File, error) {
	name, err := cleanGeneratorFileName(f.Name)
	if err != nil {
		return nil, err
	}

	content, err := f.render()
	if err != nil {
		return nil, err
	}

	return &plugin_go.CodeGeneratorResponse_File{
		Name:    proto.String(name),
		Content: proto.String(content),
	}, nil
}

// A GeneratorAppend Artifact appends content to the end of the specified protoc
// generated file. This Artifact can only be used if another Module generates a
// file with the same name.
type GeneratorAppend struct {
	GeneratorArtifact

	// Filename of the file to append to, relative to the protoc-plugin's generation
	// output directory.
	FileName string

	// Contents to be appended to the file
	Contents string
}

// ProtoFile satisfies the GeneratorArtifact interface. An error is returned if
// the name field is not a path relative to and within the protoc-plugin's
// generation output directory.
func (f GeneratorAppend) ProtoFile() (*plugin_go.CodeGeneratorResponse_File, error) {
	if _, err := cleanGeneratorFileName(f.FileName); err != nil {
		return nil, err
	}

	return &plugin_go.CodeGeneratorResponse_File{
		Content: proto.String(f.Contents),
	}, nil
}

// A GeneratorTemplateAppend appends content to a protoc-generated file from a
// Template. See GeneratorAppend for limitations.
type GeneratorTemplateAppend struct {
	GeneratorArtifact
	TemplateArtifact

	// Filename of the file to append to, relative to the protoc-plugin's generation
	// output directory.
	FileName string
}

// ProtoFile satisfies the GeneratorArtifact interface. An error is returned if
// the name field is not a path relative to and within the protoc-plugin's
// generation output directory or if there is an error executing the Template.
func (f GeneratorTemplateAppend) ProtoFile() (*plugin_go.CodeGeneratorResponse_File, error) {
	if _, err := cleanGeneratorFileName(f.FileName); err != nil {
		return nil, err
	}

	content, err := f.render()
	if err != nil {
		return nil, err
	}

	return &plugin_go.CodeGeneratorResponse_File{
		Content: proto.String(content),
	}, nil
}

// A GeneratorInjection Artifact inserts content into a protoc-generated file
// at the specified insertion point. The target file does not need to be
// generated by this protoc-plugin but must be generated by a prior plugin
// executed by protoc.
type GeneratorInjection struct {
	GeneratorArtifact

	// Filename of the file to inject into, relative to the protoc-plugin's
	// generation output directory.
	FileName string

	// The name of the insertion point to inject into
	InsertionPoint string

	// Contents to be inject into the file
	Contents string
}

// ProtoFile satisfies the GeneratorArtifact interface. An error is returned if
// the name field is not a path relative to and within the protoc-plugin's
// generation output directory.
func (f GeneratorInjection) ProtoFile() (*plugin_go.CodeGeneratorResponse_File, error) {
	name, err := cleanGeneratorFileName(f.FileName)
	if err != nil {
		return nil, err
	}

	return &plugin_go.CodeGeneratorResponse_File{
		Name:           proto.String(name),
		InsertionPoint: proto.String(f.InsertionPoint),
		Content:        proto.String(f.Contents),
	}, nil
}

// A GeneratorTemplateInjection Artifact inserts content rendered from a
// Template into protoc-generated file at the specified insertion point. The
// target file does not need to be generated by this protoc-plugin but must be
// generated by a prior plugin executed by protoc.
type GeneratorTemplateInjection struct {
	GeneratorArtifact
	TemplateArtifact

	// Filename of the file to inject into, relative to the protoc-plugin's
	// generation output directory.
	FileName string

	// The name of the insertion point to inject into
	InsertionPoint string
}

// ProtoFile satisfies the GeneratorArtifact interface. An error is returned if
// the name field is not a path relative to and within the protoc-plugin's
// generation output directory or if there is an error executing the Template.
func (f GeneratorTemplateInjection) ProtoFile() (*plugin_go.CodeGeneratorResponse_File, error) {
	name, err := cleanGeneratorFileName(f.FileName)
	if err != nil {
		return nil, err
	}

	content, err := f.render()
	if err != nil {
		return nil, err
	}

	return &plugin_go.CodeGeneratorResponse_File{
		Name:           proto.String(name),
		InsertionPoint: proto.String(f.InsertionPoint),
		Content:        proto.String(content),
	}, nil
}

// CustomFile Artifacts are files generated directly against the file system,
// and do not use protoc for the generation. CustomFiles should be used over
// GeneratorFiles when custom permissions need to be set (such as executable
// scripts or read-only configs) or when the file needs to be created outside
// of the protoc-plugin's generation output directory.
type CustomFile struct {
	Artifact

	// Name of the file to generate. If relative, the file is created relative to
	// the directory in which protoc is executed. If absolute, the file is
	// created as specified.
	Name string

	// Contents are the body of the file.
	Contents string

	// Perms are the file permission to generate the file with. Note that the
	// umask of the process will be applied against these permissions.
	Perms os.FileMode

	// Overwrite indicates if an existing file on disk should be overwritten by
	// this file.
	Overwrite bool
}

// CustomTemplateFile Artifacts are files generated from a Template directly
// against the file system, and do not use protoc for the generation.
// CustomFiles should be used over GeneratorFiles when custom permissions need
// to be set (such as executable scripts or read-only configs) or when the file
// needs to be created outside of the protoc-plugin's generation output
// directory.
type CustomTemplateFile struct {
	Artifact
	TemplateArtifact

	// Name of the file to generate. If relative, the file is created relative to
	// the directory in which protoc is executed. If absolute, the file is
	// created as specified.
	Name string

	// Perms are the file permission to generate the file with. Note that the
	// umask of the process will be applied against these permissions.
	Perms os.FileMode

	// Overwrite indicates if an existing file on disk should be overwritten by
	// this file.
	Overwrite bool
}

func cleanGeneratorFileName(name string) (string, error) {
	if filepath.IsAbs(name) {
		return "", errors.New("generator file names must be relative paths")
	}

	if name = filepath.Clean(name); name == "." || strings.HasPrefix(name, "..") {
		return "", errors.New("generator file names must be not contain . or .. within them")
	}

	return name, nil
}

// GeneratorError Artifacts are strings describing errors that happened in the
// code generation, but have not been fatal. They'll be used to populate the
// CodeGeneratorResponse's `error` field. Since that field is a string, multiple
// GeneratorError Artifacts will be concatenated.
type GeneratorError struct {
	Artifact

	Message string
}
