package pgs

import (
	"io"

	"github.com/golang/protobuf/protoc-gen-go/descriptor"
	"github.com/golang/protobuf/protoc-gen-go/generator"
	"github.com/golang/protobuf/protoc-gen-go/plugin"
)

// ProtocGenGo is a superset of the generator.Generator API from the
// protoc-gen-go library. It exposes many of the members of the original struct,
// but also exposes others that permit easier testing of code that relies upon
// accessing protected members.
type ProtocGenGo interface {
	// Unwrap returns the underlying generator.Generator instance. Typically this
	// is called to access public fields off this struct.
	Unwrap() *generator.Generator

	// The following methods/interfaces match the interface of a protoc-gen-go
	// generator.Generator struct.
	io.Writer
	Error(err error, msgs ...string)
	Fail(msgs ...string)
	ObjectNamed(n string) generator.Object
	GoType(message *generator.Descriptor, field *descriptor.FieldDescriptorProto) (typ string, wire string)
	GoPackageName(importPath generator.GoImportPath) generator.GoPackageName
	P(args ...interface{})
	In()
	Out()

	// The following methods simplify execution in the protoc-gen-star Generator & Gatherer
	prepare(params Parameters)
	generate()
	request() *plugin_go.CodeGeneratorRequest
	setRequest(req *plugin_go.CodeGeneratorRequest)
	response() *plugin_go.CodeGeneratorResponse
	setResponse(res *plugin_go.CodeGeneratorResponse)
}

// Wrap converts a generator.Generator instance into a type that satisfies the
// ProtocGenGo interface.
func Wrap(g *generator.Generator) ProtocGenGo { return &wrappedPGG{g} }

type wrappedPGG struct{ *generator.Generator }

func (pgg *wrappedPGG) Unwrap() *generator.Generator                     { return pgg.Generator }
func (pgg *wrappedPGG) request() *plugin_go.CodeGeneratorRequest         { return pgg.Request }
func (pgg *wrappedPGG) setRequest(req *plugin_go.CodeGeneratorRequest)   { pgg.Request = req }
func (pgg *wrappedPGG) response() *plugin_go.CodeGeneratorResponse       { return pgg.Response }
func (pgg *wrappedPGG) setResponse(res *plugin_go.CodeGeneratorResponse) { pgg.Response = res }

func (pgg *wrappedPGG) prepare(params Parameters) {
	pgg.CommandLineParameters(params.String())
	pgg.WrapTypes()
	pgg.SetPackageNames()
	pgg.BuildTypeNameMap()
}

func (pgg *wrappedPGG) generate() { pgg.GenerateAllFiles() }

var _ ProtocGenGo = (*wrappedPGG)(nil)
