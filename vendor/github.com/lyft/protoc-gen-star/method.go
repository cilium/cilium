package pgs

import (
	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/protoc-gen-go/descriptor"
)

// Method describes a method on a proto service
type Method interface {
	Entity

	// Descriptor returns the underlying proto descriptor for this.
	Descriptor() *descriptor.MethodDescriptorProto

	// Service returns the parent service for this.
	Service() Service

	// Input returns the Message representing the input type for this.
	Input() Message

	// Output returns the Message representing the output type for this.
	Output() Message

	// ClientStreaming indicates if this method allows clients to stream inputs.
	ClientStreaming() bool

	// ServerStreaming indicates if this method allows servers to stream outputs.
	ServerStreaming() bool

	setService(Service)
}

type method struct {
	desc    *descriptor.MethodDescriptorProto
	fqn     string
	service Service

	in, out Message

	info SourceCodeInfo
}

func (m *method) Name() Name                                    { return Name(m.desc.GetName()) }
func (m *method) FullyQualifiedName() string                    { return m.fqn }
func (m *method) Syntax() Syntax                                { return m.service.Syntax() }
func (m *method) Package() Package                              { return m.service.Package() }
func (m *method) File() File                                    { return m.service.File() }
func (m *method) BuildTarget() bool                             { return m.service.BuildTarget() }
func (m *method) SourceCodeInfo() SourceCodeInfo                { return m.info }
func (m *method) Descriptor() *descriptor.MethodDescriptorProto { return m.desc }
func (m *method) Service() Service                              { return m.service }
func (m *method) Input() Message                                { return m.in }
func (m *method) Output() Message                               { return m.out }
func (m *method) ClientStreaming() bool                         { return m.desc.GetClientStreaming() }
func (m *method) ServerStreaming() bool                         { return m.desc.GetServerStreaming() }
func (m *method) BiDirStreaming() bool                          { return m.ClientStreaming() && m.ServerStreaming() }

func (m *method) Imports() (i []File) {
	mine := m.File().Name()
	input := m.Input().File()
	output := m.Output().File()

	if mine != input.Name() {
		i = append(i, input)
	}
	if mine != output.Name() && input.Name() != output.Name() {
		i = append(i, output)
	}
	return
}

func (m *method) Extension(desc *proto.ExtensionDesc, ext interface{}) (ok bool, err error) {
	return extension(m.desc.GetOptions(), desc, &ext)
}

func (m *method) accept(v Visitor) (err error) {
	if v == nil {
		return
	}

	_, err = v.VisitMethod(m)
	return
}

func (m *method) setService(s Service) { m.service = s }

func (m *method) childAtPath(path []int32) Entity {
	if len(path) == 0 {
		return m
	}
	return nil
}

func (m *method) addSourceCodeInfo(info SourceCodeInfo) { m.info = info }

var m Method = (*method)(nil)
