package pgs

import (
	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/protoc-gen-go/descriptor"
)

// Service describes an proto service
type Service interface {
	Entity

	// Descriptor returns the underlying proto descriptor for this service
	Descriptor() *descriptor.ServiceDescriptorProto

	// Methods returns each rpc method exposed by this service
	Methods() []Method

	setFile(f File)
	addMethod(m Method)
}

type service struct {
	desc    *descriptor.ServiceDescriptorProto
	methods []Method
	file    File

	comments string
}

func (s *service) Name() Name                                     { return Name(s.desc.GetName()) }
func (s *service) FullyQualifiedName() string                     { return fullyQualifiedName(s.file, s) }
func (s *service) Syntax() Syntax                                 { return s.file.Syntax() }
func (s *service) Package() Package                               { return s.file.Package() }
func (s *service) File() File                                     { return s.file }
func (s *service) BuildTarget() bool                              { return s.file.BuildTarget() }
func (s *service) Comments() string                               { return s.comments }
func (s *service) Descriptor() *descriptor.ServiceDescriptorProto { return s.desc }

func (s *service) Extension(desc *proto.ExtensionDesc, ext interface{}) (bool, error) {
	return extension(s.desc.GetOptions(), desc, &ext)
}

func (s *service) Imports() (i []Package) {
	for _, m := range s.methods {
		i = append(i, m.Imports()...)
	}
	return
}

func (s *service) Methods() []Method {
	m := make([]Method, len(s.methods))
	copy(m, s.methods)
	return m
}

func (s *service) setFile(f File) { s.file = f }

func (s *service) addMethod(m Method) {
	m.setService(s)
	s.methods = append(s.methods, m)
}

func (s *service) accept(v Visitor) (err error) {
	if v == nil {
		return
	}

	if v, err = v.VisitService(s); err != nil || v == nil {
		return
	}

	for _, m := range s.methods {
		if err = m.accept(v); err != nil {
			return
		}
	}

	return
}
