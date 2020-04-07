package pgs

import (
	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/protoc-gen-go/descriptor"
)

// Service describes a proto service definition (typically, gRPC)
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
	fqn     string

	info SourceCodeInfo
}

func (s *service) Name() Name                                     { return Name(s.desc.GetName()) }
func (s *service) FullyQualifiedName() string                     { return s.fqn }
func (s *service) Syntax() Syntax                                 { return s.file.Syntax() }
func (s *service) Package() Package                               { return s.file.Package() }
func (s *service) File() File                                     { return s.file }
func (s *service) BuildTarget() bool                              { return s.file.BuildTarget() }
func (s *service) SourceCodeInfo() SourceCodeInfo                 { return s.info }
func (s *service) Descriptor() *descriptor.ServiceDescriptorProto { return s.desc }

func (s *service) Extension(desc *proto.ExtensionDesc, ext interface{}) (bool, error) {
	return extension(s.desc.GetOptions(), desc, &ext)
}

func (s *service) Imports() (i []File) {
	// Mapping for avoiding duplicate entries
	mp := make(map[string]File, len(s.methods))
	for _, m := range s.methods {
		for _, imp := range m.Imports() {
			mp[imp.File().Name().String()] = imp
		}
	}
	for _, f := range mp {
		i = append(i, f)
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

func (s *service) childAtPath(path []int32) Entity {
	switch {
	case len(path) == 0:
		return s
	case len(path)%2 != 0:
		return nil
	case path[0] == serviceTypeMethodPath:
		return s.methods[path[1]].childAtPath(path[2:])
	default:
		return nil
	}
}

func (s *service) addSourceCodeInfo(info SourceCodeInfo) { s.info = info }

var _ Service = (*service)(nil)
