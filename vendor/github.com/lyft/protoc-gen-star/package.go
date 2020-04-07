package pgs

import "github.com/golang/protobuf/protoc-gen-go/descriptor"

// Package is a container that encapsulates all the files under a single
// package namespace.
type Package interface {
	Node

	// The name of the proto package.
	ProtoName() Name

	// All the files loaded for this Package
	Files() []File

	addFile(f File)

	setComments(c string)
}

type pkg struct {
	fd    *descriptor.FileDescriptorProto
	files []File

	comments string
}

func (p *pkg) ProtoName() Name  { return Name(p.fd.GetPackage()) }
func (p *pkg) Comments() string { return p.comments }

func (p *pkg) Files() []File { return p.files }

func (p *pkg) accept(v Visitor) (err error) {
	if v == nil {
		return nil
	}

	if v, err = v.VisitPackage(p); err != nil || v == nil {
		return
	}

	for _, f := range p.Files() {
		if err = f.accept(v); err != nil {
			return
		}
	}

	return
}

func (p *pkg) addFile(f File) {
	f.setPackage(p)
	p.files = append(p.files, f)
}

func (p *pkg) setComments(comments string) {
	p.comments = comments
}
