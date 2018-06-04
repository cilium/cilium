package pgs

// Node represents any member of the proto descriptor AST. Typically, the
// highest level Node is the Package.
type Node interface {
	accept(Visitor) error
}

// A Visitor exposes methods to walk an AST Node and its children in a depth-
// first manner. If the returned Visitor v is non-nil, it will be used to
// descend into the children of the current node. If nil, those children will
// be skipped. Any error returned will immediately halt execution.
type Visitor interface {
	VisitPackage(Package) (v Visitor, err error)
	VisitFile(File) (v Visitor, err error)
	VisitMessage(Message) (v Visitor, err error)
	VisitEnum(Enum) (v Visitor, err error)
	VisitEnumValue(EnumValue) (v Visitor, err error)
	VisitField(Field) (v Visitor, err error)
	VisitOneOf(OneOf) (v Visitor, err error)
	VisitService(Service) (v Visitor, err error)
	VisitMethod(Method) (v Visitor, err error)
}

// Walk applies a depth-first visitor pattern with v against Node n.
func Walk(v Visitor, n Node) error { return n.accept(v) }

type nilVisitor struct{}

// NilVisitor returns a Visitor that always responds with (nil, nil) for all
// methods. This is useful as an anonymous embedded struct to satisfy the
// Visitor interface for implementations that don't require visiting every Node
// type. NilVisitor should be used over PassThroughVisitor if short-circuiting
// behavior is desired.
func NilVisitor() Visitor { return nilVisitor{} }

func (nv nilVisitor) VisitPackage(p Package) (v Visitor, err error)     { return nil, nil }
func (nv nilVisitor) VisitFile(f File) (v Visitor, err error)           { return nil, nil }
func (nv nilVisitor) VisitMessage(m Message) (v Visitor, err error)     { return nil, nil }
func (nv nilVisitor) VisitEnum(e Enum) (v Visitor, err error)           { return nil, nil }
func (nv nilVisitor) VisitEnumValue(e EnumValue) (v Visitor, err error) { return nil, nil }
func (nv nilVisitor) VisitField(f Field) (v Visitor, err error)         { return nil, nil }
func (nv nilVisitor) VisitOneOf(o OneOf) (v Visitor, err error)         { return nil, nil }
func (nv nilVisitor) VisitService(s Service) (v Visitor, err error)     { return nil, nil }
func (nv nilVisitor) VisitMethod(m Method) (v Visitor, err error)       { return nil, nil }

var _ Visitor = nilVisitor{}

type passVisitor struct {
	v Visitor
}

// PassThroughVisitor returns a Visitor that always responds with (v, nil) for
// all methods. This is useful as an anonymous embedded struct to satisfy the
// Visitor interface for implementations that need access to deep child nodes
// (eg, EnumValue, Field, Method) without implementing each method of the
// interface explicitly.
func PassThroughVisitor(v Visitor) Visitor { return passVisitor{v: v} }

func (pv passVisitor) VisitPackage(Package) (v Visitor, err error)     { return pv.v, nil }
func (pv passVisitor) VisitFile(File) (v Visitor, err error)           { return pv.v, nil }
func (pv passVisitor) VisitMessage(Message) (v Visitor, err error)     { return pv.v, nil }
func (pv passVisitor) VisitEnum(Enum) (v Visitor, err error)           { return pv.v, nil }
func (pv passVisitor) VisitEnumValue(EnumValue) (v Visitor, err error) { return pv.v, nil }
func (pv passVisitor) VisitField(Field) (v Visitor, err error)         { return pv.v, nil }
func (pv passVisitor) VisitOneOf(OneOf) (v Visitor, err error)         { return pv.v, nil }
func (pv passVisitor) VisitService(Service) (v Visitor, err error)     { return pv.v, nil }
func (pv passVisitor) VisitMethod(Method) (v Visitor, err error)       { return pv.v, nil }

var (
	_ Visitor = nilVisitor{}
	_ Visitor = passVisitor{}
)
