package pgs

// FieldTypeElem describes a component of a FieldType. This type only shows up
// in repeated and map FieldTypes.
type FieldTypeElem interface {
	// ParentType returns the parent FieldType that holds this element.
	ParentType() FieldType

	// ProtoType returns the ProtoType describing this component.
	ProtoType() ProtoType

	// IsEmbed returns true if the component is an embedded message.
	IsEmbed() bool

	// IsEnum returns true if the component is an enum value.
	IsEnum() bool

	// Name returns the TypeName describing this component (independent of the
	// parent FieldType).
	Name() TypeName

	// Imports includes all external packages required by this field.
	Imports() []Package

	// Enum returns the Enum associated with this FieldTypeElem. If IsEnum
	// returns false, this value will be nil.
	Enum() Enum

	// Embed returns the embedded Message associated with this FieldTypeElem. If
	// IsEmbed returns false, this value will be nil.
	Embed() Message

	setType(t FieldType)
}

type scalarE struct {
	typ   FieldType
	ptype ProtoType
	name  TypeName
}

func (s *scalarE) ParentType() FieldType { return s.typ }
func (s *scalarE) ProtoType() ProtoType  { return s.ptype }
func (s *scalarE) IsEmbed() bool         { return false }
func (s *scalarE) IsEnum() bool          { return false }
func (s *scalarE) Name() TypeName        { return s.name }
func (s *scalarE) setType(t FieldType)   { s.typ = t }
func (s *scalarE) Imports() []Package    { return nil }
func (s *scalarE) Enum() Enum            { return nil }
func (s *scalarE) Embed() Message        { return nil }

type enumE struct {
	*scalarE
	enum Enum
}

func (e *enumE) IsEnum() bool { return true }
func (e *enumE) Enum() Enum   { return e.enum }

func (e *enumE) Imports() []Package {
	if pkg := e.enum.Package(); pkg.GoName() != e.ParentType().Field().Package().GoName() {
		return []Package{pkg}
	}
	return nil
}

type embedE struct {
	*scalarE
	msg Message
}

func (e *embedE) IsEmbed() bool  { return true }
func (e *embedE) Embed() Message { return e.msg }

func (e *embedE) Imports() []Package {
	if pkg := e.msg.Package(); pkg.GoName() != e.ParentType().Field().Package().GoName() {
		return []Package{pkg}
	}
	return nil
}

var (
	_ FieldTypeElem = (*scalarE)(nil)
	_ FieldTypeElem = (*enumE)(nil)
	_ FieldTypeElem = (*embedE)(nil)
)
