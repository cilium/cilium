package protocol

// An Attribute is a FieldValue that resides within the imediant context of
// another field. Such as XML attribute for tags.
type Attribute struct {
	Name  string
	Value ValueMarshaler
	Meta  Metadata
}

// Metadata is a collection of configuration flags for encoders to render the
// output.
type Metadata struct {
	Attributes []Attribute

	Flatten bool

	ListLocationName     string
	MapLocationNameKey   string
	MapLocationNameValue string

	XMLNamespacePrefix string
	XMLNamespaceURI    string
}
