package smithy

// Document provides access to loosely structured data in a document-like
// format.
type Document interface {
	UnmarshalDocument(interface{}) error
	GetValue() (interface{}, error)
}
