package smithy

// The MediaType interface is intended to be implemented by string and
// byte array types whose values can be defined by RFC638 media types.
type MediaType interface {
	// Describes the contents of the string or byte array using a media type
	// as defined by RFC6838.
	MediaType() string
}
