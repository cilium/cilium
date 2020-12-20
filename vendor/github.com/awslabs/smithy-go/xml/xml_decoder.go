package xml

import (
	"encoding/xml"
	"fmt"
)

// NodeDecoder is a XML decoder wrapper that is responsible to decoding
// a single XML Node element and it's nested member elements. This wrapper decoder
// takes in the start element of the top level node being decoded.
type NodeDecoder struct {
	Decoder *xml.Decoder
	StartEl xml.StartElement
}

// WrapNodeDecoder returns an initialized XMLNodeDecoder
func WrapNodeDecoder(decoder *xml.Decoder, startEl xml.StartElement) NodeDecoder {
	return NodeDecoder{
		Decoder: decoder,
		StartEl: startEl,
	}
}

// Token on a Node Decoder returns a xml StartElement. It returns a boolean that indicates the
// a token is the node decoder's end node token; and an error which indicates any error
// that occurred while retrieving the start element
func (d NodeDecoder) Token() (t xml.StartElement, done bool, err error) {
	for {
		token, e := d.Decoder.Token()
		if e != nil {
			return t, done, e
		}

		// check if we reach end of the node being decoded
		if el, ok := token.(xml.EndElement); ok {
			return t, el == d.StartEl.End(), err
		}

		if t, ok := token.(xml.StartElement); ok {
			return t, false, err
		}

		// skip token if it is a comment or preamble or empty space value due to indentation
		// or if it's a value and is not expected
	}

	return
}

// Value provides an abstraction to retrieve char data value within an xml element.
// The method will return an error if it encounters a nested xml element instead of char data.
// This method should only be used to retrieve simple type or blob shape values as []byte.
func (d NodeDecoder) Value() (c []byte, done bool, err error) {
	t, e := d.Decoder.Token()
	if e != nil {
		return c, done, e
	}

	// check if token is of type charData
	if ev, ok := t.(xml.CharData); ok {
		return ev, done, err
	}

	if ev, ok := t.(xml.EndElement); ok {
		if ev == d.StartEl.End() {
			return c, true, err
		}
	}

	return c, done, fmt.Errorf("expected value for %v element, got %T type %v instead", d.StartEl.Name.Local, t, t)
}

// FetchRootElement takes in a decoder and returns the first start element within the xml body.
// This function is useful in fetching the start element of an XML response and ignore the
// comments and preamble
func FetchRootElement(decoder *xml.Decoder) (startElement xml.StartElement, err error) {
	for {
		t, e := decoder.Token()
		if e != nil {
			return startElement, e
		}

		if startElement, ok := t.(xml.StartElement); ok {
			return startElement, err
		}
	}
}
