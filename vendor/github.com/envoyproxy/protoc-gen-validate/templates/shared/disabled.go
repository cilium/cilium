package shared

import (
	"github.com/lyft/protoc-gen-star"
	"github.com/envoyproxy/protoc-gen-validate/validate"
)

// Disabled returns true if validations are disabled for msg
func Disabled(msg pgs.Message) (disabled bool, err error) {
	_, err = msg.Extension(validate.E_Disabled, &disabled)
	return
}

// RequiredOneOf returns true if the oneof field requires a field to be set
func RequiredOneOf(oo pgs.OneOf) (required bool, err error) {
	_, err = oo.Extension(validate.E_Required, &required)
	return
}
