package defaults

import (
	"github.com/aws/aws-sdk-go-v2/aws"
)

// ValidateParametersHandler is a request handler to validate the input parameters.
// Validating parameters only has meaning if done prior to the request being sent.
var ValidateParametersHandler = aws.NamedHandler{Name: "core.ValidateParametersHandler", Fn: func(r *aws.Request) {
	if !r.ParamsFilled() {
		return
	}

	if v, ok := r.Params.(aws.Validator); ok {
		if err := v.Validate(); err != nil {
			r.Error = err
		}
	}
}}
