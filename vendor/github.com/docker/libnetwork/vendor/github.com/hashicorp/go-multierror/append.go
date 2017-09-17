package multierror

// Append is a helper function that will append more errors
// onto an Error in order to create a larger multi-error.
//
// If err is not a multierror.Error, then it will be turned into
// one. If any of the errs are multierr.Error, they will be flattened
// one level into err.
func Append(err error, errs ...error) *Error {
	switch err := err.(type) {
	case *Error:
		// Typed nils can reach here, so initialize if we are nil
		if err == nil {
			err = new(Error)
		}

		err.Errors = append(err.Errors, errs...)
		return err
	default:
		newErrs := make([]error, len(errs)+1)
		newErrs[0] = err
		copy(newErrs[1:], errs)
		return &Error{
			Errors: newErrs,
		}
	}
}
