package errs

import (
	"github.com/sirupsen/logrus"
	"go.uber.org/multierr"
)

// Into is a helper around multierr.AppendInto that ensures that it never panics
// in the case of a nil error pointer.
func Into(into *error, err error) bool {
	if into == nil {
		logrus.Error("[BUG] errs.Into called with nil error pointer")
		return err != nil
	}
	return multierr.AppendInto(into, err)
}
