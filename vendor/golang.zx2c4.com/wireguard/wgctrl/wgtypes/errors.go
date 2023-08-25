package wgtypes

import (
	"errors"
)

// ErrUpdateOnlyNotSupported is returned due to missing kernel support of
// the PeerConfig UpdateOnly flag.
var ErrUpdateOnlyNotSupported = errors.New("the UpdateOnly flag is not supported by this platform")

