// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"errors"
	"fmt"

	"golang.org/x/exp/slices"
)

var closedWatchChannel = func() <-chan struct{} {
	ch := make(chan struct{})
	close(ch)
	return ch
}()

const (
	// maxJoinedErrors limits the number of errors to join and return from
	// failed reconciliation. This avoids constructing a massive error for
	// health status when many operations fail at once.
	maxJoinedErrors = 10
)

func omittedError(n int) error {
	return fmt.Errorf("%d further errors omitted", n)
}

func joinErrors(errs []error) error {
	if len(errs) > maxJoinedErrors {
		errs = append(slices.Clone(errs)[:maxJoinedErrors], omittedError(len(errs)))
	}
	return errors.Join(errs...)
}
