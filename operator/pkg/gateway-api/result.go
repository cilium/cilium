// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"time"

	ctrl "sigs.k8s.io/controller-runtime"
)

func success() (ctrl.Result, error) {
	return ctrl.Result{}, nil
}

func fail(e error) (ctrl.Result, error) {
	return ctrl.Result{}, e
}

func requeue(after time.Duration) (ctrl.Result, error) {
	return ctrl.Result{
		Requeue:      true,
		RequeueAfter: after,
	}, nil
}
