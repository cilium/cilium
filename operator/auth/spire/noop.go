// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package spire

import "context"

type noopClient struct {
}

func (n noopClient) Upsert(_ context.Context, _ string) error {
	return nil
}

func (n noopClient) Delete(_ context.Context, _ string) error {
	return nil
}
