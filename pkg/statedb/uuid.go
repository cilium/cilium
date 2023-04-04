// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package statedb

import "github.com/google/uuid"

type UUID = string

func NewUUID() UUID {
	return UUID(uuid.New().String())
}
