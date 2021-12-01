// SPDX-License-Identifier: Apache-2.0
// Copyright 2017-2019 Authors of Cilium

//go:build !lockdebug
// +build !lockdebug

package lock

import (
	"sync"
)

type internalRWMutex struct {
	sync.RWMutex
}

func (i *internalRWMutex) UnlockIgnoreTime() {
	i.RWMutex.Unlock()
}

type internalMutex struct {
	sync.Mutex
}

func (i *internalMutex) UnlockIgnoreTime() {
	i.Mutex.Unlock()
}
