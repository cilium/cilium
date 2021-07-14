// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of Cilium

// Package subscriber implements a mechanism to represent K8s watcher
// subscribers and allows K8s events to objects / resources to notify their
// respective subscribers. The intent is to allow the K8s watchers to
// consolidate all the event handling from various subsystems into one place.
package subscriber

import "github.com/cilium/cilium/pkg/lock"

type list struct {
	lock.RWMutex
}
