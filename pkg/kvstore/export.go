// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package kvstore

import (
	"context"

	"github.com/cilium/cilium/pkg/inctimer"
	client "go.etcd.io/etcd/client/v3"
)

var (
	// etcdDummyAddress can be overwritten from test invokers using ldflags
	etcdDummyAddress = "http://127.0.0.1:4002"
)

func EtcdDummyAddress() string {
	return etcdDummyAddress
}

func (e *EtcdModule) setConfigDummy() {
	e.config = &client.Config{}
	e.config.Endpoints = []string{etcdDummyAddress}
}

func ExportedGetBackend(name string) backendModule {
	return getBackend(name)
}

func (e *EtcdModule) ExportedSetConfig(opts map[string]string) error {
	return e.setConfig(opts) // Pass 'opts' instead of 'map'
}

func (e *EtcdModule) ExportedSetConfigDummy() {
	e.setConfigDummy()
}

func ExportedInitClient(ctx context.Context, module backendModule, opts *ExtraOptions) error {
	return initClient(ctx, module, opts)
}

func NewIncTimer() (inctimer.IncTimer, func() bool) {
	return inctimer.New()
}
