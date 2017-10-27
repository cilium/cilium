// Copyright 2016-2017 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package kvstore

import (
	"fmt"
	"strings"
	"sync"

	"github.com/cilium/cilium/pkg/lock"

	etcdAPI "github.com/coreos/etcd/clientv3"
	consulAPI "github.com/hashicorp/consul/api"
	log "github.com/sirupsen/logrus"
)

// Supported key-value store types.
const (
	Consul = "consul"
	Etcd   = "etcd"
)

var (
	// this variable is set via Makefile for test purposes and allows to tie a
	// binary to a particular backend
	backend       = ""
	consulAddress = "127.0.0.1:8501"

	consulConfig *consulAPI.Config // Consul configuration
	etcdConfig   *etcdAPI.Config   // Etcd Configuration
	etcdCfgPath  string            // Etcd Configuration path
)

// validateOpts iterates through all of the keys in kvStoreOpts, and errors out
// if the key in kvStoreOpts is not a supported key in supportedOpts.
func validateOpts(kvStore string, kvStoreOpts map[string]string, supportedOpts map[string]bool) error {
	for k := range kvStoreOpts {
		if !supportedOpts[k] {
			return fmt.Errorf("provided configuration value %q is not supported as a key-value store option for kvstore %s", k, kvStore)
		}
	}
	return nil
}

// SetupDummy sets up kvstore for tests
func SetupDummy() {
	switch backend {
	case Consul:
		consulConfig = consulAPI.DefaultConfig()
		consulConfig.Address = consulAddress

	case Etcd:
		etcdConfig = &etcdAPI.Config{}
		etcdConfig.Endpoints = []string{"http://127.0.0.1:4002"}

	default:
		log.WithField("backend", backend).Panic("Unknown kvstore backend")
	}

	if err := initClient(); err != nil {
		log.WithError(err).Panic("Unable to initialize kvstore client")
	}
}

var (
	setupLock lock.Mutex
	setupOnce sync.Once
)

// Setup sets up the key-value store specified in kvStore and configures
// it with the options provided in kvStoreOpts.
func Setup(selectedBackend string, opts map[string]string) error {
	var err error

	// Ensure that multiple calls to Setup() block and the kvstore is
	// always configured after a successful call to Setup()
	setupLock.Lock()
	defer setupLock.Unlock()

	setupOnce.Do(func() {
		backend = selectedBackend

		switch backend {
		case Etcd:
			err = validateOpts(backend, opts, EtcdOpts)
			if err != nil {
				return
			}
			addr, ok := opts[eAddr]
			config, ok2 := opts[eCfg]
			if ok || ok2 {
				etcdConfig = &etcdAPI.Config{}
				etcdCfgPath = config
				etcdConfig.Endpoints = []string{addr}
			} else {
				err = fmt.Errorf("invalid configuration for etcd provided; please specify an etcd configuration path with --kvstore-opt %s=<path> or an etcd agent address with --kvstore-opt %s=<address>", eCfg, eAddr)
				return
			}

		case Consul:
			err = validateOpts(backend, opts, ConsulOpts)
			if err != nil {
				return
			}
			consulAddr, ok := opts[cAddr]
			if ok {
				consulDefaultAPI := consulAPI.DefaultConfig()
				consulSplitAddr := strings.Split(consulAddr, "://")
				if len(consulSplitAddr) == 2 {
					consulAddr = consulSplitAddr[1]
				} else if len(consulSplitAddr) == 1 {
					consulAddr = consulSplitAddr[0]
				}
				consulDefaultAPI.Address = consulAddr
				consulConfig = consulDefaultAPI
			} else {
				err = fmt.Errorf("invalid configuration for consul provided; please specify the address to a consul instance with --kvstore-opt %s=<consul address> option", cAddr)
				return
			}

		case "":
			err = fmt.Errorf("kvstore not configured. Please specify --kvstore. See http://cilium.link/err-kvstore for details")
			return

		default:
			err = fmt.Errorf("unsupported key-value store %q provided; check http://cilium.link/err-kvstore for more information about how to properly configure key-value store", backend)
			return
		}

		err = initClient()
	})

	return err
}
