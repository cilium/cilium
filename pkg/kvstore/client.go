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

	log "github.com/Sirupsen/logrus"
)

// Client is the instance of the key-value as configured
var Client KVClient

func initClient() error {
	switch backend {
	case Consul:
		if consulConfig == nil {
			return fmt.Errorf("mising consul server address, please specify, e.g. --kvstore-opt consul.address=127.0.0.1:8500")
		}

		c, err := newConsulClient(consulConfig)
		if err != nil {
			return err
		}

		log.Infof("Using consul as key-value store")
		Client = c

	case Etcd:
		if etcdCfgPath == "" && etcdConfig == nil {
			return fmt.Errorf("missing etcd endpoints; please specify , e.g. --kvstore-opt etcd.address=127.0.0.1:2379")
		}

		c, err := newEtcdClient(etcdConfig, etcdCfgPath)
		if err != nil {
			return err
		}

		log.Infof("Using etcd as key-value store")
		Client = c

	default:
		panic("BUG: kvstore backend not specified")
	}

	return nil
}
