// Copyright 2021 Authors of Cilium
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

package main

import (
	"flag"
	"fmt"
	"os"

	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/clientcmd/api"
)

func main() {
	flags()

	config1, err := clientcmd.LoadFromFile(flag.Arg(0))
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	config2, err := clientcmd.LoadFromFile(flag.Arg(1))
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	config := mergeKubeconfigs(config1, config2)

	clientcmd.WriteToFile(*config, flag.Arg(2))
}

func flags() {
	flag.Parse()
	if flag.NArg() != 3 {
		fmt.Println("Provide two kubeconfig files that need merging and target file")
		os.Exit(1)
	}
}

func mergeKubeconfigs(conf1, conf2 *api.Config) *api.Config {
	for name, cluster := range conf2.Clusters {
		conf1.Clusters[name] = cluster
	}

	userOverrides := map[string]string{}
	for name, user := range conf2.AuthInfos {
		if _, ok := conf1.AuthInfos[name]; ok {
			userOverrides[name] = name + "-override"
			name = userOverrides[name]
		}
		conf1.AuthInfos[name] = user
	}

	for name, context := range conf2.Contexts {
		if _, ok := userOverrides[context.AuthInfo]; ok {
			context.AuthInfo = userOverrides[context.AuthInfo]
		}
		conf1.Contexts[name] = context
	}

	return conf1
}
