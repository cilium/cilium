/*
Copyright 2014 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// The controller manager is responsible for monitoring replication
// controllers, and creating corresponding pods to achieve the desired
// state.  It uses the API to listen for new controllers and to create/delete
// pods.
package main

import (
	"fmt"
	"os"

	"k8s.io/apiserver/pkg/server/healthz"
	"k8s.io/apiserver/pkg/util/flag"
	"k8s.io/apiserver/pkg/util/logs"
	"k8s.io/kubernetes/cmd/kube-controller-manager/app"
	"k8s.io/kubernetes/cmd/kube-controller-manager/app/options"
	_ "k8s.io/kubernetes/pkg/client/metrics/prometheus" // for client metric registration
	_ "k8s.io/kubernetes/pkg/util/reflector/prometheus" // for reflector metric registration
	_ "k8s.io/kubernetes/pkg/util/workqueue/prometheus" // for workqueue metric registration
	_ "k8s.io/kubernetes/pkg/version/prometheus"        // for version metric registration
	"k8s.io/kubernetes/pkg/version/verflag"

	"github.com/spf13/pflag"
)

func init() {
	healthz.DefaultHealthz()
}

func main() {
	s := options.NewCMServer()
	s.AddFlags(pflag.CommandLine, app.KnownControllers(), app.ControllersDisabledByDefault.List())

	flag.InitFlags()
	logs.InitLogs()
	defer logs.FlushLogs()

	verflag.PrintAndExitIfRequested()

	if err := app.Run(s); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}
