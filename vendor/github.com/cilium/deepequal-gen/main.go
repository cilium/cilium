/*
SPDX-License-Identifier: Apache-2.0
Copyright 2015 The Kubernetes Authors.
Copyright 2019 Wind River Systems, Inc.
*/

// deepequal-gen is a tool for auto-generating DeepEqual functions.  Refer to
// the README.md file for more information

package main

import (
	"flag"
	"github.com/spf13/pflag"
	"k8s.io/gengo/v2"
	"k8s.io/gengo/v2/generator"
	"k8s.io/klog/v2"

	"github.com/cilium/deepequal-gen/args"
	"github.com/cilium/deepequal-gen/generators"
)

func main() {
	klog.InitFlags(nil)
	args := args.New()

	args.AddFlags(pflag.CommandLine)
	flag.Set("logtostderr", "true")
	pflag.CommandLine.AddGoFlagSet(flag.CommandLine)
	pflag.Parse()

	if err := args.Validate(); err != nil {
		klog.Fatalf("Error: %v", err)
	}

	myTargets := func(context *generator.Context) []generator.Target {
		return generators.GetTargets(context, args)
	}

	// Run it.
	if err := gengo.Execute(
		generators.NameSystems(),
		generators.DefaultNameSystem(),
		myTargets,
		gengo.StdBuildTag,
		pflag.Args(),
	); err != nil {
		klog.Fatalf("Error: %v", err)
	}
	klog.V(2).Info("Completed successfully.")
}
