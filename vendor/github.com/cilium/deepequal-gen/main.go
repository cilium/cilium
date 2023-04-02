/*
SPDX-License-Identifier: Apache-2.0
Copyright 2015 The Kubernetes Authors.
Copyright 2019 Wind River Systems, Inc.
*/

// deepequal-gen is a tool for auto-generating DeepEqual functions.  Refer to
// the README.md file for more information

package main

import (
	"github.com/spf13/pflag"
	"k8s.io/gengo/args"
	"k8s.io/klog"

	"github.com/cilium/deepequal-gen/generators"
)

func main() {
	klog.InitFlags(nil)
	arguments := args.Default()

	// Override defaults.
	arguments.OutputFileBaseName = "deepequal_generated"

	// Custom args.
	customArgs := &generators.CustomArgs{}
	pflag.CommandLine.StringSliceVar(&customArgs.BoundingDirs, "bounding-dirs", customArgs.BoundingDirs,
		"Comma-separated list of import paths which bound the types for which deep-copies will be generated.")
	arguments.CustomArgs = customArgs

	// Run it.
	if err := arguments.Execute(
		generators.NameSystems(),
		generators.DefaultNameSystem(),
		generators.Packages,
	); err != nil {
		klog.Fatalf("Error: %v", err)
	}
	klog.V(2).Info("Completed successfully.")
}
