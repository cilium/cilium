# clusterdebug tool

# Overview
 The clusterdebug tool can help identify the most commonly encountered
 issues in cilium deployments. The tool currently supports Kubernetes 
 and Minikube clusters only.

 The tool performs various checks and provides hints to fix specific
  issues that it has identified.

# Implementation details
 The `ModuleCheck` class implements the basic notion of a check.
 It can be extended by changing the default on-success and on-failure callback
  methods.

 The `ModuleCheckGroup` class provides a grouping construct for grouping 
 related `ModuleChecks`. The `ModuleChecks` in a `ModuleCheckGroup` are 
 run in a serial manner. The execution of a `ModuleCheckGroup` terminates
  on the first `ModuleCheck` failure. In other words, if a `ModuleCheck` 
  fails, all subsequent `ModuleChecks` in the group will be skipped.

 The current implementation implements two `ModuleCheckGroups` -- one for 
 Kubernetes checks, and the other for Cilium specific checks.

# Prerequisites
- Requires Python >= 2.7.*
- Requires `kubectl`. 
- `kubectl` should be pointing to your cluster before running the tool.

# (Optional) Re-build zip file
    make build

# Run:
    python clusterdebug.zip

