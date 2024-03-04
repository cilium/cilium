// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"context"

	"github.com/cilium/cilium/cilium-cli/connectivity"
	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium-cli/k8s"
	"github.com/cilium/cilium-cli/sysdump"
)

// key is a context.Context value key type. It's unexported to avoid key collisions.
type key int

const (
	namespaceKey key = iota
	k8sClientKey
)

// SetNamespaceContextValue stores a namespace string as a context value and
// returns the resulting context. You can access the namespace by calling
// GetNamespaceContextValue.
func SetNamespaceContextValue(ctx context.Context, namespace string) context.Context {
	return context.WithValue(ctx, namespaceKey, namespace)
}

// SetK8sClientContextValue stores a namespace string as a context value and
// returns the resulting context. You can access the namespace by calling
// GetK8sClientContextValue.
func SetK8sClientContextValue(ctx context.Context, client *k8s.Client) context.Context {
	return context.WithValue(ctx, k8sClientKey, client)
}

// GetNamespaceContextValue retrieves the namespace from a context that was
// stored by SetNamespaceContextValue.
func GetNamespaceContextValue(ctx context.Context) (string, bool) {
	namespace, ok := ctx.Value(namespaceKey).(string)
	return namespace, ok
}

// GetK8sClientContextValue retrieves the k8s.Client from a context that was
// stored by SetK8sClientContextValue.
func GetK8sClientContextValue(ctx context.Context) (*k8s.Client, bool) {
	client, ok := ctx.Value(k8sClientKey).(*k8s.Client)
	return client, ok
}

// Hooks to extend the default cilium-cli command with additional functionality.
type Hooks interface {
	ConnectivityTestHooks
	sysdump.Hooks
	// InitializeCommand gets called with the root command before returning it
	// from cli.NewCiliumCommand.
	InitializeCommand(rootCmd *cobra.Command)
}

// ConnectivityTestHooks to extend cilium-cli with additional connectivity tests and related flags.
type ConnectivityTestHooks interface {
	connectivity.Hooks
	// AddConnectivityTestFlags is an hook to register additional connectivity test flags.
	AddConnectivityTestFlags(flags *pflag.FlagSet)
}

type NopHooks struct{}

var _ Hooks = &NopHooks{}

func (*NopHooks) AddSysdumpFlags(*pflag.FlagSet)                                  {}
func (*NopHooks) AddSysdumpTasks(*sysdump.Collector) error                        { return nil }
func (*NopHooks) AddConnectivityTestFlags(*pflag.FlagSet)                         {}
func (*NopHooks) AddConnectivityTests(*check.ConnectivityTest) error              { return nil }
func (*NopHooks) DetectFeatures(context.Context, *check.ConnectivityTest) error   { return nil }
func (*NopHooks) SetupAndValidate(context.Context, *check.ConnectivityTest) error { return nil }
func (*NopHooks) InitializeCommand(*cobra.Command)                                {}
