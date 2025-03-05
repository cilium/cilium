// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package troubleshoot

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"

	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/cilium/cilium/pkg/dial"
	"github.com/cilium/cilium/pkg/kvstore"
)

// Cmd represents the troubleshoot command. Note that this command
// is additionally registered as a subcommand of the Cilium operator.
var Cmd = &cobra.Command{
	Use:   "troubleshoot",
	Short: "Run troubleshooting utilities to check control-plane connectivity",
}

var _ kvstore.EtcdDbgDialer = (*troubleshootDialer)(nil)

// newTroubleshootDialer attempts to construct a dialer which performs service name
// to IP address resolution leveraging the kubernetes client, to mimic the behavior
// of the Cilium agent, as by default it uses the host DNS, not CoreDNS (to avoid
// circular dependencies). If the Kubernetes client cannot be instantiated, this
// function prints a warning message, and returns the default dialer.
func newTroubleshootDialer(w io.Writer, disabled bool) kvstore.EtcdDbgDialer {
	if disabled {
		return kvstore.DefaultEtcdDbgDialer{}
	}

	var cs kubernetes.Interface

	// We don't use the hive infrastructure to initialize the client here to keep
	// things simple, and because we don't want to fail hard in case it cannot be
	// created. At the moment, we account for the most common scenario (i.e., we
	// are running inside a pod), and fallback to the default dialer (i.e., without
	// automatic service name to IP translation) in all the other cases.
	restcfg, err := rest.InClusterConfig()
	if err == nil {
		cs, err = kubernetes.NewForConfig(restcfg)
	}

	if err != nil {
		fmt.Fprintf(w, "⚠️ Could not initialize k8s client, service resolution may not work: %s\n\n", err)
		return kvstore.DefaultEtcdDbgDialer{}
	}

	dialer := &troubleshootDialer{
		cs:    cs,
		cache: make(map[types.NamespacedName]tdCacheEntry),
	}

	logger := slog.New(slog.DiscardHandler)
	dialer.dial = dial.NewContextDialer(logger, dialer)
	return dialer
}

type troubleshootDialer struct {
	cs    kubernetes.Interface
	cache map[types.NamespacedName]tdCacheEntry
	dial  func(ctx context.Context, addr string) (conn net.Conn, e error)
}

type tdCacheEntry struct {
	resolved string
	err      error
}

func (td *troubleshootDialer) DialContext(ctx context.Context, addr string) (conn net.Conn, e error) {
	return td.dial(ctx, addr)
}

func (td *troubleshootDialer) LookupIP(ctx context.Context, hostname string) ([]net.IP, error) {
	// Let's mimic the same behavior of the dialer returned by k8s.CreateCustomDialer,
	// that is try to first resolve the hostname as a service, and then fallback to
	// the system resolver.
	addr, err := td.Resolve(ctx, hostname)
	if err != nil {
		return net.DefaultResolver.LookupIP(ctx, "ip", hostname)
	}

	parsed := net.ParseIP(addr)
	if parsed == nil {
		return net.DefaultResolver.LookupIP(ctx, "ip", hostname)
	}

	return []net.IP{parsed}, nil
}

func (td *troubleshootDialer) Resolve(ctx context.Context, hostname string) (resolved string, err error) {
	nsname, err := dial.ServiceURLToNamespacedName(hostname)
	if err != nil {
		return "", err
	}

	if entry, ok := td.cache[nsname]; ok {
		return entry.resolved, entry.err
	}

	defer func() { td.cache[nsname] = tdCacheEntry{resolved, err} }()

	svc, err := td.cs.CoreV1().Services(nsname.Namespace).Get(ctx, nsname.Name, metav1.GetOptions{})
	if err != nil {
		return "", err
	}

	if _, err := netip.ParseAddr(svc.Spec.ClusterIP); err != nil {
		return "", fmt.Errorf("cannot parse ClusterIP address: %w", err)
	}

	return svc.Spec.ClusterIP, nil
}
