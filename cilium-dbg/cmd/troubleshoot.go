// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"
	"fmt"
	"io"
	"net"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/loadbalancer"
)

// TroubleshootCmd represents the troubleshoot command
var TroubleshootCmd = &cobra.Command{
	Use:   "troubleshoot",
	Short: "Run troubleshooting utilities to check control-plane connectivity",
}

func init() {
	RootCmd.AddCommand(TroubleshootCmd)
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
		cache: make(map[k8s.ServiceID]*loadbalancer.L3n4Addr),
	}

	logger := logrus.New()
	logger.SetOutput(io.Discard)
	dialer.dial = k8s.CreateCustomDialer(dialer, logger, true)
	return dialer
}

type troubleshootDialer struct {
	cs    kubernetes.Interface
	cache map[k8s.ServiceID]*loadbalancer.L3n4Addr
	dial  func(ctx context.Context, addr string) (conn net.Conn, e error)
}

func (td *troubleshootDialer) DialContext(ctx context.Context, addr string) (conn net.Conn, e error) {
	return td.dial(ctx, addr)
}

func (td *troubleshootDialer) LookupIP(ctx context.Context, hostname string) ([]net.IP, error) {
	// Let's mimic the same behavior of the dialer returned by k8s.CreateCustomDialer,
	// that is try to first resolve the hostname as a service, and then fallback to
	// the system resolver.
	svc := k8s.ParseServiceIDFrom(hostname)
	if svc == nil {
		return net.DefaultResolver.LookupIP(ctx, "ip", hostname)
	}

	addr := td.GetServiceIP(*svc)
	if addr == nil {
		return net.DefaultResolver.LookupIP(ctx, "ip", hostname)
	}

	return []net.IP{addr.AddrCluster.Addr().AsSlice()}, nil
}

func (td *troubleshootDialer) GetServiceIP(svcID k8s.ServiceID) (addr *loadbalancer.L3n4Addr) {
	return td.getServiceIP(context.Background(), svcID)
}

func (td *troubleshootDialer) getServiceIP(ctx context.Context, svcID k8s.ServiceID) (addr *loadbalancer.L3n4Addr) {
	if addr, ok := td.cache[svcID]; ok {
		return addr
	}

	defer func() { td.cache[svcID] = addr }()

	svc, err := td.cs.CoreV1().Services(svcID.Namespace).Get(ctx, svcID.Name, metav1.GetOptions{})
	if err != nil {
		return nil
	}

	for _, port := range svc.Spec.Ports {
		return loadbalancer.NewL3n4Addr(
			string(port.Protocol),
			cmtypes.MustAddrClusterFromIP(net.ParseIP(svc.Spec.ClusterIP)),
			uint16(port.Port),
			loadbalancer.ScopeExternal,
		)
	}

	return nil
}
