package service

import (
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/cilium/cilium/api/v1/models"
	serviceapi "github.com/cilium/cilium/api/v1/server/restapi/service"
	"github.com/cilium/cilium/pkg/api"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/loadbalancer"
)

func (s *Service) UpsertAPIService(config client.Config) error {
	host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
	if len(host) == 0 || len(port) == 0 {
		return fmt.Errorf("KUBERNETES_SERVICE_HOST or KUBERNETES_SERVICE_PORT not set")
	}
	s.logger.Info("[APISERVER-LB] service:port [%s:%s]", host, port)

	urls := config.K8sAPIServerURLs
	svcAddr := net.JoinHostPort(host, port)
	// backends := []string{"172.21.0.4:6443", "172.21.0.5:6443"
	backends := make([]string, len(urls))
	for i := range backends {
		backends[i] = strings.TrimPrefix(urls[i], "https://")
	}
	s.logger.Info("[APISERVER-LB] backends %v", backends)
	fa := s.parseFrontendAddress("tcp", svcAddr)
	spec := &models.ServiceSpec{ID: 1}
	spec.Flags = &models.ServiceSpecFlags{Type: models.ServiceSpecFlagsTypeClusterIP}
	spec.FrontendAddress = fa

	for _, backend := range backends {
		ip, port, proto, err := parseAddress("tcp", backend)
		if err != nil {
			s.logger.Error("Cannot parse backend address %q: %s", backend, err)
			return err
		}
		// Backend ID will be set by the daemon
		be := loadbalancer.NewBackend(0, strings.ToUpper(proto), cmtypes.MustAddrClusterFromIP(ip), uint16(port))

		if fa.Port == 0 && port != 0 {
			s.logger.Error("L4 backend found (%v:%d) with L3 frontend", fa, port)
			return err
		}
		ba := be.GetBackendModel()
		spec.BackendAddresses = append(spec.BackendAddresses, ba)
	}
	be := make([]*loadbalancer.Backend, len(spec.BackendAddresses))
	for _, v := range spec.BackendAddresses {
		b, err := loadbalancer.NewBackendFromBackendModel(v)
		if err != nil {
			return api.Error(serviceapi.PutServiceIDInvalidBackendCode, err)
		}
		be = append(be, b)
	}
	f, err := loadbalancer.NewL3n4AddrFromModel(spec.FrontendAddress)
	if err != nil {
		return api.Error(serviceapi.PutServiceIDInvalidFrontendCode, err)
	}

	frontend := loadbalancer.L3n4AddrID{
		L3n4Addr: *f,
		ID:       loadbalancer.ID(1),
	}
	p := &loadbalancer.SVC{
		Name:     loadbalancer.ServiceName{Name: "kubernetes", Namespace: "kube-system"},
		Type:     loadbalancer.SVCTypeClusterIP,
		Frontend: frontend,
		Backends: be,
	}
	s.logger.Info("[APISERVER-LB] params %v", p)
	_, id, err := s.UpsertService(p)
	if err != nil {
		s.logger.Info("[apiserver-lb] API Service upserted with id %s", id)
	} else {
		s.logger.Error("[apiserver-lb] Error upserting API service %v", err)
	}

	return nil
}

func (s *Service) parseFrontendAddress(l4Protocol, address string) *models.FrontendAddress {
	ip, port, proto, err := parseAddress(l4Protocol, address)
	if err != nil {
		s.logger.Error("Unable to parse frontend address: %s", err)
	}

	return &models.FrontendAddress{
		IP:       ip.String(),
		Port:     uint16(port),
		Protocol: proto,
	}
}

func parseAddress(l4Protocol, address string) (ip net.IP, port int, proto string, err error) {
	switch proto = strings.ToLower(l4Protocol); proto {
	case "tcp":
		var tcpAddr *net.TCPAddr
		tcpAddr, err = net.ResolveTCPAddr(proto, address)
		if err != nil {
			return
		}
		ip = tcpAddr.IP
		port = tcpAddr.Port
	case "udp":
		var udpAddr *net.UDPAddr
		udpAddr, err = net.ResolveUDPAddr(proto, address)
		if err != nil {
			return
		}
		ip = udpAddr.IP
		port = udpAddr.Port
	default:
		err = fmt.Errorf("unrecognized protocol %q", l4Protocol)
	}
	return
}
