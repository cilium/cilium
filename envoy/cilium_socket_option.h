#pragma once

#include "envoy/network/listen_socket.h"
#include "common/common/logger.h"

#include "proxymap.h"

namespace Envoy {
namespace Cilium {

class SocketMarkOption : public Network::Socket::Options, public Logger::Loggable<Logger::Id::filter> {
public:
  SocketMarkOption(uint32_t mark) : mark_(mark) {}

  bool setOptions(Network::Socket& socket) const override {
    int rc = setsockopt(socket.fd(), SOL_SOCKET, SO_MARK, &mark_, sizeof(mark_));
    if (rc < 0) {
      if (errno == EPERM) {
	// Do not assert out in this case so that we can run tests without CAP_NET_ADMIN.
	ENVOY_LOG(critical,
		  "Failed to set socket option SO_MARK to {}, capability CAP_NET_ADMIN needed: {}",
		  mark_, strerror(errno));
      } else {
	ENVOY_LOG(critical, "Socket option failure. Failed to set SO_MARK to {}: {}", mark_,
		  strerror(errno));
	return false;
      }
    }
    return true;
  }
  uint32_t hashKey() const override { return mark_; }

  uint32_t mark_;
};

class SocketOption : public SocketMarkOption {
public:
SocketOption(const ProxyMapSharedPtr& maps, uint32_t mark, uint32_t source_identity, bool ingress, uint16_t port, uint16_t proxy_port)
    : SocketMarkOption(mark), maps_(maps), source_identity_(source_identity), ingress_(ingress), port_(port), proxy_port_(proxy_port) {
    ENVOY_LOG(debug, "Cilium SocketOption(): mark: {}, source_identity: {}, ingress: {}, port: {}, proxy_port: {}", mark, source_identity_, ingress_, port_, proxy_port_);
  }

  ProxyMapSharedPtr maps_;
  uint32_t source_identity_;
  bool ingress_;
  uint16_t port_;
  uint16_t proxy_port_;
};

} // namespace Cilium
} // namespace Envoy
