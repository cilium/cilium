#pragma once

#include "envoy/network/listen_socket.h"
#include "common/common/logger.h"

#include "proxymap.h"

namespace Envoy {
namespace Cilium {

class SocketMarkOption : public Network::Socket::Option, public Logger::Loggable<Logger::Id::filter> {
public:
  SocketMarkOption(uint16_t identity, bool ingress) : identity_(identity), ingress_(ingress) {}

  bool setOption(Network::Socket& socket, Network::Socket::SocketState state) const override {
    // Only set the option once per socket
    if (state != Network::Socket::SocketState::PreBind) {
      return true;
    }
    uint32_t mark = ((ingress_) ? 0xFEA : 0xFEB) | (identity_ << 16);
    int rc = setsockopt(socket.fd(), SOL_SOCKET, SO_MARK, &mark, sizeof(mark));
    if (rc < 0) {
      if (errno == EPERM) {
	// Do not assert out in this case so that we can run tests without CAP_NET_ADMIN.
	ENVOY_LOG(critical,
		  "Failed to set socket option SO_MARK to {}, capability CAP_NET_ADMIN needed: {}",
		  mark, strerror(errno));
      } else {
	ENVOY_LOG(critical, "Socket option failure. Failed to set SO_MARK to {}: {}", mark,
		  strerror(errno));
	return false;
      }
    }
    return true;
  }
  void hashKey(std::vector<uint8_t>& key) const override {
    // Add the source identity to the hash key. This will separate upstream connection pools
    // per security ID.
    key.emplace_back(uint8_t(identity_ >> 8));
    key.emplace_back(uint8_t(identity_));
  }

  uint32_t identity_;
  bool ingress_;
};

class SocketOption : public SocketMarkOption {
public:
SocketOption(const ProxyMapSharedPtr& maps, uint32_t source_identity, bool ingress, uint16_t port, uint16_t proxy_port)
  : SocketMarkOption(source_identity, ingress), maps_(maps), port_(port), proxy_port_(proxy_port) {
    ENVOY_LOG(debug, "Cilium SocketOption(): source_identity: {}, ingress: {}, port: {}, proxy_port: {}", identity_, ingress_, port_, proxy_port_);
  }

  ProxyMapSharedPtr maps_;
  uint16_t port_;
  uint16_t proxy_port_;
};

} // namespace Cilium
} // namespace Envoy
