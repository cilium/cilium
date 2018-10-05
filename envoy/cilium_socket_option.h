#pragma once

#include "envoy/api/v2/core/base.pb.h"
#include "envoy/network/listen_socket.h"
#include "common/common/logger.h"

#include "proxymap.h"

namespace Envoy {
namespace Cilium {

class SocketMarkOption : public Network::Socket::Option, public Logger::Loggable<Logger::Id::filter> {
public:
  SocketMarkOption(uint32_t identity, bool ingress) : identity_(identity), ingress_(ingress) {}

  bool setOption(Network::Socket& socket, envoy::api::v2::core::SocketOption::SocketState state) const override {
    // Only set the option once per socket
    if (state != envoy::api::v2::core::SocketOption::STATE_PREBIND) {
      ENVOY_LOG(trace, "Skipping setting socket ({}) option SO_MARK, state != STATE_PREBIND", socket.fd());
      return true;
    }
    uint32_t cluster_id = (identity_ >> 16) & 0xFF;
    uint32_t identity_id = (identity_ & 0xFFFF) << 16;
    uint32_t mark = ((ingress_) ? 0xA00 : 0xB00) | cluster_id | identity_id;
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
    ENVOY_LOG(trace, "Set socket ({}) option SO_MARK to {:x} (magic mark: {:x}, id: {}, cluster: {})", socket.fd(), mark, mark & 0xff00, mark >> 16, mark & 0xff);
    return true;
  }
  void hashKey(std::vector<uint8_t>& key) const override {
    // Add the source identity to the hash key. This will separate upstream connection pools
    // per security ID.
    key.emplace_back(uint8_t(identity_ >> 16));
    key.emplace_back(uint8_t(identity_ >> 8));
    key.emplace_back(uint8_t(identity_));
  }

  uint32_t identity_;
  bool ingress_;
};

class SocketOption : public SocketMarkOption {
public:
  SocketOption(const ProxyMapSharedPtr& maps, uint32_t source_identity, uint32_t destination_identity, bool ingress, uint16_t port, uint16_t proxy_port)
    : SocketMarkOption(source_identity, ingress), maps_(maps), destination_identity_(destination_identity), port_(port), proxy_port_(proxy_port) {
    ENVOY_LOG(debug, "Cilium SocketOption(): source_identity: {}, destination_identity: {}, ingress: {}, port: {}, proxy_port: {}", identity_, destination_identity_, ingress_, port_, proxy_port_);
  }

  ProxyMapSharedPtr maps_;
  uint32_t destination_identity_;
  uint16_t port_;
  uint16_t proxy_port_;
};

} // namespace Cilium
} // namespace Envoy
