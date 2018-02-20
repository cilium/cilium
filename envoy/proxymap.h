#pragma once

#include "envoy/network/address.h"
#include "envoy/network/listen_socket.h"

#include "common/common/logger.h"

#include "bpf.h"

namespace Envoy {

namespace Filter {
namespace BpfMetadata {
class Config;
}
} // namespace Filter

namespace Cilium {

class SocketMarkOption : public Network::Socket::Options, Logger::Loggable<Logger::Id::filter> {
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

class ProxyMap : Logger::Loggable<Logger::Id::filter> {
public:
  ProxyMap(const std::string &bpf_root, Filter::BpfMetadata::Config &parent);

  bool getBpfMetadata(Network::ConnectionSocket &socket);

private:
  class Proxy4Map : public Bpf {
  public:
    Proxy4Map();
  };

  class Proxy6Map : public Bpf {
  public:
    Proxy6Map();
  };

  Filter::BpfMetadata::Config &parent_;
  Proxy4Map proxy4map_;
  Proxy6Map proxy6map_;
};

} // namespace Cilium
} // namespace Envoy
