#pragma once

#include "envoy/network/listen_socket.h"

#include "common/common/logger.h"

#include "bpf.h"

namespace Envoy {

namespace Filter {
namespace BpfMetadata {
class Config;
} // namespace BpfMetadata
} // namespace Filter

namespace Cilium {

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
