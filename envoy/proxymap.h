#pragma once

#include "common/common/logger.h"
#include "envoy/network/listen_socket.h"
#include "envoy/network/connection.h"
#include "envoy/singleton/instance.h"

#include "bpf.h"

namespace Envoy {
namespace Cilium {

class ProxyMap : public Singleton::Instance, Logger::Loggable<Logger::Id::filter> {
public:
  ProxyMap(const std::string &bpf_root);

  const std::string& bpfRoot() { return bpf_root_; }

  bool getBpfMetadata(Network::ConnectionSocket& socket, uint32_t* identity, uint16_t* orig_dport, uint16_t* proxy_port);
  bool removeBpfMetadata(Network::Connection& conn, uint16_t proxy_port);

private:
  class Proxy4Map : public Bpf {
  public:
    Proxy4Map();
  };

  class Proxy6Map : public Bpf {
  public:
    Proxy6Map();
  };

  std::string bpf_root_;
  Proxy4Map proxy4map_;
  Proxy6Map proxy6map_;
};

typedef std::shared_ptr<ProxyMap> ProxyMapSharedPtr;
 
} // namespace Cilium
} // namespace Envoy
