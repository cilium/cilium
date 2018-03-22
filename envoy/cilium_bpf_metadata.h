#pragma once

#include "envoy/json/json_object.h"
#include "envoy/network/filter.h"
#include "envoy/server/filter_config.h"

#include "common/common/logger.h"

#include "cilium/cilium_bpf_metadata.pb.h"
#include "proxymap.h"

namespace Envoy {
namespace Filter {
namespace BpfMetadata {

/**
 * Global configuration for Bpf Metadata listener filter. This
 * represents all global state shared among the working thread
 * instances of the filter.
 */
class Config : Logger::Loggable<Logger::Id::config> {
public:
  Config(const ::cilium::BpfMetadata &config, Server::Configuration::ListenerFactoryContext& context);
  virtual ~Config() {}

  uint32_t getMark(uint32_t identity) {
    // Magic marker values must match with Cilium.
    return ((is_ingress_) ? 0xFEA : 0xFEB) | (identity << 16);
  }

  virtual bool getBpfMetadata(Network::ConnectionSocket &socket);

  bool is_ingress_;
  Cilium::ProxyMapSharedPtr maps_;
};

typedef std::shared_ptr<Config> ConfigSharedPtr;

/**
 * Implementation of a bpf metadata listener filter.
 */
class Instance : public Network::ListenerFilter,
                 Logger::Loggable<Logger::Id::filter> {
public:
  Instance(ConfigSharedPtr config) : config_(config) {}

  // Network::ListenerFilter
  Network::FilterStatus onAccept(Network::ListenerFilterCallbacks &cb) override;

private:
  ConfigSharedPtr config_;
};

} // namespace BpfMetadata
} // namespace Filter
} // namespace Envoy
