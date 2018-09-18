#pragma once

#include "envoy/json/json_object.h"
#include "envoy/network/connection.h"
#include "envoy/network/filter.h"
#include "envoy/server/filter_config.h"

#include "common/buffer/buffer_impl.h"
#include "common/common/logger.h"

#include "cilium/cilium_network_filter.pb.h"
#include "proxymap.h"

#include "cilium_proxylib.h"

namespace Envoy {
namespace Filter {
namespace CiliumL3 {

/**
 * Shared configuration for Cilium network filter worker
 * Instances. Each new network connection (on each worker thread)
 * get's their own Instance, but they all share a common Config for
 * any given filter chain.
 */
class Config : Logger::Loggable<Logger::Id::config> {
public:
  Config(const ::cilium::NetworkFilter& config, Server::Configuration::FactoryContext& context);
  Config(const Json::Object& config, Server::Configuration::FactoryContext& context);
  virtual ~Config() {}

  std::string go_proto_;
  Cilium::GoFilterSharedPtr proxylib_;
  std::string policy_name_;
};

typedef std::shared_ptr<Config> ConfigSharedPtr;

/**
 * Implementation of a Cilium network filter.
 */
class Instance : public Network::Filter, public Network::ConnectionCallbacks,
                 Logger::Loggable<Logger::Id::filter> {
public:
  Instance(const ConfigSharedPtr& config) : config_(config) {}

  // Network::ReadFilter
  Network::FilterStatus onData(Buffer::Instance&, bool end_stream) override;
  Network::FilterStatus onNewConnection() override;
  void initializeReadFilterCallbacks(Network::ReadFilterCallbacks& callbacks) override {
    callbacks_ = &callbacks;
  }

  // Network::WriteFilter
  Network::FilterStatus onWrite(Buffer::Instance&, bool end_stream) override;
  
  // Network::ConnectionCallbacks
  void onEvent(Network::ConnectionEvent event) override;
  void onAboveWriteBufferHighWatermark() override {}
  void onBelowWriteBufferLowWatermark() override {}

private:
  const ConfigSharedPtr config_;
  Network::ReadFilterCallbacks* callbacks_ = nullptr;
  Cilium::ProxyMapSharedPtr maps_{};
  uint16_t proxy_port_ = 0;
  Cilium::GoFilter::InstancePtr go_parser_;
};

} // namespace CiliumL3
} // namespace Filter
} // namespace Envoy
