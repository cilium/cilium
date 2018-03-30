#pragma once

#include <string>

#include "envoy/api/v2/core/base.pb.h"
#include "common/config/grpc_subscription_impl.h"
#include "common/config/utility.h"
#include "common/protobuf/protobuf.h"

namespace Envoy {
namespace Cilium {

template <typename Protocol>
std::unique_ptr<Envoy::Config::Subscription<Protocol>>
subscribe(const std::string& grpc_method, const envoy::api::v2::core::Node& node,
	  Upstream::ClusterManager& cm, Event::Dispatcher& dispatcher, Stats::Scope &scope) {
  // Hard-coded Cilium gRPC cluster
  envoy::api::v2::core::ApiConfigSource api_config_source{};
  api_config_source.set_api_type(envoy::api::v2::core::ApiConfigSource::GRPC);
  api_config_source.add_cluster_names("xdsCluster");

  Config::Utility::checkApiConfigSourceSubscriptionBackingCluster(cm.clusters(), api_config_source);
  Config::SubscriptionStats stats = Config::Utility::generateStats(scope);

  const auto* method = Protobuf::DescriptorPool::generated_pool()->FindMethodByName(grpc_method);

  if (method == nullptr) {
    throw EnvoyException(fmt::format("gRPC method {} not found.", grpc_method));
  }

  return std::make_unique<Config::GrpcSubscriptionImpl<Protocol>>(
                node,
		Config::Utility::factoryForApiConfigSource(cm.grpcAsyncClientManager(),
							   api_config_source,
							   scope)->create(),
		dispatcher, *method, stats);
}

} // namespace Cilium
} // namespace Envoy
