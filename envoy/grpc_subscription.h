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
subscribe(const std::string& grpc_method, const LocalInfo::LocalInfo& local_info,
	  Upstream::ClusterManager& cm, Event::Dispatcher& dispatcher,
	  Runtime::RandomGenerator& random, Stats::Scope &scope) {
  // Hard-coded Cilium gRPC cluster
  envoy::api::v2::core::ApiConfigSource api_config_source{};
  api_config_source.set_api_type(envoy::api::v2::core::ApiConfigSource::GRPC);
  api_config_source.add_grpc_services()->mutable_envoy_grpc()->set_cluster_name("xds-grpc-cilium");

  Config::Utility::checkApiConfigSourceSubscriptionBackingCluster(cm.clusters(), api_config_source);
  const auto* method = Protobuf::DescriptorPool::generated_pool()->FindMethodByName(grpc_method);

  if (method == nullptr) {
    throw EnvoyException(fmt::format("gRPC method {} not found.", grpc_method));
  }

  return std::make_unique<Config::GrpcSubscriptionImpl<Protocol>>(
                local_info,
		Config::Utility::factoryForGrpcApiConfigSource(cm.grpcAsyncClientManager(),
							       api_config_source,
							       scope)->create(),
		dispatcher, random, *method, Config::Utility::generateStats(scope));
}

} // namespace Cilium
} // namespace Envoy
