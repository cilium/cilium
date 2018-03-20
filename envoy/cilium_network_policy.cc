#include "cilium_network_policy.h"
#include "cilium/npds.pb.validate.h"

#include <string>
#include <unordered_set>

#include "common/config/grpc_subscription_impl.h"
#include "common/config/utility.h"
#include "common/protobuf/protobuf.h"
#include "envoy/singleton/instance.h"

namespace Envoy {
namespace Cilium {

namespace {

std::unique_ptr<Envoy::Config::Subscription<cilium::NetworkPolicy>>
subscribe(const envoy::api::v2::core::ApiConfigSource& api_config_source,
	  const LocalInfo::LocalInfo& local_info,
	  Upstream::ClusterManager& cm, Event::Dispatcher& dispatcher,
	  Stats::Scope &scope) {
  Config::Utility::checkApiConfigSourceSubscriptionBackingCluster(cm.clusters(), api_config_source);
  Config::SubscriptionStats stats = Config::Utility::generateStats(scope);

  return std::make_unique<Config::GrpcSubscriptionImpl<cilium::NetworkPolicy>>(
                local_info.node(),
		Config::Utility::factoryForApiConfigSource(cm.grpcAsyncClientManager(),
							   api_config_source,
							   scope)->create(),
		dispatcher,
		*Protobuf::DescriptorPool::generated_pool()->FindMethodByName(
		      "cilium.NetworkPolicyDiscoveryService.StreamNetworkPolicies"),
		stats);
}

} // namespace

NetworkPolicyMap::NetworkPolicyMap(std::unique_ptr<Envoy::Config::Subscription<cilium::NetworkPolicy>>&& subscription,
				   ThreadLocal::SlotAllocator& tls)
  : tls_(tls.allocateSlot()), subscription_(std::move(subscription)) {
  tls_->set([&](Event::Dispatcher&) -> ThreadLocal::ThreadLocalObjectSharedPtr {
      return std::make_shared<ThreadLocalPolicyMap>();
  });
  subscription_->start({}, *this);
}

NetworkPolicyMap::NetworkPolicyMap(const envoy::api::v2::core::ApiConfigSource& api_config_source,
				   const LocalInfo::LocalInfo& local_info,
				   Upstream::ClusterManager& cm, Event::Dispatcher& dispatcher,
				   Stats::Scope &scope, ThreadLocal::SlotAllocator& tls)
  : NetworkPolicyMap(subscribe(api_config_source, local_info, cm, dispatcher, scope), tls) {}

void NetworkPolicyMap::onConfigUpdate(const ResourceVector& resources) {
  ENVOY_LOG(debug, "NetworkPolicyMap::onConfigUpdate({}), version: {}", resources.size(), subscription_->versionInfo());

  if (resources.empty()) {
    ENVOY_LOG(warn, "Empty Network Policy in onConfigUpdate()");
    return;
  }
  std::unordered_set<std::string> keeps;

  // Collect a shared vector of policies to be added
  auto to_be_added = std::make_shared<std::vector<std::shared_ptr<PolicyInstance>>>();
  for (const auto& config: resources) {
    ENVOY_LOG(debug, "Received Network Policy for endpoint {} in onConfigUpdate() version {}", config.name(), subscription_->versionInfo(), config.name());
    keeps.insert(config.name());

    MessageUtil::validate(config);

    // First find the old config to figure out if an update is needed.
    const uint64_t new_hash = MessageUtil::hash(config);
    const auto& old_policy = GetPolicyInstance(config.name());
    if (old_policy && old_policy->hash_ == new_hash &&
	Protobuf::util::MessageDifferencer::Equals(old_policy->policy_proto_, config)) {
      ENVOY_LOG(debug, "New policy is equal to old one, not updating.");
      continue;
    }

    // May throw
    to_be_added->emplace_back(std::make_shared<PolicyInstance>(new_hash, config));
  }

  // Collect a shared vector of policy names to be removed
  auto to_be_deleted = std::make_shared<std::vector<std::string>>();
  for (auto& pair: tls_->getTyped<ThreadLocalPolicyMap>().policies_) {
    if (keeps.find(pair.first) == keeps.end()) {
      to_be_deleted->emplace_back(pair.first);
    }
  }

  // Execute changes on all threads.
  tls_->runOnAllThreads([this, to_be_added, to_be_deleted]() -> void {
      if (tls_->get().get() == nullptr) {
	ENVOY_LOG(warn, "Cilium L7 NetworkPolicyMap::onConfigUpdate(): NULL TLS object!");
	return;
      }
      auto& npmap = tls_->getTyped<ThreadLocalPolicyMap>().policies_;
      for (const auto& policy_name: *to_be_deleted) {
	ENVOY_LOG(debug, "Cilium deleting removed network policy for endpoint {}", policy_name);
	npmap.erase(policy_name);
      }
      for (const auto& new_policy: *to_be_added) {
	ENVOY_LOG(debug, "Cilium updating network policy for endpoint {}", new_policy->policy_proto_.name());
	npmap[new_policy->policy_proto_.name()] = new_policy;
      }
    });
}

void NetworkPolicyMap::onConfigUpdateFailed(const EnvoyException*) {
  // We need to allow server startup to continue, even if we have a bad
  // config.
  ENVOY_LOG(warn, "Bad Network Policy Configuration");
}

} // namespace Cilium
} // namespace Envoy
