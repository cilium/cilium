#include "cilium_network_policy.h"
#include "cilium/npds.pb.validate.h"
#include "grpc_subscription.h"

#include <string>
#include <unordered_set>

#include "common/config/utility.h"
#include "common/protobuf/protobuf.h"

namespace Envoy {
namespace Cilium {

uint64_t NetworkPolicyMap::instance_id_ = 0;

NetworkPolicyMap::NetworkPolicyMap(ThreadLocal::SlotAllocator& tls) : tls_(tls.allocateSlot()) {
  instance_id_++;
  name_ = "cilium.policymap." + fmt::format("{}", instance_id_) + ".";
  ENVOY_LOG(debug, "NetworkPolicyMap({}) created.", name_);  

  tls_->set([&](Event::Dispatcher&) -> ThreadLocal::ThreadLocalObjectSharedPtr {
      return std::make_shared<ThreadLocalPolicyMap>();
  });
}

// This is used for testing with a file-based subscription
NetworkPolicyMap::NetworkPolicyMap(std::unique_ptr<Envoy::Config::Subscription<cilium::NetworkPolicy>>&& subscription,
				   ThreadLocal::SlotAllocator& tls)
  : NetworkPolicyMap(tls) {
  subscription_ = std::move(subscription);
}

// This is used in production
NetworkPolicyMap::NetworkPolicyMap(const envoy::api::v2::core::Node& node,
				   Upstream::ClusterManager& cm, Event::Dispatcher& dispatcher,
				   Stats::Scope &scope, ThreadLocal::SlotAllocator& tls)
  : NetworkPolicyMap(tls) {
  scope_ = scope.createScope(name_);
  subscription_ = subscribe<cilium::NetworkPolicy>("cilium.NetworkPolicyDiscoveryService.StreamNetworkPolicies", node, cm, dispatcher, *scope_);
}

void NetworkPolicyMap::onConfigUpdate(const ResourceVector& resources, const std::string& version_info) {
  ENVOY_LOG(debug, "NetworkPolicyMap::onConfigUpdate({}), {} resources, version: {}", name_, resources.size(), version_info);

  std::unordered_set<std::string> keeps;

  // Collect a shared vector of policies to be added
  auto to_be_added = std::make_shared<std::vector<std::shared_ptr<PolicyInstance>>>();
  for (const auto& config: resources) {
    ENVOY_LOG(debug, "Received Network Policy for endpoint {} in onConfigUpdate() version {}", config.name(), version_info);
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

  // 'this' may be already deleted when the worker threads get to execute the updates.
  // Manage this by taking a weak_ptr on 'this' and then, when the worker thread gets
  // to execute the posted lambda, try to convert the weak_ptr to a temporary shared_ptr.
  // If that succeeds then this NetworkPolicyMap is still alive and the policy
  // should be updated.
  std::weak_ptr<NetworkPolicyMap> weak_this = shared_from_this();

  // Execute changes on all threads.
  tls_->runOnAllThreads([weak_this, to_be_added, to_be_deleted]() -> void {
      std::shared_ptr<NetworkPolicyMap> shared_this = weak_this.lock();
      if (shared_this && shared_this->tls_->get().get() != nullptr) {
	ENVOY_LOG(debug, "Cilium L7 NetworkPolicyMap::onConfigUpdate(): Starting updates on the next thread");
	auto& npmap = shared_this->tls_->getTyped<ThreadLocalPolicyMap>().policies_;
	for (const auto& policy_name: *to_be_deleted) {
	  ENVOY_LOG(debug, "Cilium deleting removed network policy for endpoint {}", policy_name);
	  npmap.erase(policy_name);
	}
	for (const auto& new_policy: *to_be_added) {
	  ENVOY_LOG(debug, "Cilium updating network policy for endpoint {}", new_policy->policy_proto_.name());
	  npmap[new_policy->policy_proto_.name()] = new_policy;
	}
      } else {
	// Keep this at info level for now to see if this happens in the wild
	ENVOY_LOG(warn, "Skipping stale network policy update");
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
