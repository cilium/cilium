#include "cilium_host_map.h"
#include "cilium/nphds.pb.validate.h"
#include "grpc_subscription.h"

#include <string>
#include <unordered_set>

#include "common/config/utility.h"
#include "common/protobuf/protobuf.h"

namespace Envoy {
namespace Cilium {

PolicyHostMap::PolicyHostMap(std::unique_ptr<Envoy::Config::Subscription<cilium::NetworkPolicyHosts>>&& subscription,
				   ThreadLocal::SlotAllocator& tls)
  : tls_(tls.allocateSlot()), subscription_(std::move(subscription)) {
  auto empty_map = std::make_shared<ThreadLocalHostMap>();
  tls_->set([empty_map](Event::Dispatcher&) -> ThreadLocal::ThreadLocalObjectSharedPtr {
      return empty_map;
  });
}

PolicyHostMap::PolicyHostMap(const envoy::api::v2::core::Node& node, Upstream::ClusterManager& cm,
			     Event::Dispatcher& dispatcher, Stats::Scope &scope,
			     ThreadLocal::SlotAllocator& tls)
  : PolicyHostMap(subscribe<cilium::NetworkPolicyHosts>("cilium.NetworkPolicyHostsDiscoveryService.StreamNetworkPolicyHosts", node, cm, dispatcher, scope), tls) {}

void PolicyHostMap::onConfigUpdate(const ResourceVector& resources) {
  ENVOY_LOG(debug, "PolicyHostMap::onConfigUpdate({}), version: {}", resources.size(), subscription_->versionInfo());

  auto newmap = std::make_shared<ThreadLocalHostMap>();
  
  // Update the copy.
  for (const auto& config: resources) {
    ENVOY_LOG(debug, "Received NetworkPolicyHosts for policy {} in onConfigUpdate() version {}", config.policy(), subscription_->versionInfo());

    MessageUtil::validate(config);

    newmap->insert(config);
  }

  // Force 'this' to be not deleted for as long as the lambda stays
  // alive.  Note that generally capturing a shared pointer is
  // dangerous as it may happen that there is a circular reference
  // from 'this' to itself via the lambda capture, leading to 'this'
  // never being released. It should happen in this case, though.
  std::shared_ptr<PolicyHostMap> shared_this = shared_from_this();

  // Assign the new map to all threads.
  tls_->set([shared_this, newmap](Event::Dispatcher&) -> ThreadLocal::ThreadLocalObjectSharedPtr {
      UNREFERENCED_PARAMETER(shared_this);
      return newmap;
  });
}

void PolicyHostMap::onConfigUpdateFailed(const EnvoyException*) {
  // We need to allow server startup to continue, even if we have a bad
  // config.
  ENVOY_LOG(warn, "Bad NetworkPolicyHosts Configuration");
}

} // namespace Cilium
} // namespace Envoy
