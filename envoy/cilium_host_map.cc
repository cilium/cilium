#include "cilium_host_map.h"
#include "cilium/nphds.pb.validate.h"
#include "grpc_subscription.h"

#include <string>
#include <unordered_set>

#include "common/config/utility.h"
#include "common/protobuf/protobuf.h"

namespace Envoy {
namespace Cilium {

uint64_t PolicyHostMap::instance_id_ = 0;

PolicyHostMap::PolicyHostMap(ThreadLocal::SlotAllocator& tls) : tls_(tls.allocateSlot()) {
  instance_id_++;
  name_ = "cilium.hostmap." + fmt::format("{}", instance_id_) + ".";
  ENVOY_LOG(debug, "PolicyHostMap({}) created.", name_);  

  auto empty_map = std::make_shared<ThreadLocalHostMap>();
  tls_->set([empty_map](Event::Dispatcher&) -> ThreadLocal::ThreadLocalObjectSharedPtr {
      return empty_map;
  });
}

// This is used for testing with a file-based subscription
PolicyHostMap::PolicyHostMap(std::unique_ptr<Envoy::Config::Subscription<cilium::NetworkPolicyHosts>>&& subscription,
			     ThreadLocal::SlotAllocator& tls)
  : PolicyHostMap(tls) {
  subscription_ = std::move(subscription);
}

// This is used in production
PolicyHostMap::PolicyHostMap(const envoy::api::v2::core::Node& node, Upstream::ClusterManager& cm,
			     Event::Dispatcher& dispatcher, Stats::Scope &scope,
			     ThreadLocal::SlotAllocator& tls)
  : PolicyHostMap(tls) {
  scope_ = scope.createScope(name_);
  subscription_ = subscribe<cilium::NetworkPolicyHosts>("cilium.NetworkPolicyHostsDiscoveryService.StreamNetworkPolicyHosts", node, cm, dispatcher, *scope_);
}

void PolicyHostMap::onConfigUpdate(const ResourceVector& resources) {
  std::string version;
  if (subscription_) {
    version = subscription_->versionInfo();
  }
  ENVOY_LOG(debug, "PolicyHostMap::onConfigUpdate({}), {} resources, current version: {}", name_, resources.size(), version);

  auto newmap = std::make_shared<ThreadLocalHostMap>();
  
  // Update the copy.
  for (const auto& config: resources) {
    ENVOY_LOG(debug, "Received NetworkPolicyHosts for policy {} in onConfigUpdate() version {}", config.policy(), version);

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
