#pragma once

#include <arpa/inet.h>

#include "envoy/local_info/local_info.h"
#include "envoy/upstream/cluster_manager.h"
#include "envoy/event/dispatcher.h"

#include "common/common/logger.h"
#include "common/network/utility.h"
#include "envoy/config/subscription.h"
#include "envoy/singleton/instance.h"
#include "envoy/thread_local/thread_local.h"

#include "cilium/nphds.pb.h"

#include "absl/numeric/int128.h"

// std::hash specialization for Abseil uint128, needed for unordered_map key.
namespace std {
  template <> struct hash<absl::uint128>
  {
    size_t operator()(const absl::uint128& x) const
    {
      return hash<uint64_t>{}(absl::Uint128Low64(x)) ^ (hash<uint64_t>{}(absl::Uint128High64(x)) << 1);
    }
  };
}

namespace Envoy {
namespace Cilium {

template <typename I> I ntoh(I);
template <> inline uint32_t ntoh(uint32_t addr) { return ntohl(addr); }
template <> inline absl::uint128 ntoh(absl::uint128 addr) { return Network::Utility::Ip6ntohl(addr); }
template <typename I> I hton(I);
template <> inline uint32_t hton(uint32_t addr) { return htonl(addr); }
template <> inline absl::uint128 hton(absl::uint128 addr) { return Network::Utility::Ip6htonl(addr); }

template <typename I> I masked(I addr, unsigned int plen) {
  const unsigned int PLEN_MAX = sizeof(I)*8;
  return addr & ~hton((I(1) << (PLEN_MAX - plen)) - 1);
};

enum ID : uint64_t { UNKNOWN = 0, WORLD = 2 };

class PolicyHostMap : public Singleton::Instance,
                      Config::SubscriptionCallbacks<cilium::NetworkPolicyHosts>,
                      public Logger::Loggable<Logger::Id::config> {
public:
  PolicyHostMap(const envoy::api::v2::core::Node& node,
		Upstream::ClusterManager& cm, Event::Dispatcher& dispatcher,
		Stats::Scope &scope, ThreadLocal::SlotAllocator& tls);
  PolicyHostMap(std::unique_ptr<Envoy::Config::Subscription<cilium::NetworkPolicyHosts>>&& subscription,
		ThreadLocal::SlotAllocator& tls);
  PolicyHostMap(ThreadLocal::SlotAllocator& tls);
  ~PolicyHostMap() {}

  // A shared pointer to a immutable copy is held by each thread. Changes are done by
  // creating a new version and assigning the new shared pointer to the thread local
  // slot on each thread.
  struct ThreadLocalHostMap : public ThreadLocal::ThreadLocalObject {
  public:
    // Find the longest prefix match of the addr, return the matching policy id,
    // or ID::WORLD if there is no match.
    uint64_t resolve(const Network::Address::Ip* addr) const {
      auto* ipv4 = addr->ipv4();
      if (ipv4) {
	for (const auto& pair: ipv4_to_policy_) {
	  auto it = pair.second.find(masked(ipv4->address(), pair.first));
	  if (it != pair.second.end()) {
	    return it->second;
	  }
	}
      } else {
	auto* ipv6 = addr->ipv6();
	if (ipv6) {
	  for (const auto& pair: ipv6_to_policy_) {
	    auto it = pair.second.find(masked(ipv6->address(), pair.first));
	    if (it != pair.second.end()) {
	      return it->second;
	    }
	  }
	}
      }
      return ID::WORLD;
    }

  protected:
    // Vectors of <prefix-len>, <address-map> pairs, ordered in the decreasing prefix length,
    // where map keys are addresses of the given prefix length. Address bits outside of the
    // prefix are zeroes.
    std::vector<std::pair<unsigned int, std::unordered_map<uint32_t, uint64_t>>> ipv4_to_policy_;
    std::vector<std::pair<unsigned int, std::unordered_map<absl::uint128, uint64_t>>> ipv6_to_policy_;
  };
  typedef std::shared_ptr<ThreadLocalHostMap> ThreadLocalHostMapSharedPtr;

  const ThreadLocalHostMap* getHostMap() const {
    return &tls_->getTyped<ThreadLocalHostMap>();
  }

  uint64_t resolve(const Network::Address::Ip* addr) const {
    const ThreadLocalHostMap* hostmap = getHostMap();
    return (hostmap != nullptr) ? hostmap->resolve(addr) : ID::UNKNOWN;
  }

  // Config::SubscriptionCallbacks
  void onConfigUpdate(const ResourceVector& resources) override;
  void onConfigUpdateFailed(const EnvoyException* e) override;
  std::string resourceName(const ProtobufWkt::Any& resource) override {
    return fmt::format("{}", MessageUtil::anyConvert<cilium::NetworkPolicyHosts>(resource).policy());
  }

private:
  ThreadLocal::SlotPtr tls_;
  std::unique_ptr<Envoy::Config::Subscription<cilium::NetworkPolicyHosts>> subscription_;
  const ThreadLocalHostMapSharedPtr null_hostmap_{nullptr};
};

} // namespace Cilium
} // namespace Envoy
