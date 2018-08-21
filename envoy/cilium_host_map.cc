#include "cilium_host_map.h"
#include "cilium/nphds.pb.validate.h"
#include "grpc_subscription.h"

#include <string>
#include <unordered_set>

#include "common/config/utility.h"
#include "common/protobuf/protobuf.h"

namespace Envoy {
namespace Cilium {

template <typename T>
unsigned int checkPrefix(T addr, bool have_prefix, unsigned int plen, absl::string_view host) {
  const unsigned int PLEN_MAX = sizeof(T)*8;
  if (!have_prefix) {
    return PLEN_MAX;
  }
  if (plen > PLEN_MAX) {
    throw EnvoyException(fmt::format("NetworkPolicyHosts: Invalid prefix length in \'{}\'", host));
  }
  // Check for 1-bits after the prefix
  if ((plen == 0 && addr) || (plen > 0 && addr & ntoh((T(1) << (PLEN_MAX - plen)) - 1))) {
    throw EnvoyException(fmt::format("NetworkPolicyHosts: Non-prefix bits set in \'{}\'", host));
  }
  return plen;
}

struct ThreadLocalHostMapInitializer : public PolicyHostMap::ThreadLocalHostMap {
protected:
  friend class PolicyHostMap; // PolicyHostMap can insert();

  // find the map of the given prefix length, insert in the decreasing order if it does
  // not exist
  template <typename M>
  M& getMap(std::vector<std::pair<unsigned int, M>>& maps, unsigned int plen) {
    auto it = maps.begin();
    for (; it != maps.end(); it++) {
      if (it->first > plen) {
	ENVOY_LOG(trace, "Skipping map for prefix length {} while looking for {}", it->first, plen);
	continue; // check the next one
      }
      if (it->first == plen) {
	ENVOY_LOG(trace, "Found existing map for prefix length {}", plen);
	return it->second;
      }
      // Current pair has smaller prefix, insert before it to maintain order
      ENVOY_LOG(trace, "Inserting map for prefix length {} before prefix length {}", plen, it->first);
      break;
    }
    // not found, insert before the position 'it'
    ENVOY_LOG(trace, "Inserting map for prefix length {}", plen);
    return maps.emplace(it, std::make_pair(plen, M{}))->second;
  }

  bool insert(uint32_t addr, unsigned int plen, uint64_t policy) {
    auto pair = getMap(ipv4_to_policy_, plen).emplace(std::make_pair(addr, policy));
    return pair.second;
  }

  bool insert(absl::uint128 addr, unsigned int plen, uint64_t policy) {
    auto pair = getMap(ipv6_to_policy_, plen).emplace(std::make_pair(addr, policy));
    return pair.second;
  }

  void insert(const cilium::NetworkPolicyHosts& proto) {
    uint64_t policy = proto.policy();
    const auto& hosts = proto.host_addresses();
    std::string buf;

    for (const auto& host: hosts) {
      const char *addr = host.c_str();
      unsigned int plen = 0;

      ENVOY_LOG(trace, "NetworkPolicyHosts: Inserting CIDR->ID mapping {}->{}...", host, policy);

      // Find the prefix length if any
      const char *slash = strchr(addr, '/');
      bool have_prefix = (slash != nullptr);
      if (have_prefix) {
	const char *pstr = slash + 1;
	// Must start with a digit and have nothing after a zero.
	if (*pstr < '0' || *pstr > '9' || (*pstr == '0' && *(pstr + 1) != '\0')) {
	  throw EnvoyException(fmt::format("NetworkPolicyHosts: Invalid prefix length in \'{}\'", host));
	}
	// Convert to base 10 integer as long as there are digits and plen is not too large.
	// If plen is already 13, next digit will make it at least 130, which is too much.
	while (*pstr >= '0' && *pstr <= '9' && plen < 13) {
	  plen = plen * 10 + (*pstr++ - '0');
	}
	if (*pstr != '\0') {
	  throw EnvoyException(fmt::format("NetworkPolicyHosts: Invalid prefix length in \'{}\'", host));
	}
	// Copy the address without the prefix
	buf.assign(addr, slash);
	addr = buf.c_str();
      }

      uint32_t addr4;
      int rc = inet_pton(AF_INET, addr, &addr4);
      if (rc == 1) {
	plen = checkPrefix(addr4, have_prefix, plen, host);
	if (!insert(addr4, plen, policy)) {
	  uint64_t existing_policy = resolve(addr4);
	  throw EnvoyException(fmt::format("NetworkPolicyHosts: Duplicate host entry \'{}\' for policy {}, already mapped to {}", host, policy, existing_policy));
	}
	continue;
      }
      absl::uint128 addr6;
      rc = inet_pton(AF_INET6, addr, &addr6);
      if (rc == 1) {
	plen = checkPrefix(addr6, have_prefix, plen, host);
	if (!insert(addr6, plen, policy)) {
	  uint64_t existing_policy = resolve(addr6);
	  throw EnvoyException(fmt::format("NetworkPolicyHosts: Duplicate host entry \'{}\' for policy {}, already mapped to {}", host, policy, existing_policy));
	}
	continue;
      }
      throw EnvoyException(fmt::format("NetworkPolicyHosts: Invalid host entry \'{}\' for policy {}", host, policy));
    }
  }
};

uint64_t PolicyHostMap::instance_id_ = 0;

PolicyHostMap::PolicyHostMap(ThreadLocal::SlotAllocator& tls) : tls_(tls.allocateSlot()) {
  instance_id_++;
  name_ = "cilium.hostmap." + fmt::format("{}", instance_id_) + ".";
  ENVOY_LOG(debug, "PolicyHostMap({}) created.", name_);  

  auto empty_map = std::make_shared<ThreadLocalHostMapInitializer>();
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

void PolicyHostMap::onConfigUpdate(const ResourceVector& resources, const std::string& version_info) {
  ENVOY_LOG(debug, "PolicyHostMap::onConfigUpdate({}), {} resources, version: {}", name_, resources.size(), version_info);

  auto newmap = std::make_shared<ThreadLocalHostMapInitializer>();
  
  for (const auto& config: resources) {
    ENVOY_LOG(trace, "Received NetworkPolicyHosts for policy {} in onConfigUpdate() version {}", config.policy(), version_info);

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
      ENVOY_LOG(trace, "PolicyHostMap: Assigning new map");
      return newmap;
  });
  logmaps("onConfigUpdate");
}

void PolicyHostMap::onConfigUpdateFailed(const EnvoyException*) {
  // We need to allow server startup to continue, even if we have a bad
  // config.
  ENVOY_LOG(warn, "Bad NetworkPolicyHosts Configuration");
  logmaps("onConfigUpdateFailed(): keeping old config");
}

} // namespace Cilium
} // namespace Envoy
