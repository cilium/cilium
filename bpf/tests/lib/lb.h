/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#ifdef ENABLE_IPV4
static __always_inline void
lb_v4_delete_service(__be32 addr, __be16 port, __u8 proto)
{
	struct lb4_key svc_key = {
		.address = addr,
		.dport = port,
		.proto = proto,
		.scope = LB_LOOKUP_SCOPE_EXT,
	};

	map_delete_elem(&cilium_lb4_services_v2, &svc_key);
	svc_key.scope = LB_LOOKUP_SCOPE_INT;
	map_delete_elem(&cilium_lb4_services_v2, &svc_key);
}

static __always_inline void
__lb_v4_upsert_service(__be32 addr, __be16 port, __u8 proto, __u8 proto_int,
		       __u16 backend_count, __u16 rev_nat_index, __u8 flags, __u8 flags2,
		       bool session_affinity, __u32 affinity_timeout)
{
	struct lb4_key svc_key = {
		.address = addr,
		.dport = port,
		.proto = proto,
		.scope = LB_LOOKUP_SCOPE_EXT,
	};
	struct lb4_service svc_value = {
		.count = backend_count,
		.flags = flags,
		.flags2 = flags2,
		.rev_nat_index = rev_nat_index,
	};
	if (session_affinity) {
		/* 0 indicates the svc frontend */
		svc_key.backend_slot = 0;
		svc_value.flags |= SVC_FLAG_AFFINITY;
		svc_value.affinity_timeout = affinity_timeout;
	}
	map_update_elem(&cilium_lb4_services_v2, &svc_key, &svc_value, BPF_ANY);

	if (lb4_svc_is_two_scopes(&svc_value)) {
		/* Register with both scopes: */
		svc_key.proto = proto_int;
		svc_key.scope = LB_LOOKUP_SCOPE_INT;
		map_update_elem(&cilium_lb4_services_v2, &svc_key, &svc_value, BPF_ANY);
	}
}

static __always_inline void
lb_v4_upsert_service(__be32 addr, __be16 port, __u8 proto, __u16 backend_count,
		     __u16 rev_nat_index)
{
	__lb_v4_upsert_service(addr, port, proto, proto, backend_count, rev_nat_index,
			       SVC_FLAG_ROUTABLE, 0, false, 0);
}

static __always_inline void
__lb_v4_add_service(__be32 addr, __be16 port, __u8 proto, __u8 proto_int,
		    __u16 backend_count, __u16 rev_nat_index, __u8 flags,
		    __u8 flags2, bool session_affinity, __u32 affinity_timeout)
{
	/* Register with both scopes: */
	__lb_v4_upsert_service(addr, port, proto, proto_int, backend_count, rev_nat_index,
			       flags, flags2, session_affinity, affinity_timeout);

	/* Insert a reverse NAT entry for the above service */
	struct lb4_reverse_nat revnat_value = {
		.address = addr,
		.port = port,
	};
	map_update_elem(&cilium_lb4_reverse_nat, &rev_nat_index, &revnat_value, BPF_ANY);
}

static __always_inline void
lb_v4_add_service(__be32 addr, __be16 port, __u8 proto, __u16 backend_count,
		  __u16 rev_nat_index)
{
	__lb_v4_add_service(addr, port, proto, proto, backend_count, rev_nat_index,
			    SVC_FLAG_ROUTABLE, 0, false, 0);
}

static __always_inline void
lb_v4_add_service_with_flags(__be32 addr, __be16 port, __u8 proto, __u16 backend_count,
			     __u16 rev_nat_index, __u8 flags, __u8 flags2)
{
	__lb_v4_add_service(addr, port, proto, proto, backend_count, rev_nat_index,
			    flags, flags2, false, 0);
}

static __always_inline void
lb_v4_add_mixed_proto_service_with_flags(__be32 addr, __be16 port, __u8 proto,
					 __u8 proto_int, __u16 backend_count,
					 __u16 rev_nat_index, __u8 flags, __u8 flags2)
{
	__lb_v4_add_service(addr, port, proto, proto_int, backend_count, rev_nat_index,
			    flags, flags2, false, 0);
}

static __always_inline void
lb_v4_upsert_backend(__u32 backend_id, __be32 backend_addr, __be16 backend_port,
		     __u8 backend_proto, __u8 flags, __u8 cluster_id)
{
	struct lb4_backend backend = {
		.address = backend_addr,
		.port = backend_port,
		.proto = backend_proto,
		.flags = flags,
		.cluster_id = cluster_id,
	};

	map_update_elem(&cilium_lb4_backends_v3, &backend_id, &backend, BPF_ANY);
}

static __always_inline void
__lb_v4_add_backend(__be32 svc_addr, __be16 svc_port, __u16 backend_slot, __u32 backend_id,
		    __be32 backend_addr, __be16 backend_port, __u8 backend_proto, __u8 cluster_id,
		    bool session_affinity)
{
	/* Create the actual backend: */
	lb_v4_upsert_backend(backend_id, backend_addr, backend_port,
			     backend_proto, BE_STATE_ACTIVE, cluster_id);

	struct lb4_key svc_key = {
		.address = svc_addr,
		.dport = svc_port,
		.proto = backend_proto,
		.backend_slot = backend_slot,
		.scope = LB_LOOKUP_SCOPE_EXT,
	};
	struct lb4_service svc_value = {
		.backend_id = backend_id,
		.flags = SVC_FLAG_ROUTABLE,
	};
	if (session_affinity)
		svc_value.flags |= SVC_FLAG_AFFINITY;
	/* Point the service's backend_slot at the created backend: */
	map_update_elem(&cilium_lb4_services_v2, &svc_key, &svc_value, BPF_ANY);
}

static __always_inline void
lb_v4_add_backend(__be32 svc_addr, __be16 svc_port, __u16 backend_slot, __u32 backend_id,
		  __be32 backend_addr, __be16 backend_port, __u8 backend_proto,	__u8 cluster_id)
{
	__lb_v4_add_backend(svc_addr, svc_port, backend_slot, backend_id, backend_addr,
			    backend_port, backend_proto, cluster_id, false);
}
#endif

#ifdef ENABLE_IPV6
static __always_inline void
__lb_v6_add_service(const union v6addr *addr, __be16 port, __u8 proto,
		    __u16 backend_count, __u16 rev_nat_index,
		    __u8 flags, __u8 flags2)
{
	struct lb6_key svc_key __align_stack_8 = {
		.dport = port,
		.proto = proto,
		.scope = LB_LOOKUP_SCOPE_EXT,
	};
	struct lb6_service svc_value = {
		.count = backend_count,
		.flags = flags,
		.flags2 = flags2,
		.rev_nat_index = rev_nat_index,
	};

	memcpy(&svc_key.address, addr, sizeof(*addr));
	map_update_elem(&cilium_lb6_services_v2, &svc_key, &svc_value, BPF_ANY);
	svc_key.scope = LB_LOOKUP_SCOPE_INT;
	map_update_elem(&cilium_lb6_services_v2, &svc_key, &svc_value, BPF_ANY);

	/* Insert a reverse NAT entry for the above service */
	struct lb6_reverse_nat revnat_value __align_stack_8 = {
		.port = port,
	};

	memcpy(&revnat_value.address, addr, sizeof(*addr));
	map_update_elem(&cilium_lb6_reverse_nat, &rev_nat_index, &revnat_value, BPF_ANY);
}

static __always_inline void
lb_v6_add_service(const union v6addr *addr, __be16 port, __u8 proto,
		  __u16 backend_count, __u16 rev_nat_index)
{
	__lb_v6_add_service(addr, port, proto, backend_count, rev_nat_index,
			    SVC_FLAG_ROUTABLE, 0);
}

static __always_inline void
lb_v6_add_service_with_flags(const union v6addr *addr, __be16 port, __u8 proto,
			     __u16 backend_count, __u16 rev_nat_index, __u8 flags,
			     __u8 flags2)
{
	__lb_v6_add_service(addr, port, proto, backend_count, rev_nat_index, flags,
			    flags2);
}

static __always_inline void
lb_v6_add_backend(const union v6addr *svc_addr, __be16 svc_port, __u16 backend_slot,
		  __u32 backend_id, const union v6addr *backend_addr,
		  __be16 backend_port, __u8 backend_proto, __u8 cluster_id)
{
	struct lb6_key svc_key __align_stack_8 = {
		.dport = svc_port,
		.backend_slot = backend_slot,
		.proto = backend_proto,
		.scope = LB_LOOKUP_SCOPE_EXT,
	};
	struct lb6_service svc_value = {
		.backend_id = backend_id,
		.flags = SVC_FLAG_ROUTABLE,
	};

	memcpy(&svc_key.address, svc_addr, sizeof(*svc_addr));
	map_update_elem(&cilium_lb6_services_v2, &svc_key, &svc_value, BPF_ANY);

	struct lb6_backend backend __align_stack_8 = {
		.port = backend_port,
		.proto = backend_proto,
		.flags = BE_STATE_ACTIVE,
		.cluster_id = cluster_id,
	};

	memcpy(&backend.address, backend_addr, sizeof(*backend_addr));
	map_update_elem(&cilium_lb6_backends_v3, &backend_id, &backend, BPF_ANY);
}
#endif
