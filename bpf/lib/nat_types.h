#pragma once

#include "common.h"

struct nat_entry {
	__u64 created;
	__u64 needs_ct;		/* Only single bit used. */
	__u64 pad1;		/* Future use. */
	__u64 pad2;		/* Future use. */
};

struct ipv6_nat_entry {
	struct nat_entry common;
	union {
		struct lb6_reverse_nat nat_info;
		struct {
			union v6addr to_saddr;
			__be16       to_sport;
		};
		struct {
			union v6addr to_daddr;
			__be16       to_dport;
		};
	};
};
