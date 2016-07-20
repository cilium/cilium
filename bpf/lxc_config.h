/*
 * This is just a dummy header with dummy values to allow for test
 * compilation without the full code generation engine backend.
 */

#define LXC_MAC { .addr = { 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff } }
#define LXC_IP { .addr = { 0xbe, 0xef, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x1, 0x1, 0x65, 0x82, 0xbc } }
#define LXC_IPV4 0x10203040
#define LXC_ID 0x1010
#define LXC_ID_NB 0x1010
#ifndef SECLABEL
#define SECLABEL 0xfffff
#define SECLABEL_NB 0xfffff
#endif
#define POLICY_MAP cilium_policy_foo
#define NODE_MAC { .addr = { 0xde, 0xad, 0xbe, 0xef, 0xc0, 0xde } }
#define GENEVE_OPTS { 0xff, 0xff, 0x1, 0x1, 0x0, 0x0, 0x1, 0x1e }
#define DROP_NOTIFY
#define CT_MAP6 cilium_ct6_111
#define CT_MAP4 cilium_ct4_111
#define CT_MAP_SIZE 4096
