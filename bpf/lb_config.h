#ifndef __LB_CONFIG_H__
#define __LB_CONFIG_H__

/*
 * This is just a dummy header with dummy values to allow for test
 * compilation without the full code generation engine backend.
 */

#define HANDLE_NS

/* Prefix to use when sending packet to server */
#define SERVER_PREFIX { 0xf0, 0x0d, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 }
/* Load balancer IPv6 address */
#define ROUTER_IP { 0x20, 0x01, 0x0d, 0xb8, 0xaa, 0xaa, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x03 }
/* Load balancer Mac address */
#define NODE_MAC { .addr = { 0x52, 0x54, 0x0, 0xa6, 0xf2, 0x22 } }

/*
 * FIXME: Next two defines are not needed by having stack handle the packet
 */

/* mac address of the server */
#define LXC_MAC { .addr = { 0x52, 0x54, 0x0, 0xb3, 0x02, 0xe8 }}
 /* ifindex of load balancer server side interface */
#define LB_SERVER_IFINDEX 3

#endif /* __LB_CONFIG_H__ */
