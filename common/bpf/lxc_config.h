/* Dummy configuration for test compilation */

/*
 * Container ID: 33468
 * MAC: aa:bb:cc:dd:ee:ff
 * IP: beef::1:165:82bc
 * Router MAC: de:ad:be:ef:c0:de
 */

#define NODE_ID 1
#define LXC_MAC { .addr = { 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff } }
#define LXC_IP { .addr = { 0xbe, 0xef, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x1, 0x1, 0x65, 0x82, 0xbc } }
#define ROUTER_MAC { .addr = { 0xde, 0xad, 0xbe, 0xef, 0xc0, 0xde } }
#define ROUTER_IP { 0xbe, 0xef, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x1, 0, 0, 0, 0 }
