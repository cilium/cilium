/*
 *  Copyright (C) 2016 Authors of Cilium
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */
#ifndef __LB_CONFIG_H__
#define __LB_CONFIG_H__

/*
 * This is just a dummy header with dummy values to allow for test
 * compilation without the full code generation engine backend.
 */

#define HANDLE_NS

/* Prefix to use when sending packet to server */
#define SERVER_PREFIX { 0xf0, 0x0d, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 }
/* Load balancer eth1 IPv6 address */
#define ROUTER_IP { 0x20, 0x01, 0x0d, 0xb8, 0xaa, 0xaa, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x02 }
/* Load balancer eth1 Mac address */
#define NODE_MAC { .addr = { 0x52, 0x54, 0x0, 0xc9, 0xa6, 0xbf } }

#endif /* __LB_CONFIG_H__ */
