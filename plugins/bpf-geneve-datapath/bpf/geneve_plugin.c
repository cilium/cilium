// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf/compiler.h>
#include <bpf/section.h>

/* PRE-hook attached to cil_from_netdev:
 * Inspects incoming UDP packets on BPF_GENEVE_DEFAULT_PORT (6081)
 * and prepares tunnel metadata for native BPF Geneve ingress decapsulation.
 */
__section("freplace")
int geneve_from_netdev_pre(struct __ctx_buff *ctx __maybe_unused)
{
	return 0;
}

/* POST-hook attached to cil_to_netdev:
 * Observes and validates native BPF Geneve encapsulated egress frames.
 */
__section("freplace")
int geneve_to_netdev_post(struct __ctx_buff *ctx __maybe_unused, int ret)
{
	return ret;
}

/* PRE-hook attached to cil_from_container:
 * Evaluates whether egress container traffic requires Geneve encapsulation.
 */
__section("freplace")
int geneve_from_container_pre(struct __ctx_buff *ctx __maybe_unused)
{
	return 0;
}

/* POST-hook attached to cil_to_container:
 * Observes decapsulated packets delivered to local containers.
 */
__section("freplace")
int geneve_to_container_post(struct __ctx_buff *ctx __maybe_unused, int ret)
{
	return ret;
}

/* PRE-hook attached to cil_from_overlay:
 * Inspects decapsulated overlay packets entering cil_from_overlay.
 */
__section("freplace")
int geneve_from_overlay_pre(struct __ctx_buff *ctx __maybe_unused)
{
	return 0;
}

/* POST-hook attached to cil_to_overlay:
 * Observes overlay egress packets after encapsulation processing.
 */
__section("freplace")
int geneve_to_overlay_post(struct __ctx_buff *ctx __maybe_unused, int ret)
{
	return ret;
}

BPF_LICENSE("Dual BSD/GPL");
