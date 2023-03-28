// SPDX-License-Identifier: GPL-2.0
/// Find missing calls to identity_is_remote_node and identity_is_node.
/// We want to use those functions whenever possible, to make sure
/// KUBE_APISERVER_NODE_ID is properly accounted for and to prepare for
/// future extensions.
// Confidence: Medium
// Copyright Authors of Cilium.
// Comments:
// Options: --include-headers

@initialize:python@
@@

cnt = 0


@rule@
position p1 : script:python() { p1[0].current_element not in ["identity_is_node"] };
position p2 : script:python() { p2[0].current_element not in ["identity_is_remote_node"] };
expression e;
@@

(
- e != HOST_ID && e != REMOTE_NODE_ID@p1
+ !identity_is_node(e)
|
- e != REMOTE_NODE_ID@p1 && e != HOST_ID
+ !identity_is_node(e)
|
- e == HOST_ID || e == REMOTE_NODE_ID@p1
+ identity_is_node(e)
|
- e == REMOTE_NODE_ID@p1 || e == HOST_ID
+ identity_is_node(e)
|
- e == REMOTE_NODE_ID@p2
+ identity_is_remote_node(e)
|
- e != REMOTE_NODE_ID@p2
+ !identity_is_remote_node(e)
)


@script:python@
p1 << rule.p1 = [];
p2 << rule.p2 = [];
@@

if len(p1) > 0:
  print("* file %s: use identity_is_node on line %s" % (p1[0].file, p1[0].line))
  cnt += 1

if len(p2) > 0:
  print("* file %s: use identity_is_remote_node on line %s" % (p2[0].file, p2[0].line))
  cnt += 1


@finalize:python@
@@

if cnt > 0:
  print("""Use the following command to fix the above issues:
docker run --rm --user 1000 --workdir /workspace -v `pwd`:/workspace \\
    -e COCCINELLE_HOME=/usr/local/lib/coccinelle \\
    -it docker.io/cilium/coccicheck:2.4@sha256:24abe3fbb8e829fa41a68a3b76cb4df84fd5a87a7d1d6254c1c1fe5effb5bd1b \\
    spatch --include-headers --very-quiet --in-place bpf/ \\
    --sp-file contrib/coccinelle/identity_is_node.cocci\n
""")
