#!/bin/sh
# shellcheck disable=SC2166

# This script is copied from upstream with below link
# https://github.com/kubernetes-sigs/iptables-wrappers/blob/e139a115350974aac8a82ec4b815d2845f86997e/iptables-wrapper-installer.sh
# Copyright 2020 The Kubernetes Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Usage:
#
#   iptables-wrapper-installer.sh [--no-sanity-check]
#
# Installs a wrapper iptables script in a container that will figure out
# whether iptables-legacy or iptables-nft is in use on the host and then
# replaces itself with the correct underlying iptables version.
#
# Unless "--no-sanity-check" is passed, it will first verify that the
# container already contains a suitable version of iptables.

# NOTE: This can only use POSIX /bin/sh features; the build container
# might not contain bash.

set -eu

# Find iptables binary location
if [ -d /usr/sbin -a -e /usr/sbin/iptables ]; then
    sbin="/usr/sbin"
elif [ -d /sbin -a -e /sbin/iptables ]; then
    sbin="/sbin"
else
    echo "ERROR: iptables is not present in either /usr/sbin or /sbin" 1>&2
    exit 1
fi

# Determine how the system selects between iptables-legacy and iptables-nft
if [ -x /usr/sbin/alternatives ]; then
    # Fedora/SUSE style alternatives
    altstyle="fedora"
elif [ -x /usr/sbin/update-alternatives ]; then
    # Debian style alternatives
    altstyle="debian"
else
    # No alternatives system
    altstyle="none"
fi

if [ "${1:-}" != "--no-sanity-check" ]; then
    # Ensure dependencies are installed
    if ! version=$("${sbin}/iptables-nft" --version 2> /dev/null); then
        echo "ERROR: iptables-nft is not installed" 1>&2
        exit 1
    fi
    if ! "${sbin}/iptables-legacy" --version > /dev/null 2>&1; then
        echo "ERROR: iptables-legacy is not installed" 1>&2
        exit 1
    fi

    case "${version}" in
    *v1.8.[0123]\ *)
        echo "ERROR: iptables 1.8.0 - 1.8.3 have compatibility bugs." 1>&2
        echo "       Upgrade to 1.8.4 or newer." 1>&2
        exit 1
        ;;
    *)
        # 1.8.4+ are OK
        ;;
    esac
fi

# Start creating the wrapper...
rm -f "${sbin}/iptables-wrapper"
cat > "${sbin}/iptables-wrapper" <<EOF
#!/bin/sh

# Copyright 2020 The Kubernetes Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# NOTE: This can only use POSIX /bin/sh features; the container image
# might not contain bash.

# This is a Cilium variant of the original Kubernetes iptablejs-wrapper
# the change is to follow Kube-proxy instead of Kubelet. This fixes
# issues where kube-proxy and kubelet iptables versions are not in
# sync and we observed kube-proxy incorrectly using different ipt/nft
# configuration from kubelet.

set -eu

# In kubernetes 1.17 and later, kubelet will have created at least
# one chain in the "mangle" table (either "KUBE-IPTABLES-HINT" or
# "KUBE-KUBELET-CANARY"), we expect kubeproxy will follow similar
# pattern so we check that first, against iptables-nft, because we
# can check that more efficiently and it's more common these days.
nft_kubeproxy_rules=\$( (iptables-nft-save -t mangle || true; ip6tables-nft-save -t mangle || true) 2>/dev/null | grep -E '^:(KUBE-IPTABLES-HINT|KUBE-PROXY-CANARY)' | wc -l)
if [ "\${nft_kubeproxy_rules}" -ne 0 ]; then
    mode=nft
else
    # Next lets check for a kubeproxy canary in iptables indicating
    # kube-proxy is using ipt.
    legacy_kubeproxy_rules=\$( (iptables-legacy-save || true; ip6tables-legacy-save || true) 2>/dev/null | grep -E '^:(KUBE-IPTABLES-HINT|KUBE-PROXY-CANARY)' | wc -l)
    if [ "\${legacy_kubeproxy_rules}" -ne 0 ]; then
        mode=legacy
    else
	# If we did not find a kube proxy canary either we started before
	# kube-proxy or it doesn't exist so lets use ipwrapper standard
	# logic to follow kubelet.
        nft_kubelet_rules=\$( (iptables-nft-save -t mangle || true; ip6tables-nft-save -t mangle || true) 2>/dev/null | grep -E '^:KUBE-KUBELET-CANARY' | wc -l)
        if [ "\${nft_kubeproxy_rules}" -ne 0 ]; then
		mode = nft
	else
    	    # Check for kubernetes 1.17-or-later with iptables-legacy. We
    	    # can't pass "-t mangle" to iptables-legacy-save because it would
    	    # cause the kernel to create that table if it didn't already
    	    # exist, which we don't want. So we have to grab all the rules
    	    legacy_kubelet_rules=\$( (iptables-legacy-save || true; ip6tables-legacy-save || true) 2>/dev/null | grep -E '^:KUBE-KUBELET-CANARY' | wc -l)
    	    if [ "\${legacy_kubelet_rules}" -ne 0 ]; then
    	        mode=legacy
    	    else
    	        # With older kubernetes releases there may not be any _specific_
    	        # rules we can look for, but we assume that some non-containerized process
    	        # (possibly kubelet) will have created _some_ iptables rules.
    	        num_legacy_lines=\$( (iptables-legacy-save || true; ip6tables-legacy-save || true) 2>/dev/null | grep '^-' | wc -l)
	        num_nft_lines=\$( (iptables-nft-save || true; ip6tables-nft-save || true) 2>/dev/null | grep '^-' | wc -l)
                if [ "\${num_legacy_lines}" -gt "\${num_nft_lines}" ]; then
            	    mode=legacy
                else
            	    mode=nft
	        fi
            fi
	fi
    fi
fi

EOF

# Write out the appropriate alternatives-selection commands
case "${altstyle}" in
    fedora)
cat >> "${sbin}/iptables-wrapper" <<EOF
# Update links to point to the selected binaries
alternatives --set iptables "/usr/sbin/iptables-\${mode}" > /dev/null || failed=1
EOF
    ;;

    debian)
cat >> "${sbin}/iptables-wrapper" <<EOF
# Update links to point to the selected binaries
update-alternatives --set iptables "/usr/sbin/iptables-\${mode}" > /dev/null || failed=1
update-alternatives --set ip6tables "/usr/sbin/ip6tables-\${mode}" > /dev/null || failed=1
EOF
    ;;

    *)
cat >> "${sbin}/iptables-wrapper" <<EOF
# Update links to point to the selected binaries
for cmd in iptables iptables-save iptables-restore ip6tables ip6tables-save ip6tables-restore; do
    rm -f "${sbin}/\${cmd}"
    ln -s "${sbin}/xtables-\${mode}-multi" "${sbin}/\${cmd}"
done 2>/dev/null || failed=1
EOF
    ;;
esac

# Write out the post-alternatives-selection error checking and final wrap-up
cat >> "${sbin}/iptables-wrapper" <<EOF
if [ "\${failed:-0}" = 1 ]; then
    echo "Unable to redirect iptables binaries. (Are you running in an unprivileged pod?)" 1>&2
    # fake it, though this will probably also fail if they aren't root
    exec "${sbin}/xtables-\${mode}-multi" "\$0" "\$@"
fi

# Now re-exec the original command with the newly-selected alternative
exec "\$0" "\$@"
EOF
chmod +x "${sbin}/iptables-wrapper"

# Now back in the installer script, point the iptables binaries at our
# wrapper
case "${altstyle}" in
    fedora)
	alternatives \
            --install /usr/sbin/iptables iptables /usr/sbin/iptables-wrapper 100 \
            --slave /usr/sbin/iptables-restore iptables-restore /usr/sbin/iptables-wrapper \
            --slave /usr/sbin/iptables-save iptables-save /usr/sbin/iptables-wrapper \
            --slave /usr/sbin/ip6tables iptables /usr/sbin/iptables-wrapper \
            --slave /usr/sbin/ip6tables-restore iptables-restore /usr/sbin/iptables-wrapper \
            --slave /usr/sbin/ip6tables-save iptables-save /usr/sbin/iptables-wrapper
	;;

    debian)
	update-alternatives \
            --install /usr/sbin/iptables iptables /usr/sbin/iptables-wrapper 100 \
            --slave /usr/sbin/iptables-restore iptables-restore /usr/sbin/iptables-wrapper \
            --slave /usr/sbin/iptables-save iptables-save /usr/sbin/iptables-wrapper
	update-alternatives \
            --install /usr/sbin/ip6tables ip6tables /usr/sbin/iptables-wrapper 100 \
            --slave /usr/sbin/ip6tables-restore ip6tables-restore /usr/sbin/iptables-wrapper \
            --slave /usr/sbin/ip6tables-save ip6tables-save /usr/sbin/iptables-wrapper
	;;

    *)
	for cmd in iptables iptables-save iptables-restore ip6tables ip6tables-save ip6tables-restore; do
            rm -f "${sbin}/${cmd}"
            ln -s "${sbin}/iptables-wrapper" "${sbin}/${cmd}"
	done
	;;
esac

# Cleanup
rm -f "$0"
