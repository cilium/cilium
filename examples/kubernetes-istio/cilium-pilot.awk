{ print }

# Add the "cilium" filter into the list of Pilot plugins to configure
# the Cilium filter into every sidecar proxy.
/\- "discovery"/ {
	indent = $0 ; gsub(/[^ ].*/, "", indent)
	print indent "- --plugins=authn,authz,health,mixer,envoyfilter,cilium"
}
