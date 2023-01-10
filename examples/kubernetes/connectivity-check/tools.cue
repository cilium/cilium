package connectivity_check

// Definitions in this file are not intended for continuous integration
// deployment, as their readiness/liveness probes are overridden to always
// pass. Instead, they can be deployed and their logs followed for manual
// testing via commands like the following:
//
// $ kubectl logs -l name=query-dns-policy --timestamps -f

// query-dns-policy is written for debugging by watching the logs; the
// liveness/readiness probes are bypassed so it will always report success!
deployment: "query-dns-policy": {
	_image: "cilium/demo-client"
	_command: ["/bin/sh", "-c", "while true; do dig +noall +question +answer +timeout=1 +tries=1 www.google.com && sleep 1 ; done"]
	_allowProbe: [ "true"]
	metadata: labels: {
		component: "proxy-check"
		type:      "tool"
	}
}
egressCNP: "query-dns-policy": {
	metadata: labels: {
		component: "proxy-check"
		type:      "tool"
	}
	_allowDNS:            true
	_enableDNSVisibility: true
}
