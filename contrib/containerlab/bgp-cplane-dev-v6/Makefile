deploy:
	kind create cluster --config cluster.yaml
	sudo containerlab -t topo.yaml deploy

destroy:
	sudo containerlab -t topo.yaml destroy -c
	kind delete clusters bgp-cplane-dev-v6

apply-policy:
	kubectl apply -f bgpp.yaml
	# In IPv6 single-stack, Cilium cannot pick router-id automatically.
	kubectl -n kube-system annotate node bgp-cplane-dev-v6-control-plane "cilium.io/bgp-virtual-router.65001=router-id=10.0.0.2"
	kubectl -n kube-system annotate node bgp-cplane-dev-v6-worker "cilium.io/bgp-virtual-router.65002=router-id=10.0.0.3"
