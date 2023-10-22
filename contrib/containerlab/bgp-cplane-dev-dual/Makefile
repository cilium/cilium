deploy:
	kind create cluster --config cluster.yaml
	sudo containerlab -t topo.yaml deploy

destroy:
	sudo containerlab -t topo.yaml destroy -c
	kind delete clusters bgp-cplane-dev-dual

apply-policy:
	kubectl apply -f bgpp.yaml
