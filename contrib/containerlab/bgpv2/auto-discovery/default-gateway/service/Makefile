CHART_DIR ?= $(shell git rev-parse --show-toplevel)/install/kubernetes/cilium
KIND_CLUSTER_NAME ?= bgpv2-cplane-dev-service
VALUES_FILE ?= $(shell pwd)/values.yaml

deploy:
	kind create cluster --config cluster.yaml
	sudo containerlab -t topo.yaml deploy
	# remove taint from control plane node
	kubectl taint nodes bgpv2-cplane-dev-service-control-plane node-role.kubernetes.io/control-plane:NoSchedule-
	# create secret for bgp
	kubectl -n kube-system create secret generic --type=string bgp-auth-secret --from-literal=password=cilium123
	# build and load cilium images to kind
	cd $(shell git rev-parse --show-toplevel) && KIND_CLUSTER_NAME=$(KIND_CLUSTER_NAME) make kind-image
	# install cilium with local chart and locally built images
	cilium install --chart-directory=$(CHART_DIR) \
    	-f $(VALUES_FILE) \
    	--set image.override="localhost:5000/cilium/cilium-dev:local" \
    	--set image.pullPolicy=Never \
    	--set operator.image.override="localhost:5000/cilium/operator-generic:local" \
		--set operator.image.pullPolicy=Never \
	cilium status --wait --namespace kube-system

destroy:
	sudo containerlab -t topo.yaml destroy -c
	kind delete clusters bgpv2-cplane-dev-service
	rm -f .topo.yaml.bak

reload:
	$(MAKE) destroy
	$(MAKE) deploy

apply-bgp:
	kubectl apply -f bgp.yaml

delete-bgp:
	kubectl delete -f bgp.yaml

apply-service:
	kubectl apply -f service.yaml

apply-lb:
	kubectl apply -f lb-ip.yaml
