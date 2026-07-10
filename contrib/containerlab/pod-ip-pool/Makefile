VERSION ?= $(shell curl -s https://raw.githubusercontent.com/cilium/cilium/main/stable.txt)
ROOT_DIR := $(shell git rev-parse --show-toplevel)
KIND_CLUSTER_NAME ?= bgp-cplane-dev-pod-ip-pool

deploy:
	kind create cluster --config cluster.yaml
	sudo containerlab -t topo.yaml deploy
	# remove taint from control plane node
	kubectl taint nodes bgp-cplane-dev-pod-ip-pool-control-plane node-role.kubernetes.io/control-plane:NoSchedule-
	# create secret for bgp
	kubectl -n kube-system create secret generic --type=string bgp-auth-secret --from-literal=password=cilium123
	# install cilium
	if [ "$(VERSION)" = "local" ]; then \
		$(MAKE) -C $(ROOT_DIR) kind-image KIND_CLUSTER_NAME=$(KIND_CLUSTER_NAME); \
		helm install cilium -n kube-system $(ROOT_DIR)/install/kubernetes/cilium/ -f values.yaml \
			--set image.override="localhost:5000/cilium/cilium-dev:local"  \
			--set image.pullPolicy=Never \
			--set operator.image.override="localhost:5000/cilium/operator-generic:local" \
			--set operator.image.pullPolicy=Never; \
	else \
		helm install cilium -n kube-system cilium/cilium --version $(VERSION) -f values.yaml; \
	fi

destroy:
	sudo containerlab -t topo.yaml destroy -c
	kind delete clusters bgp-cplane-dev-pod-ip-pool
	rm -f .topo.yaml.bak

reload:
	$(MAKE) destroy
	$(MAKE) deploy

apply-bgp:
	kubectl apply -f bgp.yaml
