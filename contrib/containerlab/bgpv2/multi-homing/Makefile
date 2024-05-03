# version of cilium to deploy
HELM_CHART ?= oci://quay.io/cilium-charts-dev/cilium
VERSION ?= 1.16.0-dev-dev.247-main-8c97a2119d

deploy:
	kind create cluster --config cluster.yaml
	sudo containerlab -t topo.yaml deploy
	# create secret for bgp
	kubectl -n kube-system create secret generic --type=string bgp-auth-secret --from-literal=password=cilium123
	# install cilium
	helm install cilium -n kube-system $(HELM_CHART) --version $(VERSION) -f values.yaml
	cilium status --wait --namespace kube-system

destroy:
	sudo containerlab -t topo.yaml destroy -c
	kind delete clusters bgpv2-cplane-dev-multi-homing
	rm -f .topo.yaml.bak

reload:
	$(MAKE) destroy
	$(MAKE) deploy

apply-bgp:
	kubectl apply -f bgp.yaml
