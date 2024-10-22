VERSION ?= v1.16.0

deploy:
	kind create cluster --config cluster.yaml
	sudo containerlab -t topo.yaml deploy
	# remove taint from control plane node
	kubectl taint nodes bgpv2-cplane-dev-service-control-plane node-role.kubernetes.io/control-plane:NoSchedule-
	# create secret for bgp
	kubectl -n kube-system create secret generic --type=string bgp-auth-secret --from-literal=password=cilium123
	# install cilium
	helm install cilium -n kube-system cilium/cilium --version $(VERSION) -f values.yaml
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

apply-service:
	kubectl apply -f service.yaml

apply-lb:
	kubectl apply -f lb-ip.yaml
