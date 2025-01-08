NAME=bgp-lb-ipam
VERSION=1.16.5

deploy:
	kind create cluster --config cluster.yaml
	sudo containerlab -t topo.yaml deploy
	kubectl apply -f https://raw.githubusercontent.com/kubernetes-sigs/gateway-api/v1.2.0/config/crd/standard/gateway.networking.k8s.io_gatewayclasses.yaml
	kubectl apply -f https://raw.githubusercontent.com/kubernetes-sigs/gateway-api/v1.2.0/config/crd/standard/gateway.networking.k8s.io_gateways.yaml
	kubectl apply -f https://raw.githubusercontent.com/kubernetes-sigs/gateway-api/v1.2.0/config/crd/standard/gateway.networking.k8s.io_httproutes.yaml
	kubectl apply -f https://raw.githubusercontent.com/kubernetes-sigs/gateway-api/v1.2.0/config/crd/standard/gateway.networking.k8s.io_referencegrants.yaml
	kubectl apply -f https://raw.githubusercontent.com/kubernetes-sigs/gateway-api/v1.2.0/config/crd/standard/gateway.networking.k8s.io_grpcroutes.yaml
	kubectl apply -f https://raw.githubusercontent.com/kubernetes-sigs/gateway-api/v1.2.0/config/crd/experimental/gateway.networking.k8s.io_tlsroutes.yaml
	helm install --kube-context kind-$(NAME) -n kube-system cilium cilium/cilium --version $(VERSION) -f values.yaml
	kubectl apply -f netshoot-ds.yaml
	kubectl apply -f ns.yaml

reload:
	kind delete clusters $(NAME)
	sudo containerlab -t topo.yaml destroy
	kind create cluster --config cluster.yaml
	sudo containerlab -t topo.yaml deploy
	kubectl apply -f https://raw.githubusercontent.com/kubernetes-sigs/gateway-api/v1.2.0/config/crd/standard/gateway.networking.k8s.io_gatewayclasses.yaml
	kubectl apply -f https://raw.githubusercontent.com/kubernetes-sigs/gateway-api/v1.2.0/config/crd/standard/gateway.networking.k8s.io_gateways.yaml
	kubectl apply -f https://raw.githubusercontent.com/kubernetes-sigs/gateway-api/v1.2.0/config/crd/standard/gateway.networking.k8s.io_httproutes.yaml
	kubectl apply -f https://raw.githubusercontent.com/kubernetes-sigs/gateway-api/v1.2.0/config/crd/standard/gateway.networking.k8s.io_referencegrants.yaml
	kubectl apply -f https://raw.githubusercontent.com/kubernetes-sigs/gateway-api/v1.2.0/config/crd/standard/gateway.networking.k8s.io_grpcroutes.yaml
	kubectl apply -f https://raw.githubusercontent.com/kubernetes-sigs/gateway-api/v1.2.0/config/crd/experimental/gateway.networking.k8s.io_tlsroutes.yaml
	helm install --kube-context kind-$(NAME) -n kube-system cilium cilium/cilium --version $(VERSION) -f values.yaml
	kubectl apply -f netshoot-ds.yaml
	kubectl apply -f ns.yaml

destroy:
	kind delete clusters $(NAME)
	sudo containerlab -t topo.yaml destroy

apply-policy:
	kubectl apply -f cilium-bgp-cluster.yaml

delete-policy:
	kubectl delete -f cilium-bgp-cluster.yaml

show-rib:
	@echo "======== router0 ========"
	docker exec -it clab-$(NAME)-router0 vtysh -c 'show bgp ipv4 wide'
	@echo "======== tor0    ========"
	docker exec -it clab-$(NAME)-tor0 vtysh -c 'show bgp ipv4 wide'
	@echo "======== tor1    ========"
	docker exec -it clab-$(NAME)-tor1 vtysh -c 'show bgp ipv4 wide'

show-fib:
	@echo "======== router0 ========"
	docker exec -it clab-$(NAME)-router0 ip r
	@echo "======== tor0    ========"
	docker exec -it clab-$(NAME)-tor0 ip r
	@echo "======== tor1    ========"
	docker exec -it clab-$(NAME)-tor1 ip r

show-neighbors:
	@echo "======== router0 ========"
	docker exec -it clab-$(NAME)-router0 vtysh -c 'show bgp ipv4 summary wide'
	@echo "======== tor0    ========"
	docker exec -it clab-$(NAME)-tor0 vtysh -c 'show bgp ipv4 summary wide'
	@echo "======== tor1    ========"
	docker exec -it clab-$(NAME)-tor1 vtysh -c 'show bgp ipv4 summary wide'

show-bgp:
	@echo "======== router0 ========"
	docker exec -it clab-$(NAME)-router0 vtysh -c 'show bgp ipv4'
	@echo "======== tor0    ========"
	docker exec -it clab-$(NAME)-tor0 vtysh -c 'show bgp ipv4'
	@echo "======== tor1    ========"
	docker exec -it clab-$(NAME)-tor1 vtysh -c 'show bgp ipv4'
