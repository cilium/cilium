.PHONY: apply reapply deploy kind install tables port-forward run-nginx stop-nginx

monitoring.yaml: metrics.json monitoring_part1.yaml monitoring_part2.yaml
	cp monitoring_part1.yaml monitoring.yaml
	sed 's,^,    ,' metrics.json >> monitoring.yaml
	cat monitoring_part2.yaml >> monitoring.yaml

apply: monitoring.yaml
	kubectl apply -f monitoring.yaml

reapply: monitoring.yaml
	kubectl delete ns/cilium-monitoring
	kubectl apply -f monitoring.yaml

deploy: kind install apply

kind:
	kind get nodes || (cd ../ && make kind)

install:
	cd ../ && make kind-image-fast kind-install-cilium-fast

tables:
	for table in services4 backends4 revnat4; do \
		echo "--- $$table ---"; \
		kubectl exec -q -n kube-system ds/cilium -- cilium-dbg statedb $$table; \
		echo; \
	done

health:
	kubectl exec -q -n kube-system ds/cilium -- cilium-dbg status --all-health

port-forward:
	kubectl -n cilium-monitoring port-forward service/grafana --address 0.0.0.0 --address :: 3000:3000

run-nginx:
	kubectl create namespace nginx || true
	for i in $$(seq 1 40); do kubectl run -n nginx -q nginx$$i --image=nginx  --expose --port=80 & done

stop-nginx:
	kubectl delete ns/nginx

