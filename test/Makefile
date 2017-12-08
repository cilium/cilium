provision = true
# If you set provision to false the test will run without compile the code
# again.

run:
	ginkgo --focus " Runtime*" -v -- --cilium.provision=$(provision)

k8s:
	ginkgo --focus " K8s*" -v -- --cilium.provision=$(provision)

k8s16:
	K8S_VERSION=1.6 ginkgo --focus " K8s*" -v -- --cilium.provision=$(provision)
