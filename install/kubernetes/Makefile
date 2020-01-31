QUICK_INSTALL=quick-install.yaml

all: $(QUICK_INSTALL)

$(QUICK_INSTALL): $(shell find cilium/ -type f)
	helm template cilium --namespace=kube-system $(OPTS) > $(QUICK_INSTALL)

clean:
	$(RM) $(QUICK_INSTALL)
