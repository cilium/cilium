QUICK_INSTALL=quick-install.yaml

all: $(QUICK_INSTALL)

$(QUICK_INSTALL):
	helm template helm --namespace=kube-system $(OPTS) > $(QUICK_INSTALL)

clean:
	$(RM) $(QUICK_INSTALL)
