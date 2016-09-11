include ../Makefile.defs

TARGET=cilium-net-daemon

all: $(TARGET)

run:

clean:
	go clean
	rm -f $(TARGET)

$(TARGET):

install:
	groupadd -f cilium
	$(INSTALL) -m 0755 -d $(DESTDIR)$(LIBDIR)/cilium/ui
	cp -r ui/. $(DESTDIR)$(LIBDIR)/cilium/ui
	chown root.cilium -R $(DESTDIR)$(LIBDIR)/cilium/ui
