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
	for dir in `find ui -type d`; do \
		$(INSTALL) -m 0755 -o root -g cilium -d $(DESTDIR)$(LIBDIR)/cilium/$$dir; \
		for f in `find $$dir -maxdepth 1 -type f`; do \
			$(INSTALL) -m 0644 -o root -g cilium -t $(DESTDIR)$(LIBDIR)/cilium/$$dir $$f; \
		done; \
	done
