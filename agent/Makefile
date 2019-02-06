CC=gcc
DISTRO:=$(shell lsb_release -is)
override QUBES_CFLAGS := -I. -I../libqrexec -g -O2 -Wall -Wextra -Werror \
   `pkg-config --cflags vchan-$(BACKEND_VMM)` -fstack-protector \
   -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fPIC \
   $(CFLAGS)
override LDFLAGS += -pie -Wl,-z,relro,-z,now
override LDLIBS=`pkg-config --libs vchan-$(BACKEND_VMM)` -lqrexec-utils -lpam

.PHONY: all install

all: qrexec-agent qrexec-client-vm qrexec-fork-server #qrexec-client-vm.1.gz
qrexec-agent: qrexec-agent.o qrexec-agent-data.o
qrexec-fork-server: qrexec-fork-server.o qrexec-agent-data.o
qrexec-client-vm: qrexec-client-vm.o qrexec-agent-data.o
clean:
	rm -f -- *.o *~ qrexec-agent qrexec-client-vm *.o.dep

install: all
	install -d $(DESTDIR)/etc/qubes-rpc $(DESTDIR)/usr/lib/qubes \
		$(DESTDIR)/usr/bin $(DESTDIR)/usr/share/main/man1
	install qrexec-agent $(DESTDIR)/usr/lib/qubes
	install qrexec-client-vm $(DESTDIR)/usr/bin
	if [ -f qrexec-client-vm.1.gz ]; then \
		install qrexec-client-vm.1.gz $(DESTDIR)/usr/share/man/man1; \
	fi
	ln -sf ../../bin/qrexec-client-vm $(DESTDIR)/usr/lib/qubes/qrexec-client-vm
	install qrexec-fork-server $(DESTDIR)/usr/bin

ifeq ($(DISTRO), Debian)
	install -D -m 0644 qrexec.pam.debian $(DESTDIR)/etc/pam.d/qrexec
else ifeq ($(DISTRO), Arch)
	install -D -m 0644 qrexec.pam.archlinux $(DESTDIR)/etc/pam.d/qrexec
else
	install -D -m 0644 qrexec.pam $(DESTDIR)/etc/pam.d/qrexec
endif

%.o: %.c
	$(CC) $< -c -o $@ $(QUBES_CFLAGS) -MD -MP -MF $@.dep

%.1: %.rst
	$(PANDOC) $< > $@

%.1.gz: %.1
	gzip -f $<

-include *.o.dep
