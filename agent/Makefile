CC=gcc
CFLAGS+=-I. -g -O2 -Wall -Wextra -Werror -pie -fPIC `pkg-config --cflags vchan-$(BACKEND_VMM)`
LDFLAGS=-pie
LDLIBS=`pkg-config --libs vchan-$(BACKEND_VMM)` -lqrexec-utils -lpam
PANDOC=pandoc

all: qrexec-agent qrexec-client-vm qrexec-fork-server qrexec-client-vm.1.gz
qrexec-agent: qrexec-agent.o qrexec-agent-data.o
qrexec-fork-server: qrexec-fork-server.o qrexec-agent-data.o
qrexec-client-vm: qrexec-client-vm.o qrexec-agent-data.o
clean:
	rm -f *.o *~ qrexec-agent qrexec-client-vm

install:
	install -d $(DESTDIR)/etc/qubes-rpc
	install -d $(DESTDIR)/usr/lib/qubes $(DESTDIR)/usr/bin
	install qrexec-agent $(DESTDIR)/usr/lib/qubes
	install qrexec-client-vm $(DESTDIR)/usr/bin
	install -d $(DESTDIR)/usr/share/man/man1
	install qrexec-client-vm.1.gz $(DESTDIR)/usr/share/man/man1
	ln -s ../../bin/qrexec-client-vm $(DESTDIR)/usr/lib/qubes/qrexec-client-vm
	ln -s ../../bin/qrexec-client-vm $(DESTDIR)/usr/lib/qubes/qrexec_client_vm
	install qrexec-fork-server $(DESTDIR)/usr/bin
ifeq ($(shell lsb_release -is), Debian)
	install -D -m 0644 qrexec.pam.debian $(DESTDIR)/etc/pam.d/qrexec
else ifeq ($(shell lsb_release -is), Arch)
	install -D -m 0644 qrexec.pam.archlinux $(DESTDIR)/etc/pam.d/qrexec
else
	install -D -m 0644 qrexec.pam $(DESTDIR)/etc/pam.d/qrexec
endif

%.1: %.rst
	$(PANDOC) $< > $@

%.1.gz: %.1
	gzip -f $<
