CC=gcc
QUBES_CFLAGS:=-I. -I../libqrexec -g -O2 -Wall -Wextra -Werror -pie -fPIC \
   `pkg-config --cflags vchan-$(BACKEND_VMM)` -fstack-protector \
   -D_FORTIFY_SOURCE=2 -fstack-protector-strong
QUBES_LDFLAGS := -pie -Wl,-z,relro,-z,now $(LDFLAGS) -L../libqrexec
QUBES_LDLIBS:=`pkg-config --libs vchan-$(BACKEND_VMM)` -lqrexec-utils \
	-lpam $(LDLIBS)

DISTRO:=$(shell lsb_release -is)

PANDOC := pandoc

.PHONY: all install clean

all: qrexec-agent qrexec-client-vm qrexec-fork-server qrexec-client-vm.1.gz
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
	install qrexec-client-vm.1.gz $(DESTDIR)/usr/share/man/man1
	ln -sf ../../bin/qrexec-client-vm $(DESTDIR)/usr/lib/qubes/qrexec-client-vm
	ln -sf ../../bin/qrexec-client-vm $(DESTDIR)/usr/lib/qubes/qrexec_client_vm
	install qrexec-fork-server $(DESTDIR)/usr/bin
ifeq ($(DISTRO),Debian)
	install -D -m 0644 qrexec.pam.debian $(DESTDIR)/etc/pam.d/qrexec
else ifeq ($(DISTRO),Arch)
	install -D -m 0644 qrexec.pam.archlinux $(DESTDIR)/etc/pam.d/qrexec
else
	install -D -m 0644 qrexec.pam $(DESTDIR)/etc/pam.d/qrexec
endif

%.1: %.rst
	$(PANDOC) $< > $@

%.1.gz: %.1
	gzip -f $<

%: %.o
	$(CC) $(QUBES_LDFLAGS) -pie -g -o $@ $^ $(QUBES_LDLIBS)

%.o: %.c
	$(CC) $< -c -o $@ $(QUBES_CFLAGS) $(CFLAGS) -MD -MP -MF $@.dep

-include *.o.dep
