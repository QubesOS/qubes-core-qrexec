MAKEFLAGS=-rR
CC := gcc
PANDOC ?= pandoc
BACKEND_VMM ?= xen
DESTDIR ?= /
shellescape = '$(subst ','\'',$1)'#)'
define escape_vars
override $v := $$(call shellescape,$$(patsubst %/,%,$$($v)))
export $v
endef
$(eval $(foreach v,DESTDIR PANDOC CC BUILDDIR BACKEND_VMM,$(escape_vars)))

QUBES_CFLAGS:=-I. -I../libqrexec -g -O2 -Wall -Wextra -Werror -pie -fPIC \
   $(shell pkg-config --cflags vchan-$(BACKEND_VMM)) -fstack-protector \
   -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fstack-clash-protection
QUBES_LDFLAGS := -pie -Wl,-z,relro,-z,now,-E $(LDFLAGS) -L../libqrexec
QUBES_LDLIBS:=$(shell pkg-config --libs vchan-$(BACKEND_VMM)) -lqrexec-utils \
	-lpam $(LDLIBS)

DISTRO:=$(shell lsb_release -is)



.PHONY: all install clean

override remove_generated := \
	rm -f -- *.o *~ qrexec-agent qrexec-client-vm *.o.dep

all: qrexec-agent qrexec-client-vm qrexec-fork-server qrexec-client-vm.1.gz
qrexec-agent: qrexec-agent.o qrexec-agent-data.o
qrexec-fork-server: qrexec-fork-server.o qrexec-agent-data.o
qrexec-client-vm: qrexec-client-vm.o qrexec-agent-data.o
clean:
ifeq ($(BUILDDIR),)
	$(remove_generated)
else
	cd -P -- $(BUILDDIR) && $(remove_generated)
endif


install: all
	install -d $(DESTDIR)/etc/qubes-rpc $(DESTDIR)/usr/lib/qubes \
		$(DESTDIR)/usr/bin $(DESTDIR)/usr/share/man/man1
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
	$(CC) $(QUBES_LDFLAGS) -pie -g -o $@ -Xlinker --start-group $^ -Xlinker --end-group $(QUBES_LDLIBS)

%.o: %.c
	$(CC) $< -c -o $@ $(QUBES_CFLAGS) $(CFLAGS) -MD -MP -MF $@.dep

-include *.o.dep
