MAKEFLAGS=-r
CC ?= gcc
PYTHON ?= python3
export PYTHON GCC MAKEFLAGS

SYSLIBDIR ?= /lib

help:
	:
.PHONY: help

clean:
	+$(MAKE) -C libqrexec clean
	+$(MAKE) -C daemon clean
	+$(MAKE) -C agent clean
	rm -rf selinux/*.pp selinux/tmp/
.PHONY: clean


all: all-base all-dom0 all-vm
.PHONY: all

all-base:
	+$(MAKE) all -C libqrexec
	$(PYTHON) setup.py build
.PHONY: all-base

install-base: all-base
	+$(MAKE) install -C libqrexec
	$(PYTHON) setup.py install -O1 $(PYTHON_PREFIX_ARG) --skip-build --root $(DESTDIR)
	ln -s qrexec-policy-exec $(DESTDIR)/usr/bin/qrexec-policy
	install -d $(DESTDIR)/usr/lib/qubes -m 755
	install -t $(DESTDIR)/usr/lib/qubes -m 755 lib/*
	install -d $(DESTDIR)/etc/qubes-rpc -m 755
	ln -s /var/run/qubes/policy-agent.sock $(DESTDIR)/etc/qubes-rpc/policy.Ask
	ln -s /var/run/qubes/policy-agent.sock $(DESTDIR)/etc/qubes-rpc/policy.Notify
	install -d $(DESTDIR)/etc/xdg/autostart -m 755
	install -m 644 policy-agent-extra/qrexec-policy-agent.desktop \
		$(DESTDIR)/etc/xdg/autostart/qrexec-policy-agent.desktop
.PHONY: install-base


all-dom0:
	+$(MAKE) all -C daemon
.PHONY: all-dom0

install-dom0: all-dom0
	+$(MAKE) install -C daemon
	install -d $(DESTDIR)/etc/qubes-rpc -m 755
	install -t $(DESTDIR)/etc/qubes-rpc -m 755 qubes-rpc-dom0/*

	for RPCNAME in \
		policy.List policy.Get policy.Replace policy.Remove \
		policy.include.List policy.include.Get policy.include.Replace \
		policy.include.Remove policy.GetFiles; \
	do ln -s /usr/bin/qubes-policy-admin $(DESTDIR)/etc/qubes-rpc/$$RPCNAME; \
	done

	install -d $(DESTDIR)/etc/qubes-rpc/policy -m 775
	install -d $(DESTDIR)/etc/qubes-rpc/policy/include -m 775
	install -d $(DESTDIR)/etc/qubes/policy.d -m 775
	install -t $(DESTDIR)/etc/qubes/policy.d -m 664 policy.d/*.policy
	install -t $(DESTDIR)/etc/qubes/policy.d -m 664 policy.d/README
	install -d $(DESTDIR)/etc/qubes/policy.d/include -m 775
	install -t $(DESTDIR)/etc/qubes/policy.d/include -m 664 policy.d/include/*
	install -d $(DESTDIR)/lib/systemd/system -m 755
	install -t $(DESTDIR)/lib/systemd/system -m 644 systemd/qubes-qrexec-policy-daemon.service
.PHONY: install-dom0


all-vm:
	+$(MAKE) all -C agent
all-vm-selinux:
	+$(MAKE) -f /usr/share/selinux/devel/Makefile -C selinux qubes-core-qrexec.pp
.PHONY: all-vm

install-vm: all-vm
	+$(MAKE) install -C agent
	install -d $(DESTDIR)/$(SYSLIBDIR)/systemd/system -m 755
	install -t $(DESTDIR)/$(SYSLIBDIR)/systemd/system -m 644 systemd/qubes-qrexec-agent.service
	install -m 0644 -D qubes-rpc-config/README $(DESTDIR)/etc/qubes/rpc-config/README
install-vm-selinux:
	install -m 0644 -D -t $(DESTDIR)/usr/share/selinux/packages selinux/qubes-core-qrexec.pp
	install -m 0644 -D selinux/qubes-core-qrexec.if $(DESTDIR)/usr/share/selinux/devel/include/contrib/ipp-qubes-core-qrexec.if
#	install -d $(DESTDIR)/etc/qubes-rpc -m 755
#	install -t $(DESTDIR)/etc/qubes-rpc -m 755 qubes-rpc/*
.PHONY: install-vm

all: all-vm all-dom0
.PHONY: all
