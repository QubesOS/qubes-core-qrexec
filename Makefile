MAKEFLAGS=-r
CC ?= gcc
PYTHON ?= python3
export PYTHON GCC MAKEFLAGS

help:
	:
.PHONY: help

clean:
	+$(MAKE) -C libqrexec clean
	+$(MAKE) -C daemon clean
	+$(MAKE) -C agent clean
.PHONY: clean

all-base:
	+$(MAKE) all -C libqrexec
	$(PYTHON) setup.py build
.PHONY: all-base

install-base:
	+$(MAKE) install -C libqrexec
	$(PYTHON) setup.py install -O1 $(PYTHON_PREFIX_ARG) --skip-build --root $(DESTDIR)
	ln -s qrexec-policy-exec $(DESTDIR)/usr/bin/qrexec-policy
	install -d $(DESTDIR)/usr/lib/qubes -m 755
	install -t $(DESTDIR)/usr/lib/qubes -m 755 lib/*
.PHONY: install-base


all-dom0: all-base
	+$(MAKE) all -C daemon
.PHONY: all-dom0

install-dom0: all-dom0
	+$(MAKE) install -C daemon
	install -d $(DESTDIR)/etc/qubes-rpc -m 755
	install -t $(DESTDIR)/etc/qubes-rpc -m 755 qubes-rpc-dom0/*
	ln -s /var/run/qubes/policy.Ask $(DESTDIR)/etc/qubes-rpc/policy.Ask
	install -d $(DESTDIR)/etc/qubes-rpc/policy -m 775
	install -d $(DESTDIR)/etc/qubes-rpc/policy/include -m 775
	install -d $(DESTDIR)/etc/xdg/autostart -m 755
	install -m 644 policy-agent-extra/qrexec-policy-agent.desktop \
		$(DESTDIR)/etc/xdg/autostart/qrexec-policy-agent.desktop
	install -d $(DESTDIR)/etc/qubes/policy.d -m 775
	install -d $(DESTDIR)/etc/qubes/policy.d/include -m 775
	install -t $(DESTDIR)/etc/qubes/policy.d -m 664 policy.d/*
	install -d $(DESTDIR)/lib/systemd/system -m 755
	install -t $(DESTDIR)/lib/systemd/system -m 644 systemd/qubes-qrexec-policy-daemon.service
.PHONY: install-dom0


all-vm: all-base
	+$(MAKE) all -C agent
.PHONY: all-vm

install-vm: all-vm
	+$(MAKE) install -C agent
	install -d $(DESTDIR)/lib/systemd/system -m 755
	install -t $(DESTDIR)/lib/systemd/system -m 644 systemd/qubes-qrexec-agent.service
	install -m 0644 -D qubes-rpc-config/README $(DESTDIR)/etc/qubes/rpc-config/README
#	install -d $(DESTDIR)/etc/qubes-rpc -m 755
#	install -t $(DESTDIR)/etc/qubes-rpc -m 755 qubes-rpc/*
.PHONY: install-vm

all: all-vm all-dom0
.PHONY: all
