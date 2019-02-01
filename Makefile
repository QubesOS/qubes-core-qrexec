PYTHON ?= python3
override shellescape = '$(subst ','\'',$1)'#)'
DESTDIR := $(call shellescape,$(DESTDIR))
PYTHON := $(call shellescape,$(PYTHON))

help:
	:
.PHONY: help


all-base:
	+make all -C libqrexec
	$(PYTHON) setup.py build
.PHONY: all-base

install-base:
	+make install -C libqrexec
	$(PYTHON) setup.py install -O1 --skip-build --root $(DESTDIR)/
	install -d $(DESTDIR)/usr/lib/qubes -m 755
	install -t $(DESTDIR)/usr/lib/qubes -m 755 lib/*
.PHONY: install-base


all-dom0: all-base
	+$(MAKE) all -C daemon
.PHONY: all-dom0

install-dom0: install-base
	+$(MAKE) install -C daemon
	install -d $(DESTDIR)/etc/qubes-rpc -m 755
	install -t $(DESTDIR)/etc/qubes-rpc -m 755 qubes-rpc-dom0/*
	install -d $(DESTDIR)/etc/qubes-rpc/policy -m 775
	install -d $(DESTDIR)/etc/qubes-rpc/policy/include -m 775
	install -t $(DESTDIR)/etc/qubes-rpc/policy -m 664 qubes-rpc-policy/*
.PHONY: install-dom0


all-vm: all-base
	+$(MAKE) all -C agent
.PHONY: all-vm

install-vm: install-base
	+$(MAKE) install -C agent
	install -d $(DESTDIR)/lib/systemd/system -m 755
	install -t $(DESTDIR)/lib/systemd/system -m 644 systemd/*
#	install -d $(DESTDIR)/etc/qubes-rpc -m 755
#	install -t $(DESTDIR)/etc/qubes-rpc -m 755 qubes-rpc/*
.PHONY: install-vm

