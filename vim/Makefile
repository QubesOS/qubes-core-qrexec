MAKEFLAGS=-r
DESTDIR ?= /
os := $(shell lsb_release -is)
ifeq ($(os), Debian)
	target_dir := /vim-qrexec
else
	target_dir := /vim/vimfiles
endif

remove_generated := \
	rm -f -- spell/*.spl

all: vim
vim: spell/qrexec.ascii.spl
clean:
ifeq ($(BUILDDIR),)
	$(remove_generated)
else
	cd -P -- $(BUILDDIR) && $(remove_generated)
endif
install: all
	install -d $(DESTDIR)$(DATADIR)$(target_dir) -m 755
	cp -vr ale_linters $(DESTDIR)$(DATADIR)$(target_dir)
	cp -vr autoload    $(DESTDIR)$(DATADIR)$(target_dir)
	cp -vr compiler    $(DESTDIR)$(DATADIR)$(target_dir)
	cp -vr doc         $(DESTDIR)$(DATADIR)$(target_dir)
	cp -vr ftdetect    $(DESTDIR)$(DATADIR)$(target_dir)
	cp -vr ftplugin    $(DESTDIR)$(DATADIR)$(target_dir)
	cp -vr indent      $(DESTDIR)$(DATADIR)$(target_dir)
	cp -vr spell       $(DESTDIR)$(DATADIR)$(target_dir)
	cp -vr syntax      $(DESTDIR)$(DATADIR)$(target_dir)
.PHONY: all clean install

spell/%.spl: spell/%.add
	vim -u NONE -c 'mkspell! -ascii spell/qrexec.ascii.spl spell/qrexec.ascii.add' -c q
