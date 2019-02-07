CC=gcc
QUBES_CFLAGS:=-I. -g -O2 -Wall -Wextra -Werror -pie -fPIC \
   `pkg-config --cflags vchan-$(BACKEND_VMM)` -fstack-protector \
   -D_FORTIFY_SOURCE=2 -fstack-protector-strong
QUBES_LDFLAGS := -pie -Wl,-z,relro,-z,now $(LDFLAGS)

DISTRO:=$(shell lsb_release -is)
QUBES_LDFLAGS +=-shared

COMMONIOALL=ioall.o
SO_VER=2
VCHANLIBS = `pkg-config --libs vchan-$(BACKEND_VMM)`
LIBDIR ?= /usr/lib
INCLUDEDIR ?= /usr/include

_XENSTORE_H=$(shell ls /usr/include/xenstore.h 2>/dev/null)
ifneq "$(_XENSTORE_H)" ""
QUBES_CFLAGS += -DUSE_XENSTORE_H
endif


all: libqrexec-utils.so
libqrexec-utils.so: unix-server.o ioall.o buffer.o exec.o txrx-vchan.o write-stdin.o
	$(CC) $(QUBES_LDFLAGS) -Wl,-soname,$@.$(SO_VER) -o $@.$(SO_VER) $^ $(VCHANLIBS)
	ln -sf $@.$(SO_VER) $@ 

%.a:
	$(AR) rcs $@ $^
clean:
	rm -f *.o *~ *.a *.so.* *.o.dep

install:
	install -d -m 0755 $(DESTDIR)$(LIBDIR)
	install libqrexec-utils.so.$(SO_VER) $(DESTDIR)$(LIBDIR)
	ln -sf libqrexec-utils.so.$(SO_VER) $(DESTDIR)$(LIBDIR)/libqrexec-utils.so
	install -d -m 0755 $(DESTDIR)$(INCLUDEDIR)
	install -m 0644 libqrexec-utils.h $(DESTDIR)$(INCLUDEDIR)
	install -m 0644 qrexec.h $(DESTDIR)$(INCLUDEDIR)

%.o: %.c
	$(CC) $< -c -o $@ $(QUBES_CFLAGS) $(CFLAGS) -MD -MP -MF $@.dep

-include *.o.dep
