LIBDIR ?= /usr/lib
INCLUDEDIR ?= /usr/include

CC=gcc
QUBES_CFLAGS:=-I. -g -O2 -Wall -Wextra -Werror -pie -fPIC \
   `pkg-config --cflags vchan-$(BACKEND_VMM)` -fstack-protector \
   -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fstack-clash-protection

QUBES_LDFLAGS := -pie -Wl,-z,relro,-z,now $(LDFLAGS)

DISTRO:=$(shell lsb_release -is)
QUBES_LDFLAGS +=-shared

COMMONIOALL=ioall.o
SO_VER=2
VCHANLIBS = `pkg-config --libs vchan-$(BACKEND_VMM)`
LIBDIR ?= /usr/lib
INCLUDEDIR ?= /usr/include

all: libqrexec-utils.so libqrexec-utils.so.$(SO_VER)
libqrexec-utils.so.$(SO_VER): unix-server.o ioall.o buffer.o exec.o txrx-vchan.o write-stdin.o
	$(CC) $(LDFLAGS) -shared -Wl,-soname,$@ -o $@ $^ $(VCHANLIBS)

libqrexec-utils.so: libqrexec-utils.so.$(SO_VER)
	ln -sf libqrexec-utils.so.$(SO_VER) libqrexec-utils.so

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
