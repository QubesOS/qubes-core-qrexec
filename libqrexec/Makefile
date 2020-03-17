CC=gcc
override QUBES_CFLAGS := -I. -I../libqrexec -g -O2 -Wall -Wextra -Werror \
   $(shell pkg-config --cflags vchan-$(BACKEND_VMM)) -fstack-protector \
   -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fPIC -std=gnu11 -D_POSIX_C_SOURCE=200809L \
   -D_GNU_SOURCE $(CFLAGS)
override LDFLAGS += -pie -Wl,-z,relro,-z,now -shared

override SO_VER=3
override VCHANLIBS := $(shell pkg-config --libs vchan-$(BACKEND_VMM))
LIBDIR ?= /usr/lib
INCLUDEDIR ?= /usr/include

_XENSTORE_H=$(shell ls /usr/include/xenstore.h 2>/dev/null)
ifneq "$(_XENSTORE_H)" ""
QUBES_CFLAGS += -DUSE_XENSTORE_H
endif


all: libqrexec-utils.so
libqrexec-utils.so.$(SO_VER): unix-server.o ioall.o buffer.o exec.o txrx-vchan.o write-stdin.o replace.o remote.o process_io.o log.o
	$(CC) $(LDFLAGS) -Wl,-soname,$@ -o $@ $^ $(VCHANLIBS)

libqrexec-utils.so: libqrexec-utils.so.$(SO_VER)
	ln -sf $@.$(SO_VER) $@

%.a:
	$(AR) rcs $@ $^
clean:
	rm -f *.o *~ *.a *.so *.so.* *.o.dep

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
