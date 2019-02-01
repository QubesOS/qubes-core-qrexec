CC=gcc
override CFLAGS:=-I. -g -O2 -Wall -Wextra -Werror -pie -fPIC `pkg-config --cflags vchan-$(BACKEND_VMM)`$(CFLAGS)
COMMONIOALL=ioall.o
SO_VER=2
LDFLAGS+=-shared
VCHANLIBS = `pkg-config --libs vchan-$(BACKEND_VMM)`

_XENSTORE_H=$(shell ls /usr/include/xenstore.h)
ifneq "$(_XENSTORE_H)" ""
	CFLAGS+= -DUSE_XENSTORE_H
endif


all: libqrexec-utils.so.$(SO_VER)
libqrexec-utils.so.$(SO_VER): unix-server.o ioall.o buffer.o exec.o txrx-vchan.o write-stdin.o
	$(CC) $(LDFLAGS) -Wl,-soname,$@ -o $@ $^ $(VCHANLIBS)

%.a:
	$(AR) rcs $@ $^
clean:
	rm -f *.o *~ *.a *.so.*

install:
	mkdir -p $(DESTDIR)$(LIBDIR)
	install libqrexec-utils.so.$(SO_VER) $(DESTDIR)$(LIBDIR)
	ln -sf libqrexec-utils.so.$(SO_VER) $(DESTDIR)$(LIBDIR)/libqrexec-utils.so
	mkdir -p $(DESTDIR)$(INCLUDEDIR)
	install -m 0644 libqrexec-utils.h $(DESTDIR)$(INCLUDEDIR)
	install -m 0644 qrexec.h $(DESTDIR)$(INCLUDEDIR)

