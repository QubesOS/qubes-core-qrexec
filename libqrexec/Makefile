LIBDIR ?= /usr/lib
INCLUDEDIR ?= /usr/include

CC=gcc
CFLAGS+=-I. -g -O2 -Wall -Wextra -Werror -pie -fPIC `pkg-config --cflags vchan-$(BACKEND_VMM)`
COMMONIOALL=ioall.o
SO_VER=2
LDFLAGS+=-shared
VCHANLIBS = `pkg-config --libs vchan-$(BACKEND_VMM)`

all: libqrexec-utils.so libqrexec-utils.so.$(SO_VER)
libqrexec-utils.so.$(SO_VER): unix-server.o ioall.o buffer.o exec.o txrx-vchan.o write-stdin.o
	$(CC) $(LDFLAGS) -Wl,-soname,$@ -o $@ $^ $(VCHANLIBS)

libqrexec-utils.so: libqrexec-utils.so.$(SO_VER)
	ln -s libqrexec-utils.so.$(SO_VER) libqrexec-utils.so

%.a:
	$(AR) rcs $@ $^
clean:
	rm -f *.o *~ *.a *.so *.so.*

install:
	mkdir -p $(DESTDIR)$(LIBDIR)
	cp libqrexec-utils.so.$(SO_VER) $(DESTDIR)$(LIBDIR)
	ln -s libqrexec-utils.so.$(SO_VER) $(DESTDIR)$(LIBDIR)/libqrexec-utils.so
	mkdir -p $(DESTDIR)$(INCLUDEDIR)
	cp libqrexec-utils.h $(DESTDIR)$(INCLUDEDIR)
	cp qrexec.h $(DESTDIR)$(INCLUDEDIR)
