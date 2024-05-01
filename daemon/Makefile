CC ?=gcc
VCHAN_PKG = $(if $(BACKEND_VMM),vchan-$(BACKEND_VMM),vchan)
CFLAGS += -I../libqrexec -g -O2 -Wall -Wextra -Werror -fPIC \
   $(shell pkg-config --cflags $(VCHAN_PKG)) -fstack-protector \
   -fstack-protector-strong -std=gnu11 -D_POSIX_C_SOURCE=200809L \
   -D_GNU_SOURCE \
   -Wstrict-prototypes -Wold-style-definition -Wmissing-declarations \
   -fvisibility=hidden -fno-strict-aliasing -Wvla
LDFLAGS += -pie -Wl,-z,relro,-z,now -L../libqrexec
LDLIBS += $(shell pkg-config --libs $(VCHAN_PKG)) -lqrexec-utils

MAKEFLAGS := -r
.SUFFIXES:

all: qrexec-daemon qrexec-client
clean:
	rm -f -- *.o *~ qrexec-daemon qrexec-client *.o.dep *.gcda *.gcno
install: all
	install -d $(DESTDIR)/usr/sbin $(DESTDIR)/usr/bin
	install -t $(DESTDIR)/usr/sbin -m 755 qrexec-daemon
	install -t $(DESTDIR)/usr/bin -m 755 qrexec-client
	install -d $(DESTDIR)/usr/lib/qubes
	ln -sf ../../bin/qrexec-client $(DESTDIR)/usr/lib/qubes/qrexec-client
.PHONY: all clean install

qrexec-daemon qrexec-client: %: %.o qrexec-daemon-common.o
	$(CC) $(LDFLAGS) -pie -g -o $@ $^ $(LDLIBS)

%.o: %.c
	$(CC) $< -c -o $@ $(CFLAGS) -MD -MP -MF $@.dep

-include *.o.dep
