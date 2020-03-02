CC ?=gcc
override QUBES_CFLAGS:=-I../libqrexec -g -O2 -Wall -Wextra -Werror -pie -fPIC \
   $(shell pkg-config --cflags vchan-$(BACKEND_VMM)) -fstack-protector \
   -D_FORTIFY_SOURCE=2 -fstack-protector-strong -std=gnu11 -D_POSIX_C_SOURCE=200809L \
   -D_GNU_SOURCE $(CFLAGS)
override LDFLAGS += -pie -Wl,-z,relro,-z,now -L../libqrexec
override LDLIBS += $(shell pkg-config --libs vchan-$(BACKEND_VMM)) -lqrexec-utils

MAKEFLAGS := -r
.SUFFIXES:

all: qrexec-daemon qrexec-client
clean:
	rm -f *.o *~ qrexec-daemon qrexec-client *.o.dep
install: all
	install -d $(DESTDIR)/usr/sbin $(DESTDIR)/usr/bin
	install -t $(DESTDIR)/usr/sbin -m 755 qrexec-daemon
	install -t $(DESTDIR)/usr/bin -m 755 qrexec-client
	install -d $(DESTDIR)/usr/lib/qubes
	ln -s ../../bin/qrexec-client $(DESTDIR)/usr/lib/qubes/qrexec-client
.PHONY: all clean install

%: %.o
	$(CC) $(LDFLAGS) -pie -g -o $@ $< $(LDLIBS)

%.o: %.c
	$(CC) $< -c -o $@ $(QUBES_CFLAGS) -MD -MP -MF $@.dep

-include *.o.dep
