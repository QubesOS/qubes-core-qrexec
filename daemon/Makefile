CC=gcc
MAKEFLAGS := -rR
.SUFFIXES:
QUBES_CFLAGS:=-I. -I../libqrexec -g -O2 -Wall -Wextra -Werror -pie -fPIC \
   `pkg-config --cflags vchan-$(BACKEND_VMM)` -fstack-protector \
   -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fstack-clash-protection \
   -Wl,-z,relro,-z,now,-E

QUBES_LDFLAGS := -pie -Wl,-z,relro,-z,now,-E $(LDFLAGS)
QUBES_LDLIBS:=`pkg-config --libs vchan-$(BACKEND_VMM)` -lqrexec-utils $(LDLIBS)

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
	$(CC) $(QUBES_LDFLAGS) -pie -g -o $@ $< $(QUBES_LDLIBS)

%.o: %.c
	$(CC) $< -c -o $@ $(QUBES_CFLAGS) $(CFLAGS) -MD -MP -MF $@.dep

-include *.o.dep
