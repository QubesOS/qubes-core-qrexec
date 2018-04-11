CC=gcc
CFLAGS+=-I. -g -O2 -Wall -Wextra -Werror -pie -fPIC `pkg-config --cflags vchan-$(BACKEND_VMM)`
LIBS=`pkg-config --libs vchan-$(BACKEND_VMM)` -lqrexec-utils


all: qrexec-daemon qrexec-client 
clean:
	rm -f *.o *~ qrexec-daemon qrexec-client
install:
	install -d $(DESTDIR)/usr/sbin
	install -t $(DESTDIR)/usr/sbin -m 755 qrexec-daemon
	install -d $(DESTDIR)/usr/bin
	install -t $(DESTDIR)/usr/bin -m 755 qrexec-client
.PHONY: all clean install

qrexec-daemon: qrexec-daemon.o
	$(CC) -pie -g -o qrexec-daemon qrexec-daemon.o $(LIBS)
qrexec-client: qrexec-client.o
	$(CC) -pie -g -o qrexec-client qrexec-client.o $(LIBS)

