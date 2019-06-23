CC      = gcc
RM      = rm -f
CFLAGS := -pthread -g
LDFLAGS := -pthread
LIBRELEASE = v4.8.0

default: bridgefdbd

all: getlib bridgefdbd install

bridgefdbd: bridgefdbd.c
	@[ ! -f ./libnetlink.c ] && echo "\n\nYou need to 'make getlib' first.\n\n" || echo -n
	$(CC) $(CFLAGS) $(LDFLAGS) -o bridgefdbd bridgefdbd.c libnetlink.c

getlib:
	rm -f libnetlink.*
	@wget -nv https://raw.githubusercontent.com/shemminger/iproute2/$(LIBRELEASE)/include/libnetlink.h
	@wget -nv https://raw.githubusercontent.com/shemminger/iproute2/$(LIBRELEASE)/lib/libnetlink.c
	$(RM) bridgefdbd

install:
	(systemctl stop    bridgefdbd ; exit 0)
	(systemctl disable bridgefdbd ; exit 0)
	cp -f ./bridgefdbd         /usr/local/sbin/
	(cp -f ./bridgefdbd.sh      /usr/local/sbin/ ; exit 0)
	cp -f ./bridgefdbd.service /etc/systemd/system/
	cp -f ./bridgefdbd_default /etc/default/bridgefdbd
	systemctl enable  bridgefdbd
	systemctl start   bridgefdbd
	systemctl status  bridgefdbd --no-pager

remove:
	(systemctl stop    bridgefdbd ; exit 0)
	(systemctl disable bridgefdbd ; exit 0)
	rm -f /usr/local/sbin/bridgefdbd
	rm -f /etc/systemd/system/bridgefdbd.service
	rm -f /usr/local/sbin/bridgefdbd
	rm -f /etc/default/bridgefdbd

clean:
	$(RM) bridgefdbd

veryclean:
	$(RM) bridgefdbd
	rm -f libnetlink.*

