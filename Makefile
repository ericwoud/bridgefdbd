CC      = gcc
RM      = rm -f
CP      = cp -f
CFLAGS := -pthread -g
LDFLAGS := -pthread
LIBRELEASE = v4.8.0

default: bridgefdbd

all: getlib bridgefdbd install

bridgefdbd: bridgefdbd.c
	@[ ! -f ./libnetlink.c ] && echo "\n\nYou need to 'make getlib' first.\n\n" || echo -n
	$(CC) $(CFLAGS) $(LDFLAGS) -o bridgefdbd bridgefdbd.c libnetlink.c

getlib:
	$(RM) libnetlink.*
	@wget -nv --no-check-certificate https://raw.githubusercontent.com/shemminger/iproute2/$(LIBRELEASE)/include/libnetlink.h
	@wget -nv --no-check-certificate https://raw.githubusercontent.com/shemminger/iproute2/$(LIBRELEASE)/lib/libnetlink.c
	$(RM) bridgefdbd

install:
	(systemctl stop    bridgefdbd ; exit 0)
	(systemctl disable bridgefdbd ; exit 0)
	($(CP) ./bridgefdbd         /usr/local/sbin/ ; exit 0)
	($(CP) ./bridgefdbd.sh      /usr/local/sbin/ ; exit 0)
	($(CP) ./bridgefdbd.service /etc/systemd/system/ ; exit 0)
	($(CP) ./bridgefdbd_default /etc/default/bridgefdbd ; exit 0)
	systemctl enable  bridgefdbd
	systemctl start   bridgefdbd
	systemctl status  bridgefdbd --no-pager

remove:
	(systemctl stop    bridgefdbd ; exit 0)
	(systemctl disable bridgefdbd ; exit 0)
	$(RM) /usr/local/sbin/bridgefdbd.sh
	$(RM) /etc/systemd/system/bridgefdbd.service
	$(RM) /usr/local/sbin/bridgefdbd
	$(RM) /etc/default/bridgefdbd

clean:
	$(RM) bridgefdbd

veryclean:
	$(RM) bridgefdbd
	$(RM) libnetlink.*

