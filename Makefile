CC      = gcc
RM      = rm -f
CP      = cp -f
CFLAGS := -g0 -Wall
LDFLAGS := -lsystemd
LIBRELEASE = v4.8.0

default: bridgefdbd

bridgefdbd: bridgefdbd.c
	$(CC) $(CFLAGS) -o bridgefdbd bridgefdbd.c $(LDFLAGS)

install:
	(systemctl stop    bridgefdbd ; exit 0)
	(systemctl disable bridgefdbd ; exit 0)
	($(CP) ./bridgefdbd         /usr/local/sbin/ ; exit 0)
	($(CP) ./bridgefdbd.service /etc/systemd/system/ ; exit 0)
	($(CP) ./bridgefdbd_default /etc/default/bridgefdbd ; exit 0)
	systemctl daemon-reload
	systemctl enable  bridgefdbd
	systemctl start   bridgefdbd
	systemctl status  bridgefdbd --no-pager

installscript:
	($(CP) ./bridgefdbd.sh      /usr/local/sbin/ ; exit 0)


remove:
	(systemctl stop    bridgefdbd ; exit 0)
	(systemctl disable bridgefdbd ; exit 0)
	$(RM) /usr/local/sbin/bridgefdbd.sh
	$(RM) /etc/systemd/system/bridgefdbd.service
	$(RM) /usr/local/sbin/bridgefdbd
	$(RM) /etc/default/bridgefdbd

removescript:
	$(RM) /usr/local/sbin/bridgefdbd.sh

clean:
	$(RM) bridgefdbd


