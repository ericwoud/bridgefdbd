# Bridge FDB Daemon

A daemon to use when directly bridging your wifi interface to your network.

Ever tried to make an Acces Point (AP) by directly adding your wifi interface to the bridge on your AP? Why doesn't his work as expected? Why do you need to IPforward or use a NAT or somethin similar? When you add the wifi interface to the AP bridge the following happens:

Your wifi client was first connected to your wireless router. Let's say you use your phone to test it. Look at the Forwarding DataBase (FDB) on both your router and AP by typing 'bridge fdb show' on a command prompt when possible. Locate your phones MAC address and see how network packets get send through the bridges on your network.

Now connect your phone to the wifi on your AP (make it forget about the router wifi so it does never try to connect to it again). The wifi connection to the AP is made but there everything stops. No IP is retreived through dhcp. Why not? Look at the FDB on both bridges again and notice that nothing has changed. All network packet are still being send to the router as if your phone is still connected to your router. This is why network traffic is not working at the moment. Of course you would be googling for and trying for some answers and after a X amount of minutes, you found it, it works again somehow, but you cannot figure out why. Look at your bridges FDB again and see the situation has changed. All packets are now send to the AP and everything works, including DHCP and other services that only work on local network like DLNA and mDNS, etc. But now if you connect to the router again this connection does not work anymore. 

What happened is after a certain amount of minutes the FDB entries are cleaned up if they have not been used and everything works again until you switch from AP to router or from router to AP.

If you want to change from router to AP more smoothly you will need to apply some fix. I have 2 solutions for this problem. 

1. [FDB Deamon](https://github.com/ericwoud/bridgefdbd) It deletes the MAC address from the FDB on all bridges whenever a wifi client connects/disconnects to hostapd for a wifi connection. You need to be able to install the bridgefdbd program on your AP AND also on your wireless router. Your wifi client gets the same MAC and IP number on router and AP.

2. [Mc Spoof](https://github.com/ericwoud/mcspoof) It applies a technique called MAC spoofing. Your wifi client gets a different MAC and IP number on the wireless router then on the AP. It adds a fixed number to the mac address of the wifi client. You only need to install it on all AP's and wireless router, except one, usually your wireless router. If you cannot install custom software on your wireless router, this is the way to go. It is however more of a hack and is likely to break more easily.

## Getting Started with Bridge FDB Daemon

You need to build the program from source.

### Prerequisites

You need to be able to install the bridgefdbd program on your AP AND also on your wireless router. Connect the router and AP directly without using a network switch. Hostapd needs to be in control of your wifi interfaces on your router and AP. On the AP the wifi interface needs to be added to the lan bridge.

### Installing


Clone from Git

```
git clone https://github.com/ericwoud/bridgefdbd.git
```

Change directory

```
cd bridgefdbd
```

Get the libnetlink library.

```
make getlib
```

Now build the executable.

```
make
```

On Debian/Ubuntu you can use the following to copy the files to the needed locations and start and enable the systemd service. You may need to use sudo if not logged on as root.

```
make install
```

Edit the /etc/default/bridgefdbd file. At least make sure that the IP addresses of the bridges on your router and on your AP are in the BRIDGEFDBD_ADDRS line. Restart the service if nessecairy.


Other make options:

Do a make getlib, make and make install:
```
make all
```

Remove the installation:
```
make remove
```

Clean:
```
make clean
```

Clean and remove the library:
```
make veryclean
```

## Features

The command line options are:

* -d number      : debug information 0 = none, 1 = some (default), 2 = all.
* -p number      : port number to use for internal network communication (UDP).
* -s script      : location of optional bash script that listens if some client connected on any bridge on your network (default = ./bridgefdbd.sh). If not used at all it can be removed.
* -h path        ; hostapd ctrl_interface to use (default = /var/run/hostapd).

After the options all the IP addresses of all your network bridges that run bridgefdbd are listed. 

On the commandline you can use CTRL-Z to make a clean exit, CTRL-C for a quick and dirty exit.


## Acknowledgments

* [Iproute2](https://github.com/shemminger/iproute2)

