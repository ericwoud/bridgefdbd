/*
 * bridgefdbd - Bridge FDB Daemon
 *
 * Copyright (C) 2019      Eric Woudstra
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License v2
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

// apt install libsystemd-dev

#define _GNU_SOURCE

#include <stdlib.h>
#include <stdarg.h>
#include <dirent.h> 
#include <errno.h>
#include <net/if.h>
#include <stdbool.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/inotify.h>
#include <sys/epoll.h>
#include <linux/if_ether.h>
#include <linux/rtnetlink.h>
#include <linux/neighbour.h>
#include <arpa/inet.h>

#define USE_SYSTEMD 1 
#ifdef USE_SYSTEMD
#include <systemd/sd-daemon.h>
#endif

#define EVENT_BUF_LEN  32678
#define STRINGSIZE      1024

#define NDA_RTA(r) \
	((struct rtattr *)(((char *)(r)) + NLMSG_ALIGN(sizeof(struct ndmsg))))

char **                ip_strings;
int                    ip_strings_cnt;
in_addr_t              ip_addrs[16];
int                    port = 11111;
int                    debuglevel = 1;
bool                   should_exit = false;
const char             *localsocketstr="/tmp/bridgefdb-%d";
const char             *hostapdmatch = "CONNECTED ";
char                   *varrunhostapd = "/var/run/hostapd";
char                   *script ="./bridgefdbd.sh";
FILE                   *stdinprocess = NULL;
char                   lockfile[STRINGSIZE]="";
int                    epfd = -1, lffd=-1, nlfd=-1, infd=-1, inwd=-1;
pid_t                  pidsh = 0;
int                    notifysystemd=0;
char                   buffer[EVENT_BUF_LEN];
struct iovec           iovbuffer = { buffer, sizeof(buffer) };
struct sockaddr_nl     sanlevent = { .nl_family = AF_NETLINK, .nl_groups = RTMGRP_IPV4_IFADDR};
struct sockaddr_nl     sanldump =  { .nl_family = AF_NETLINK };
int                    globalindexcount=-10; // negative indexes

#define NODE_HOSTAPD          1
#define NODE_IP               2
#define NODE_REQUEST_DUMP     3

#define LEVEL_EXIT       -32000

#if (ETH_ALEN*3) >  IF_NAMESIZE
#define NAMELEN      ETH_ALEN*3
#else
#define NAMELEN     IF_NAMESIZE
#endif           
typedef struct addr_node {
    struct    addr_node * next;
    int                   type;
    int                   ifindex;
    in_addr_t             addr;
    int                   sockfd;
    int                   synchrfd;
    char                  name[NAMELEN];
    char                  mac[ETH_ALEN];
} addr_node_t;
addr_node_t * threadlist;

int debugprintf(int level, const char *fmt, ...)
{
  if (level > debuglevel) return 0;
  va_list args;
  int printed=0;
  va_start(args, fmt);
  printed = vprintf(fmt, args);
  va_end(args);
  fflush(stdout);
  if (level != LEVEL_EXIT) return printed;
  else exit(EXIT_FAILURE);
}

addr_node_t * node_from_ifindex(addr_node_t * head, int ifindex) {
  addr_node_t * current = head;
  while (current != NULL) {
    if (current->ifindex==ifindex) return current; 
    current = current->next;
  }
  return NULL; 
}

addr_node_t * node_from_addr(addr_node_t * head, in_addr_t addr) {
  addr_node_t * current = head;
  while (current != NULL) {
    if (current->addr==addr) return current; 
    current = current->next;
  }
  return NULL; 
}

addr_node_t * node_add(int type, addr_node_t ** head, char *name, in_addr_t addr) {
  int index;
  if ((index=if_nametoindex(name)) == 0) {
    index=--globalindexcount;
    globalindexcount |= 0x40000000; // always keep number negative
  }
  addr_node_t * current = *head;
  addr_node_t * a;
  struct in_addr in_ad={0};
  in_ad.s_addr = addr;
  if (index==0) return NULL;
  
  if (current==NULL) {
    current = (addr_node_t *) malloc(sizeof(addr_node_t));
    *head = current;
  }
  else {
    if (current->ifindex == index) return NULL;
    while (current->next != NULL) {
      current = current->next;
      if (current->ifindex == index) return NULL;
    }
    current->next = (addr_node_t *) malloc(sizeof(addr_node_t));
    current = current->next;
  }
  a=current;
  a->type=type;
  a->ifindex=index;
  a->addr=addr;
  if_indextoname(index, a->name);
  switch (type) {
    case NODE_HOSTAPD:
      // Start listening on hostapd
      if ((a->sockfd = socket(PF_UNIX, SOCK_DGRAM, 0)) !=-1) {
        struct sockaddr_un sa_local = {0}, sa_dest = {0};
        sa_local.sun_family = AF_UNIX;
        snprintf(sa_local.sun_path, sizeof(sa_local.sun_path),  localsocketstr, a->sockfd);
        unlink(sa_local.sun_path); // Just in case we did not unlink it when exiting
        if (bind(a->sockfd, (struct sockaddr *) &sa_local, sizeof(sa_local)) !=-1) {
          sa_dest.sun_family = AF_UNIX;
          snprintf(sa_dest.sun_path, sizeof(sa_dest.sun_path),  "%s/%s", varrunhostapd, a->name);
          if (connect(a->sockfd, (struct sockaddr *) &sa_dest, sizeof(sa_dest)) != -1) { 
            int flags = fcntl(a->sockfd, F_GETFL);
            if (flags >= 0) fcntl(a->sockfd, F_SETFL, flags | O_NONBLOCK);
            send(a->sockfd, "DETACH", 6, 0); // // Just in case we did not send DETACH when exiting
            send(a->sockfd, "ATTACH", 6, 0);
            debugprintf(1, "Started listening on %s\n", a->name);
          }
        }
      }
      if ((a->synchrfd = socket(PF_UNIX, SOCK_DGRAM, 0)) !=-1) {
        struct sockaddr_un sa_local = {0}, sa_dest = {0};
        sa_local.sun_family = AF_UNIX;
        snprintf(sa_local.sun_path, sizeof(sa_local.sun_path),  localsocketstr, a->synchrfd);
        unlink(sa_local.sun_path); // Just in case we did not unlink it when exiting
        if (bind(a->synchrfd, (struct sockaddr *) &sa_local, sizeof(sa_local)) !=-1) {
          sa_dest.sun_family = AF_UNIX;
          snprintf(sa_dest.sun_path, sizeof(sa_dest.sun_path),  "%s/%s", varrunhostapd, a->name);
          if (connect(a->synchrfd, (struct sockaddr *) &sa_dest, sizeof(sa_dest)) != -1) { 
            send(a->synchrfd, "STATUS", 6, 0);
            int recsize;
            if ((recsize=recv(a->synchrfd, buffer, sizeof(buffer), 0)) > 0) {  // flags ???
              if (recsize >= sizeof(buffer)) recsize = sizeof(buffer) -1; 
              buffer[recsize] = '\0';
              debugprintf(2, "STATUS RETURNS:%s:ENDOF STATUS", buffer);
            }
                        
          }
        }
      }
      break;
    case NODE_IP:
      // Start listening on ip
      if ((a->sockfd = socket(PF_INET, SOCK_DGRAM, 0)) !=-1) {
        struct sockaddr_in si_me = {
          .sin_family = AF_INET,
          .sin_port = htons(port),
          .sin_addr.s_addr = a->addr,
        };
        int one = 1; setsockopt(a->sockfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)); // DO WE NEED THIS?
        if (bind(a->sockfd, (struct sockaddr*)&si_me, sizeof(si_me)) !=-1) {
          debugprintf(1, "Started listening on %s:%d\n", inet_ntoa(in_ad), port);
        }
      }
      break;
    case NODE_REQUEST_DUMP:
      {
        char *mac;
        if ((mac = strstr(name, hostapdmatch)) == NULL) mac = name; else mac += strlen(hostapdmatch);
        if (strlen(mac)<(ETH_ALEN*3-1)) break;
        strncpy(a->name, mac, ETH_ALEN*3-1); a->name[ETH_ALEN*3-1] = 0;
        if (sscanf(a->name, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", a->mac, a->mac+1, 
                                      a->mac+2, a->mac+3, a->mac+4, a->mac+5) != 6) break;
        if ((a->sockfd = socket(AF_NETLINK, SOCK_RAW | SOCK_NONBLOCK, NETLINK_ROUTE)) !=-1) {
          if (bind(a->sockfd, (struct sockaddr *) &sanldump, sizeof(sanldump)) !=-1) {
            struct ndmsg *ndm;
            struct nlmsghdr *nlh = (struct nlmsghdr *)calloc(1, NLMSG_SPACE(sizeof(*ndm)));
            nlh->nlmsg_len = NLMSG_LENGTH(sizeof(*ndm));
            nlh->nlmsg_pid = getpid();
            nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP; // 
            nlh->nlmsg_type = RTM_GETNEIGH;
            ndm = (struct ndmsg *)NLMSG_DATA(nlh);
            ndm->ndm_family = PF_BRIDGE;
            ndm->ndm_ifindex = 0;
            struct iovec iov = { .iov_base=nlh, .iov_len=nlh->nlmsg_len };
            struct msghdr msg = {
              .msg_name = (void *)&sanldump,
              .msg_namelen = sizeof(sanldump),
              .msg_iov = &iov,
              .msg_iovlen = 1,
            };
            sendmsg(a->sockfd,&msg,0);
            free(nlh);
            debugprintf(2, "Send dump request, delete %s\n", a->name);
          }
        }
      }
      break;
  }
  if (a->sockfd != -1) {
    struct epoll_event ev={
      .events = EPOLLIN|EPOLLET,
      .data.fd = a->sockfd,
    };
    epoll_ctl(epfd, EPOLL_CTL_ADD, a->sockfd, &ev);
  }
  current->next = NULL;
  return current;
}

int node_remove(addr_node_t ** head, addr_node_t *a) {
  if (a==NULL) return -1;
  int retval = -1;
  struct in_addr in_ad = {0};
  in_ad.s_addr = a->addr;
  addr_node_t * current = *head, * temp_node = NULL;

  switch (a->type) {
    case NODE_HOSTAPD:
      // Stop listening on hostapd
      if (a->synchrfd != -1) {
       char localfile[32];
       snprintf(localfile, sizeof(localfile),  localsocketstr, a->synchrfd);
       unlink(localfile); // Not done if CTRL-C is pressed
      }
      if (a->sockfd != -1) {
       char localfile[32];
       snprintf(localfile, sizeof(localfile),  localsocketstr, a->sockfd);
       send(a->sockfd, "DETACH", 6, 0);
       unlink(localfile); // Not done if CTRL-C is pressed
      }
      debugprintf(1, "Stopped listening on %s\n", a->name);
      break;
    case NODE_IP:
    // Stop listening on ip
      debugprintf(1, "Stopped listening on %s:%d\n", inet_ntoa(in_ad), port);
      break;
    case NODE_REQUEST_DUMP:
      break;
  }
  if (a->sockfd != -1) {
    epoll_ctl(epfd, EPOLL_CTL_DEL, a->sockfd, NULL);
    close(a->sockfd);
  }
  if (current == NULL) return -1;
  if (current == a) {
    temp_node = (*head)->next;
    retval = (*head)->ifindex;
    free(*head);
    *head = temp_node;
  } else {
    while (current->next != a) {
      if (current->next == NULL) return -1;
      current = current->next;
    }
    temp_node = current->next;
    retval = temp_node->ifindex;
    current->next = temp_node->next;
    free(temp_node);
  }
  return retval;
}

void send2script(char *ip, char *buff) {
  if (stdinprocess != NULL) {
    char s[STRINGSIZE];
    snprintf(s, STRINGSIZE,  "%s %s\n", ip, buff);
    fwrite(s, sizeof(char), strlen(s), stdinprocess);
    fflush(stdinprocess);
    debugprintf(2, "Recieved from %s: %s\n", ip, buff);
  }
}

void exitfunc() {
  if (getpid() != pidsh) {
    while (threadlist) node_remove(&threadlist,threadlist);
    if (inwd != -1) inotify_rm_watch( infd, inwd );
    if (infd >=0) close(infd);
    if (nlfd >=0) close(nlfd);
    if (epfd >=0) close(epfd);
    remove(lockfile);
    rmdir(varrunhostapd);
  }
}

void intHandler(int signo) {
  switch (signo) {
    case SIGINT:  
      debugprintf(2, "intHandler received SIGINT\n");
      fflush(stdout);
      exit(EXIT_SUCCESS);
      break;
    case SIGTERM:  
      debugprintf(2, "intHandler received SIGTERM\n");
      break;
    case SIGQUIT:  
      debugprintf(2, "intHandler received SIGQUIT\n");
      break;
    case SIGTSTP:  
      debugprintf(2, "intHandler received SIGTSTP\n");
      break;
  }
  fflush(stdout);
  should_exit = true;
}

void sendsanldump() {
  struct sockaddr_nl sanldump = { .nl_family = AF_NETLINK };
  struct ifaddrmsg *ifa;
  struct nlmsghdr *nlh = (struct nlmsghdr *)calloc(1, NLMSG_SPACE(sizeof(*ifa)));
  nlh->nlmsg_len = NLMSG_LENGTH(sizeof(*ifa));
  nlh->nlmsg_pid = getpid();
  nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP; // 
  nlh->nlmsg_type = RTM_GETADDR;
  ifa = (struct ifaddrmsg *)NLMSG_DATA(nlh);
  ifa->ifa_family = AF_INET;
  ifa->ifa_index = 0;
  struct iovec iov = { .iov_base=nlh, .iov_len=nlh->nlmsg_len };
  struct msghdr msg = {
    .msg_name = (void *)&sanldump,
    .msg_namelen = sizeof(sanldump),
    .msg_iov = &iov,
    .msg_iovlen = 1,
  };
  sendmsg(nlfd,&msg,0);
  free(nlh);
}

void process_inotify() {
  int length, ret, i = 0;
  length = read (infd, buffer, sizeof(buffer)); // infd is IN_NONBLOCK
  if (length <= 0) return;
  while (i <length) {
    struct inotify_event * event = (struct inotify_event *) & buffer[i];
    if (event->len) {
      if (event->mask & IN_CREATE) {
        node_add(NODE_HOSTAPD, &threadlist, event->name, 0);
      }
      else if (event->mask & IN_DELETE) {
        if ((ret=if_nametoindex(event->name))) {
          node_remove(&threadlist, node_from_ifindex(threadlist, ret));
        }
      }            
    }
    i += sizeof (struct inotify_event) + event->len;
  }
}

void process_netlink() {
  struct msghdr msg = { &sanlevent, sizeof(sanlevent), &iovbuffer, 1, NULL, 0, 0 };
  int len = recvmsg(nlfd, &msg, MSG_DONTWAIT);
  for (struct nlmsghdr *nh = (struct nlmsghdr *) buffer; NLMSG_OK (nh, len); nh = NLMSG_NEXT (nh, len)) {
    if (nh->nlmsg_type == NLMSG_DONE) break;
    if (nh->nlmsg_type == NLMSG_ERROR) continue;
    if ((nh->nlmsg_type==RTM_NEWADDR) || (nh->nlmsg_type==RTM_DELADDR) || (nh->nlmsg_type==RTM_GETADDR)) {
      struct ifaddrmsg *ifaddr = (struct ifaddrmsg *)NLMSG_DATA(nh);
      int index=ifaddr->ifa_index;
      struct rtattr *rta = IFA_RTA(NLMSG_DATA(nh));
      int rta_len = nh->nlmsg_len - NLMSG_LENGTH(sizeof(struct ifaddrmsg));
      in_addr_t addr=0;
      char *name="";
      for (; RTA_OK(rta, rta_len); rta = RTA_NEXT(rta, rta_len)) {
        if (rta->rta_type == IFA_ADDRESS) addr=((struct in_addr *)RTA_DATA(rta))->s_addr;
        else if (rta->rta_type == IFA_LABEL) name = (char *)RTA_DATA(rta);
      }
      if ((addr==0x0100007f) && (notifysystemd >=0)) notifysystemd++;
      if ((nh->nlmsg_type == RTM_NEWADDR) || (nh->nlmsg_type == RTM_GETADDR)) {
        for (int i = 0 ; i<ip_strings_cnt; i++) {
          if (ip_addrs[i] == addr) {
            node_add(NODE_IP, &threadlist, name, addr);
          }
        }
      }
      else if (nh->nlmsg_type == RTM_DELADDR){
        node_remove(&threadlist, node_from_ifindex(threadlist, index));
      }
    }
  }
}

void process_socket(addr_node_t *a)
{
  int recsize;
  struct sockaddr_in si_other;
  socklen_t addr_size= sizeof(si_other);

  while ((recsize=recvfrom(a->sockfd, buffer, sizeof(buffer), MSG_DONTWAIT, 
                           (struct sockaddr*)& si_other, &addr_size)) > 0) {
    if (recsize >= sizeof(buffer)) recsize = sizeof(buffer) -1; 
    buffer[recsize] = '\0';
    int skip=0;
    if ((buffer[0]=='<') && (buffer[2]=='>')) skip=3;
    if      (strcmp(buffer, "OK\n") ==0)   buffer[2]=0;
    else if (strcmp(buffer, "FAIL\n") ==0) buffer[4]=0;
    else if (strstr(buffer, hostapdmatch) != NULL) {
      node_add(NODE_REQUEST_DUMP, &threadlist, buffer+skip, 0); // delete mac from fdb
      if (a->type==NODE_HOSTAPD) {
        int sockfd, linelen;
        in_addr_t local_addr = 0;
        char line[STRINGSIZE];
        linelen = snprintf(line, sizeof(line), "%s %s", a->name, buffer+skip);
        if ((sockfd = socket(PF_INET, SOCK_DGRAM, 0)) !=-1) {
          for (int i = 0 ; i<ip_strings_cnt; i++) {
            if (node_from_addr(threadlist, ip_addrs[i]) != NULL) {
              local_addr = ip_addrs[i];
              continue;
            }  
            struct sockaddr_in si_bridges = {
              .sin_family = AF_INET,
              .sin_port = htons(port),
              .sin_addr.s_addr = ip_addrs[i],
            };
            if (sendto(sockfd, line, linelen, 0, 
                     (struct sockaddr*)&si_bridges, sizeof(si_bridges)) != -1) { 
              debugprintf(2, "Data send to %s:%d string %s\n", ip_strings[i], port, line);
            }
          }
          close(sockfd);
        }
        struct in_addr in_ad = {0};
        in_ad.s_addr = local_addr;   // This needs to be ip address of bridge the interface is attached to
        send2script(inet_ntoa(in_ad), line);
      } else {
        send2script(inet_ntoa(si_other.sin_addr), buffer+skip);
      }
    }  
  }
}

void process_request_socket(addr_node_t *a)
{
  struct msghdr msg = { &sanldump, sizeof(sanldump), &iovbuffer, 1, NULL, 0, 0 };
  int len = recvmsg(a->sockfd, &msg, 0);
  int reclen = len, count = 0; 
  debugprintf(2, "Received dump request, delete %s\n", a->name);
  for (struct nlmsghdr *nh = (struct nlmsghdr *) buffer; NLMSG_OK (nh, len); nh = NLMSG_NEXT (nh, len)) {
    if (nh->nlmsg_type == NLMSG_DONE) break;
    if (nh->nlmsg_type == NLMSG_ERROR) continue;
    bool found = false;
    unsigned char *ll = 0;
    if ((nh->nlmsg_type==RTM_NEWNEIGH) || (nh->nlmsg_type==RTM_DELNEIGH) || (nh->nlmsg_type==RTM_GETNEIGH)) {
      struct ndmsg *ndm = (struct ndmsg *)NLMSG_DATA(nh);
      int index=ndm->ndm_ifindex;
      struct rtattr *rta = NDA_RTA(NLMSG_DATA(nh));
      int rta_len = nh->nlmsg_len - NLMSG_LENGTH(sizeof(struct ndmsg));
      unsigned int master=0, vlan=0;
      for (; RTA_OK(rta, rta_len); rta = RTA_NEXT(rta, rta_len)) {
             if (rta->rta_type == NDA_LLADDR) ll = (unsigned char *)RTA_DATA(rta); 
        else if (rta->rta_type == NDA_MASTER) master=*(unsigned int*)RTA_DATA(rta);
        else if (rta->rta_type == NDA_VLAN) vlan=*(unsigned int*)RTA_DATA(rta);
      }
      if (ll) {
        if (memcmp(ll, a->mac, ETH_ALEN) == 0) {
          debugprintf(2, "Delete %02x:%02x:%02x:%02x:%02x:%02x index %d vlan %d master %d\n", 
              ll[0], ll[1], ll[2], ll[3], ll[4], ll[5], index, vlan, master);
          nh->nlmsg_pid = getpid();
          nh->nlmsg_flags = NLM_F_REQUEST;
          nh->nlmsg_type = RTM_DELNEIGH;
          ndm = (struct ndmsg *)NLMSG_DATA(nh);
          ndm->ndm_state = 0;
          count++; found = true;
        }
      }
    }
    if (!found) nh->nlmsg_type = NLMSG_NOOP;
  }
  if (count) { // send the altered msg back
    struct iovec iov = { buffer, reclen };
    struct msghdr msg = {
      .msg_name = (void *)&sanldump,
      .msg_namelen = sizeof(sanldump),
      .msg_iov = &iov,
      .msg_iovlen = 1,
    };
    sendmsg(a->sockfd,&msg,0);
  }
  node_remove(&threadlist, a);
}

int main(int argc, char *argv[])
{
  int i, pipefd[2];
  struct sigaction act={.sa_handler = intHandler};
  struct epoll_event rtev;
  DIR *d;
  struct dirent *dir;

  argv++; argc--; 
  if (argc > 0) {
    while (argv[0][0] == '-') {
      if (argc<2) debugprintf(LEVEL_EXIT, "Option error: %s\n", argv[0]);
      if (strlen(argv[0]) != 2) debugprintf(LEVEL_EXIT, "Unknown option: %s\n", argv[0]);
      switch (argv[0][1]) {
        case 'd':
          debuglevel = (int)strtol(argv[1], NULL, 10);
          argv+=2; argc-=2;
          break;
        case 'p':
          port = (int)strtol(argv[1], NULL, 10);
          argv+=2; argc-=2;
          break;
        case 's':
          script = argv[1];
          argv+=2; argc-=2;
          break;
        case 'h':
          varrunhostapd = argv[1];
          argv+=2; argc-=2;
          break;
        default:
          debugprintf(LEVEL_EXIT, "Unknown option: %s\n", argv[0]);
      }
      if (argc <= 0) break;
    }
  }
  ip_strings = argv;
  ip_strings_cnt = argc; if (ip_strings_cnt < 0) debugprintf(LEVEL_EXIT, "Arguments error.\n");
  for (i = 0 ; i<ip_strings_cnt; i++) 
    if ((ip_addrs[i] = inet_addr(ip_strings[i])) == INADDR_NONE) 
      debugprintf(LEVEL_EXIT, "IP address argument error: %s\n", ip_strings[i]);

  if (sigaction(SIGTERM, &act, NULL) == -1) debugprintf(LEVEL_EXIT, "Signal action SIGTERM error: %s\n", strerror(errno));
  if (sigaction(SIGTSTP, &act, NULL) == -1) debugprintf(LEVEL_EXIT, "Signal action SIGTSTP error: %s\n", strerror(errno));
  if (sigaction(SIGQUIT, &act, NULL) == -1) debugprintf(LEVEL_EXIT, "Signal action SIGQUIT error: %s\n", strerror(errno));
  if (sigaction(SIGINT,  &act, NULL) == -1) debugprintf(LEVEL_EXIT, "Signal action SIGINT error: %s\n", strerror(errno));

  atexit(&exitfunc);
  mkdir(varrunhostapd, 0x0750);
  snprintf(lockfile, sizeof(lockfile)-1,  "%s/bridgefdbd-%d", varrunhostapd, getpid());
  if ((lffd = open(lockfile, O_RDWR|O_CREAT, 0770)) == -1) 
    debugprintf(LEVEL_EXIT, "open() lockfile error: %s\n", strerror(errno));
  close(lffd);

  epfd = epoll_create(sizeof(epfd));
  if (epfd < 0) debugprintf(LEVEL_EXIT,"epoll_create failed: %s\n", strerror(errno));

  nlfd = socket(AF_NETLINK, SOCK_RAW | SOCK_NONBLOCK, NETLINK_ROUTE);
  if (nlfd < 0) debugprintf(LEVEL_EXIT, "netlink socket() error: %s\n", strerror(errno));
  bind(nlfd, (struct sockaddr *) &sanlevent, sizeof(sanlevent));       
  {struct epoll_event ev = {
      .events = EPOLLIN|EPOLLET,
      .data.fd = nlfd,
    };
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, nlfd, &ev) < 0) 
      debugprintf(LEVEL_EXIT,"Could not add netlink to epoll: %s\n", strerror(errno));
  }
  sendsanldump();
      
  if ((infd = inotify_init1(IN_NONBLOCK)) < 0) 
    debugprintf(LEVEL_EXIT, "inotify_init() error %s\n", strerror(errno));
  {struct epoll_event ev = {
      .events = EPOLLIN|EPOLLET,
      .data.fd = infd,
    };
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, infd, &ev) < 0) 
      debugprintf(LEVEL_EXIT,"Could not add inotify to epoll %s\n", strerror(errno));
  }
  if ((inwd = inotify_add_watch( infd, varrunhostapd, IN_CREATE | IN_DELETE )) == -1) 
    debugprintf(LEVEL_EXIT, "inotify_add_watch error: %s\n", strerror(errno));
  if ((d = opendir(varrunhostapd)) != NULL) {
    while ((dir = readdir(d)) != NULL)  
      if (dir->d_type == DT_SOCK) {
        node_add(NODE_HOSTAPD, &threadlist, dir->d_name, 0);
      }
    closedir(d);
  }    
 
  if( access( script, F_OK ) != -1 ) {
    pipe(pipefd);
    pidsh = fork();
    if (pidsh == 0) { // Child process
      close(pipefd[1]);
      dup2(pipefd[0], STDIN_FILENO);
      execl(script, script, (char*) NULL);
      debugprintf(LEVEL_EXIT, "Error starting child process: %s\n", strerror(errno));
    }
    close(pipefd[0]);
    stdinprocess = fdopen(pipefd[1], "w");
  }

  while (should_exit == false)
  {
    switch (epoll_wait(epfd, &rtev, 1, -1)) { // the only place in the code we wait
      case -1: // epoll_wait failed
        continue;
      case 0:  // epoll_wait timeout
        continue;
      default:
        if (rtev.data.fd==infd) {
          process_inotify();
        }
        else if (rtev.data.fd==nlfd) {
         process_netlink();          
         if (notifysystemd > 0) { // after receiving 127.0.0.1, we are ready
           #ifdef USE_SYSTEMD
             sd_notify(0, "READY=1");
           #endif
           notifysystemd=-99999;
         }
        }
        else for (addr_node_t *a = threadlist; a; a = a->next) {
          if (rtev.data.fd != a->sockfd) continue;
          switch (a->type) {
            case NODE_HOSTAPD:
            case NODE_IP:
              process_socket(a);
              break;
            case NODE_REQUEST_DUMP:
              process_request_socket(a);
              break;
          }
        }
        break;
    }
  }
  #ifdef USE_SYSTEMD
    sd_notify(0, "STOPPING=1");
  #endif
  if (stdinprocess != NULL) {
    send2script("0.0.0.0", "dummy EXIT\n");
    for(i=0; i<50; i++) {
      if (waitpid(pidsh, NULL, WNOHANG) > 0) break;
      usleep(100000);
    } // wait for a maximum of 5 seconds
    fclose(stdinprocess);
  }
  
  exit(EXIT_SUCCESS);
}

