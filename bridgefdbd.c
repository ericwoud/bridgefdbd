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

// apt install libmnl-dev libsystemd-dev

#define _GNU_SOURCE

#include <stdlib.h>
#include <stdarg.h>
#include <dirent.h> 
#include <errno.h>
#include <net/if.h>
#include <time.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/inotify.h>
#include <sys/epoll.h>
#include <linux/if_ether.h>
#include <linux/rtnetlink.h>
#include <linux/neighbour.h>
#include <arpa/inet.h>

#include <libmnl/libmnl.h>
#include <systemd/sd-daemon.h>

#define EVENT_BUF_LEN     ( 64 * ( sizeof (struct inotify_event) + 16 ) )

#define STRINGSIZE       256
#define LEVEL_EXIT    -32000

#define MNL_SOCKET_DUMP_SIZE 32768

char **    ip_strings;
int        ip_strings_cnt;
in_addr_t  ip_addrs[16];
int        port = 11111;
int        debuglevel = 1;
bool       should_exit = false;
const char *localsocketstr="/tmp/bridgefdb-%d";
const char *hostapdmatch = "CONNECTED ";
const char *ndmsgflags[] = {"use", "self", "master", "proxy", "extlearned", "offloaded", "sticky", "router"};
char       *varrunhostapd = "/var/run/hostapd";
char       *script ="./bridgefdbd.sh";
FILE       *stdinprocess = NULL;
char       lockfile[STRINGSIZE]="";
int        epfd = -1, lffd=-1, nlfd=-1, infd=-1, inwd=-1;
pid_t      pidsh = 0;

typedef struct addr_node {
    struct    addr_node * next;
    int                   ifindex;
    int                   masterindex;
    int                   flags;
    in_addr_t             addr;
    int                   sockfd;
    char                  name[IFNAMSIZ];
    char                  mac[ETH_ALEN];
} addr_node_t;
addr_node_t * threadlist;

struct cb_arg {
  char        *mac;  
  struct      addr_node * addr_list;
};

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

addr_node_t * node_add(addr_node_t ** head, addr_node_t *a) {
    addr_node_t * current = *head;
    struct in_addr in_ad={0};
    in_ad.s_addr = a->addr;

    if (current==NULL) {
      current = (addr_node_t *) malloc(sizeof(addr_node_t));
      *head = current;
    }
    else {
      if (current->ifindex == a->ifindex) return NULL;
      while (current->next != NULL) {
        current = current->next;
        if (current->ifindex == a->ifindex) return NULL;
      }
      current->next = (addr_node_t *) malloc(sizeof(addr_node_t));
      current = current->next;
    }
    if (a->masterindex) {
      // Start listening on hostapd
      struct sockaddr_un sa_local = {0}, sa_dest = {0};
      if ((a->sockfd = socket(PF_UNIX, SOCK_DGRAM, 0)) !=-1) {
        sa_local.sun_family = AF_UNIX;
        snprintf(sa_local.sun_path, sizeof(sa_local.sun_path),  localsocketstr, a->sockfd);
        unlink(sa_local.sun_path); // Just in case we did not unlink it when exiting
        if (bind(a->sockfd, (struct sockaddr *) &sa_local, sizeof(sa_local)) !=-1) {
          sa_dest.sun_family = AF_UNIX;
          snprintf(sa_dest.sun_path, sizeof(sa_dest.sun_path),  "%s/%s", varrunhostapd, a->name);
          struct epoll_event ev={
            .events = EPOLLIN|EPOLLET,
            .data.fd = a->sockfd,
          };
          if (epoll_ctl(epfd, EPOLL_CTL_ADD, a->sockfd, &ev) !=-1) {
            if (connect(a->sockfd, (struct sockaddr *) &sa_dest, sizeof(sa_dest)) != -1) { 
              send(a->sockfd, "DETACH", 6, 0); // // Just in case we did not send DETACH when exiting
              send(a->sockfd, "ATTACH", 6, 0);
              debugprintf(1, "Started listening on %s\n", a->name);
            }
          }
        }
      }
    }
    else {
      // Start listening on ip
     struct sockaddr_in si_me = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
        .sin_addr.s_addr = a->addr,
      };
      if ((a->sockfd = socket(PF_INET, SOCK_DGRAM, 0)) !=-1) {
        int one = 1; setsockopt(a->sockfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)); // DO WE NEED THIS?
        if (bind(a->sockfd, (struct sockaddr*)&si_me, sizeof(si_me)) !=-1) {
          struct epoll_event ev={
            .events = EPOLLIN|EPOLLET,
            .data.fd = a->sockfd,
          };
          if (epoll_ctl(epfd, EPOLL_CTL_ADD, a->sockfd, &ev) !=-1) 
            debugprintf(1, "Started listening on %s:%d\n", inet_ntoa(in_ad), port);
        }
      }
    }
    memcpy(current, a, sizeof(addr_node_t));
    current->next = NULL;
    return current;
}

int node_remove(addr_node_t ** head, addr_node_t *a) {
    int retval = -1;
    struct in_addr in_ad = {0};
    if (a==NULL) return -1;
    in_ad.s_addr = a->addr;
    addr_node_t * current = *head, * temp_node = NULL;

    if (a->masterindex) {
      // Stop listening on hostapd
      if (a->sockfd != -1) {
       char localfile[32];
       snprintf(localfile, sizeof(localfile),  localsocketstr, a->sockfd);
       send(a->sockfd, "DETACH", 6, 0);
       epoll_ctl(epfd, EPOLL_CTL_DEL, a->sockfd, NULL);
       unlink(localfile); // Not done if CTRL-C is pressed
       close(a->sockfd);
      }
      debugprintf(1, "Stopped listening on %s\n", a->name);
    }
    else {
      // Stop listening on ip
      if (a->sockfd != -1) {
        epoll_ctl(epfd, EPOLL_CTL_DEL, a->sockfd, NULL);
        close(a->sockfd);
      }
      debugprintf(1, "Stopped listening on %s:%d\n", inet_ntoa(in_ad), port);
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

static int data_attr_addr_cb(const struct nlattr *attr, void *data)
{
  const struct nlattr **tb = data;
  int type = mnl_attr_get_type(attr);
  if (mnl_attr_type_valid(attr, IFA_MAX) < 0) return MNL_CB_OK;
  switch(type) {
    case IFA_ADDRESS:
      if (mnl_attr_validate(attr, MNL_TYPE_BINARY) < 0) return MNL_CB_ERROR;
      break;
  }
  tb[type] = attr;
  return MNL_CB_OK;
}

static int data_attr_link_cb(const struct nlattr *attr, void *data)
{
  const struct nlattr **tb = data;
  int type = mnl_attr_get_type(attr);
  if (mnl_attr_type_valid(attr, IFLA_MAX) < 0) return MNL_CB_OK;
  switch(type) {
    case IFLA_IFNAME:
      if (mnl_attr_validate(attr, MNL_TYPE_STRING) < 0) return MNL_CB_ERROR;
      break;
  }
  tb[type] = attr;
  return MNL_CB_OK;
}

static int data_attr_neigh_cb(const struct nlattr *attr, void *data)
{
  const struct nlattr **tb = data;
  int type = mnl_attr_get_type(attr);
  if (mnl_attr_type_valid(attr, NDA_MAX) < 0) return MNL_CB_OK;
  switch(type) {
    case NDA_LLADDR:
      if (mnl_attr_validate(attr, MNL_TYPE_BINARY) < 0) return MNL_CB_ERROR;
      break;
    case NDA_MASTER:
      if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0) return MNL_CB_ERROR;
      break;
  }
  tb[type] = attr;
  return MNL_CB_OK;
}

static int data_neigh_cb(const struct nlmsghdr *nlh, void *data)
{
  struct nlattr *tb[NDA_MAX + 1] = {};
  struct ndmsg *ndm = mnl_nlmsg_get_payload(nlh);

  mnl_attr_parse(nlh, sizeof(*ndm), data_attr_neigh_cb, tb);
  if (tb[NDA_LLADDR]) {
    void *addr = mnl_attr_get_payload(tb[NDA_LLADDR]);
    struct cb_arg *fa = data;
    if (memcmp(addr, fa->mac, ETH_ALEN) == 0) {
      if (tb[NDA_MASTER]) ndm->ndm_flags |= NTF_MASTER;
      for (addr_node_t *a = fa->addr_list; a; a = a->next) {
        if (ndm->ndm_ifindex == a->ifindex) {
          a->flags |= ndm->ndm_flags; // Add flag on entry already found
          return MNL_CB_OK;
        }
      }
      addr_node_t *new = (addr_node_t *) malloc(sizeof(addr_node_t));
      new->next = fa->addr_list;
      new->ifindex = ndm->ndm_ifindex;
      new->flags = ndm->ndm_flags;
      fa->addr_list = new;
    }
  }
  return MNL_CB_OK;
}

void fdb_delmac(char *string)
{
  struct mnl_socket *nl;
  char abuf[ETH_ALEN], macstr[STRINGSIZE], *mac;
  unsigned int seq;
  char buf[MNL_SOCKET_DUMP_SIZE];
  struct cb_arg fa = {.mac=abuf};
  
  if ((mac = strstr(string, hostapdmatch)) == NULL) mac = string; else mac += strlen(hostapdmatch);
  if (strlen(mac)<(ETH_ALEN*3-1)) return;
  strncpy(macstr, mac, ETH_ALEN*3-1); macstr[ETH_ALEN*3-1] = 0;
  if (sscanf(macstr, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", abuf, abuf+1, abuf+2, abuf+3, abuf+4, abuf+5) != 6) return;

  if ((nl = mnl_socket_open(NETLINK_ROUTE)) != NULL) {
    if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) >= 0) {
      struct nlmsghdr *nlh;
      struct ndmsg *ndm;
      unsigned int portid = mnl_socket_get_portid(nl);

      nlh = mnl_nlmsg_put_header(buf);
      nlh->nlmsg_type = RTM_GETNEIGH;
      nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
      nlh->nlmsg_seq = seq = time(NULL);
      ndm = mnl_nlmsg_put_extra_header(nlh, sizeof(*ndm));
      ndm->ndm_family = PF_BRIDGE;

      if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) >= 0) {
        int ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
        while (ret > 0) {
          ret = mnl_cb_run(buf, ret, seq, portid, data_neigh_cb, &fa);
          if (ret <= MNL_CB_STOP) break;
          ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
        }
        if (ret != -1) {  
          for (addr_node_t *a = fa.addr_list; a; a = a->next) {
            nlh = mnl_nlmsg_put_header(buf);
            nlh->nlmsg_type = RTM_DELNEIGH;
            nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
            nlh->nlmsg_seq = seq = time(NULL);
            ndm = mnl_nlmsg_put_extra_header(nlh, sizeof(*ndm));
            ndm->ndm_family = PF_BRIDGE,
            ndm->ndm_ifindex = a->ifindex;
            ndm->ndm_flags = a->flags; 
            mnl_attr_put(nlh, NDA_LLADDR, ETH_ALEN, abuf);
            if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) >= 0) {
              if ((ret = mnl_socket_recvfrom(nl, buf, sizeof(buf))) != -1) {
                if ((ret = mnl_cb_run(buf, ret, seq, portid, NULL, NULL)) != -1){
                  char flags[STRINGSIZE]="";
                  bool first=true;
                  for (int i=0 ; i< (sizeof(ndmsgflags)/sizeof(ndmsgflags[0])) ; i++) {
                    if ( (1<<i) & a->flags) {
                      if (!first) strncat(flags, " + ", sizeof(flags)-1);
                      strncat(flags, ndmsgflags[i], sizeof(flags)-1);
                      first=false;
                    }
                  }
                  debugprintf(2, "Deleted MAC %s %s\n", macstr, flags); 
                }
              }
            }
          }
      
        }
        while (fa.addr_list != NULL) {
          addr_node_t * next = fa.addr_list->next;
          free(fa.addr_list);
          fa.addr_list = next;
        }
      }
    }
    mnl_socket_close(nl);
  }
}

void send2script(char *interface, char *from, char *buff) {
  if (stdinprocess != NULL) {
    char s[STRINGSIZE];
    snprintf(s, STRINGSIZE,  "%s %s %s\n", interface, from, buff);
    fwrite(s, sizeof(char), strlen(s), stdinprocess);
    fflush(stdinprocess);
  }
}

static int data_addr_cb(const struct nlmsghdr *nlh, void *data)
{
  struct nlattr *tb[IFA_MAX + 1] = {};
  struct ifaddrmsg *ifa = mnl_nlmsg_get_payload(nlh);
  mnl_attr_parse(nlh, sizeof(*ifa), data_attr_addr_cb, tb);
  if (tb[IFA_ADDRESS]) {
    void *addr = mnl_attr_get_payload(tb[IFA_ADDRESS]);
    struct cb_arg *fa = data;
    for (addr_node_t *a = fa->addr_list; a; a = a->next) {
      if ((a->ifindex == ifa->ifa_index) || (a->masterindex == ifa->ifa_index)) 
         a->addr = ((struct in_addr *)addr)->s_addr;
    }
  }
  return MNL_CB_OK;
}

static int data_link_cb(const struct nlmsghdr *nlh, void *data)
{
  struct nlattr *tb[IFLA_MAX+1] = {};
  struct ifinfomsg *ifm = mnl_nlmsg_get_payload(nlh);
  mnl_attr_parse(nlh, sizeof(*ifm), data_attr_link_cb, tb);
  if (tb[IFLA_IFNAME]) {
    struct cb_arg *fa = data;
    addr_node_t *new = (addr_node_t *) malloc(sizeof(addr_node_t));
    new->next = fa->addr_list;
    new->addr = 0;
    new->ifindex = ifm->ifi_index;
    strncpy(new->name, mnl_attr_get_str(tb[IFLA_IFNAME]), IFNAMSIZ);
    new->masterindex = (tb[IFLA_MASTER]) ? mnl_attr_get_u32(tb[IFLA_MASTER]) : 0;
    fa->addr_list = new;
  }
  return MNL_CB_OK;
}

void link_addr(int index)
{
  struct mnl_socket *nl;
  int ret;
  unsigned int seq, portid;
  char buf[MNL_SOCKET_DUMP_SIZE];
  struct cb_arg fa= {};
  addr_node_t * next;

  if ((nl = mnl_socket_open(NETLINK_ROUTE)) != NULL) {
    if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) >= 0) {
      struct nlmsghdr *nlh;
      struct ifinfomsg *ifi;
      struct ifaddrmsg *ifa;
      portid = mnl_socket_get_portid(nl);
      char path[PATH_MAX];

      nlh = mnl_nlmsg_put_header(buf);
      nlh->nlmsg_type = RTM_GETLINK;
      nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
      nlh->nlmsg_seq = seq = time(NULL);
      ifi = mnl_nlmsg_put_extra_header(nlh, sizeof(*ifi));

      if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) >= 0) {
        ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
        while (ret > 0) {
          ret = mnl_cb_run(buf, ret, seq, portid, data_link_cb, &fa);
          if (ret <= MNL_CB_STOP) break;
          ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
        }
        if (ret == -1) return; 
      }

      nlh = mnl_nlmsg_put_header(buf);
      nlh->nlmsg_type = RTM_GETADDR;
      nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
      nlh->nlmsg_seq = seq = time(NULL);
      ifa = mnl_nlmsg_put_extra_header(nlh, sizeof(*ifa));
      ifa->ifa_family = AF_INET;

      if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) >= 0) {
        ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
        while (ret > 0) {
          ret = mnl_cb_run(buf, ret, seq, portid, data_addr_cb, &fa);
          if (ret <= MNL_CB_STOP) break;
          ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
        }
        if (ret == -1) return; 
      }

      for (addr_node_t *a = fa.addr_list; a; a = a->next) {
        if (index != -1) if (a->ifindex != index) continue;
        for (int i = 0 ; i<ip_strings_cnt; i++) { 
          if (ip_addrs[i] == a->addr) {
            if (a->masterindex ==0) {
              node_add(&threadlist, a);
            }
            else {
              snprintf(path, PATH_MAX, "%s/%s", varrunhostapd, a->name);
              if (access( path, F_OK ) != -1 ) {
                node_add(&threadlist, a);
              } 
            }
          }
        }
      }
      while (fa.addr_list != NULL) {
        next = fa.addr_list->next;
        free(fa.addr_list);
        fa.addr_list = next;
      }
    }
    mnl_socket_close(nl);
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


int main(int argc, char *argv[])
{
    int i, pipefd[2];
    struct sigaction act={.sa_handler = intHandler};
    struct epoll_event rtev;
    char buffer[EVENT_BUF_LEN];
    int recsize, length, ret;
    struct iovec iov = { buffer, sizeof(buffer) };

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

    nlfd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (nlfd < 0) debugprintf(LEVEL_EXIT, "netlink socket() error: %s\n", strerror(errno));
    struct sockaddr_nl sanl = {.nl_family = AF_NETLINK, .nl_groups = RTMGRP_IPV4_IFADDR};
    bind(nlfd, (struct sockaddr *) &sanl, sizeof(sanl));       
    {struct epoll_event ev = {
        .events = EPOLLIN|EPOLLET,
        .data.fd = nlfd,
      };
      if (epoll_ctl(epfd, EPOLL_CTL_ADD, nlfd, &ev) < 0) 
        debugprintf(LEVEL_EXIT,"Could not add netlink to epoll: %s\n", strerror(errno));
    }
    if ((infd = inotify_init()) < 0) debugprintf(LEVEL_EXIT, "inotify_init() error %s\n", strerror(errno));
    {struct epoll_event ev = {
        .events = EPOLLIN|EPOLLET,
        .data.fd = infd,
      };
      if (epoll_ctl(epfd, EPOLL_CTL_ADD, infd, &ev) < 0) 
        debugprintf(LEVEL_EXIT,"Could not add inotify to epoll %s\n", strerror(errno));
    }
    if ((inwd = inotify_add_watch( infd, varrunhostapd, IN_CREATE | IN_DELETE )) == -1) 
      debugprintf(LEVEL_EXIT, "inotify_add_watch error: %s\n", strerror(errno));
 
    link_addr(-1);

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

    sd_notify(0, "READY=1");

    while (should_exit == false)
    {
      switch (epoll_wait(epfd, &rtev, 1, 1000)) {
        case -1: // select failed
        case 0: // select timeout
          continue;
        default:
          if (rtev.data.fd==infd) { // Recieved inotify event
            length = read (infd, buffer, sizeof(buffer));
            if (length <= 0) continue;
            i = 0;
            while (i <length) {
              struct inotify_event * event = (struct inotify_event *) & buffer[i];
              if (event->len) {
                if (event->mask & IN_CREATE) {
                  link_addr(if_nametoindex(event->name));
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
          else if (rtev.data.fd==nlfd) { // Recieved netlink event
            struct msghdr msg = { &sanl, sizeof(sanl), &iov, 1, NULL, 0, 0 };
            int len = recvmsg(nlfd, &msg, 0);
            for (struct nlmsghdr *nh = (struct nlmsghdr *) buffer; NLMSG_OK (nh, len); nh = NLMSG_NEXT (nh, len)) {
              if (nh->nlmsg_type == NLMSG_DONE) break;
              if (nh->nlmsg_type == NLMSG_ERROR) continue;
              if (nh->nlmsg_type == RTM_NEWADDR){
                int index=((struct ifaddrmsg *)NLMSG_DATA(nh))->ifa_index;
                link_addr(index);
              }
              else if (nh->nlmsg_type == RTM_DELADDR){
                int index=((struct ifaddrmsg *)NLMSG_DATA(nh))->ifa_index;
                node_remove(&threadlist, node_from_ifindex(threadlist, index));
              }
            }
          }
          else for (addr_node_t *a = threadlist; a; a = a->next) {
            if (rtev.data.fd==a->sockfd) { // Recieved interface socket event
              int skip=0;
              struct sockaddr_in si_other;
              socklen_t addr_size= sizeof(si_other);
              struct in_addr in_ad = {0};
              while ((recsize=recvfrom(a->sockfd, buffer, sizeof(buffer), MSG_DONTWAIT, (struct sockaddr*)& si_other, &addr_size)) > 0) {
                if (recsize >= sizeof(buffer)) recsize = sizeof(buffer) -1; 
                buffer[recsize] = '\0';
                if ((buffer[0]=='<') && (buffer[2]=='>')) skip=3;
                if      (strcmp(buffer, "OK\n") ==0)   buffer[2]=0;
                else if (strcmp(buffer, "FAIL\n") ==0) buffer[4]=0;
                else if (strstr(buffer, hostapdmatch) != NULL) {
                  fdb_delmac(buffer+skip);
                  if (a->masterindex) {
                    int sockfd;
                    if ((sockfd = socket(PF_INET, SOCK_DGRAM, 0)) !=-1) {
                      for (int i = 0 ; i<ip_strings_cnt; i++) {
                        if (ip_addrs[i] != a->addr) {
                          struct sockaddr_in si_bridges = {
                            .sin_family = AF_INET,
                            .sin_port = htons(port),
                            .sin_addr.s_addr = ip_addrs[i],
                          };
                          if (sendto(sockfd, buffer+skip, recsize-skip, 0, (struct sockaddr*)&si_bridges, sizeof(si_bridges)) != -1) { 
                            debugprintf(2, "Data send to %s:%d string %s\n", ip_strings[i], port, buffer+skip);
                          }
                        }
                      }
                      close(sockfd);
                    }
                    debugprintf(2, "Recieved from %s: %s\n", a->name, buffer+skip);
                    in_ad.s_addr = a->addr;
                    send2script(a->name, inet_ntoa(in_ad), buffer+skip);
                  } else {
                    debugprintf(2, "Recieved from %s: %s\n", inet_ntoa(si_other.sin_addr), buffer+skip);
                    send2script(a->name, inet_ntoa(si_other.sin_addr), buffer+skip);
                  }
                }  
              }
            }
          }
          break;
      }
    }
    sd_notify(0, "STOPPING=1");

    if (stdinprocess != NULL) {
      send2script("exit", "0.0.0.0", "EXIT\n");
      for(i=0; i<50; i++) {
        if (waitpid(pidsh, NULL, WNOHANG) > 0) break;
        usleep(100000);
      } // wait for a maximum of 5 seconds
      fclose(stdinprocess);
    }
  
    exit(EXIT_SUCCESS);

}

