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

#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdarg.h>
#include <unistd.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <dirent.h> 
#include <signal.h>
#include <errno.h>
#include <net/if.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>

#include "libnetlink.h"

#define BUFFERSIZE      1024
#define STRINGSIZE       256
#define SMALLSTRINGSIZE   16
#define ARRAYSIZE         16
#define TIMEOUT            1
#define LEVEL_EXIT    -32000

struct rtnl_handle rth = { .fd = -1 };
static int       stderr_fd = -1;
static fpos_t    stderr_pos;
char             bridge_string[SMALLSTRINGSIZE];
int              bridge_ifindex;
in_addr_t        bridge_addr = INADDR_NONE;
char **          ip_strings;
int              ip_strings_cnt;
in_addr_t        ip_addrs[ARRAYSIZE];
int              port = 11111;
char             threadnames[ARRAYSIZE][SMALLSTRINGSIZE];
#define          bridge_ipstring threadnames[0]
bool             threads_should_exit = false;
bool             thread0_listening = false;
int              debuglevel = 1;
char             *varrunhostapd = "/var/run/hostapd";
char             *script ="./bridgefdbd.sh";
FILE             *stdinprocess = NULL;
pthread_mutex_t  libnetlink_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_t        tid[ARRAYSIZE] = { [ 0 ... ARRAYSIZE-1] = (pthread_t)NULL };

struct fdb_entry {
  __s32 ifindex;
  __u16 state;
  __s16 vid;
  __u8 flags;
  __u8 pad0;
  __u16 unused;
};

struct fdb_arg {
  char *mac;
  struct fdb_entry *fdb_entries;
  int count; 
};

int debugprintf(int level, const char *fmt, ...)
{
  if (level > debuglevel) return 0;
  va_list args;
  int printed;
  va_start(args, fmt);
  printed = vprintf(fmt, args);
  va_end(args);
  fflush(stdout);
  if (level != LEVEL_EXIT) return printed;
  else exit(EXIT_FAILURE);
}


void nullStderr()
{
  if  (stderr_fd == -1) {
    fflush(stderr);
    fgetpos(stderr, &stderr_pos);
    stderr_fd = dup(fileno(stderr));
    freopen("/dev/null", "w", stderr);
  }
}

void revertStderr()
{
  if  (stderr_fd != -1) {
    fflush(stderr);
    dup2(stderr_fd, fileno(stderr));
    close(stderr_fd);
    clearerr(stderr);
    fsetpos(stderr, &stderr_pos);
    stderr_fd = -1;
  }
}

int fdb_dump(const struct sockaddr_nl *who, struct nlmsghdr *n, void *arg)
{
  struct ndmsg *r = NLMSG_DATA(n);
  struct rtattr *tb[NDA_MAX+1];
  struct fdb_arg *fa=arg;
  __s16 vid = -1;
  int len = n->nlmsg_len;

  if (n->nlmsg_type != RTM_NEWNEIGH && n->nlmsg_type != RTM_DELNEIGH) return 0;
  len -= NLMSG_LENGTH(sizeof(*r)); if (len < 0) return -1;
  if (r->ndm_family != AF_BRIDGE) return 0;
  parse_rtattr(tb, NDA_MAX, NDA_RTA(r), len);
  if (!tb[NDA_LLADDR]) return 0;
  if (memcmp(RTA_DATA(tb[NDA_LLADDR]), fa->mac, ETH_ALEN) != 0) return 0;
  if (tb[NDA_VLAN]) vid = rta_getattr_u16(tb[NDA_VLAN]);
  fa->fdb_entries[fa->count].ifindex = r->ndm_ifindex;
  fa->fdb_entries[fa->count].state = r->ndm_state;
  fa->fdb_entries[fa->count].vid = vid;
  fa->fdb_entries[fa->count].flags = r->ndm_flags;
  if (tb[NDA_MASTER]) fa->fdb_entries[fa->count].flags |= NTF_MASTER;
  fa->count++;
  return 0;
}

static int fdb_delete(char *abuf, struct fdb_entry fe)
{
  struct {
    struct nlmsghdr	n;
    struct ndmsg		ndm;
    char			buf[256];
  } req = {
    .n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ndmsg)),
    .n.nlmsg_flags = NLM_F_REQUEST,
    .n.nlmsg_type = RTM_DELNEIGH,
    .ndm.ndm_family = PF_BRIDGE,
    .ndm.ndm_state = NUD_NOARP,
    .ndm.ndm_ifindex = fe.ifindex,
    .ndm.ndm_flags = fe.flags,
    .ndm.ndm_state = fe.state,
  };
  if (fe.vid >= 0) addattr16(&req.n, sizeof(req), NDA_VLAN, fe.vid);
  if (!(req.ndm.ndm_flags&(NTF_SELF|NTF_MASTER))) req.ndm.ndm_flags |= NTF_SELF;
  if (!(req.ndm.ndm_state&(NUD_PERMANENT|NUD_REACHABLE))) req.ndm.ndm_state |= NUD_PERMANENT;
  addattr_l(&req.n, sizeof(req), NDA_LLADDR, abuf, ETH_ALEN);
  if (rtnl_talk(&rth, &req.n, NULL, 0) < 0) return -1;
  return 0;
}

void fdb_delmac(const char *string)
{
  struct {
    struct nlmsghdr	n;
    struct ifinfomsg	ifm;
    char			buf[256];
  } req = {
    .n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg)),
    .ifm.ifi_family = PF_BRIDGE,
  };

  int msg_size = sizeof(struct ifinfomsg);
  const char *match = "CONNECTED ";
  char abuf[ETH_ALEN], macstr[STRINGSIZE], *mac;
  struct fdb_entry fe[16];
  struct fdb_arg fa;

  if ((mac = strstr(string, match)) == NULL) return;
  if (strlen(mac)<(ETH_ALEN*3-1)) return;
  strncpy(macstr, mac+strlen(match), ETH_ALEN*3-1); macstr[ETH_ALEN*3-1] = 0;
  if (sscanf(macstr, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", abuf, abuf+1, abuf+2, abuf+3, abuf+4, abuf+5) != 6) return;
  addattr32(&req.n, sizeof(req), IFLA_MASTER, bridge_ifindex);
  msg_size += RTA_LENGTH(4);
  fa.count=0;
  fa.fdb_entries=fe;
  fa.mac=abuf;

  pthread_mutex_lock(&libnetlink_mutex);
  if (rtnl_dump_request(&rth, RTM_GETNEIGH, &req.ifm, msg_size) < 0) goto error;
  if (rtnl_dump_filter(&rth, fdb_dump, &fa) < 0) goto error;
  for(int i=0; i<fa.count; i++) if (fdb_delete(abuf, fe[i]) < 0) goto error;
  debugprintf(1, "fdb_delmac deleted %s with %d entry/entries\n", macstr, fa.count); 
error:
  pthread_mutex_unlock(&libnetlink_mutex);
  return;
}

void send2script(char *from, char *buff) {
  if (stdinprocess != NULL) {
    char s[STRINGSIZE];
    snprintf(s, STRINGSIZE,  "%s %s %s\n", bridge_string, from, buff);
    fwrite(s, sizeof(char), strlen(s), stdinprocess);
    fflush(stdinprocess);
  }
}

int recvtimeout(int s, char *buf, int len, int flags)
{
  fd_set readfds;
  struct timeval tv={.tv_sec=TIMEOUT,.tv_usec=0};
  int ready;    
  FD_ZERO(&readfds);
  FD_SET(s, &readfds);
  if ((ready=select(s + 1, &readfds, NULL, NULL, &tv)) < 0) return -1;
  if (ready == 0) return 0; // Timeout
  if (!FD_ISSET(s, &readfds)) return -1;
  return recv(s, buf, len, 0); 
}

void* bridgefdb_threads(void *arg)
{
    int sockfd, tnr;
    char buffer[BUFFERSIZE];
    pthread_t id = pthread_self();

    for (tnr=0; tnr < ARRAYSIZE; tnr++) if(pthread_equal(id,tid[tnr])) break;

    if(tnr == 0) { // First Thread
      int one = 1;
      socklen_t addr_size;
      struct sockaddr_in si_me, si_other;
      struct timeval timeout = {.tv_sec=TIMEOUT, .tv_usec=0};
      memset(&si_me, '\0', sizeof(si_me));
      si_me.sin_family = AF_INET;
      si_me.sin_port = htons(port);
      si_me.sin_addr.s_addr = bridge_addr;
      if ((sockfd = socket(PF_INET, SOCK_DGRAM, 0)) !=-1) {
        setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)); // DO WE NEED THIS?
        setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout));
        setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(timeout));
        if (bind(sockfd, (struct sockaddr*)&si_me, sizeof(si_me)) !=-1) {
          thread0_listening = true;
          debugprintf(1, "Listening on %s:%d\n", bridge_ipstring, port);
          addr_size = sizeof(si_other);
          while ( threads_should_exit == false ) {
            if (recvfrom(sockfd, buffer, BUFFERSIZE, 0, (struct sockaddr*)& si_other, &addr_size) > 0) {
                fdb_delmac(buffer);
                send2script(inet_ntoa(si_other.sin_addr), buffer);
                debugprintf(2, "Received from %s:%d string %s\n", inet_ntoa(si_other.sin_addr), port, buffer);
            }
          }
        }
      }
    }
    else { // Other Threads
      int hapdsockfd, recsize;
      struct sockaddr_un local, dest;
      struct sockaddr_in si_bridges;
      while (thread0_listening == false) usleep(10000); 
      if ((sockfd = socket(PF_INET, SOCK_DGRAM, 0)) !=-1) {
        if ((hapdsockfd = socket(PF_UNIX, SOCK_DGRAM, 0)) !=-1) {
	  local.sun_family = AF_UNIX;
          snprintf(local.sun_path, sizeof(local.sun_path),  "/tmp/bridgefdb-%d", tnr);
          unlink(local.sun_path); // Just in case we did not unlink it when exiting
          if (bind(hapdsockfd, (struct sockaddr *) &local, sizeof(local)) !=-1) {
            dest.sun_family = AF_UNIX;
            snprintf(dest.sun_path, sizeof(dest.sun_path),  "%s/%s", varrunhostapd, threadnames[tnr]);
	    if (connect(hapdsockfd, (struct sockaddr *) &dest, sizeof(dest)) >= 0) {
              if (send(hapdsockfd, "DETACH", 6, 0) >= 0) { // // Just in case we did not send DETACH when exiting
                if (send(hapdsockfd, "ATTACH", 6, 0) >= 0) {
                  debugprintf(1, "Listening on %s\n", threadnames[tnr]);
                  while ( threads_should_exit == false ) {
                    if ((recsize=recvtimeout(hapdsockfd, buffer, BUFFERSIZE, 0)) > 0) {
                      if (recsize >= BUFFERSIZE) recsize = BUFFERSIZE -1; 
                      buffer[recsize] = '\0';
                      if      (strcmp(buffer, "OK\n") ==0)   buffer[2]=0;
                      else if (strcmp(buffer, "FAIL\n") ==0) buffer[4]=0;
                      else {
                        for (int i = 0 ; i<ip_strings_cnt; i++) {
                          if (ip_addrs[i] != bridge_addr) {
                            memset(&si_bridges, '\0', sizeof(si_bridges));
                            si_bridges.sin_family = AF_INET;
                            si_bridges.sin_port = htons(port);
                            si_bridges.sin_addr.s_addr = ip_addrs[i];
                            if (sendto(sockfd, buffer, BUFFERSIZE, 0, (struct sockaddr*)&si_bridges, sizeof(si_bridges)) != -1) { 
                              debugprintf(2, "Data send to %s:%d string %s\n", ip_strings[i], port, buffer);
                            }
                          }
                        }
                        fdb_delmac(buffer);
                        send2script(bridge_ipstring, buffer);
                        debugprintf(2, "Recieved from hostapd-%s: %s\n", threadnames[tnr], buffer);
                      } 
                    }
                  }
                  send(hapdsockfd, "DETACH", 6, 0); // Not done if CTRL-C is pressed
                }
              }
            }
          }
          unlink(local.sun_path); // Not done if CTRL-C is pressed
        }
      }
    }
    pthread_exit(NULL);
    return NULL;
}

void intHandler(int signo) {
  if (signo == SIGTERM) debugprintf(1, "intHandler received SIGTERM\n");
  else if (signo == SIGTSTP) {
    printf("\n");
    fflush(stdout);
    debugprintf(1, "intHandler received SIGTSTP\n");
  }
  threads_should_exit = true;
}

int main(int argc, char *argv[])
{
    int n, i, err, pipefd[2], numthreads=0;
    struct ifaddrs *ifaddr, *ifa;
    struct in_addr inaddr;
    struct dirent *dir;
    struct sigaction act;
    DIR *d;
    char path[PATH_MAX];
    pid_t pid = 0;

    argv++; argc--; 
    if (argc > 0) {
      while (argv[0][0] == '-') {
        if (argc<2) debugprintf(LEVEL_EXIT, "Option error: %s", argv[0]);
        if (strlen(argv[0]) != 2) debugprintf(LEVEL_EXIT, "Unknown option: %s", argv[0]);
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
            debugprintf(LEVEL_EXIT, "Unknown option: %s", argv[0]);
        }
        if (argc <= 0) break;
      }
    }
    ip_strings = argv;
    ip_strings_cnt = argc; if (ip_strings_cnt < 0) debugprintf(LEVEL_EXIT, "Arguments error.");
    for (i = 0 ; i<ip_strings_cnt; i++) 
      if ((ip_addrs[i] = inet_addr(ip_strings[i])) == INADDR_NONE) debugprintf(LEVEL_EXIT, "IP address error: %s", ip_strings[i]);

    if( access( script, F_OK ) != -1 ) {
      pipe(pipefd);
      pid = fork();
      if (pid == 0) { // Child process
        close(pipefd[1]);
        dup2(pipefd[0], STDIN_FILENO);
        execl(script, script, (char*) NULL);
        debugprintf(LEVEL_EXIT, "Error starting child process: %s", strerror(errno));
      }
      close(pipefd[0]);
      stdinprocess = fdopen(pipefd[1], "w");
    }

    if (getifaddrs(&ifaddr) == -1) debugprintf(LEVEL_EXIT, "Get interface addresses error: %s", strerror(errno));
    for (ifa = ifaddr, n = 0; ifa != NULL; ifa = ifa->ifa_next, n++) {
      if (ifa->ifa_addr == NULL) continue;
      if (ifa->ifa_addr->sa_family == AF_INET) 
        if (bridge_string[0] == 0) {
          snprintf(path, PATH_MAX, "/sys/class/net/%s/bridge", ifa->ifa_name);
          if (access( path, F_OK ) != -1 ) {
            for (i = 0 ; i<ip_strings_cnt; i++) { 
              if (ip_addrs[i] == ((struct sockaddr_in *) ifa->ifa_addr)->sin_addr.s_addr) {
                bridge_addr = ip_addrs[i];
                strncpy(bridge_string, ifa->ifa_name, SMALLSTRINGSIZE);                
              }
            }
          }
        }
    }
    freeifaddrs(ifaddr);
    if (bridge_addr==INADDR_NONE) debugprintf(LEVEL_EXIT, "Bridge not found.");
    if ((bridge_ifindex = if_nametoindex(bridge_string)) == 0) 
      debugprintf(LEVEL_EXIT, "Get bridge interface index error (%s): %s", bridge_string, strerror(errno));
    inaddr.s_addr = bridge_addr;
    strncpy(bridge_ipstring, inet_ntoa(inaddr), SMALLSTRINGSIZE);                

    if (d = opendir(varrunhostapd)) {
      while (((dir = readdir(d)) != NULL) && ( numthreads < (ARRAYSIZE-1))) 
        if (dir->d_type == DT_SOCK) {
          numthreads++;
          strncpy(threadnames[numthreads], dir->d_name, SMALLSTRINGSIZE);
        }
      closedir(d);
    }   

    memset(&act, 0, sizeof(act));
    act.sa_handler = intHandler;
    if (sigaction(SIGTERM, &act, NULL) == -1) debugprintf(LEVEL_EXIT, "Signal action SIGTERM error: %s", strerror(errno));
    if (sigaction(SIGTSTP, &act, NULL) == -1) debugprintf(LEVEL_EXIT, "Signal action SIGTSTP error: %s", strerror(errno));

    if (rtnl_open(&rth, 0) < 0) debugprintf(LEVEL_EXIT, "Unable to open libnetlink.");;
    if (debuglevel < 2) nullStderr(); // Do not show libnetlink errors

    for(i=0; i<=numthreads; i++) {
        if ((err = pthread_create(&(tid[i]), NULL, &bridgefdb_threads, NULL)) != 0) {
            tid[i] = (pthread_t)NULL;
            debugprintf(LEVEL_EXIT, "Can't create thread: %s", strerror(err));
        }
    }

    while (threads_should_exit == false) pause();

    for(i=0; i<=numthreads;i++) if (tid[i]!=(pthread_t)NULL) pthread_join(tid[i], NULL);

    revertStderr();
    if (rth.fd != -1) rtnl_close(&rth);

    if (stdinprocess != NULL) {
      send2script(bridge_ipstring, "EXIT\n");
      for(i=0; i<50; i++) {
        if (waitpid(pid, NULL, WNOHANG) > 0) break;
        struct timeval tv={.tv_sec=0,.tv_usec=100000};
        select(0, NULL, NULL, NULL, &tv);
      } // wait for a maximum of 5 seconds
      fclose(stdinprocess);
    }

    return 0;
}

