/* Copyright 2013-present Barefoot Networks, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Antonin Bas (antonin@barefootnetworks.com)
 *
 */

#include <unistd.h>
#include <pthread.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

#include "bmi_interface.h"
#include "BMI/bmi_port.h"

#include <fcntl.h>
#include <sys/stat.h>

typedef struct bmi_port_s {
  bmi_interface_t *bmi;
  int port_num;
  char *ifname;
  int fd;
  pthread_mutex_t stats_lock;
  bmi_port_stats_t stats;
} bmi_port_t;

#define PORT_COUNT_MAX 512

typedef struct bmi_port_mgr_s {
  bmi_port_t ports_info[PORT_COUNT_MAX];
  fd_set fds;
  int max_fd;
  void *cookie;
  bmi_packet_handler_t packet_handler;
  pthread_t select_thread;
  /* We use a RW mutex to protect port_mgr and port state. Send & receive will
  acquire a read lock, while port_add and port_remove will acquire a write
  lock. Using a single mutex for the port_mgr is much easier than having one for
  each port, even though it means that adding / removing a port will block send
  & receive for all ports. */
  pthread_rwlock_t lock;
} bmi_port_mgr_t;

static inline int port_in_use(bmi_port_t *port) {
  return (port->bmi != NULL);
}

static inline int port_num_valid(int port_num) {
  return (port_num >= 0 && port_num < PORT_COUNT_MAX);
}

static inline bmi_port_t *get_port(bmi_port_mgr_t *port_mgr, int port_num) {
  return &port_mgr->ports_info[port_num];
}

static void *run_select(void *data) {
  bmi_port_mgr_t *port_mgr = (bmi_port_mgr_t *) data;
  int n;
  int i;
  bmi_port_t *port_info;
  const char *pkt_data;
  int pkt_len;
  fd_set fds;
  int max_fd;

  struct timeval timeout;
  while(1) {
    /* timeout is needed to update set */
    timeout.tv_sec = 0;
    timeout.tv_usec = 100000;

    /* copy the FD set for select call */
    pthread_rwlock_rdlock(&port_mgr->lock);
    fds = port_mgr->fds;
    max_fd = port_mgr->max_fd;
    pthread_rwlock_unlock(&port_mgr->lock);

    n = select(max_fd + 1, &fds, NULL, NULL, &timeout);
    assert(n >= 0 || errno == EINTR);

    /* the thread terminates */
    if(max_fd == -1) return NULL;

    if(n <= 0) { // timeout or EINTR
      continue;
    }

    pthread_rwlock_rdlock(&port_mgr->lock);

    /* if we had a mutex for each port, there would potentially be a lot of
    overhead to acquire / release the lock at each iteration - we would need to
    hold the lock to call FD_ISSET... */
    for(i = 0; n && i < PORT_COUNT_MAX; i++) {
      port_info = get_port(port_mgr, i);
      if(!FD_ISSET(port_info->fd, &fds)) continue;
      --n;
      if(!port_info->bmi) continue;
      pkt_len = bmi_interface_recv(port_info->bmi, &pkt_data);
      if(pkt_len < 0 || !port_mgr->packet_handler) continue;
      port_mgr->packet_handler(i, pkt_data, pkt_len, port_mgr->cookie);
      pthread_mutex_lock(&port_info->stats_lock);
      port_info->stats.in_packets += 1;
      port_info->stats.in_octets += pkt_len;
      pthread_mutex_unlock(&port_info->stats_lock);
    }

    pthread_rwlock_unlock(&port_mgr->lock);
  }

  return NULL;
}

int bmi_start_mgr(bmi_port_mgr_t* port_mgr) {
  return pthread_create(&port_mgr->select_thread, NULL, run_select, port_mgr);
}

int bmi_port_create_mgr(bmi_port_mgr_t **port_mgr) {
  bmi_port_mgr_t *port_mgr_ = malloc(sizeof(bmi_port_mgr_t));
  int exitCode;
  if(!port_mgr) return -1;

  memset(port_mgr_, 0, sizeof(bmi_port_mgr_t));

  FD_ZERO(&port_mgr_->fds);

  exitCode = pthread_rwlock_init(&port_mgr_->lock, NULL);
  if (exitCode != 0)
    return exitCode;

  int i;
  for(i = 0; i < PORT_COUNT_MAX; i++) {
    bmi_port_t *port_info = get_port(port_mgr_, i);
    exitCode = pthread_mutex_init(&port_info->stats_lock, NULL);
    if (exitCode != 0)
      return exitCode;
  }

  *port_mgr = port_mgr_;
  return 0;
}

int bmi_set_packet_handler(bmi_port_mgr_t *port_mgr,
                           bmi_packet_handler_t packet_handler,
                           void *cookie) {
  pthread_rwlock_wrlock(&port_mgr->lock);
  port_mgr->packet_handler = packet_handler;
  port_mgr->cookie = cookie;
  pthread_rwlock_unlock(&port_mgr->lock);
  return 0;
}

int bmi_port_send(bmi_port_mgr_t *port_mgr,
                  int port_num, const char *buffer, int len) {
  if(!port_num_valid(port_num)) return -1;
  bmi_port_t *port = get_port(port_mgr, port_num);
  pthread_rwlock_rdlock(&port_mgr->lock);

  if(!port_in_use(port)) {
    pthread_rwlock_unlock(&port_mgr->lock);
    return -1;
  }

  int exitCode = bmi_interface_send(port->bmi, buffer, len);
  if (!exitCode) {
    pthread_mutex_lock(&port->stats_lock);
    port->stats.out_packets += 1;
    port->stats.out_octets += len;
    pthread_mutex_unlock(&port->stats_lock);
  }

  pthread_rwlock_unlock(&port_mgr->lock);
  return exitCode;
}

/* internal version of bmi_port_interface_add which doesn't acquire a lock */
static int _bmi_port_interface_add(bmi_port_mgr_t *port_mgr,
                                   const char *ifname, int port_num,
                                   const char *pcap_input_dump,
                                   const char* pcap_output_dump) {
  bmi_port_t *port = get_port(port_mgr, port_num);
  if(port_in_use(port)) return -1;
  port->ifname = strdup(ifname);

  bmi_interface_t *bmi;
  if(bmi_interface_create(&bmi, ifname) != 0) return -1;

  if(pcap_input_dump) bmi_interface_add_dumper(bmi, pcap_input_dump, 1);
  if(pcap_output_dump) bmi_interface_add_dumper(bmi, pcap_output_dump, 0);

  port->bmi = bmi;

  memset(&port->stats, 0, sizeof(port->stats));

  int fd = bmi_interface_get_fd(port->bmi);
  port->fd = fd;

  if(fd > port_mgr->max_fd) port_mgr->max_fd = fd;
  FD_SET(fd, &port_mgr->fds);

  return 0;
}

int bmi_port_interface_add(bmi_port_mgr_t *port_mgr,
			   const char *ifname, int port_num,
			   const char *pcap_input_dump,
			   const char* pcap_output_dump) {
  int exitCode;
  if(!port_num_valid(port_num)) return -1;
  pthread_rwlock_wrlock(&port_mgr->lock);
  exitCode = _bmi_port_interface_add(port_mgr, ifname, port_num,
                                     pcap_input_dump,
                                     pcap_output_dump);
  pthread_rwlock_unlock(&port_mgr->lock);
  return exitCode;
}

/* internal version of bmi_port_interface_remove which doesn't acquire a lock */
static int _bmi_port_interface_remove(bmi_port_mgr_t *port_mgr, int port_num) {
  bmi_port_t *port = get_port(port_mgr, port_num);
  if(!port_in_use(port)) return -1;
  free(port->ifname);

  if(bmi_interface_destroy(port->bmi) != 0) return -1;

  memset(port, 0, sizeof(bmi_port_t));

  FD_CLR(port->fd, &port_mgr->fds);

  return 0;
}

int bmi_port_interface_remove(bmi_port_mgr_t *port_mgr, int port_num) {
  int exitCode;
  if(!port_num_valid(port_num)) return -1;
  pthread_rwlock_wrlock(&port_mgr->lock);
  exitCode = _bmi_port_interface_remove(port_mgr, port_num);
  pthread_rwlock_unlock(&port_mgr->lock);
  return exitCode;
}

int bmi_port_destroy_mgr(bmi_port_mgr_t *port_mgr) {
  pthread_rwlock_wrlock(&port_mgr->lock);
  int i;
  for(i = 0; i < PORT_COUNT_MAX; i++) {
    bmi_port_t *port = get_port(port_mgr, i);
    if(port_in_use(port)) _bmi_port_interface_remove(port_mgr, i);
  }

  port_mgr->max_fd = -1;  // used to signal the thread it needs to terminate
  pthread_rwlock_unlock(&port_mgr->lock);
  pthread_join(port_mgr->select_thread, NULL);

  for(i = 0; i < PORT_COUNT_MAX; i++) {
    bmi_port_t *port = get_port(port_mgr, i);
    pthread_mutex_destroy(&port->stats_lock);
  }

  pthread_rwlock_destroy(&port_mgr->lock);
  free(port_mgr);

  return 0;
}

int bmi_port_interface_is_up(bmi_port_mgr_t *port_mgr,
                             int port_num,
                             bool *is_up) {
  if (!port_num_valid(port_num)) return -1;

  bmi_port_t *port = get_port(port_mgr, port_num);

  char c = 0;
  char path[1024];

  pthread_rwlock_rdlock(&port_mgr->lock);
  if (!port_in_use(port)) {
    pthread_rwlock_unlock(&port_mgr->lock);
    return -1;
  }
  snprintf(path, sizeof(path), "/sys/class/net/%s/operstate", port->ifname);
  pthread_rwlock_unlock(&port_mgr->lock);

  int fd = open(path, O_RDONLY);
  if (-1 == fd) {
    perror("open");
    return -1;
  }

  if (read(fd, &c, 1) != 1) {
    perror("read");
    return -1;

  }
  close(fd);
  *is_up = (c == 'u');
  return 0;

}

int bmi_port_get_stats(bmi_port_mgr_t *port_mgr,
                       int port_num,
                       bmi_port_stats_t *port_stats) {
  if (!port_num_valid(port_num)) return -1;

  bmi_port_t *port = get_port(port_mgr, port_num);

  pthread_rwlock_rdlock(&port_mgr->lock);
  if (!port_in_use(port)) {
    pthread_rwlock_unlock(&port_mgr->lock);
    return -1;
  }

  pthread_mutex_lock(&port->stats_lock);
  *port_stats = port->stats;
  pthread_mutex_unlock(&port->stats_lock);

  pthread_rwlock_unlock(&port_mgr->lock);

  return 0;
}

int bmi_port_clear_stats(bmi_port_mgr_t *port_mgr,
                       int port_num,
                       bmi_port_stats_t *port_stats) {
  if (!port_num_valid(port_num)) return -1;

  bmi_port_t *port = get_port(port_mgr, port_num);

  pthread_rwlock_rdlock(&port_mgr->lock);
  if (!port_in_use(port)) {
    pthread_rwlock_unlock(&port_mgr->lock);
    return -1;
  }

  pthread_mutex_lock(&port->stats_lock);
  if (port_stats != NULL)
    *port_stats = port->stats;
  memset(&port->stats, 0, sizeof(port->stats));
  pthread_mutex_unlock(&port->stats_lock);

  pthread_rwlock_unlock(&port_mgr->lock);

  return 0;
}
