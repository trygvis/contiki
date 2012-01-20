/*
 * Copyright (c) 2001, Swedish Institute of Computer Science.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * Author: Adam Dunkels <adam@sics.se>
 *
 * $Id: tapdev.c,v 1.2 2007/05/20 21:32:24 oliverschmidt Exp $
 */

#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/socket.h>

#if TAPDEV_USE_PCAP == 1
#include <pcap.h>
#endif

#ifdef linux
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#define DEVTAP "/dev/net/tun"
#else  /* linux */
#define DEVTAP "/dev/tap0"
#endif /* linux */

#include "contiki-net.h"
#include "tapdev.h"

#define DROP 0

#if DROP
static int drop = 0;
#endif

#ifndef TAPDEV_IP
#define TAPDEV_IP "10.1.1.100"
#endif

#ifndef TAPDEV_ADD_ROUTE
#define TAPDEV_ADD_ROUTE 1
#endif

static int fd;

static unsigned long lasttime;

#define BUF ((struct uip_eth_hdr *)&uip_buf[0])

#if TAPDEV_USE_PCAP == 1

static pcap_dumper_t* pcap_dumper;
static pcap_t* pcap;

static void
log_open() {

  pcap = pcap_open_dead(DLT_EN10MB, 8 * 1024);
  if(pcap == NULL) {
    fprintf(stderr, "Could not initialize pcap: %s\n", pcap_geterr(pcap));
    exit(EXIT_FAILURE);
  }

  pcap_dumper = pcap_dump_open(pcap, "pcap.out");
  if(pcap_dumper == NULL) {
    fprintf(stderr, "Could not open pcap dump file: %s\n", pcap_geterr(pcap));
    exit(EXIT_FAILURE);
  }
}

static void
log_close() {
  pcap_dump_close(pcap_dumper);
  pcap_close(pcap);
}

static void
log_packet(void* buf, int len)
{
  struct timeval ts;
  gettimeofday(&ts, NULL);
  struct pcap_pkthdr pkthdr;
  pkthdr.ts = ts;
  pkthdr.caplen = len;
  pkthdr.len = len;

  pcap_dump((u_char*)pcap_dumper, &pkthdr, buf);
  pcap_dump_flush(pcap_dumper);
}
#else
static void log_open() {}
static void log_close() {}
static void log_packet(void* buf, size_t len) {}
#endif /* TAPDEV_USE_PCAP */

/*---------------------------------------------------------------------------*/
static void
remove_route(void)
{
  char buf[1024];
  snprintf(buf, sizeof(buf), "route delete -net 172.16.0.0");
  system(buf);
  printf("%s\n", buf);

}
/*---------------------------------------------------------------------------*/
void
tapdev_init(void)
{
  char buf[1024];
  int set_ip = 1;

  fd = open(DEVTAP, O_RDWR);
  if(fd == -1) {
    perror("tapdev: tapdev_init: open");
    return;
  }

#ifdef linux
  {
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    char *dev = getenv("TAPDEV");
    if(dev) {
      strncpy(ifr.ifr_name, dev, IFNAMSIZ);
      /* If we're using an externally configured TAP interface, don't set the IP */
      set_ip = 0;
    }
    ifr.ifr_flags = IFF_TAP|IFF_NO_PI;
    if (ioctl(fd, TUNSETIFF, (void *) &ifr) < 0) {
      perror(buf);
      exit(1);
    }
  }
#endif /* Linux */

  if(set_ip) {
    snprintf(buf, sizeof(buf), "ifconfig tap0 inet " TAPDEV_IP);
    system(buf);
    printf("%s\n", buf);
  }

#if TAPDEV_ADD_ROUTE == 1
#ifdef linux
  /* route add for linux */
  snprintf(buf, sizeof(buf), "route add -net 172.16.0.0/16 gw 192.168.1.2");
#else /* linux */
  /* route add for freebsd */
  snprintf(buf, sizeof(buf), "route add -net 172.16.0.0/16 192.168.1.2");
#endif /* linux */

  system(buf);
  printf("%s\n", buf);
  atexit(remove_route);
#endif /* TAPDEV_ADD_ROUTE */

  log_open();

  lasttime = 0;
}
/*---------------------------------------------------------------------------*/
u16_t
tapdev_poll(void)
{
  fd_set fdset;
  struct timeval tv;
  int ret;
  
  tv.tv_sec = 0;
  tv.tv_usec = 0;
  
  FD_ZERO(&fdset);
  if(fd > 0) {
    FD_SET(fd, &fdset);
  }

  ret = select(fd + 1, &fdset, NULL, NULL, &tv);

  if(ret == 0) {
    return 0;
  }
  ret = read(fd, uip_buf, UIP_BUFSIZE);

  if(ret == -1) {
    perror("tapdev_poll: read");
  }

  if(ret > 0) {
    log_packet(uip_buf, ret);
  }

  return ret;
}
/*---------------------------------------------------------------------------*/
void
tapdev_send(void)
{
  int ret;

  if(fd <= 0) {
    return;
  }
 
  /*  printf("tapdev_send: sending %d bytes\n", size);*/
  /*  check_checksum(uip_buf, size);*/

#if DROP
  drop++;
  if(drop % 8 == 7) {
    printf("Dropped an output packet!\n");
    return;
  }
#endif /* DROP */

  if(uip_len == 0) {
    return;
  }

  log_packet(uip_buf, uip_len);

  ret = write(fd, uip_buf, uip_len);

  if(ret == -1) {
    perror("tap_dev: tapdev_send: writev");
    exit(1);
  }
}
/*---------------------------------------------------------------------------*/
void
tapdev_exit(void)
{
  log_close();
}
/*---------------------------------------------------------------------------*/
