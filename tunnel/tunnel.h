/*
 * tunnel.h -- the point-to-point tunnel the monitor observes.
 *
 * The tunnel takes IP packets off a TUN device and carries them to the peer
 * inside a raw Ethernet frame, then unwraps them on the far side. The outer
 * frame is built by hand, which is why the headers below are declared here
 * instead of coming from a system header: they describe bytes on the wire, so
 * their layout has to be exactly what is written, with no padding inserted.
 */

#ifndef TUNNEL_H
#define TUNNEL_H

#include <stdbool.h>
#include <stdint.h>

/* The script the server runs to bring up tun0, NAT and forwarding. */
#define SERVER_SCRIPT "server.sh"

/* Largest Ethernet frame, header and payload together. */
#define ETH_LEN 1518

struct eth_hdr {
    uint8_t dst_addr[6];
    uint8_t src_addr[6];
    uint16_t eth_type;
} __attribute__((packed));

struct ip_hdr {
    uint8_t ver;      /* version and header length */
    uint8_t tos;      /* type of service */
    uint16_t len;     /* total length */
    uint16_t id;      /* identification */
    uint16_t off;     /* fragment offset */
    uint8_t ttl;      /* time to live */
    uint8_t proto;    /* protocol */
    uint16_t sum;     /* header checksum */
    uint8_t src[4];   /* source address */
    uint8_t dst[4];   /* destination address */
} __attribute__((packed));

struct eth_ip_s {
    struct eth_hdr ethernet;
    struct ip_hdr ip;
} __attribute__((packed));

/*
 * Per-packet tracing, off by default. It used to be unconditional, which meant
 * a hex dump of every packet on stdout -- unreadable in a terminal and, once
 * the lab moved into containers, an enormous amount of log for no benefit.
 * Set TUNNEL_VERBOSE=1 in the environment to turn it back on.
 */
extern bool tunnel_verbose;

int tun_alloc(const char *dev, int flags);
int tun_read(int tun_fd, char *buffer, int length);
int tun_write(int tun_fd, char *buffer, int length);
void run_tunnel(int server, int argc, char *argv[]);

#endif /* TUNNEL_H */
