/*
 * packet.h -- decoding a captured frame into a classified packet.
 *
 * Everything in this header is pure: bytes go in, a filled `struct packet`
 * comes out. There is no socket, no file and no global state, which is what
 * makes the classifier testable without root and without a network -- the
 * tests hand these functions hand-built byte arrays.
 */

#ifndef PACKET_H
#define PACKET_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <netinet/in.h> /* INET6_ADDRSTRLEN */

/* Longest summary kept for a packet, including the terminator. */
#define PACKET_INFO_MAX 256

typedef enum {
    NETWORK_NONE = 0,
    NETWORK_IPV4,
    NETWORK_IPV6,
    NETWORK_OTHER
} network_proto;

typedef enum {
    TRANSPORT_NONE = 0,
    TRANSPORT_TCP,
    TRANSPORT_UDP,
    TRANSPORT_ICMP,
    TRANSPORT_OTHER
} transport_proto;

typedef enum {
    APP_NONE = 0,
    APP_HTTP,
    APP_HTTPS,
    APP_DNS,
    APP_DHCP,
    APP_NTP,
    APP_OTHER
} app_proto;

struct packet {
    network_proto network;
    char src_ip[INET6_ADDRSTRLEN];
    char dst_ip[INET6_ADDRSTRLEN];

    /* The protocol/next-header byte, kept raw so the CSV can record protocols
     * this program does not decode. */
    uint8_t ip_protocol;

    /* Size of the packet at the network layer. This is the length the IP
     * header claims, clamped to the number of bytes actually captured: a
     * forged header must not be able to inflate the byte counters. */
    size_t length;

    transport_proto transport;
    uint16_t src_port;
    uint16_t dst_port;

    app_proto application;

    /* Human-readable summary: the first line of an HTTP request, the queried
     * name for DNS, and so on. Always printable ASCII and NUL-terminated --
     * see sanitize_into() in packet.c. "-" when there is nothing to say. */
    char info[PACKET_INFO_MAX];
};

/*
 * Decode one captured frame. Returns false when the frame is too short or too
 * damaged to classify, in which case `out` is left zeroed.
 *
 * `tun_interface` tells the link-layer detector that the capture comes from a
 * TUN device, which hands over bare IP packets with no link header at all.
 */
bool packet_decode(const uint8_t *frame, size_t len, bool tun_interface,
                   struct packet *out);

/*
 * Find where the network layer starts. A TUN device delivers bare IP, an
 * Ethernet NIC delivers a 14-byte header, and some captures arrive in Linux
 * "cooked" (SLL) framing; this recognises all four and reports the EtherType
 * plus the number of bytes to skip.
 */
bool packet_parse_link_layer(const uint8_t *frame, size_t len,
                             bool tun_interface,
                             uint16_t *ethertype, size_t *header_len);

/* Guess the application protocol from the well-known port numbers. */
app_proto packet_detect_application(transport_proto transport,
                                    uint16_t src_port, uint16_t dst_port);

const char *network_proto_name(network_proto proto);
const char *transport_proto_name(transport_proto proto);
const char *app_proto_name(app_proto proto);

#endif /* PACKET_H */
