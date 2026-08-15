#include "frames.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* A test that overflows its own buffer is a broken test, not a finding, so
 * these abort loudly instead of truncating quietly. */
static void require_capacity(size_t needed, size_t capacity, const char *what)
{
    if (needed > capacity) {
        fprintf(stderr, "frames.c: %s needs %zu bytes, buffer holds %zu\n",
                what, needed, capacity);
        abort();
    }
}

static void put_u16(uint8_t *p, uint16_t value)
{
    p[0] = (uint8_t)(value >> 8);
    p[1] = (uint8_t)(value & 0xFF);
}

uint16_t frame_get_u16(const uint8_t *frame, size_t offset)
{
    return (uint16_t)((uint16_t)frame[offset] << 8 | frame[offset + 1]);
}

void frame_set_u16(uint8_t *frame, size_t offset, uint16_t value)
{
    put_u16(frame + offset, value);
}

size_t frame_add_link(uint8_t *out, size_t capacity, frame_link framing,
                      uint16_t ethertype, const uint8_t *packet, size_t packet_len)
{
    size_t header_len;

    switch (framing) {
    case FRAMING_ETHERNET: header_len = 14; break;
    case FRAMING_SLL: header_len = 16; break;
    case FRAMING_SLL2: header_len = 20; break;
    case FRAMING_NONE:
    default: header_len = 0; break;
    }

    require_capacity(header_len + packet_len, capacity, "link header");
    memset(out, 0, header_len);

    switch (framing) {
    case FRAMING_ETHERNET:
        /* Destination and source MAC stay zero; only the EtherType matters. */
        put_u16(out + 12, ethertype);
        break;
    case FRAMING_SLL:
        put_u16(out + 14, ethertype);
        break;
    case FRAMING_SLL2:
        put_u16(out, ethertype);
        break;
    case FRAMING_NONE:
    default:
        break;
    }

    memcpy(out + header_len, packet, packet_len);
    return header_len + packet_len;
}

size_t frame_ipv4(uint8_t *out, size_t capacity, uint8_t protocol,
                  const char *src, const char *dst,
                  const void *payload, size_t payload_len)
{
    size_t total = IPV4_HEADER_LEN + payload_len;
    require_capacity(total, capacity, "IPv4 packet");
    memset(out, 0, IPV4_HEADER_LEN);

    out[0] = 0x45; /* version 4, header length 5 words */
    out[1] = 0;    /* type of service */
    put_u16(out + 2, (uint16_t)total);
    put_u16(out + 4, 0x1234); /* identification */
    put_u16(out + 6, 0);      /* flags and fragment offset */
    out[8] = 64;              /* time to live */
    out[9] = protocol;
    put_u16(out + 10, 0); /* header checksum, which the monitor never reads */

    if (inet_pton(AF_INET, src, out + 12) != 1 ||
        inet_pton(AF_INET, dst, out + 16) != 1) {
        fprintf(stderr, "frames.c: bad IPv4 address '%s' or '%s'\n", src, dst);
        abort();
    }

    if (payload_len > 0)
        memcpy(out + IPV4_HEADER_LEN, payload, payload_len);
    return total;
}

size_t frame_ipv4_tcp(uint8_t *out, size_t capacity, const char *src, const char *dst,
                      uint16_t src_port, uint16_t dst_port,
                      const void *payload, size_t payload_len)
{
    uint8_t segment[2048];
    size_t segment_len = TCP_HEADER_LEN + payload_len;

    require_capacity(segment_len, sizeof(segment), "TCP segment");
    memset(segment, 0, TCP_HEADER_LEN);

    put_u16(segment, src_port);
    put_u16(segment + 2, dst_port);
    put_u16(segment + 4, 0); /* sequence number */
    put_u16(segment + 8, 0); /* acknowledgement number */
    segment[12] = 5 << 4;    /* data offset: 5 words, no options */
    segment[13] = 0x18;      /* PSH, ACK */
    put_u16(segment + 14, 65535); /* window */

    if (payload_len > 0)
        memcpy(segment + TCP_HEADER_LEN, payload, payload_len);

    return frame_ipv4(out, capacity, 6 /* TCP */, src, dst, segment, segment_len);
}

size_t frame_ipv4_udp(uint8_t *out, size_t capacity, const char *src, const char *dst,
                      uint16_t src_port, uint16_t dst_port,
                      const void *payload, size_t payload_len)
{
    uint8_t datagram[2048];
    size_t datagram_len = UDP_HEADER_LEN + payload_len;

    require_capacity(datagram_len, sizeof(datagram), "UDP datagram");
    memset(datagram, 0, UDP_HEADER_LEN);

    put_u16(datagram, src_port);
    put_u16(datagram + 2, dst_port);
    put_u16(datagram + 4, (uint16_t)datagram_len);
    put_u16(datagram + 6, 0); /* checksum, optional over IPv4 */

    if (payload_len > 0)
        memcpy(datagram + UDP_HEADER_LEN, payload, payload_len);

    return frame_ipv4(out, capacity, 17 /* UDP */, src, dst, datagram, datagram_len);
}

size_t frame_ipv4_icmp(uint8_t *out, size_t capacity, const char *src, const char *dst,
                       uint8_t type, uint8_t code)
{
    uint8_t message[8];

    memset(message, 0, sizeof(message));
    message[0] = type;
    message[1] = code;
    put_u16(message + 2, 0);      /* checksum */
    put_u16(message + 4, 0x0001); /* identifier */
    put_u16(message + 6, 0x0001); /* sequence */

    return frame_ipv4(out, capacity, 1 /* ICMP */, src, dst, message, sizeof(message));
}

size_t frame_ipv6(uint8_t *out, size_t capacity, const char *src, const char *dst,
                  uint8_t next_header, const void *payload, size_t payload_len)
{
    size_t total = IPV6_HEADER_LEN + payload_len;
    require_capacity(total, capacity, "IPv6 packet");
    memset(out, 0, IPV6_HEADER_LEN);

    out[0] = 0x60; /* version 6, traffic class zero */
    put_u16(out + 4, (uint16_t)payload_len);
    out[6] = next_header;
    out[7] = 64; /* hop limit */

    if (inet_pton(AF_INET6, src, out + 8) != 1 ||
        inet_pton(AF_INET6, dst, out + 24) != 1) {
        fprintf(stderr, "frames.c: bad IPv6 address '%s' or '%s'\n", src, dst);
        abort();
    }

    if (payload_len > 0)
        memcpy(out + IPV6_HEADER_LEN, payload, payload_len);
    return total;
}

size_t frame_dns_message(uint8_t *out, size_t capacity, uint16_t id,
                         const char *name, bool response)
{
    require_capacity(12, capacity, "DNS header");
    memset(out, 0, 12);

    put_u16(out, id);
    put_u16(out + 2, response ? 0x8180 : 0x0100); /* flags */
    put_u16(out + 4, 1);                          /* one question */
    put_u16(out + 6, response ? 1 : 0);           /* answers */

    size_t offset = 12;

    /* Encode the name as length-prefixed labels: "example.com" becomes
     * 7 'example' 3 'com' 0. */
    const char *label = name;
    while (*label != '\0') {
        const char *dot = strchr(label, '.');
        size_t label_len = (dot != NULL) ? (size_t)(dot - label) : strlen(label);

        require_capacity(offset + 1 + label_len, capacity, "DNS label");
        out[offset++] = (uint8_t)label_len;
        memcpy(out + offset, label, label_len);
        offset += label_len;

        if (dot == NULL)
            break;
        label = dot + 1;
    }

    require_capacity(offset + 5, capacity, "DNS question");
    out[offset++] = 0;         /* root label */
    put_u16(out + offset, 1);  /* type A */
    offset += 2;
    put_u16(out + offset, 1);  /* class IN */
    offset += 2;

    return offset;
}
