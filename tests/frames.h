/*
 * frames.h -- building packets by hand for the tests.
 *
 * The monitor's input is a byte array off a network. The tests supply that
 * byte array directly instead of capturing one, which is what makes them run
 * anywhere: no interface, no root, no traffic, and a malformed packet is as
 * easy to produce as a well-formed one.
 *
 * Every builder writes into the caller's buffer and returns the frame length.
 */

#ifndef FRAMES_H
#define FRAMES_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* How a frame is wrapped before the IP header. Bare IP is what a TUN device
 * delivers and is what the monitor normally sees. */
typedef enum {
    FRAMING_NONE = 0,
    FRAMING_ETHERNET,
    FRAMING_SLL,
    FRAMING_SLL2
} frame_link;

/* Wrap an already-built IP packet in a link-layer header. */
size_t frame_add_link(uint8_t *out, size_t capacity, frame_link framing,
                      uint16_t ethertype, const uint8_t *packet, size_t packet_len);

/* An IPv4 packet with an arbitrary payload after the 20-byte header. */
size_t frame_ipv4(uint8_t *out, size_t capacity, uint8_t protocol,
                  const char *src, const char *dst,
                  const void *payload, size_t payload_len);

size_t frame_ipv4_tcp(uint8_t *out, size_t capacity, const char *src, const char *dst,
                      uint16_t src_port, uint16_t dst_port,
                      const void *payload, size_t payload_len);

size_t frame_ipv4_udp(uint8_t *out, size_t capacity, const char *src, const char *dst,
                      uint16_t src_port, uint16_t dst_port,
                      const void *payload, size_t payload_len);

size_t frame_ipv4_icmp(uint8_t *out, size_t capacity, const char *src, const char *dst,
                       uint8_t type, uint8_t code);

size_t frame_ipv6(uint8_t *out, size_t capacity, const char *src, const char *dst,
                  uint8_t next_header, const void *payload, size_t payload_len);

/* A DNS message carrying one question for `name`. */
size_t frame_dns_message(uint8_t *out, size_t capacity, uint16_t id,
                         const char *name, bool response);

/* Read and write the 16-bit big-endian field at `offset`, for tests that need
 * to corrupt a header after building it. */
uint16_t frame_get_u16(const uint8_t *frame, size_t offset);
void frame_set_u16(uint8_t *frame, size_t offset, uint16_t value);

/* Offsets inside an IPv4 header, for the same reason. */
#define IPV4_OFFSET_IHL 0
#define IPV4_OFFSET_TOTAL_LENGTH 2
#define IPV4_HEADER_LEN 20
#define TCP_HEADER_LEN 20
#define UDP_HEADER_LEN 8
#define IPV6_HEADER_LEN 40

#endif /* FRAMES_H */
