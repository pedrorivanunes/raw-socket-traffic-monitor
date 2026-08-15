/*
 * packet.c -- the classifier.
 *
 * Two rules run through this file.
 *
 * First, nothing is read without checking that the bytes are there. Every
 * header access is preceded by a length test against what was actually
 * captured, because the input is attacker-controlled: anyone on the tunnel can
 * send a packet whose header claims a size the packet does not have.
 *
 * Second, headers are copied into a local struct before being read, instead of
 * casting the buffer to `struct iphdr *` and dereferencing it in place. A cast
 * like that is undefined behaviour: after a 14-byte Ethernet header the IP
 * source address lands on offset 26, so a 4-byte load happens on a 2-byte
 * boundary. x86 forgives it, other architectures fault, and UBSan reports it
 * either way. The memcpy costs a few dozen bytes and makes the problem go away.
 */

#define _DEFAULT_SOURCE

#include "packet.h"

#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include <linux/if_ether.h> /* ETH_P_IP, ETH_P_IPV6, struct ethhdr */

/* The DNS header, which no system header provides in a usable form. */
struct dns_header {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
};

#define DNS_HEADER_LEN 12u

/* A DHCP message carries 236 bytes of fixed fields plus a 4-byte magic cookie
 * before the options begin. */
#define DHCP_OPTIONS_OFFSET 240u

/* ---------------------------------------------------------------- helpers */

static uint16_t read_u16be(const uint8_t *p)
{
    return (uint16_t)((uint16_t)p[0] << 8 | (uint16_t)p[1]);
}

/*
 * Force a string down to printable ASCII.
 *
 * This is not cosmetic. The summary is built from payload bytes the program
 * does not control, and it ends up in a CSV: a stray comma splits a column, a
 * stray newline splits a row, and a TLS handshake is binary from the first
 * byte. Quoting in csv.c handles the separator; this handles the rest, so the
 * file stays readable no matter what arrives on the wire.
 */
static void sanitize(char *s)
{
    for (; *s != '\0'; s++) {
        unsigned char c = (unsigned char)*s;
        if (c < 0x20 || c > 0x7E)
            *s = '.';
    }
}

static void set_info(struct packet *out, const char *text)
{
    snprintf(out->info, sizeof(out->info), "%s", text);
}

/* ------------------------------------------------------------ link layer */

bool packet_parse_link_layer(const uint8_t *frame, size_t len,
                             bool tun_interface,
                             uint16_t *ethertype, size_t *header_len)
{
    if (frame == NULL || ethertype == NULL || header_len == NULL || len < 1)
        return false;

    /* A TUN device has no link layer: the first nibble is the IP version. This
     * is checked first because it is the common case here, and because an
     * Ethernet header never starts with 0x4n or 0x6n in practice -- that would
     * be a multicast MAC in an unassigned OUI. */
    uint8_t version = frame[0] >> 4;
    if (version == 4) {
        *ethertype = ETH_P_IP;
        *header_len = 0;
        return true;
    }
    if (version == 6) {
        *ethertype = ETH_P_IPV6;
        *header_len = 0;
        return true;
    }

    if (!tun_interface) {
        if (len < sizeof(struct ethhdr))
            return false;
        *ethertype = read_u16be(frame + offsetof(struct ethhdr, h_proto));
        *header_len = sizeof(struct ethhdr);
        return true;
    }

    /* Linux "cooked" capture headers, which appear when the capture is not
     * bound to a single Ethernet device. v1 is 16 bytes with the protocol at
     * offset 14; v2 is 20 bytes with the protocol first. */
    if (len >= 16) {
        uint16_t proto = read_u16be(frame + 14);
        if (proto == ETH_P_IP || proto == ETH_P_IPV6) {
            *ethertype = proto;
            *header_len = 16;
            return true;
        }
    }
    if (len >= 20) {
        uint16_t proto = read_u16be(frame);
        if (proto == ETH_P_IP || proto == ETH_P_IPV6) {
            *ethertype = proto;
            *header_len = 20;
            return true;
        }
    }

    /* Last resort: if an IP header appears where SLL v1 would put one, trust
     * it. This is a heuristic and it is the only guess in this function. */
    if (len > 16) {
        version = frame[16] >> 4;
        if (version == 4) {
            *ethertype = ETH_P_IP;
            *header_len = 16;
            return true;
        }
        if (version == 6) {
            *ethertype = ETH_P_IPV6;
            *header_len = 16;
            return true;
        }
    }

    return false;
}

/* ------------------------------------------------------- application layer */

app_proto packet_detect_application(transport_proto transport,
                                    uint16_t src_port, uint16_t dst_port)
{
    if (transport == TRANSPORT_TCP) {
        if (src_port == 443 || dst_port == 443)
            return APP_HTTPS;
        if (src_port == 80 || dst_port == 80 || src_port == 8080 || dst_port == 8080)
            return APP_HTTP;
    }
    if (transport == TRANSPORT_TCP || transport == TRANSPORT_UDP) {
        if (src_port == 53 || dst_port == 53 || src_port == 5353 || dst_port == 5353)
            return APP_DNS;
    }
    if (transport == TRANSPORT_UDP) {
        if ((src_port == 67 && dst_port == 68) || (src_port == 68 && dst_port == 67))
            return APP_DHCP;
        if (src_port == 123 || dst_port == 123)
            return APP_NTP;
    }
    return APP_OTHER;
}

/*
 * Only treat a payload as HTTP when it starts like HTTP.
 *
 * A TCP stream on port 80 is not HTTP in every packet: a segment from the
 * middle of a body starts with arbitrary bytes. Copying those into the summary
 * is what used to fill the CSV with noise. Checking for a method or a status
 * line costs one comparison and means the summary is either a real request
 * line or nothing at all.
 */
static bool looks_like_http(const uint8_t *payload, size_t len)
{
    static const char *const starts[] = {
        "GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS ",
        "PATCH ", "TRACE ", "CONNECT ", "HTTP/",
    };

    for (size_t i = 0; i < sizeof(starts) / sizeof(starts[0]); i++) {
        size_t n = strlen(starts[i]);
        if (len >= n && memcmp(payload, starts[i], n) == 0)
            return true;
    }
    return false;
}

/* The request or status line, which is the useful half of an HTTP header. */
static void build_http_info(const uint8_t *payload, size_t len, struct packet *out)
{
    if (!looks_like_http(payload, len)) {
        set_info(out, "-");
        return;
    }

    size_t max = len;
    if (max > sizeof(out->info) - 1)
        max = sizeof(out->info) - 1;

    size_t i = 0;
    while (i < max && payload[i] != '\r' && payload[i] != '\n') {
        out->info[i] = (char)payload[i];
        i++;
    }
    out->info[i] = '\0';
}

/*
 * The question section of a DNS message.
 *
 * Only the question is read, and that is a deliberate limit rather than a
 * missing feature: the question is the first section, so its name is never
 * compressed -- DNS name compression can only point backwards, and there is
 * nothing behind it to point at. Reading answer records would mean following
 * 0xC0 pointers, which this does not do.
 */
static void build_dns_info(const uint8_t *payload, size_t len, struct packet *out)
{
    if (len < DNS_HEADER_LEN) {
        set_info(out, "-");
        return;
    }

    struct dns_header header;
    memcpy(&header, payload, sizeof(header));

    uint16_t id = ntohs(header.id);
    uint16_t flags = ntohs(header.flags);
    uint16_t questions = ntohs(header.qdcount);
    const char *kind = (flags & 0x8000) ? "response" : "query";

    char name[128];
    size_t name_len = 0;
    name[0] = '\0';

    size_t offset = DNS_HEADER_LEN;
    while (questions > 0 && offset < len) {
        uint8_t label_len = payload[offset];

        if (label_len == 0) /* root label: the name ends here */
            break;
        if ((label_len & 0xC0) != 0) /* a pointer, or a reserved form */
            break;

        offset++;
        if (offset + label_len > len)
            break;

        if (name_len > 0 && name_len < sizeof(name) - 1)
            name[name_len++] = '.';
        for (uint8_t i = 0; i < label_len && name_len < sizeof(name) - 1; i++)
            name[name_len++] = (char)payload[offset + i];

        offset += label_len;
    }
    name[name_len] = '\0';

    if (name[0] == '\0')
        snprintf(out->info, sizeof(out->info), "%s id=%u", kind, id);
    else
        snprintf(out->info, sizeof(out->info), "%s id=%u name=%s", kind, id, name);
}

/* DHCP option 53 carries the message type, which is the one field worth
 * showing; the rest of the message is addresses the monitor already has. */
static void build_dhcp_info(const uint8_t *payload, size_t len, struct packet *out)
{
    static const char *const names[] = {
        NULL, "DISCOVER", "OFFER", "REQUEST", "DECLINE",
        "ACK", "NAK", "RELEASE", "INFORM",
    };

    if (len < DHCP_OPTIONS_OFFSET) {
        set_info(out, "-");
        return;
    }

    uint8_t message_type = 0;
    size_t offset = DHCP_OPTIONS_OFFSET;
    while (offset + 2 <= len) {
        uint8_t option = payload[offset];

        if (option == 0xFF) /* end option */
            break;
        if (option == 0x00) { /* padding */
            offset++;
            continue;
        }

        uint8_t option_len = payload[offset + 1];
        if (offset + 2 + option_len > len)
            break;
        if (option == 53 && option_len >= 1) {
            message_type = payload[offset + 2];
            break;
        }
        offset += 2u + option_len;
    }

    if (message_type == 0) {
        set_info(out, "-");
        return;
    }

    const char *name = "unknown";
    if (message_type < sizeof(names) / sizeof(names[0]) && names[message_type] != NULL)
        name = names[message_type];
    snprintf(out->info, sizeof(out->info), "type=%s(%u)", name, message_type);
}

/* The first NTP byte packs leap indicator, version and mode. */
static void build_ntp_info(const uint8_t *payload, size_t len, struct packet *out)
{
    if (len < 1) {
        set_info(out, "-");
        return;
    }
    uint8_t first = payload[0];
    snprintf(out->info, sizeof(out->info), "LI=%u,VN=%u,Mode=%u",
             (first >> 6) & 0x3u, (first >> 3) & 0x7u, first & 0x7u);
}

static void build_app_info(const uint8_t *payload, size_t len, struct packet *out)
{
    switch (out->application) {
    case APP_HTTP:
        build_http_info(payload, len, out);
        break;
    case APP_DNS:
        build_dns_info(payload, len, out);
        break;
    case APP_DHCP:
        build_dhcp_info(payload, len, out);
        break;
    case APP_NTP:
        build_ntp_info(payload, len, out);
        break;
    /* HTTPS is encrypted; there is nothing to read, and pretending otherwise
     * is how binary noise got into the CSV in the first place. */
    case APP_HTTPS:
    default:
        set_info(out, "-");
        break;
    }
}

/* --------------------------------------------------------- transport layer */

static void decode_transport(const uint8_t *frame, size_t len, size_t offset,
                             uint8_t protocol, struct packet *out)
{
    size_t available = len - offset;

    if (protocol == IPPROTO_TCP && available >= sizeof(struct tcphdr)) {
        struct tcphdr tcp;
        memcpy(&tcp, frame + offset, sizeof(tcp));

        out->transport = TRANSPORT_TCP;
        out->src_port = ntohs(tcp.source);
        out->dst_port = ntohs(tcp.dest);
        out->application = packet_detect_application(TRANSPORT_TCP, out->src_port, out->dst_port);

        /* The data offset is in 32-bit words and a valid header is at least
         * five of them; a smaller value means a malformed packet rather than a
         * short header, so the payload is not trusted. */
        size_t header_len = (size_t)tcp.doff * 4u;
        if (header_len < sizeof(struct tcphdr) || offset + header_len > len) {
            set_info(out, "-");
            return;
        }

        size_t payload_offset = offset + header_len;
        build_app_info(frame + payload_offset, len - payload_offset, out);
        return;
    }

    if (protocol == IPPROTO_UDP && available >= sizeof(struct udphdr)) {
        struct udphdr udp;
        memcpy(&udp, frame + offset, sizeof(udp));

        out->transport = TRANSPORT_UDP;
        out->src_port = ntohs(udp.source);
        out->dst_port = ntohs(udp.dest);
        out->application = packet_detect_application(TRANSPORT_UDP, out->src_port, out->dst_port);

        size_t payload_offset = offset + sizeof(struct udphdr);
        build_app_info(frame + payload_offset, len - payload_offset, out);
        return;
    }

    if (protocol == IPPROTO_ICMP) {
        out->transport = TRANSPORT_ICMP;
        if (available >= sizeof(struct icmphdr)) {
            struct icmphdr icmp;
            memcpy(&icmp, frame + offset, sizeof(icmp));
            snprintf(out->info, sizeof(out->info), "type=%u,code=%u", icmp.type, icmp.code);
        }
        return;
    }

    out->transport = TRANSPORT_OTHER;
}

/* ----------------------------------------------------------- network layer */

static bool decode_ipv4(const uint8_t *frame, size_t len, size_t offset, struct packet *out)
{
    if (len < offset + sizeof(struct iphdr))
        return false;

    struct iphdr ip;
    memcpy(&ip, frame + offset, sizeof(ip));

    size_t header_len = (size_t)ip.ihl * 4u;
    if (header_len < sizeof(struct iphdr) || len < offset + header_len)
        return false;

    out->network = NETWORK_IPV4;
    out->ip_protocol = ip.protocol;

    struct in_addr src = { ip.saddr };
    struct in_addr dst = { ip.daddr };
    inet_ntop(AF_INET, &src, out->src_ip, sizeof(out->src_ip));
    inet_ntop(AF_INET, &dst, out->dst_ip, sizeof(out->dst_ip));

    /* Believe the header only as far as the capture backs it up. A packet
     * claiming 65535 bytes must not add 65535 to a client's byte total. A zero
     * length means the sender offloaded segmentation to the NIC. */
    size_t captured = len - offset;
    size_t claimed = ntohs(ip.tot_len);
    out->length = (claimed == 0 || claimed > captured) ? captured : claimed;

    decode_transport(frame, len, offset + header_len, ip.protocol, out);
    return true;
}

static bool decode_ipv6(const uint8_t *frame, size_t len, size_t offset, struct packet *out)
{
    if (len < offset + sizeof(struct ip6_hdr))
        return false;

    struct ip6_hdr ip6;
    memcpy(&ip6, frame + offset, sizeof(ip6));

    out->network = NETWORK_IPV6;
    out->ip_protocol = ip6.ip6_ctlun.ip6_un1.ip6_un1_nxt;
    inet_ntop(AF_INET6, &ip6.ip6_src, out->src_ip, sizeof(out->src_ip));
    inet_ntop(AF_INET6, &ip6.ip6_dst, out->dst_ip, sizeof(out->dst_ip));

    size_t captured = len - offset;
    size_t claimed = (size_t)ntohs(ip6.ip6_ctlun.ip6_un1.ip6_un1_plen) + sizeof(struct ip6_hdr);
    out->length = (claimed > captured) ? captured : claimed;

    /* IPv6 stops at the network layer. Going further means walking the
     * extension-header chain before reaching TCP or UDP, and the lab this was
     * built for carried no IPv6 traffic to test that against. */
    return true;
}

/* ------------------------------------------------------------------ public */

bool packet_decode(const uint8_t *frame, size_t len, bool tun_interface,
                   struct packet *out)
{
    if (frame == NULL || out == NULL)
        return false;

    memset(out, 0, sizeof(*out));
    set_info(out, "-");
    snprintf(out->src_ip, sizeof(out->src_ip), "-");
    snprintf(out->dst_ip, sizeof(out->dst_ip), "-");

    uint16_t ethertype = 0;
    size_t link_len = 0;
    if (!packet_parse_link_layer(frame, len, tun_interface, &ethertype, &link_len))
        return false;

    bool decoded;
    if (ethertype == ETH_P_IP) {
        decoded = decode_ipv4(frame, len, link_len, out);
    } else if (ethertype == ETH_P_IPV6) {
        decoded = decode_ipv6(frame, len, link_len, out);
    } else {
        out->network = NETWORK_OTHER;
        out->length = len;
        decoded = true;
    }

    if (!decoded) {
        memset(out, 0, sizeof(*out));
        return false;
    }

    /* One place, so no summary can reach the CSV unsanitized. */
    sanitize(out->info);
    if (out->info[0] == '\0')
        set_info(out, "-");
    return true;
}

const char *network_proto_name(network_proto proto)
{
    switch (proto) {
    case NETWORK_IPV4: return "IPv4";
    case NETWORK_IPV6: return "IPv6";
    case NETWORK_OTHER: return "other";
    case NETWORK_NONE:
    default: return "none";
    }
}

const char *transport_proto_name(transport_proto proto)
{
    switch (proto) {
    case TRANSPORT_TCP: return "TCP";
    case TRANSPORT_UDP: return "UDP";
    case TRANSPORT_ICMP: return "ICMP";
    case TRANSPORT_OTHER: return "other";
    case TRANSPORT_NONE:
    default: return "none";
    }
}

const char *app_proto_name(app_proto proto)
{
    switch (proto) {
    case APP_HTTP: return "HTTP";
    case APP_HTTPS: return "HTTPS";
    case APP_DNS: return "DNS";
    case APP_DHCP: return "DHCP";
    case APP_NTP: return "NTP";
    case APP_OTHER: return "other";
    case APP_NONE:
    default: return "none";
    }
}
