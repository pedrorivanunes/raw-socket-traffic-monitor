/*
 * test_packet.c -- the classifier.
 *
 * Half of these tests are well-formed packets and half are packets that lie:
 * a header claiming a length the frame does not have, an option field pointing
 * past the end, a payload that is not what the port says it is. That split is
 * deliberate. The monitor reads whatever the network hands it, so "what
 * happens when the input is wrong" is the interesting half.
 */

#include "harness.h"

#include <string.h>

#include <linux/if_ether.h>

#include "frames.h"
#include "packet.h"

#define CLIENT_IP "172.31.66.101"
#define REMOTE_IP "93.184.216.34"

/* ------------------------------------------------------------- link layer */

static void link_layer_detects_bare_ipv4(void)
{
    uint8_t frame[128];
    size_t len = frame_ipv4_icmp(frame, sizeof(frame), CLIENT_IP, REMOTE_IP, 8, 0);

    uint16_t ethertype = 0;
    size_t header_len = 999;

    CHECK(packet_parse_link_layer(frame, len, true, &ethertype, &header_len));
    CHECK_INT(ethertype, ETH_P_IP);
    CHECK_INT(header_len, 0);
}

static void link_layer_detects_bare_ipv6(void)
{
    uint8_t frame[128];
    size_t len = frame_ipv6(frame, sizeof(frame), "2001:db8::1", "2001:db8::2", 59, NULL, 0);

    uint16_t ethertype = 0;
    size_t header_len = 999;

    CHECK(packet_parse_link_layer(frame, len, true, &ethertype, &header_len));
    CHECK_INT(ethertype, ETH_P_IPV6);
    CHECK_INT(header_len, 0);
}

static void link_layer_detects_ethernet(void)
{
    uint8_t packet[128];
    uint8_t frame[160];

    size_t packet_len = frame_ipv4_icmp(packet, sizeof(packet), CLIENT_IP, REMOTE_IP, 8, 0);
    size_t len = frame_add_link(frame, sizeof(frame), FRAMING_ETHERNET, ETH_P_IP,
                                packet, packet_len);

    uint16_t ethertype = 0;
    size_t header_len = 999;

    CHECK(packet_parse_link_layer(frame, len, false, &ethertype, &header_len));
    CHECK_INT(ethertype, ETH_P_IP);
    CHECK_INT(header_len, 14);
}

static void link_layer_detects_cooked_v1(void)
{
    uint8_t packet[128];
    uint8_t frame[160];

    size_t packet_len = frame_ipv4_icmp(packet, sizeof(packet), CLIENT_IP, REMOTE_IP, 8, 0);
    size_t len = frame_add_link(frame, sizeof(frame), FRAMING_SLL, ETH_P_IP,
                                packet, packet_len);

    uint16_t ethertype = 0;
    size_t header_len = 999;

    CHECK(packet_parse_link_layer(frame, len, true, &ethertype, &header_len));
    CHECK_INT(ethertype, ETH_P_IP);
    CHECK_INT(header_len, 16);
}

static void link_layer_detects_cooked_v2(void)
{
    uint8_t packet[128];
    uint8_t frame[160];

    size_t packet_len = frame_ipv4_icmp(packet, sizeof(packet), CLIENT_IP, REMOTE_IP, 8, 0);
    size_t len = frame_add_link(frame, sizeof(frame), FRAMING_SLL2, ETH_P_IP,
                                packet, packet_len);

    uint16_t ethertype = 0;
    size_t header_len = 999;

    CHECK(packet_parse_link_layer(frame, len, true, &ethertype, &header_len));
    CHECK_INT(ethertype, ETH_P_IP);
    CHECK_INT(header_len, 20);
}

static void link_layer_rejects_empty_and_unknown(void)
{
    uint8_t frame[8] = { 0 };
    uint16_t ethertype = 0;
    size_t header_len = 0;

    CHECK(!packet_parse_link_layer(frame, 0, true, &ethertype, &header_len));
    CHECK(!packet_parse_link_layer(frame, sizeof(frame), true, &ethertype, &header_len));
}

/* ------------------------------------------------------------ IPv4 basics */

static void decodes_ipv4_tcp(void)
{
    uint8_t frame[256];
    size_t len = frame_ipv4_tcp(frame, sizeof(frame), CLIENT_IP, REMOTE_IP,
                                51000, 80, NULL, 0);

    struct packet pkt;
    CHECK(packet_decode(frame, len, true, &pkt));
    CHECK_INT(pkt.network, NETWORK_IPV4);
    CHECK_STR(pkt.src_ip, CLIENT_IP);
    CHECK_STR(pkt.dst_ip, REMOTE_IP);
    CHECK_INT(pkt.transport, TRANSPORT_TCP);
    CHECK_INT(pkt.src_port, 51000);
    CHECK_INT(pkt.dst_port, 80);
    CHECK_INT(pkt.length, IPV4_HEADER_LEN + TCP_HEADER_LEN);
}

static void decodes_ipv4_udp(void)
{
    const char payload[] = "hello";
    uint8_t frame[256];
    size_t len = frame_ipv4_udp(frame, sizeof(frame), CLIENT_IP, "8.8.8.8",
                                40000, 9999, payload, sizeof(payload) - 1);

    struct packet pkt;
    CHECK(packet_decode(frame, len, true, &pkt));
    CHECK_INT(pkt.transport, TRANSPORT_UDP);
    CHECK_INT(pkt.src_port, 40000);
    CHECK_INT(pkt.dst_port, 9999);
    CHECK_INT(pkt.application, APP_OTHER);
    CHECK_INT(pkt.length, IPV4_HEADER_LEN + UDP_HEADER_LEN + 5);
}

static void decodes_icmp_type_and_code(void)
{
    uint8_t frame[128];
    size_t len = frame_ipv4_icmp(frame, sizeof(frame), CLIENT_IP, REMOTE_IP, 8, 0);

    struct packet pkt;
    CHECK(packet_decode(frame, len, true, &pkt));
    CHECK_INT(pkt.transport, TRANSPORT_ICMP);
    CHECK_STR(pkt.info, "type=8,code=0");
    CHECK_INT(pkt.src_port, 0);
    CHECK_INT(pkt.dst_port, 0);
}

static void decodes_ipv6_at_the_network_layer(void)
{
    uint8_t payload[TCP_HEADER_LEN] = { 0 };
    uint8_t frame[256];
    size_t len = frame_ipv6(frame, sizeof(frame), "2001:db8::1", "2001:db8::2",
                            6, payload, sizeof(payload));

    struct packet pkt;
    CHECK(packet_decode(frame, len, true, &pkt));
    CHECK_INT(pkt.network, NETWORK_IPV6);
    CHECK_STR(pkt.src_ip, "2001:db8::1");
    CHECK_STR(pkt.dst_ip, "2001:db8::2");
    CHECK_INT(pkt.length, IPV6_HEADER_LEN + TCP_HEADER_LEN);
    /* Deliberately not decoded: reaching TCP over IPv6 means walking the
     * extension-header chain first. */
    CHECK_INT(pkt.transport, TRANSPORT_NONE);
}

/* ------------------------------------------------------- malformed input */

static void rejects_truncated_ipv4_header(void)
{
    uint8_t frame[128];
    size_t len = frame_ipv4_icmp(frame, sizeof(frame), CLIENT_IP, REMOTE_IP, 8, 0);
    (void)len;

    struct packet pkt;
    /* Ten bytes in, halfway through the header. */
    CHECK(!packet_decode(frame, 10, true, &pkt));
}

static void rejects_impossible_header_length(void)
{
    uint8_t frame[128];
    size_t len = frame_ipv4_icmp(frame, sizeof(frame), CLIENT_IP, REMOTE_IP, 8, 0);

    struct packet pkt;

    /* Four 32-bit words: smaller than the fixed part of the header. */
    frame[IPV4_OFFSET_IHL] = 0x44;
    CHECK(!packet_decode(frame, len, true, &pkt));

    /* Fifteen words: more header than the frame contains. */
    frame[IPV4_OFFSET_IHL] = 0x4F;
    CHECK(!packet_decode(frame, len, true, &pkt));
}

static void clamps_a_lying_total_length(void)
{
    uint8_t frame[256];
    size_t len = frame_ipv4_udp(frame, sizeof(frame), CLIENT_IP, "8.8.8.8",
                                40000, 9999, NULL, 0);

    struct packet pkt;

    /* A packet claiming 60000 bytes must not add 60000 to anyone's total. */
    frame_set_u16(frame, IPV4_OFFSET_TOTAL_LENGTH, 60000);
    CHECK(packet_decode(frame, len, true, &pkt));
    CHECK_INT(pkt.length, len);

    /* Zero is what segmentation offload leaves behind; fall back to what was
     * actually captured rather than reporting an empty packet. */
    frame_set_u16(frame, IPV4_OFFSET_TOTAL_LENGTH, 0);
    CHECK(packet_decode(frame, len, true, &pkt));
    CHECK_INT(pkt.length, len);
}

static void handles_a_truncated_tcp_header(void)
{
    uint8_t frame[256];
    size_t len = frame_ipv4_tcp(frame, sizeof(frame), CLIENT_IP, REMOTE_IP,
                                51000, 80, NULL, 0);

    struct packet pkt;
    /* The IP header is complete but only four bytes of TCP arrived. */
    CHECK(packet_decode(frame, IPV4_HEADER_LEN + 4, true, &pkt));
    CHECK_INT(pkt.network, NETWORK_IPV4);
    CHECK_INT(pkt.transport, TRANSPORT_OTHER);
    CHECK(len > 0);
}

static void distrusts_a_bad_tcp_data_offset(void)
{
    const char request[] = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    uint8_t frame[256];
    size_t len = frame_ipv4_tcp(frame, sizeof(frame), CLIENT_IP, REMOTE_IP,
                                51000, 80, request, sizeof(request) - 1);
    size_t data_offset_byte = IPV4_HEADER_LEN + 12;

    struct packet pkt;

    /* Four words: below the minimum, so the payload position is not credible
     * and nothing is read from it. The ports are still valid, though. */
    frame[data_offset_byte] = 4 << 4;
    CHECK(packet_decode(frame, len, true, &pkt));
    CHECK_INT(pkt.transport, TRANSPORT_TCP);
    CHECK_INT(pkt.dst_port, 80);
    CHECK_STR(pkt.info, "-");

    /* Fifteen words: the payload would start past the end of the frame. */
    frame[data_offset_byte] = 15 << 4;
    CHECK(packet_decode(frame, len, true, &pkt));
    CHECK_STR(pkt.info, "-");
}

/* -------------------------------------------------------- application layer */

static void detects_applications_by_port(void)
{
    CHECK_INT(packet_detect_application(TRANSPORT_TCP, 51000, 80), APP_HTTP);
    CHECK_INT(packet_detect_application(TRANSPORT_TCP, 8080, 51000), APP_HTTP);
    CHECK_INT(packet_detect_application(TRANSPORT_TCP, 51000, 443), APP_HTTPS);
    CHECK_INT(packet_detect_application(TRANSPORT_UDP, 51000, 53), APP_DNS);
    CHECK_INT(packet_detect_application(TRANSPORT_TCP, 53, 51000), APP_DNS);
    CHECK_INT(packet_detect_application(TRANSPORT_UDP, 68, 67), APP_DHCP);
    CHECK_INT(packet_detect_application(TRANSPORT_UDP, 123, 123), APP_NTP);
    CHECK_INT(packet_detect_application(TRANSPORT_UDP, 40000, 9999), APP_OTHER);

    /* DHCP is UDP only, and only between its two ports. */
    CHECK_INT(packet_detect_application(TRANSPORT_TCP, 68, 67), APP_OTHER);
    CHECK_INT(packet_detect_application(TRANSPORT_UDP, 67, 9999), APP_OTHER);
}

static void extracts_the_http_request_line(void)
{
    const char request[] = "GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
    uint8_t frame[256];
    size_t len = frame_ipv4_tcp(frame, sizeof(frame), CLIENT_IP, REMOTE_IP,
                                51000, 80, request, sizeof(request) - 1);

    struct packet pkt;
    CHECK(packet_decode(frame, len, true, &pkt));
    CHECK_INT(pkt.application, APP_HTTP);
    CHECK_STR(pkt.info, "GET /index.html HTTP/1.1");
}

static void extracts_the_http_status_line(void)
{
    const char response[] = "HTTP/1.1 404 Not Found\r\nServer: nginx\r\n\r\n";
    uint8_t frame[256];
    size_t len = frame_ipv4_tcp(frame, sizeof(frame), REMOTE_IP, CLIENT_IP,
                                80, 51000, response, sizeof(response) - 1);

    struct packet pkt;
    CHECK(packet_decode(frame, len, true, &pkt));
    CHECK_STR(pkt.info, "HTTP/1.1 404 Not Found");
}

/*
 * This is the bug the README used to list as a known limitation: any TCP
 * segment on an HTTP port had its first bytes copied into the summary, so a
 * segment from the middle of a body -- or a TLS record -- filled the CSV with
 * binary noise.
 */
static void ignores_a_payload_that_is_not_http(void)
{
    const uint8_t tls_hello[] = { 0x16, 0x03, 0x01, 0x00, 0x50, 0x01, 0x00, 0x00 };
    uint8_t frame[256];

    struct packet pkt;

    size_t len = frame_ipv4_tcp(frame, sizeof(frame), CLIENT_IP, REMOTE_IP,
                                51000, 80, tls_hello, sizeof(tls_hello));
    CHECK(packet_decode(frame, len, true, &pkt));
    CHECK_INT(pkt.application, APP_HTTP);
    CHECK_STR(pkt.info, "-");

    /* Port 443 is encrypted by definition, so it is labelled honestly and its
     * payload is never read. */
    len = frame_ipv4_tcp(frame, sizeof(frame), CLIENT_IP, REMOTE_IP,
                         51000, 443, tls_hello, sizeof(tls_hello));
    CHECK(packet_decode(frame, len, true, &pkt));
    CHECK_INT(pkt.application, APP_HTTPS);
    CHECK_STR(pkt.info, "-");
}

/* A control character in a header would otherwise reach the CSV as a raw byte;
 * a newline there would split one row into two. */
static void replaces_unprintable_bytes_in_the_summary(void)
{
    const char request[] = "GET /\x01\x02 HTTP/1.1\r\nHost: x\r\n\r\n";
    uint8_t frame[256];
    size_t len = frame_ipv4_tcp(frame, sizeof(frame), CLIENT_IP, REMOTE_IP,
                                51000, 80, request, sizeof(request) - 1);

    struct packet pkt;
    CHECK(packet_decode(frame, len, true, &pkt));
    CHECK_STR(pkt.info, "GET /.. HTTP/1.1");
}

/* A comma is printable, so it survives here and is dealt with by quoting in
 * csv.c instead. */
static void keeps_a_comma_in_the_summary(void)
{
    const char request[] = "GET /a,b HTTP/1.1\r\n\r\n";
    uint8_t frame[256];
    size_t len = frame_ipv4_tcp(frame, sizeof(frame), CLIENT_IP, REMOTE_IP,
                                51000, 80, request, sizeof(request) - 1);

    struct packet pkt;
    CHECK(packet_decode(frame, len, true, &pkt));
    CHECK_STR(pkt.info, "GET /a,b HTTP/1.1");
}

static void extracts_the_dns_question(void)
{
    uint8_t query[256];
    uint8_t frame[512];

    size_t query_len = frame_dns_message(query, sizeof(query), 0x1234, "example.com", false);
    size_t len = frame_ipv4_udp(frame, sizeof(frame), CLIENT_IP, "8.8.8.8",
                                51000, 53, query, query_len);

    struct packet pkt;
    CHECK(packet_decode(frame, len, true, &pkt));
    CHECK_INT(pkt.application, APP_DNS);
    CHECK_STR(pkt.info, "query id=4660 name=example.com");
}

static void marks_a_dns_response_as_such(void)
{
    uint8_t message[256];
    uint8_t frame[512];

    size_t message_len = frame_dns_message(message, sizeof(message), 0x1234,
                                           "example.com", true);
    size_t len = frame_ipv4_udp(frame, sizeof(frame), "8.8.8.8", CLIENT_IP,
                                53, 51000, message, message_len);

    struct packet pkt;
    CHECK(packet_decode(frame, len, true, &pkt));
    CHECK_STR(pkt.info, "response id=4660 name=example.com");
}

/* A 0xC0 label length is a compression pointer. It cannot legitimately appear
 * in a question, so the parser stops rather than following it. */
static void stops_at_a_dns_compression_pointer(void)
{
    uint8_t query[256];
    uint8_t frame[512];

    size_t query_len = frame_dns_message(query, sizeof(query), 0x1234, "example.com", false);
    query[12] = 0xC0; /* where the first label length would be */

    size_t len = frame_ipv4_udp(frame, sizeof(frame), CLIENT_IP, "8.8.8.8",
                                51000, 53, query, query_len);

    struct packet pkt;
    CHECK(packet_decode(frame, len, true, &pkt));
    CHECK_STR(pkt.info, "query id=4660");
}

static void handles_a_dns_message_shorter_than_its_header(void)
{
    const uint8_t stub[] = { 0x12, 0x34, 0x01 };
    uint8_t frame[256];
    size_t len = frame_ipv4_udp(frame, sizeof(frame), CLIENT_IP, "8.8.8.8",
                                51000, 53, stub, sizeof(stub));

    struct packet pkt;
    CHECK(packet_decode(frame, len, true, &pkt));
    CHECK_INT(pkt.application, APP_DNS);
    CHECK_STR(pkt.info, "-");
}

static void extracts_the_dhcp_message_type(void)
{
    uint8_t message[300];
    uint8_t frame[512];

    memset(message, 0, sizeof(message));
    message[240] = 53; /* option: message type */
    message[241] = 1;  /* length */
    message[242] = 3;  /* REQUEST */
    message[243] = 0xFF;

    size_t len = frame_ipv4_udp(frame, sizeof(frame), "0.0.0.0", "255.255.255.255",
                                68, 67, message, 244);

    struct packet pkt;
    CHECK(packet_decode(frame, len, true, &pkt));
    CHECK_INT(pkt.application, APP_DHCP);
    CHECK_STR(pkt.info, "type=REQUEST(3)");
}

static void handles_dhcp_with_no_options(void)
{
    uint8_t message[240];
    uint8_t frame[512];

    memset(message, 0, sizeof(message));
    size_t len = frame_ipv4_udp(frame, sizeof(frame), "0.0.0.0", "255.255.255.255",
                                68, 67, message, sizeof(message));

    struct packet pkt;
    CHECK(packet_decode(frame, len, true, &pkt));
    CHECK_STR(pkt.info, "-");
}

/* An option whose length runs past the end of the message must stop the walk,
 * not let it read beyond the payload. */
static void stops_at_a_dhcp_option_that_overruns(void)
{
    uint8_t message[250];
    uint8_t frame[512];

    memset(message, 0, sizeof(message));
    message[240] = 12;  /* option: host name */
    message[241] = 200; /* a length the message cannot hold */

    size_t len = frame_ipv4_udp(frame, sizeof(frame), "0.0.0.0", "255.255.255.255",
                                68, 67, message, sizeof(message));

    struct packet pkt;
    CHECK(packet_decode(frame, len, true, &pkt));
    CHECK_STR(pkt.info, "-");
}

static void extracts_the_ntp_leap_version_and_mode(void)
{
    const uint8_t ntp[48] = { 0x23 }; /* LI 0, version 4, mode 3 (client) */
    uint8_t frame[256];
    size_t len = frame_ipv4_udp(frame, sizeof(frame), CLIENT_IP, "200.160.7.186",
                                51000, 123, ntp, sizeof(ntp));

    struct packet pkt;
    CHECK(packet_decode(frame, len, true, &pkt));
    CHECK_INT(pkt.application, APP_NTP);
    CHECK_STR(pkt.info, "LI=0,VN=4,Mode=3");
}

void test_packet_suite(void)
{
    RUN(link_layer_detects_bare_ipv4);
    RUN(link_layer_detects_bare_ipv6);
    RUN(link_layer_detects_ethernet);
    RUN(link_layer_detects_cooked_v1);
    RUN(link_layer_detects_cooked_v2);
    RUN(link_layer_rejects_empty_and_unknown);

    RUN(decodes_ipv4_tcp);
    RUN(decodes_ipv4_udp);
    RUN(decodes_icmp_type_and_code);
    RUN(decodes_ipv6_at_the_network_layer);

    RUN(rejects_truncated_ipv4_header);
    RUN(rejects_impossible_header_length);
    RUN(clamps_a_lying_total_length);
    RUN(handles_a_truncated_tcp_header);
    RUN(distrusts_a_bad_tcp_data_offset);

    RUN(detects_applications_by_port);
    RUN(extracts_the_http_request_line);
    RUN(extracts_the_http_status_line);
    RUN(ignores_a_payload_that_is_not_http);
    RUN(replaces_unprintable_bytes_in_the_summary);
    RUN(keeps_a_comma_in_the_summary);
    RUN(extracts_the_dns_question);
    RUN(marks_a_dns_response_as_such);
    RUN(stops_at_a_dns_compression_pointer);
    RUN(handles_a_dns_message_shorter_than_its_header);
    RUN(extracts_the_dhcp_message_type);
    RUN(handles_dhcp_with_no_options);
    RUN(stops_at_a_dhcp_option_that_overruns);
    RUN(extracts_the_ntp_leap_version_and_mode);
}
