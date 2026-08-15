/*
 * test_stats.c -- the counters and the client tree.
 *
 * The interesting property here is direction. A request and its reply are the
 * same conversation, so they have to land in the same flow even though their
 * source and destination are swapped. Most of these tests exist to pin that
 * down, along with what happens to traffic that belongs to no client at all.
 */

#include "harness.h"

#include <stdio.h>
#include <string.h>

#include "packet.h"
#include "stats.h"

#define CLIENT_A "172.31.66.101"
#define CLIENT_B "172.31.66.102"
#define REMOTE "93.184.216.34"

/*
 * One table, shared by every test in this file and cleared before each one.
 * The structure is a few megabytes -- see the sizing note in stats.h -- so it
 * is allocated once by the suite rather than per test, and stats_reset() is
 * what makes each case start from empty.
 */
static struct traffic_stats *stats;

static struct packet make_packet(const char *src, const char *dst,
                                 transport_proto transport,
                                 uint16_t src_port, uint16_t dst_port,
                                 size_t length)
{
    struct packet pkt;
    memset(&pkt, 0, sizeof(pkt));

    pkt.network = NETWORK_IPV4;
    snprintf(pkt.src_ip, sizeof(pkt.src_ip), "%s", src);
    snprintf(pkt.dst_ip, sizeof(pkt.dst_ip), "%s", dst);
    pkt.transport = transport;
    pkt.src_port = src_port;
    pkt.dst_port = dst_port;
    pkt.length = length;
    pkt.application = packet_detect_application(transport, src_port, dst_port);
    snprintf(pkt.info, sizeof(pkt.info), "-");

    return pkt;
}

static void groups_both_directions_into_one_flow(void)
{
    stats_reset(stats);

    struct packet out = make_packet(CLIENT_A, REMOTE, TRANSPORT_TCP, 51000, 80, 100);
    struct packet back = make_packet(REMOTE, CLIENT_A, TRANSPORT_TCP, 80, 51000, 500);

    stats_record(stats, &out);
    stats_record(stats, &back);

    CHECK_INT(stats->client_count, 1);

    const struct client_stats *client = stats_find_client(stats, CLIENT_A);
    CHECK(client != NULL);
    if (client == NULL)
        return;

    const struct remote_stats *remote = stats_find_remote(client, REMOTE);
    CHECK(remote != NULL);
    if (remote == NULL)
        return;

    CHECK_INT(remote->packets, 2);
    CHECK_INT(remote->bytes, 600);
    CHECK_INT(remote->tcp, 2);

    /* One conversation, not two mirrored ones. */
    CHECK_INT(remote->flow_count, 1);
    CHECK_INT(remote->flows[0].local_port, 51000);
    CHECK_INT(remote->flows[0].remote_port, 80);
    CHECK_INT(remote->flows[0].packets, 2);
    CHECK_INT(remote->flows[0].bytes, 600);
}

static void counts_separate_ports_as_separate_flows(void)
{
    stats_reset(stats);

    struct packet first = make_packet(CLIENT_A, REMOTE, TRANSPORT_TCP, 51000, 80, 100);
    struct packet second = make_packet(CLIENT_A, REMOTE, TRANSPORT_TCP, 51001, 80, 100);
    struct packet third = make_packet(CLIENT_A, REMOTE, TRANSPORT_UDP, 51000, 80, 100);

    stats_record(stats, &first);
    stats_record(stats, &second);
    stats_record(stats, &third);

    const struct client_stats *client = stats_find_client(stats, CLIENT_A);
    CHECK(client != NULL);
    if (client == NULL)
        return;

    const struct remote_stats *remote = stats_find_remote(client, REMOTE);
    CHECK(remote != NULL);
    if (remote == NULL)
        return;

    /* Same ports but a different transport is still a different flow. */
    CHECK_INT(remote->flow_count, 3);
    CHECK_INT(remote->packets, 3);
}

static void keeps_clients_and_remotes_apart(void)
{
    stats_reset(stats);

    struct packet a = make_packet(CLIENT_A, REMOTE, TRANSPORT_TCP, 51000, 80, 100);
    struct packet b = make_packet(CLIENT_B, REMOTE, TRANSPORT_TCP, 51000, 80, 100);
    struct packet other = make_packet(CLIENT_A, "1.1.1.1", TRANSPORT_UDP, 51000, 53, 60);

    stats_record(stats, &a);
    stats_record(stats, &b);
    stats_record(stats, &other);

    CHECK_INT(stats->client_count, 2);

    const struct client_stats *client_a = stats_find_client(stats, CLIENT_A);
    CHECK(client_a != NULL);
    if (client_a != NULL)
        CHECK_INT(client_a->remote_count, 2);

    const struct client_stats *client_b = stats_find_client(stats, CLIENT_B);
    CHECK(client_b != NULL);
    if (client_b != NULL)
        CHECK_INT(client_b->remote_count, 1);
}

/*
 * Traffic with no client end, or with two, cannot be attributed to one client.
 * It still counts at the layer level -- it crossed the interface -- but it does
 * not enter the tree.
 */
static void ignores_traffic_with_no_single_client_end(void)
{
    stats_reset(stats);

    struct packet remote_to_remote = make_packet("8.8.8.8", REMOTE, TRANSPORT_TCP, 1234, 80, 100);
    struct packet client_to_client = make_packet(CLIENT_A, CLIENT_B, TRANSPORT_TCP, 1234, 80, 100);

    stats_record(stats, &remote_to_remote);
    stats_record(stats, &client_to_client);

    CHECK_INT(stats->client_count, 0);
    CHECK_INT(stats->transport.tcp, 2);
    CHECK_INT(stats->network.ipv4, 2);
}

static void records_icmp_without_creating_a_flow(void)
{
    stats_reset(stats);

    struct packet ping = make_packet(CLIENT_A, REMOTE, TRANSPORT_ICMP, 0, 0, 84);
    stats_record(stats, &ping);

    const struct client_stats *client = stats_find_client(stats, CLIENT_A);
    CHECK(client != NULL);
    if (client == NULL)
        return;

    const struct remote_stats *remote = stats_find_remote(client, REMOTE);
    CHECK(remote != NULL);
    if (remote == NULL)
        return;

    CHECK_INT(remote->icmp, 1);
    CHECK_INT(remote->packets, 1);
    CHECK_INT(remote->bytes, 84);
    /* ICMP has no ports, so there is no flow to open. */
    CHECK_INT(remote->flow_count, 0);
}

/* The four network-layer counters are meant to partition the traffic: an ICMP
 * packet lands in exactly one of them. */
static void network_counters_do_not_overlap(void)
{
    stats_reset(stats);

    struct packet tcp = make_packet(CLIENT_A, REMOTE, TRANSPORT_TCP, 51000, 80, 100);
    struct packet ping = make_packet(CLIENT_A, REMOTE, TRANSPORT_ICMP, 0, 0, 84);

    struct packet v6;
    memset(&v6, 0, sizeof(v6));
    v6.network = NETWORK_IPV6;
    snprintf(v6.src_ip, sizeof(v6.src_ip), "2001:db8::1");
    snprintf(v6.dst_ip, sizeof(v6.dst_ip), "2001:db8::2");

    stats_record(stats, &tcp);
    stats_record(stats, &ping);
    stats_record(stats, &v6);

    CHECK_INT(stats->network.ipv4, 1);
    CHECK_INT(stats->network.icmp, 1);
    CHECK_INT(stats->network.ipv6, 1);
    CHECK_INT(stats->network.other, 0);

    /* ICMP is not a transport-layer protocol here, so it is not counted twice. */
    CHECK_INT(stats->transport.tcp, 1);
    CHECK_INT(stats->transport.udp, 0);
    CHECK_INT(stats->transport.other, 0);
}

static void counts_applications_by_protocol(void)
{
    stats_reset(stats);

    struct packet http = make_packet(CLIENT_A, REMOTE, TRANSPORT_TCP, 51000, 80, 100);
    struct packet https = make_packet(CLIENT_A, REMOTE, TRANSPORT_TCP, 51001, 443, 100);
    struct packet dns = make_packet(CLIENT_A, "8.8.8.8", TRANSPORT_UDP, 51000, 53, 60);
    struct packet ntp = make_packet(CLIENT_A, "200.160.7.186", TRANSPORT_UDP, 51000, 123, 76);
    struct packet ping = make_packet(CLIENT_A, REMOTE, TRANSPORT_ICMP, 0, 0, 84);

    stats_record(stats, &http);
    stats_record(stats, &https);
    stats_record(stats, &dns);
    stats_record(stats, &ntp);
    stats_record(stats, &ping);

    CHECK_INT(stats->application.http, 1);
    CHECK_INT(stats->application.https, 1);
    CHECK_INT(stats->application.dns, 1);
    CHECK_INT(stats->application.ntp, 1);
    /* ICMP carries no application protocol, so it is not in these buckets. */
    CHECK_INT(stats->application.other, 0);
}

/* The tables are fixed-size. When one fills up the packets are dropped, and
 * the point of this test is that the drop is counted rather than silent. */
static void reports_dropped_packets_when_a_table_fills(void)
{
    stats_reset(stats);

    for (int i = 0; i < STATS_MAX_FLOWS + 5; i++) {
        struct packet pkt = make_packet(CLIENT_A, REMOTE, TRANSPORT_TCP,
                                        (uint16_t)(40000 + i), 80, 100);
        stats_record(stats, &pkt);
    }

    const struct client_stats *client = stats_find_client(stats, CLIENT_A);
    CHECK(client != NULL);
    if (client == NULL)
        return;

    const struct remote_stats *remote = stats_find_remote(client, REMOTE);
    CHECK(remote != NULL);
    if (remote == NULL)
        return;

    CHECK_INT(remote->flow_count, STATS_MAX_FLOWS);
    CHECK_INT(stats->dropped.flows, 5);
    /* The packets themselves still counted at the remote level. */
    CHECK_INT(remote->packets, STATS_MAX_FLOWS + 5);
}

static void honours_a_custom_client_subnet(void)
{
    stats_reset(stats);
    stats_set_client_prefix(stats, "10.8.0.");

    CHECK(stats_is_client(stats, "10.8.0.7"));
    CHECK(!stats_is_client(stats, CLIENT_A));

    struct packet pkt = make_packet("10.8.0.7", REMOTE, TRANSPORT_TCP, 51000, 80, 100);
    stats_record(stats, &pkt);

    CHECK_INT(stats->client_count, 1);
    CHECK(stats_find_client(stats, "10.8.0.7") != NULL);
}

static void uses_the_tunnel_subnet_by_default(void)
{
    stats_reset(stats);

    CHECK(stats_is_client(stats, CLIENT_A));
    CHECK(stats_is_client(stats, CLIENT_B));
    CHECK(!stats_is_client(stats, REMOTE));
    /* A near miss must not match: the prefix ends with a dot for this reason. */
    CHECK(!stats_is_client(stats, "172.31.660.1"));
}

void test_stats_suite(void)
{
    stats = stats_create();
    if (stats == NULL) {
        harness_begin("test_stats_suite");
        harness_fail(__FILE__, __LINE__, "could not allocate the statistics table");
        return;
    }

    RUN(groups_both_directions_into_one_flow);
    RUN(counts_separate_ports_as_separate_flows);
    RUN(keeps_clients_and_remotes_apart);
    RUN(ignores_traffic_with_no_single_client_end);
    RUN(records_icmp_without_creating_a_flow);
    RUN(network_counters_do_not_overlap);
    RUN(counts_applications_by_protocol);
    RUN(reports_dropped_packets_when_a_table_fills);
    RUN(honours_a_custom_client_subnet);
    RUN(uses_the_tunnel_subnet_by_default);

    stats_destroy(stats);
    stats = NULL;
}
