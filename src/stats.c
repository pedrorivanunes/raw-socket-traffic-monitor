/*
 * stats.c -- counters and the client -> remote -> flow tree.
 *
 * The tree is built from the direction of each packet. A packet with one end
 * inside the tunnel subnet and the other end outside it belongs to that
 * client; the ports are then recorded from the client's point of view, so a
 * request and its reply land in the same flow instead of two mirrored ones.
 */

#include "stats.h"

#include <stdlib.h>
#include <string.h>

void stats_reset(struct traffic_stats *stats)
{
    memset(stats, 0, sizeof(*stats));
    snprintf(stats->client_prefix, sizeof(stats->client_prefix), "%s",
             STATS_DEFAULT_CLIENT_PREFIX);
}

struct traffic_stats *stats_create(void)
{
    /* calloc, not a local: see the note on the table sizes in stats.h. */
    struct traffic_stats *stats = calloc(1, sizeof(*stats));
    if (stats == NULL)
        return NULL;

    stats_reset(stats);
    return stats;
}

void stats_destroy(struct traffic_stats *stats)
{
    free(stats);
}

void stats_set_client_prefix(struct traffic_stats *stats, const char *prefix)
{
    snprintf(stats->client_prefix, sizeof(stats->client_prefix), "%s", prefix);
}

bool stats_is_client(const struct traffic_stats *stats, const char *ip)
{
    size_t n = strlen(stats->client_prefix);
    if (n == 0)
        return false;
    return strncmp(ip, stats->client_prefix, n) == 0;
}

const struct client_stats *stats_find_client(const struct traffic_stats *stats,
                                             const char *ip)
{
    for (int i = 0; i < stats->client_count; i++) {
        if (strcmp(stats->clients[i].ip, ip) == 0)
            return &stats->clients[i];
    }
    return NULL;
}

const struct remote_stats *stats_find_remote(const struct client_stats *client,
                                             const char *ip)
{
    for (int i = 0; i < client->remote_count; i++) {
        if (strcmp(client->remotes[i].ip, ip) == 0)
            return &client->remotes[i];
    }
    return NULL;
}

static struct client_stats *find_or_add_client(struct traffic_stats *stats,
                                               const char *ip)
{
    for (int i = 0; i < stats->client_count; i++) {
        if (strcmp(stats->clients[i].ip, ip) == 0)
            return &stats->clients[i];
    }
    if (stats->client_count >= STATS_MAX_CLIENTS) {
        stats->dropped.clients++;
        return NULL;
    }

    struct client_stats *client = &stats->clients[stats->client_count++];
    memset(client, 0, sizeof(*client));
    snprintf(client->ip, sizeof(client->ip), "%s", ip);
    return client;
}

static struct remote_stats *find_or_add_remote(struct traffic_stats *stats,
                                               struct client_stats *client,
                                               const char *ip)
{
    for (int i = 0; i < client->remote_count; i++) {
        if (strcmp(client->remotes[i].ip, ip) == 0)
            return &client->remotes[i];
    }
    if (client->remote_count >= STATS_MAX_REMOTES) {
        stats->dropped.remotes++;
        return NULL;
    }

    struct remote_stats *remote = &client->remotes[client->remote_count++];
    memset(remote, 0, sizeof(*remote));
    snprintf(remote->ip, sizeof(remote->ip), "%s", ip);
    return remote;
}

static struct flow_stats *find_or_add_flow(struct traffic_stats *stats,
                                           struct remote_stats *remote,
                                           transport_proto transport,
                                           uint16_t local_port, uint16_t remote_port)
{
    for (int i = 0; i < remote->flow_count; i++) {
        struct flow_stats *flow = &remote->flows[i];
        if (flow->transport == transport && flow->local_port == local_port &&
            flow->remote_port == remote_port)
            return flow;
    }
    if (remote->flow_count >= STATS_MAX_FLOWS) {
        stats->dropped.flows++;
        return NULL;
    }

    struct flow_stats *flow = &remote->flows[remote->flow_count++];
    memset(flow, 0, sizeof(*flow));
    flow->transport = transport;
    flow->local_port = local_port;
    flow->remote_port = remote_port;
    return flow;
}

static void record_layer_counters(struct traffic_stats *stats, const struct packet *pkt)
{
    switch (pkt->network) {
    case NETWORK_IPV4:
        /* ICMP is pulled out of the IPv4 bucket so the four counters partition
         * the traffic instead of overlapping. */
        if (pkt->transport == TRANSPORT_ICMP)
            stats->network.icmp++;
        else
            stats->network.ipv4++;
        break;
    case NETWORK_IPV6:
        stats->network.ipv6++;
        break;
    default:
        stats->network.other++;
        break;
    }

    switch (pkt->transport) {
    case TRANSPORT_TCP: stats->transport.tcp++; break;
    case TRANSPORT_UDP: stats->transport.udp++; break;
    case TRANSPORT_ICMP: break; /* already counted at the network layer */
    case TRANSPORT_OTHER: stats->transport.other++; break;
    case TRANSPORT_NONE:
    default: break;
    }

    /* Only TCP and UDP carry an application protocol worth counting. */
    if (pkt->transport != TRANSPORT_TCP && pkt->transport != TRANSPORT_UDP)
        return;

    switch (pkt->application) {
    case APP_HTTP: stats->application.http++; break;
    case APP_HTTPS: stats->application.https++; break;
    case APP_DNS: stats->application.dns++; break;
    case APP_DHCP: stats->application.dhcp++; break;
    case APP_NTP: stats->application.ntp++; break;
    default: stats->application.other++; break;
    }
}

static void record_client_tree(struct traffic_stats *stats, const struct packet *pkt)
{
    const char *client_ip;
    const char *remote_ip;
    uint16_t local_port;
    uint16_t remote_port;

    bool src_is_client = stats_is_client(stats, pkt->src_ip);
    bool dst_is_client = stats_is_client(stats, pkt->dst_ip);

    /* Exactly one end must be a client. Traffic between two clients, or
     * between two remotes, is not attributable to a single client and is
     * deliberately left out of the tree. */
    if (src_is_client && !dst_is_client) {
        client_ip = pkt->src_ip;
        remote_ip = pkt->dst_ip;
        local_port = pkt->src_port;
        remote_port = pkt->dst_port;
    } else if (dst_is_client && !src_is_client) {
        client_ip = pkt->dst_ip;
        remote_ip = pkt->src_ip;
        local_port = pkt->dst_port;
        remote_port = pkt->src_port;
    } else {
        return;
    }

    struct client_stats *client = find_or_add_client(stats, client_ip);
    if (client == NULL)
        return;

    struct remote_stats *remote = find_or_add_remote(stats, client, remote_ip);
    if (remote == NULL)
        return;

    remote->packets++;
    remote->bytes += pkt->length;
    switch (pkt->transport) {
    case TRANSPORT_TCP: remote->tcp++; break;
    case TRANSPORT_UDP: remote->udp++; break;
    case TRANSPORT_ICMP: remote->icmp++; break;
    default: break;
    }

    /* ICMP has no ports, so it has no flow to attach to. */
    if (pkt->transport != TRANSPORT_TCP && pkt->transport != TRANSPORT_UDP)
        return;

    struct flow_stats *flow =
        find_or_add_flow(stats, remote, pkt->transport, local_port, remote_port);
    if (flow == NULL)
        return;

    flow->packets++;
    flow->bytes += pkt->length;
}

void stats_record(struct traffic_stats *stats, const struct packet *pkt)
{
    record_layer_counters(stats, pkt);
    record_client_tree(stats, pkt);
}

void stats_record_undecodable(struct traffic_stats *stats)
{
    stats->network.other++;
}

void stats_print(const struct traffic_stats *stats, FILE *out)
{
    fprintf(out, "\n=== Network traffic monitor (raw sockets) ===\n");
    fprintf(out, "Network layer:\n");
    fprintf(out, "  IPv4 (non-ICMP) : %lu\n", stats->network.ipv4);
    fprintf(out, "  IPv6            : %lu\n", stats->network.ipv6);
    fprintf(out, "  ICMP            : %lu\n", stats->network.icmp);
    fprintf(out, "  other           : %lu\n", stats->network.other);

    fprintf(out, "\nTransport layer:\n");
    fprintf(out, "  TCP             : %lu\n", stats->transport.tcp);
    fprintf(out, "  UDP             : %lu\n", stats->transport.udp);
    fprintf(out, "  other           : %lu\n", stats->transport.other);

    fprintf(out, "\nApplication layer:\n");
    fprintf(out, "  HTTP            : %lu\n", stats->application.http);
    fprintf(out, "  HTTPS           : %lu\n", stats->application.https);
    fprintf(out, "  DNS             : %lu\n", stats->application.dns);
    fprintf(out, "  DHCP            : %lu\n", stats->application.dhcp);
    fprintf(out, "  NTP             : %lu\n", stats->application.ntp);
    fprintf(out, "  other           : %lu\n", stats->application.other);

    fprintf(out, "\n=== Per client (tunnel network %s0/24) ===\n", stats->client_prefix);
    if (stats->client_count == 0)
        fprintf(out, "(no client traffic seen yet)\n");

    for (int i = 0; i < stats->client_count; i++) {
        const struct client_stats *client = &stats->clients[i];
        fprintf(out, "Client %s:\n", client->ip);

        for (int j = 0; j < client->remote_count; j++) {
            const struct remote_stats *remote = &client->remotes[j];
            fprintf(out,
                    "  Remote %s: packets=%lu, bytes=%lu, TCP=%lu, UDP=%lu, ICMP=%lu, connections=%d\n",
                    remote->ip, remote->packets, remote->bytes, remote->tcp,
                    remote->udp, remote->icmp, remote->flow_count);

            for (int k = 0; k < remote->flow_count; k++) {
                const struct flow_stats *flow = &remote->flows[k];
                fprintf(out,
                        "    %s local_port=%u -> remote_port=%u: packets=%lu, bytes=%lu\n",
                        transport_proto_name(flow->transport), flow->local_port,
                        flow->remote_port, flow->packets, flow->bytes);
            }
        }
    }

    if (stats->dropped.clients || stats->dropped.remotes || stats->dropped.flows) {
        fprintf(out, "\nDropped (table full): clients=%lu, remotes=%lu, flows=%lu\n",
                stats->dropped.clients, stats->dropped.remotes, stats->dropped.flows);
    }

    fprintf(out, "\n(Press Ctrl+C to stop)\n");
    fflush(out);
}
