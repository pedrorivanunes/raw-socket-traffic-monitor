/*
 * stats.h -- what the monitor accumulates while it runs.
 *
 * Two things live here: flat counters per layer, and a tree that answers the
 * question the assignment actually asked -- which client talked to which
 * remote host, over how many separate flows.
 *
 * All of it hangs off a `struct traffic_stats` that the caller owns, rather
 * than off file-scope variables. That is what lets a test start from an empty
 * table, feed it a handful of packets and check the result, without one test
 * leaking counts into the next.
 */

#ifndef STATS_H
#define STATS_H

#include <stdbool.h>
#include <stdio.h>

#include "packet.h"

/*
 * Fixed-size tables. A hash table would remove the ceilings, but the lab has
 * two clients, and a fixed array that reports what it dropped is easier to
 * reason about than a hash table nobody stress-tested. The drop counters below
 * are the price of that choice being visible instead of silent.
 *
 * The sizes are not free, and they multiply: the flow table is nested inside
 * the remote table, which is nested inside the client table, so the whole
 * structure costs roughly clients * remotes * flows * 24 bytes. At 32 x 128 x
 * 64 that is about 6 MB, which is why it is allocated with stats_create()
 * rather than declared as a local -- the first version of this used 64 x 256 x
 * 256 on the stack, which is 100 MB and crashes before main() does anything.
 */
#define STATS_MAX_CLIENTS 32
#define STATS_MAX_REMOTES 128
#define STATS_MAX_FLOWS 64

/* The tunnel subnet. A source or destination inside it is a client; anything
 * else is a remote host out on the Internet. */
#define STATS_DEFAULT_CLIENT_PREFIX "172.31.66."

struct flow_stats {
    transport_proto transport;
    uint16_t local_port;  /* the client side */
    uint16_t remote_port; /* the far side */
    unsigned long packets;
    unsigned long bytes;
};

struct remote_stats {
    char ip[INET6_ADDRSTRLEN];
    unsigned long packets;
    unsigned long bytes;
    unsigned long tcp;
    unsigned long udp;
    unsigned long icmp;

    struct flow_stats flows[STATS_MAX_FLOWS];
    int flow_count; /* also the number of distinct connections */
};

struct client_stats {
    char ip[INET6_ADDRSTRLEN];
    struct remote_stats remotes[STATS_MAX_REMOTES];
    int remote_count;
};

struct traffic_stats {
    /* The network-layer buckets are mutually exclusive and sum to the number
     * of frames classified: an ICMP packet is counted as ICMP, not as IPv4. */
    struct {
        unsigned long ipv4;
        unsigned long ipv6;
        unsigned long icmp;
        unsigned long other;
    } network;

    struct {
        unsigned long tcp;
        unsigned long udp;
        unsigned long other;
    } transport;

    struct {
        unsigned long http;
        unsigned long https;
        unsigned long dns;
        unsigned long dhcp;
        unsigned long ntp;
        unsigned long other;
    } application;

    /* Packets thrown away because one of the tables above was full. Reported
     * in the panel so a full table never looks like idle traffic. */
    struct {
        unsigned long clients;
        unsigned long remotes;
        unsigned long flows;
    } dropped;

    char client_prefix[INET6_ADDRSTRLEN];

    struct client_stats clients[STATS_MAX_CLIENTS];
    int client_count;
};

/*
 * Allocate a zeroed table with the default client prefix, or NULL if there is
 * no memory for it. The caller owns it and frees it with stats_destroy().
 */
struct traffic_stats *stats_create(void);
void stats_destroy(struct traffic_stats *stats);

/* Clear an existing table back to its initial state, keeping the allocation.
 * The tests use this to start each case from empty without allocating 6 MB
 * again every time. */
void stats_reset(struct traffic_stats *stats);

/* Override the tunnel subnet, e.g. "10.8.0.". */
void stats_set_client_prefix(struct traffic_stats *stats, const char *prefix);

bool stats_is_client(const struct traffic_stats *stats, const char *ip);

/* Fold one decoded packet into the counters and the client tree. */
void stats_record(struct traffic_stats *stats, const struct packet *pkt);

/* Count a frame that could not be classified at all. It is still traffic, so
 * it belongs in the totals rather than being dropped on the floor. */
void stats_record_undecodable(struct traffic_stats *stats);

/* Look up a client or one of its remotes; NULL when absent. Used by the tests
 * and by the panel. */
const struct client_stats *stats_find_client(const struct traffic_stats *stats,
                                             const char *ip);
const struct remote_stats *stats_find_remote(const struct client_stats *client,
                                             const char *ip);

void stats_print(const struct traffic_stats *stats, FILE *out);

#endif /* STATS_H */
