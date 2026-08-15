/*
 * main.c -- the capture loop.
 *
 * Everything that needs the operating system lives here: the raw socket, the
 * signal handler and the clock. The classification itself is in packet.c, the
 * accounting in stats.c and the files in csv.c, none of which know that a
 * socket exists -- which is why the tests can exercise them without root.
 */

#define _DEFAULT_SOURCE

#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <sys/socket.h>

#include <linux/if_ether.h>

#include "csv.h"
#include "packet.h"
#include "stats.h"

/* The largest an IP packet can be, so a capture is never truncated. */
#define CAPTURE_BUFFER 65536

/* Set from the signal handler; the only thing a handler here is allowed to
 * touch. Everything else -- closing files, printing the last panel -- happens
 * back in the loop, where it is safe to call stdio. */
static volatile sig_atomic_t running = 1;

static void handle_stop_signal(int signum)
{
    (void)signum;
    running = 0;
}

static void install_signal_handlers(void)
{
    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_handler = handle_stop_signal;

    /* No SA_RESTART: the point is for poll() to return EINTR so the loop gets
     * a chance to notice that `running` went to zero. */
    sigaction(SIGINT, &action, NULL);
    sigaction(SIGTERM, &action, NULL);
}

static void timestamp_now(char *buffer, size_t len)
{
    time_t now = time(NULL);
    struct tm parts;

    if (localtime_r(&now, &parts) == NULL) {
        snprintf(buffer, len, "-");
        return;
    }
    strftime(buffer, len, "%Y-%m-%d %H:%M:%S", &parts);
}

static void usage(const char *program)
{
    fprintf(stderr,
            "usage: %s <interface> [options]\n"
            "\n"
            "Classify every packet crossing an interface and write the capture to\n"
            "network_layer.csv, transport_layer.csv and application_layer.csv.\n"
            "\n"
            "options:\n"
            "  --output-dir DIR      write the CSV files into DIR (default: .)\n"
            "  --client-subnet PFX   treat addresses starting with PFX as clients\n"
            "                        (default: %s)\n"
            "  -h, --help            show this message\n"
            "\n"
            "The raw socket needs CAP_NET_RAW, so this normally runs under sudo:\n"
            "  sudo %s tun0\n",
            program, STATS_DEFAULT_CLIENT_PREFIX, program);
}

static int open_capture_socket(const char *interface)
{
    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) {
        perror("socket(AF_PACKET)");
        if (errno == EPERM)
            fprintf(stderr, "hint: a raw socket needs root or CAP_NET_RAW\n");
        return -1;
    }

    unsigned int index = if_nametoindex(interface);
    if (index == 0) {
        fprintf(stderr, "%s: %s\n", interface, strerror(errno));
        close(fd);
        return -1;
    }

    /* Binding to the interface is what limits the capture to one device;
     * without it an AF_PACKET socket sees every interface on the host. */
    struct sockaddr_ll address;
    memset(&address, 0, sizeof(address));
    address.sll_family = AF_PACKET;
    address.sll_ifindex = (int)index;
    address.sll_protocol = htons(ETH_P_ALL);

    if (bind(fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind");
        close(fd);
        return -1;
    }
    return fd;
}

int main(int argc, char *argv[])
{
    const char *interface = NULL;
    const char *output_dir = NULL;
    const char *client_subnet = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            return 0;
        }
        if (strcmp(argv[i], "--output-dir") == 0 && i + 1 < argc) {
            output_dir = argv[++i];
        } else if (strcmp(argv[i], "--client-subnet") == 0 && i + 1 < argc) {
            client_subnet = argv[++i];
        } else if (argv[i][0] == '-') {
            fprintf(stderr, "%s: unknown option '%s'\n", argv[0], argv[i]);
            usage(argv[0]);
            return 1;
        } else if (interface == NULL) {
            interface = argv[i];
        } else {
            fprintf(stderr, "%s: unexpected argument '%s'\n", argv[0], argv[i]);
            usage(argv[0]);
            return 1;
        }
    }

    if (interface == NULL) {
        usage(argv[0]);
        return 1;
    }

    /* A TUN device hands over bare IP packets with no link header, so the
     * decoder has to be told which kind of interface this is. */
    bool tun_interface = (strncmp(interface, "tun", 3) == 0);

    int socket_fd = open_capture_socket(interface);
    if (socket_fd < 0)
        return 1;

    struct csv_output output;
    if (!csv_output_open(&output, output_dir)) {
        close(socket_fd);
        return 1;
    }

    struct traffic_stats *stats = stats_create();
    if (stats == NULL) {
        fprintf(stderr, "not enough memory for the statistics tables\n");
        csv_output_close(&output);
        close(socket_fd);
        return 1;
    }
    if (client_subnet != NULL)
        stats_set_client_prefix(stats, client_subnet);

    install_signal_handlers();

    printf("=== Network traffic monitor (raw sockets) ===\n");
    printf("Interface    : %s%s\n", interface, tun_interface ? " (TUN, no link header)" : "");
    printf("Client subnet: %s0/24\n", stats->client_prefix);
    printf("Writing      : network_layer.csv, transport_layer.csv, application_layer.csv\n");
    fflush(stdout);

    static unsigned char buffer[CAPTURE_BUFFER];
    struct pollfd poll_fd = { .fd = socket_fd, .events = POLLIN, .revents = 0 };
    time_t last_print = 0;

    while (running) {
        /* The timeout is what keeps the panel alive on an idle link: without
         * it the loop would block in recv() and the display would freeze at
         * whatever the last packet left behind. */
        int ready = poll(&poll_fd, 1, 1000);
        if (ready < 0) {
            if (errno == EINTR)
                continue;
            perror("poll");
            break;
        }

        if (ready > 0 && (poll_fd.revents & POLLIN) != 0) {
            ssize_t received = recv(socket_fd, buffer, sizeof(buffer), 0);
            if (received < 0) {
                if (errno == EINTR)
                    continue;
                perror("recv");
                break;
            }

            if (received > 0) {
                struct packet pkt;
                if (packet_decode(buffer, (size_t)received, tun_interface, &pkt)) {
                    char timestamp[32];
                    timestamp_now(timestamp, sizeof(timestamp));
                    csv_output_write(&output, timestamp, &pkt);
                    stats_record(stats, &pkt);
                } else {
                    /* Too short or too damaged to classify: still traffic, so
                     * it is counted rather than silently ignored. */
                    stats_record_undecodable(stats);
                }
            }
        }

        time_t now = time(NULL);
        if (now != last_print) {
            last_print = now;
            stats_print(stats, stdout);
        }
    }

    printf("\nStopping.\n");
    stats_print(stats, stdout);

    csv_output_close(&output);
    stats_destroy(stats);
    close(socket_fd);
    return 0;
}
